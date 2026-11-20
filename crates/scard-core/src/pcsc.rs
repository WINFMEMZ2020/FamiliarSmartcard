//! Thin synchronous RAII wrapper around Windows PC/SC (`winscard.dll`).
//!
//! Design rules:
//! - no background threads;
//! - one card handle per authentication attempt;
//! - a multi-APDU sequence must hold a transaction;
//! - `Drop` resets the card so a verified PIN is not left alive.

use crate::error::{AuthError, Result};
use std::mem::size_of;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Security::Credentials::{
    SCardBeginTransaction, SCardCancel, SCardConnectW, SCardDisconnect, SCardEndTransaction,
    SCardEstablishContext, SCardGetAttrib, SCardListReadersW, SCardReleaseContext, SCardTransmit,
    SCARD_IO_REQUEST, SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCARD_SCOPE_USER, SCARD_SHARE_SHARED,
};

/// `SCARD_S_SUCCESS`
const SCARD_S_SUCCESS: i32 = 0;
/// `SCARD_E_NO_READERS_AVAILABLE`
const SCARD_E_NO_READERS_AVAILABLE: i32 = 0x8010_002E_u32 as i32;
/// `SCARD_E_NO_SMARTCARD`
const SCARD_E_NO_SMARTCARD: i32 = 0x8010_000E_u32 as i32;
/// `SCARD_W_REMOVED_CARD`
const SCARD_W_REMOVED_CARD: i32 = 0x8010_0069_u32 as i32;
/// `SCARD_E_SHARING_VIOLATION`
const SCARD_E_SHARING_VIOLATION: i32 = 0x8010_000B_u32 as i32;
/// `SCARD_E_CANCELLED`
const SCARD_E_CANCELLED: i32 = 0x8010_0002_u32 as i32;
/// `SCARD_E_TIMEOUT`
const SCARD_E_TIMEOUT: i32 = 0x8010_000A_u32 as i32;

/// OpenPGP AID: selecting another applet destroys the PIV PIN verification
/// state on RS-Key. Used only as a reset fallback.
const OPENPGP_AID_SELECT: [u8; 11] = [
    0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
];

/// `SCARD_LEAVE_CARD`
pub const SCARD_LEAVE_CARD: u32 = 0;
/// `SCARD_RESET_CARD`
pub const SCARD_RESET_CARD: u32 = 1;
/// `SCARD_UNPOWER_CARD`
pub const SCARD_UNPOWER_CARD: u32 = 2;

/// `SCARD_ATTR_ATR_STRING` = `SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, 0x0303)`
const SCARD_ATTR_ATR_STRING: u32 = 0x0009_0303;

fn pcsc_error(rc: i32) -> AuthError {
    match rc {
        SCARD_E_NO_SMARTCARD | SCARD_W_REMOVED_CARD => AuthError::NoCard,
        SCARD_E_SHARING_VIOLATION => AuthError::CardBusy,
        SCARD_E_CANCELLED | SCARD_E_TIMEOUT => AuthError::Timeout,
        _ => AuthError::Pcsc(rc),
    }
}

/// PC/SC resource-manager context. Dropping it releases the context.
pub struct ScardContext {
    handle: usize,
}

impl ScardContext {
    pub fn new() -> Result<Self> {
        let mut handle = 0usize;
        let rc = unsafe { SCardEstablishContext(SCARD_SCOPE_USER, None, None, &mut handle) };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        Ok(Self { handle })
    }

    pub fn handle(&self) -> usize {
        self.handle
    }

    /// Best-effort cancellation of outstanding blocking PC/SC calls.
    ///
    /// `SCardCancel` cancels actions waiting for the card/user, but it is not a
    /// hard guarantee for a driver-level hang. The caller should use a helper
    /// process or a watchdog for a hard timeout.
    pub fn cancel(&self) -> Result<()> {
        let rc = unsafe { SCardCancel(self.handle) };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        Ok(())
    }

    /// Enumerate all readers. Returns an empty vector when no reader exists.
    pub fn list_readers(&self) -> Result<Vec<String>> {
        let mut len = 0u32;
        let rc = unsafe { SCardListReadersW(self.handle, PCWSTR::null(), None, &mut len) };
        if rc == SCARD_E_NO_READERS_AVAILABLE {
            return Ok(Vec::new());
        }
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u16; len as usize + 1];
        let rc = unsafe {
            SCardListReadersW(
                self.handle,
                PCWSTR::null(),
                Some(PWSTR(buffer.as_mut_ptr())),
                &mut len,
            )
        };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }

        let mut readers = Vec::new();
        let mut start = 0usize;
        for i in 0..len as usize {
            if buffer[i] == 0 {
                if i > start {
                    readers.push(String::from_utf16_lossy(&buffer[start..i]));
                }
                start = i + 1;
            }
        }
        Ok(readers)
    }

    pub fn connect(&self, reader: &str) -> Result<ScardCard> {
        let reader_w: Vec<u16> = reader.encode_utf16().chain(std::iter::once(0)).collect();
        let mut card = 0usize;
        let mut protocol = 0u32;
        let rc = unsafe {
            SCardConnectW(
                self.handle,
                PCWSTR(reader_w.as_ptr()),
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                &mut card,
                &mut protocol,
            )
        };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        Ok(ScardCard {
            handle: card,
            protocol,
            in_transaction: false,
            disconnected: false,
        })
    }
}

impl Drop for ScardContext {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                let _ = SCardReleaseContext(self.handle);
            }
            self.handle = 0;
        }
    }
}

/// An open smart-card handle.
///
/// `Drop` always tries to end a transaction with `SCARD_RESET_CARD` and then
/// disconnect with `SCARD_RESET_CARD`. A card that loses power or is reset
/// drops any cached PIN verification state.
pub struct ScardCard {
    handle: usize,
    protocol: u32,
    in_transaction: bool,
    disconnected: bool,
}

impl ScardCard {
    pub fn protocol(&self) -> u32 {
        self.protocol
    }

    pub fn begin_transaction(&mut self) -> Result<()> {
        if self.in_transaction {
            return Ok(());
        }
        let rc = unsafe { SCardBeginTransaction(self.handle) };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        self.in_transaction = true;
        Ok(())
    }

    pub fn end_transaction(&mut self, disposition: u32) -> Result<()> {
        if !self.in_transaction {
            return Ok(());
        }
        let rc = unsafe { SCardEndTransaction(self.handle, disposition) };
        self.in_transaction = false;
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        Ok(())
    }

    /// Send one APDU and return the raw response (data + SW1SW2).
    pub fn transmit(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        let io = SCARD_IO_REQUEST {
            dwProtocol: self.protocol,
            cbPciLength: size_of::<SCARD_IO_REQUEST>() as u32,
        };
        let mut response = vec![0u8; 65536];
        let mut response_len = response.len() as u32;
        let rc = unsafe {
            SCardTransmit(
                self.handle,
                &io,
                apdu,
                None,
                response.as_mut_ptr(),
                &mut response_len,
            )
        };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        response.truncate(response_len as usize);
        Ok(response)
    }

    /// Read the ATR via `SCARD_ATTR_ATR_STRING`.
    pub fn atr(&self) -> Result<Vec<u8>> {
        let mut len = 0u32;
        let rc = unsafe { SCardGetAttrib(self.handle, SCARD_ATTR_ATR_STRING, None, &mut len) };
        if rc != SCARD_S_SUCCESS || len == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0u8; len as usize];
        let rc = unsafe {
            SCardGetAttrib(
                self.handle,
                SCARD_ATTR_ATR_STRING,
                Some(buffer.as_mut_ptr()),
                &mut len,
            )
        };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        buffer.truncate(len as usize);
        Ok(buffer)
    }

    /// Explicitly disconnect. Consuming `self` prevents accidental reuse.
    pub fn disconnect(mut self, disposition: u32) -> Result<()> {
        if self.in_transaction {
            let _ = self.end_transaction(disposition);
        }
        let rc = unsafe { SCardDisconnect(self.handle, disposition) };
        self.disconnected = true;
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        Ok(())
    }
}

impl Drop for ScardCard {
    fn drop(&mut self) {
        if self.disconnected {
            return;
        }

        if self.in_transaction {
            let reset = unsafe { SCardEndTransaction(self.handle, SCARD_RESET_CARD) };
            if reset != SCARD_S_SUCCESS {
                // Reset failed. Switching applets destroys the PIV PIN session
                // on RS-Key; then try the stronger unpower path.
                let _ = self.transmit(&OPENPGP_AID_SELECT);
                let _ = unsafe { SCardEndTransaction(self.handle, SCARD_UNPOWER_CARD) };
            }
            self.in_transaction = false;
        }

        let disconnect = unsafe { SCardDisconnect(self.handle, SCARD_RESET_CARD) };
        if disconnect != SCARD_S_SUCCESS {
            let _ = unsafe { SCardDisconnect(self.handle, SCARD_UNPOWER_CARD) };
        }
        self.disconnected = true;
    }
}
