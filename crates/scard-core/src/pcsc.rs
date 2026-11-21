//! Thin synchronous RAII wrapper around Windows PC/SC (`winscard.dll`).
//!
//! Design rules:
//! - no background threads inside core;
//! - one card handle per authentication attempt;
//! - a multi-APDU sequence must hold a transaction;
//! - read-only probing leaves non-matching cards untouched (`SCARD_LEAVE_CARD`);
//! - once PIN verification is attempted, `Drop` resets the card (`SCARD_RESET_CARD`).

#![deny(unsafe_op_in_unsafe_fn)]

use crate::error::{AuthError, Result};
use crate::piv::ApduTransport;
use std::cell::Cell;
use std::mem::size_of;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Security::Credentials::{
    SCardBeginTransaction, SCardCancel, SCardConnectW, SCardDisconnect, SCardEndTransaction,
    SCardEstablishContext, SCardGetAttrib, SCardListReadersW, SCardReleaseContext, SCardTransmit,
    SCARD_IO_REQUEST, SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCARD_SCOPE_USER, SCARD_SHARE_SHARED,
};

const SCARD_S_SUCCESS: i32 = 0;
const SCARD_E_NO_READERS_AVAILABLE: i32 = 0x8010_002E_u32 as i32;
const SCARD_E_NO_SMARTCARD: i32 = 0x8010_000E_u32 as i32;
const SCARD_W_REMOVED_CARD: i32 = 0x8010_0069_u32 as i32;
const SCARD_E_READER_UNAVAILABLE: i32 = 0x8010_0017_u32 as i32;
const SCARD_E_NO_SERVICE: i32 = 0x8010_001D_u32 as i32;
const SCARD_E_SERVICE_STOPPED: i32 = 0x8010_001E_u32 as i32;
const SCARD_E_COMM_DATA_LOST: i32 = 0x8010_002F_u32 as i32;
const SCARD_E_SHARING_VIOLATION: i32 = 0x8010_000B_u32 as i32;
const SCARD_E_CANCELLED: i32 = 0x8010_0002_u32 as i32;
const SCARD_E_TIMEOUT: i32 = 0x8010_000A_u32 as i32;

/// OpenPGP AID: selecting another applet clears transient PIV PIN verification
/// state on multi-applet PIV smart cards. Used only as a reset fallback when communication is alive.
const OPENPGP_AID_SELECT: [u8; 11] = [
    0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
];

pub const SCARD_LEAVE_CARD: u32 = 0;
pub const SCARD_RESET_CARD: u32 = 1;
pub const SCARD_UNPOWER_CARD: u32 = 2;

const SCARD_ATTR_ATR_STRING: u32 = 0x0009_0303;

fn pcsc_error(rc: i32) -> AuthError {
    match rc {
        SCARD_E_NO_SMARTCARD | SCARD_W_REMOVED_CARD => AuthError::NoCard,
        SCARD_E_READER_UNAVAILABLE | SCARD_E_NO_READERS_AVAILABLE => AuthError::NoReader,
        SCARD_E_SHARING_VIOLATION => AuthError::CardBusy,
        SCARD_E_CANCELLED | SCARD_E_TIMEOUT => AuthError::Timeout,
        _ => AuthError::Pcsc(rc),
    }
}

fn is_dead_channel_rc(rc: i32) -> bool {
    matches!(
        rc,
        SCARD_E_NO_SMARTCARD
            | SCARD_W_REMOVED_CARD
            | SCARD_E_READER_UNAVAILABLE
            | SCARD_E_NO_SERVICE
            | SCARD_E_SERVICE_STOPPED
            | SCARD_E_COMM_DATA_LOST
            | SCARD_E_CANCELLED
            | SCARD_E_TIMEOUT
    )
}

/// PC/SC resource-manager context. Dropping it releases the context.
pub struct ScardContext {
    handle: usize,
}

impl ScardContext {
    pub fn new() -> Result<Self> {
        let mut handle = 0usize;
        // SAFETY: `handle` is a valid out-pointer. `SCARD_SCOPE_USER` binds to the
        // calling session so RDP Smart Card Redirection sees client readers.
        let rc = unsafe { SCardEstablishContext(SCARD_SCOPE_USER, None, None, &mut handle) };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        Ok(Self { handle })
    }

    pub fn handle(&self) -> usize {
        self.handle
    }

    pub fn cancel(&self) -> Result<()> {
        // SAFETY: `self.handle` is a valid established context.
        let rc = unsafe { SCardCancel(self.handle) };
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        Ok(())
    }

    /// Enumerate all readers. Returns an empty vector when no reader exists.
    pub fn list_readers(&self) -> Result<Vec<String>> {
        let mut len = 0u32;
        // SAFETY: First call queries required UTF-16 buffer length.
        let rc = unsafe { SCardListReadersW(self.handle, PCWSTR::null(), None, &mut len) };
        if rc == SCARD_E_NO_READERS_AVAILABLE {
            return Ok(Vec::new());
        }
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        if len == 0 || len > 65536 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u16; len as usize + 1];
        // SAFETY: `buffer` has at least `len + 1` elements.
        let rc = unsafe {
            SCardListReadersW(
                self.handle,
                PCWSTR::null(),
                Some(PWSTR(buffer.as_mut_ptr())),
                &mut len,
            )
        };
        if rc == SCARD_E_NO_READERS_AVAILABLE {
            return Ok(Vec::new());
        }
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }

        let valid_len = (len as usize).min(buffer.len());
        let mut readers = Vec::new();
        let mut start = 0usize;
        for i in 0..valid_len {
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
        // SAFETY: `reader_w` is NUL-terminated; `card` and `protocol` are valid out-pointers.
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
            pin_attempted: Cell::new(false),
        })
    }
}

impl Drop for ScardContext {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: `self.handle` was created by `SCardEstablishContext` and not yet released.
            unsafe {
                let _ = SCardReleaseContext(self.handle);
            }
            self.handle = 0;
        }
    }
}

/// An open smart-card handle.
///
/// Before any PIN operation is attempted, dropping the handle leaves the card
/// untouched (`SCARD_LEAVE_CARD`) so non-matching readers/cards are not reset.
/// Once `mark_pin_attempted()` has been called, dropping always resets (or
/// unpowers) the card so a verified PIN session can never linger.
pub struct ScardCard {
    handle: usize,
    protocol: u32,
    in_transaction: bool,
    disconnected: bool,
    pin_attempted: Cell<bool>,
}

impl ScardCard {
    pub fn protocol(&self) -> u32 {
        self.protocol
    }

    pub fn begin_transaction(&mut self) -> Result<()> {
        if self.in_transaction {
            return Ok(());
        }
        // SAFETY: `self.handle` is an open card connection.
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
        // SAFETY: `self.handle` is in an active transaction.
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
        // SAFETY: `io`, `apdu`, and `response` are valid buffers for the duration of the call.
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
        response.truncate((response_len as usize).min(response.len()));
        Ok(response)
    }

    /// Read the ATR via `SCARD_ATTR_ATR_STRING`.
    pub fn atr(&self) -> Result<Vec<u8>> {
        let mut len = 0u32;
        // SAFETY: Queries required buffer size for ATR.
        let rc = unsafe { SCardGetAttrib(self.handle, SCARD_ATTR_ATR_STRING, None, &mut len) };
        if rc != SCARD_S_SUCCESS || len == 0 || len > 1024 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0u8; len as usize];
        // SAFETY: `buffer` has `len` bytes capacity.
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
        buffer.truncate((len as usize).min(buffer.len()));
        Ok(buffer)
    }

    /// Explicitly disconnect. Consuming `self` prevents accidental reuse.
    pub fn disconnect(mut self, disposition: u32) -> Result<()> {
        let effective = if self.pin_attempted.get() && disposition == SCARD_LEAVE_CARD {
            SCARD_RESET_CARD
        } else {
            disposition
        };
        if self.in_transaction {
            let _ = self.end_transaction(effective);
        }
        // SAFETY: `self.handle` is an open card connection.
        let rc = unsafe { SCardDisconnect(self.handle, effective) };
        self.disconnected = true;
        if rc != SCARD_S_SUCCESS {
            return Err(pcsc_error(rc));
        }
        Ok(())
    }
}

impl ApduTransport for ScardCard {
    fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.transmit(apdu)
    }

    fn mark_pin_attempted(&self) {
        self.pin_attempted.set(true);
    }
}

impl Drop for ScardCard {
    fn drop(&mut self) {
        if self.disconnected {
            return;
        }

        if !self.pin_attempted.get() {
            if self.in_transaction {
                // SAFETY: Valid handle in transaction; leave non-matching card undisturbed.
                let _ = unsafe { SCardEndTransaction(self.handle, SCARD_LEAVE_CARD) };
                self.in_transaction = false;
            }
            // SAFETY: Valid open card handle.
            let _ = unsafe { SCardDisconnect(self.handle, SCARD_LEAVE_CARD) };
            self.disconnected = true;
            return;
        }

        if self.in_transaction {
            // SAFETY: Valid handle in transaction; reset clears PIV PIN state.
            let reset = unsafe { SCardEndTransaction(self.handle, SCARD_RESET_CARD) };
            if reset != SCARD_S_SUCCESS {
                if !is_dead_channel_rc(reset) {
                    let _ = self.transmit(&OPENPGP_AID_SELECT);
                }
                // SAFETY: Fallback to unpower if reset failed.
                let _ = unsafe { SCardEndTransaction(self.handle, SCARD_UNPOWER_CARD) };
            }
            self.in_transaction = false;
        }

        // SAFETY: Valid open card handle.
        let disconnect = unsafe { SCardDisconnect(self.handle, SCARD_RESET_CARD) };
        if disconnect != SCARD_S_SUCCESS {
            // SAFETY: Fallback to unpower on disconnect.
            let _ = unsafe { SCardDisconnect(self.handle, SCARD_UNPOWER_CARD) };
        }
        self.disconnected = true;
    }
}
