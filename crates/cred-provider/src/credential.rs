//! Credential object: PIN field, UI projection, and GetSerialization.

use std::cell::RefCell;
use std::ffi::c_void;
use windows::core::{implement, Ref, Result as WinResult, BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::E_NOTIMPL;
use windows::Win32::Graphics::Gdi::HBITMAP;
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::UI::Shell::{
    ICredentialProviderCredential, ICredentialProviderCredential2,
    ICredentialProviderCredential2_Impl, ICredentialProviderCredentialEvents,
    ICredentialProviderCredential_Impl, CPFIS_NONE, CPFS_DISPLAY_IN_SELECTED_TILE, CPFT_LARGE_TEXT,
    CPFT_PASSWORD_TEXT, CPFT_SMALL_TEXT, CPFT_SUBMIT_BUTTON, CPFT_TILE_IMAGE,
    CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR, CPSI_NONE,
    CPSI_WARNING, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    CREDENTIAL_PROVIDER_STATUS_ICON, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};
use zeroize::Zeroizing;

use crate::guids::CLSID_FAMILIAR_SMARTCARD;
use crate::kerb::{negotiate_package, pack_kerb, protect_password};

const SFI_TILEIMAGE: u32 = 0;
const SFI_LABEL: u32 = 1;
const SFI_PIN: u32 = 2;
const SFI_SUBMIT: u32 = 3;
const SFI_STATUS: u32 = 4;
const FIELD_COUNT: u32 = 5;

#[implement(ICredentialProviderCredential, ICredentialProviderCredential2)]
pub struct Credential {
    sid: String,
    domain: String,
    username: String,
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    pin: RefCell<Zeroizing<String>>,
    status: RefCell<String>,
    events: RefCell<Option<ICredentialProviderCredentialEvents>>,
}

impl Credential {
    pub fn new(
        sid: String,
        domain: String,
        username: String,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    ) -> Self {
        Self {
            sid,
            domain,
            username,
            cpus,
            pin: RefCell::new(Zeroizing::new(String::new())),
            status: RefCell::new(String::new()),
            events: RefCell::new(None),
        }
    }

    fn clear_pin(&self) {
        let mut pin = self.pin.borrow_mut();
        pin.clear();
        pin.shrink_to_fit();
    }

    fn set_status(&self, text: String) {
        *self.status.borrow_mut() = text;
    }

    fn status_text(&self) -> String {
        self.status.borrow().clone()
    }

    fn fail(
        &self,
        ppsz_status: *mut PWSTR,
        pcpsi: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
        text: String,
        icon: CREDENTIAL_PROVIDER_STATUS_ICON,
    ) {
        self.set_status(text.clone());
        unsafe {
            *ppsz_status = alloc_pwstr(&text);
            *pcpsi = icon;
        }
        self.clear_pin();
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.clear_pin();
    }
}

impl ICredentialProviderCredential_Impl for Credential_Impl {
    fn Advise(&self, pcpce: Ref<'_, ICredentialProviderCredentialEvents>) -> WinResult<()> {
        *self.events.borrow_mut() = pcpce.clone();
        Ok(())
    }

    fn UnAdvise(&self) -> WinResult<()> {
        *self.events.borrow_mut() = None;
        Ok(())
    }

    fn SetSelected(&self) -> WinResult<BOOL> {
        // Never auto-logon.
        Ok(BOOL(0))
    }

    fn SetDeselected(&self) -> WinResult<()> {
        self.clear_pin();
        Ok(())
    }

    fn GetFieldState(
        &self,
        _dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> WinResult<()> {
        unsafe {
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            *pcpfis = CPFIS_NONE;
        }
        Ok(())
    }

    fn GetStringValue(&self, dwfieldid: u32) -> WinResult<PWSTR> {
        let value = match dwfieldid {
            SFI_LABEL => "Sign in with RS-Key".to_string(),
            SFI_PIN => self.pin.borrow().to_string(),
            SFI_SUBMIT => "Sign in".to_string(),
            SFI_STATUS => self.status_text(),
            _ => return Err(E_NOTIMPL.into()),
        };
        Ok(alloc_pwstr(&value))
    }

    fn GetBitmapValue(&self, _dwfieldid: u32) -> WinResult<HBITMAP> {
        Err(E_NOTIMPL.into())
    }

    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetSubmitButtonValue(&self, dwfieldid: u32) -> WinResult<u32> {
        if dwfieldid == SFI_SUBMIT {
            Ok(SFI_PIN)
        } else {
            Err(E_NOTIMPL.into())
        }
    }

    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32,
    ) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> WinResult<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn SetStringValue(&self, dwfieldid: u32, psz: &PCWSTR) -> WinResult<()> {
        if dwfieldid != SFI_PIN {
            return Err(E_NOTIMPL.into());
        }
        let value = unsafe { psz.to_string() }.unwrap_or_default();
        let value = value.trim().to_string();
        if value.len() > 16 {
            self.set_status("PIN is too long.".into());
            return Ok(());
        }
        let mut pin = self.pin.borrow_mut();
        pin.clear();
        pin.push_str(&value);
        Ok(())
    }

    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn SetComboBoxSelectedValue(&self, _dwfieldid: u32, _dwselecteditem: u32) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn CommandLinkClicked(&self, _dwfieldid: u32) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        ppsz_status: *mut PWSTR,
        pcpsi: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> WinResult<()> {
        unsafe {
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            *ppsz_status = PWSTR::null();
            *pcpsi = CPSI_NONE;
            *pcpcs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION::default();
        }

        let pin_text = self.pin.borrow().to_string();
        if pin_text.is_empty() {
            self.fail(
                ppsz_status,
                pcpsi,
                "Enter your RS-Key PIN.".into(),
                CPSI_WARNING,
            );
            return Ok(());
        }
        if pin_text.len() < 6 || pin_text.len() > 8 || !pin_text.chars().all(|c| c.is_ascii_digit())
        {
            self.fail(
                ppsz_status,
                pcpsi,
                "PIV PIN must be 6-8 digits.".into(),
                CPSI_WARNING,
            );
            return Ok(());
        }

        scard_core::storage::debug_log(&format!(
            "GetSerialization sid={} user={}",
            self.sid, self.username
        ));
        let vault = match scard_core::storage::read_vault(&self.sid) {
            Ok(Some(vault)) => vault,
            Ok(None) => {
                self.fail(
                    ppsz_status,
                    pcpsi,
                    "This account is not bound to an RS-Key.".into(),
                    CPSI_ERROR,
                );
                return Ok(());
            }
            Err(error) => {
                self.fail(ppsz_status, pcpsi, error.to_string(), CPSI_ERROR);
                return Ok(());
            }
        };

        let current_last_set = match scard_core::account::password_last_set(&self.username) {
            Ok(value) => value,
            Err(error) => {
                self.fail(ppsz_status, pcpsi, error.to_string(), CPSI_ERROR);
                return Ok(());
            }
        };
        if !scard_core::vault::password_last_set_matches(vault.password_last_set, current_last_set)
        {
            self.fail(
                ppsz_status,
                pcpsi,
                "The Windows password has changed; re-enrollment is required.".into(),
                CPSI_ERROR,
            );
            return Ok(());
        }

        let computer = scard_core::account::computer_name().unwrap_or_else(|_| ".".into());
        let mut pin_bytes = Zeroizing::new(pin_text.into_bytes());
        let password = match scard_core::unlock(
            vault,
            &self.sid,
            &self.username,
            &computer,
            None,
            &mut pin_bytes,
        ) {
            Ok(password) => password,
            Err(error) => {
                self.fail(ppsz_status, pcpsi, error.to_string(), CPSI_ERROR);
                return Ok(());
            }
        };

        let protected = match protect_password(&password) {
            Ok(protected) => protected,
            Err(error) => {
                self.fail(
                    ppsz_status,
                    pcpsi,
                    format!("CredProtect failed: {error}"),
                    CPSI_ERROR,
                );
                return Ok(());
            }
        };

        let packed = match pack_kerb(&self.domain, &self.username, &protected, self.cpus) {
            Ok(packed) => packed,
            Err(error) => {
                self.fail(
                    ppsz_status,
                    pcpsi,
                    format!("KERB packing failed: {error}"),
                    CPSI_ERROR,
                );
                return Ok(());
            }
        };

        let package = match negotiate_package() {
            Ok(package) => package,
            Err(error) => {
                unsafe {
                    CoTaskMemFree(Some(packed.pointer as *const c_void));
                }
                self.fail(
                    ppsz_status,
                    pcpsi,
                    format!("Negotiate package lookup failed: {error}"),
                    CPSI_ERROR,
                );
                return Ok(());
            }
        };

        unsafe {
            (*pcpcs).ulAuthenticationPackage = package;
            (*pcpcs).clsidCredentialProvider = CLSID_FAMILIAR_SMARTCARD;
            (*pcpcs).cbSerialization = packed.length;
            (*pcpcs).rgbSerialization = packed.pointer;
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
        self.set_status("Signing in...".into());
        self.clear_pin();
        Ok(())
    }

    fn ReportResult(
        &self,
        ntsstatus: windows::Win32::Foundation::NTSTATUS,
        _ntssubstatus: windows::Win32::Foundation::NTSTATUS,
        ppsz_status: *mut PWSTR,
        pcpsi: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> WinResult<()> {
        const STATUS_LOGON_FAILURE: u32 = 0xC000_006A;
        const STATUS_ACCOUNT_LOCKED_OUT: u32 = 0xC000_0234;
        const STATUS_PASSWORD_EXPIRED: u32 = 0xC000_0071;
        const STATUS_ACCOUNT_DISABLED: u32 = 0xC000_0072;

        let status = ntsstatus.0 as u32;
        let (message, icon) = if status == STATUS_LOGON_FAILURE {
            (
                "Incorrect password. Check the recovery sheet or re-enroll.",
                CPSI_ERROR,
            )
        } else if status == STATUS_ACCOUNT_LOCKED_OUT {
            ("The account is locked out.", CPSI_ERROR)
        } else if status == STATUS_PASSWORD_EXPIRED {
            (
                "The password has expired; re-enrollment is required.",
                CPSI_WARNING,
            )
        } else if status == STATUS_ACCOUNT_DISABLED {
            ("The account is disabled.", CPSI_ERROR)
        } else {
            ("Sign-in failed.", CPSI_ERROR)
        };
        self.fail(ppsz_status, pcpsi, message.into(), icon);
        Ok(())
    }
}

impl ICredentialProviderCredential2_Impl for Credential_Impl {
    fn GetUserSid(&self) -> WinResult<PWSTR> {
        Ok(alloc_pwstr(&self.sid))
    }
}

pub fn field_descriptor(index: u32) -> WinResult<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
    let (label, cpft) = match index {
        SFI_TILEIMAGE => ("RS-Key", CPFT_TILE_IMAGE),
        SFI_LABEL => ("Sign in with RS-Key", CPFT_LARGE_TEXT),
        SFI_PIN => ("PIN", CPFT_PASSWORD_TEXT),
        SFI_SUBMIT => ("Sign in", CPFT_SUBMIT_BUTTON),
        SFI_STATUS => ("Status", CPFT_SMALL_TEXT),
        _ => return Err(E_NOTIMPL.into()),
    };

    Ok(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
        dwFieldID: index,
        cpft,
        pszLabel: alloc_pwstr(label),
        guidFieldType: windows::core::GUID::zeroed(),
    })
}

pub fn field_count() -> u32 {
    FIELD_COUNT
}

pub fn alloc_pwstr(value: &str) -> PWSTR {
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide.len() * std::mem::size_of::<u16>();
    let pointer = unsafe { CoTaskMemAlloc(bytes) } as *mut u16;
    if pointer.is_null() {
        return PWSTR::null();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), pointer, wide.len());
    }
    PWSTR(pointer)
}
