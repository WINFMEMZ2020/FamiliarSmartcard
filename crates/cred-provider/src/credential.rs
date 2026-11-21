//! Credential object: bound-user and explicit ("Other user") tiles, PIN/username
//! fields, isolated helper invocation, and `GetSerialization`.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard};
use windows::core::{
    implement, interface, Error as WinError, Ref, Result as WinResult, BOOL, HRESULT, PCWSTR, PWSTR,
};
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_OUTOFMEMORY, S_FALSE, S_OK};
use windows::Win32::Graphics::Gdi::{
    CreateDIBSection, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP,
};
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::UI::Shell::{
    ICredentialProviderCredential, ICredentialProviderCredentialEvents,
    ICredentialProviderCredential_Impl, ICredentialProviderCredential_Vtbl, CPFIS_FOCUSED,
    CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_HIDDEN, CPFT_EDIT_TEXT,
    CPFT_LARGE_TEXT, CPFT_PASSWORD_TEXT, CPFT_SMALL_TEXT, CPFT_SUBMIT_BUTTON, CPFT_TILE_IMAGE,
    CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR, CPSI_NONE,
    CPSI_WARNING, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
    CREDENTIAL_PROVIDER_STATUS_ICON, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};
use zeroize::Zeroizing;

/// Raw-ABI mirror of `ICredentialProviderCredential2` (`fd672c54-40ea-4d6e-9b49-cfb1a7507bd7`).
///
/// Defining the raw out-pointer signature directly allows `GetUserSid` to both
/// reject null `ppsz_sid` pointers (`E_INVALIDARG`) and explicitly write
/// `*ppsz_sid = nullptr` when returning `S_FALSE` for the "Other user" tile.
#[interface("fd672c54-40ea-4d6e-9b49-cfb1a7507bd7")]
pub unsafe trait IRawCredentialProviderCredential2: ICredentialProviderCredential {
    pub unsafe fn GetUserSid(&self, ppsz_sid: *mut PWSTR) -> HRESULT;
}

use crate::com_guard::guard_com;
use crate::guids::CLSID_FAMILIAR_SMARTCARD;
use crate::helper_client::{
    invoke_auth_helper, DEFAULT_HELPER_TIMEOUT_MS, TOUCH_HELPER_TIMEOUT_MS,
};
use crate::kerb::{negotiate_package, pack_kerb, protect_password};
use scard_core::ipc::{HelperIcon, HelperRequest, HelperResponse};
use scard_core::piv::{TOUCH_POLICY_ALWAYS, TOUCH_POLICY_CACHED};

const SFI_TILEIMAGE: u32 = 0;
const SFI_LABEL: u32 = 1;
const SFI_USERNAME: u32 = 2;
const SFI_PIN: u32 = 3;
const SFI_SUBMIT: u32 = 4;
const SFI_STATUS: u32 = 5;
const FIELD_COUNT: u32 = 6;

#[derive(Clone)]
enum TargetMode {
    /// Bound to a known local user tile enumerated by LogonUI.
    BoundUser {
        sid: String,
        domain: String,
        username: String,
    },
    /// Attached to Windows' "Other user" / empty-user-array logon flow.
    ExplicitUser,
}

struct CredentialMutable {
    typed_username: String,
    pin: Zeroizing<String>,
    status: String,
    events: Option<ICredentialProviderCredentialEvents>,
}

#[implement(ICredentialProviderCredential, IRawCredentialProviderCredential2)]
pub struct Credential {
    mode: TargetMode,
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    inner: Mutex<CredentialMutable>,
}

impl Credential {
    pub fn new_bound(
        sid: String,
        domain: String,
        username: String,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    ) -> Self {
        Self {
            mode: TargetMode::BoundUser {
                sid,
                domain,
                username,
            },
            cpus,
            inner: Mutex::new(CredentialMutable {
                typed_username: String::new(),
                pin: Zeroizing::new(String::new()),
                status: String::new(),
                events: None,
            }),
        }
    }

    pub fn new_explicit_user(cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO) -> Self {
        Self {
            mode: TargetMode::ExplicitUser,
            cpus,
            inner: Mutex::new(CredentialMutable {
                typed_username: String::new(),
                pin: Zeroizing::new(String::new()),
                status: String::new(),
                events: None,
            }),
        }
    }

    fn lock_inner(&self) -> MutexGuard<'_, CredentialMutable> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn is_explicit_user(&self) -> bool {
        matches!(self.mode, TargetMode::ExplicitUser)
    }

    fn clear_pin(&self) {
        let mut guard = self.lock_inner();
        guard.pin.clear();
    }

    fn set_status(&self, text: String) {
        let mut guard = self.lock_inner();
        guard.status = text;
    }

    fn status_text(&self) -> String {
        self.lock_inner().status.clone()
    }

    unsafe fn fail(
        &self,
        ppsz_status: *mut PWSTR,
        pcpsi: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
        text: String,
        icon: CREDENTIAL_PROVIDER_STATUS_ICON,
    ) {
        self.set_status(text.clone());
        if let Ok(allocated) = alloc_pwstr(&text) {
            // SAFETY: Caller verified `ppsz_status` and `pcpsi` are non-null.
            unsafe {
                *ppsz_status = allocated;
                *pcpsi = icon;
            }
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
        guard_com(|| {
            self.lock_inner().events = pcpce.clone();
            Ok(())
        })
    }

    fn UnAdvise(&self) -> WinResult<()> {
        guard_com(|| {
            self.lock_inner().events = None;
            Ok(())
        })
    }

    fn SetSelected(&self) -> WinResult<BOOL> {
        // Never auto-logon.
        Ok(BOOL(0))
    }

    fn SetDeselected(&self) -> WinResult<()> {
        guard_com(|| {
            self.clear_pin();
            Ok(())
        })
    }

    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> WinResult<()> {
        if pcpfs.is_null() || pcpfis.is_null() {
            return Err(E_INVALIDARG.into());
        }
        // SAFETY: Out-pointers verified non-null above.
        unsafe {
            *pcpfs = CPFS_HIDDEN;
            *pcpfis = CPFIS_NONE;
        }

        guard_com(|| {
            let (state, interactive) = match dwfieldid {
                // `CPFS_DISPLAY_IN_BOTH` is required by Windows 10/11 XAML LogonUI so the
                // "Sign-in options" icon bar renders our credential switch button!
                SFI_TILEIMAGE => (CPFS_DISPLAY_IN_BOTH, CPFIS_NONE),
                SFI_LABEL | SFI_SUBMIT => (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE),
                SFI_USERNAME => {
                    if self.is_explicit_user() {
                        (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED)
                    } else {
                        (CPFS_HIDDEN, CPFIS_NONE)
                    }
                }
                SFI_PIN => {
                    if self.is_explicit_user() {
                        (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE)
                    } else {
                        (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED)
                    }
                }
                SFI_STATUS => {
                    if self.status_text().is_empty() {
                        (CPFS_HIDDEN, CPFIS_NONE)
                    } else {
                        (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE)
                    }
                }
                _ => return Err(E_INVALIDARG.into()),
            };

            // SAFETY: Out-pointers verified non-null above.
            unsafe {
                *pcpfs = state;
                *pcpfis = interactive;
            }
            Ok(())
        })
    }

    fn GetStringValue(&self, dwfieldid: u32) -> WinResult<PWSTR> {
        guard_com(|| match dwfieldid {
            SFI_LABEL => alloc_pwstr("Sign in with RS-Key"),
            SFI_USERNAME => {
                let guard = self.lock_inner();
                alloc_pwstr(&guard.typed_username)
            }
            SFI_PIN => {
                let guard = self.lock_inner();
                alloc_pwstr(guard.pin.as_str())
            }
            SFI_SUBMIT => alloc_pwstr("Sign in"),
            SFI_STATUS => alloc_pwstr(&self.status_text()),
            _ => Err(E_NOTIMPL.into()),
        })
    }

    fn GetBitmapValue(&self, dwfieldid: u32) -> WinResult<HBITMAP> {
        guard_com(|| {
            if dwfieldid != SFI_TILEIMAGE {
                return Err(E_INVALIDARG.into());
            }
            create_rskey_tile_bitmap()
        })
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
        if psz.is_null() {
            return Err(E_INVALIDARG.into());
        }
        guard_com(|| match dwfieldid {
            SFI_USERNAME if self.is_explicit_user() => {
                // SAFETY: `psz` was checked non-null and is NUL-terminated per COM contract.
                let raw = unsafe { psz.to_string() }.unwrap_or_default();
                if raw.len() > 256 {
                    self.set_status("Username is too long.".into());
                    return Ok(());
                }
                self.lock_inner().typed_username = raw.trim().to_string();
                Ok(())
            }
            SFI_PIN => {
                // SAFETY: `psz` was checked non-null; copy directly into a `Zeroizing` string.
                let raw = Zeroizing::new(unsafe { psz.to_string() }.unwrap_or_default());
                let trimmed = raw.trim();
                if trimmed.len() > 16 {
                    self.set_status("PIN is too long.".into());
                    return Ok(());
                }
                let mut guard = self.lock_inner();
                guard.pin.clear();
                guard.pin.push_str(trimmed);
                Ok(())
            }
            _ => Err(E_NOTIMPL.into()),
        })
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
        if pcpgsr.is_null() || pcpcs.is_null() || ppsz_status.is_null() || pcpsi.is_null() {
            return Err(E_INVALIDARG.into());
        }
        // SAFETY: All four out-pointers verified non-null; fail-closed defaults set first.
        unsafe {
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            *ppsz_status = PWSTR::null();
            *pcpsi = CPSI_NONE;
            *pcpcs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION::default();
        }

        guard_com(|| {
            let (typed_username, pin_bytes) = {
                let guard = self.lock_inner();
                (
                    guard.typed_username.clone(),
                    Zeroizing::new(guard.pin.as_bytes().to_vec()),
                )
            };

            if pin_bytes.is_empty() {
                // SAFETY: Verified non-null above.
                unsafe {
                    self.fail(
                        ppsz_status,
                        pcpsi,
                        "Enter your RS-Key PIN.".into(),
                        CPSI_WARNING,
                    );
                }
                return Ok(());
            }
            if pin_bytes.len() < 6
                || pin_bytes.len() > 8
                || !pin_bytes.iter().all(|b| b.is_ascii_digit())
            {
                // SAFETY: Verified non-null above.
                unsafe {
                    self.fail(
                        ppsz_status,
                        pcpsi,
                        "PIV PIN must be 6-8 digits.".into(),
                        CPSI_WARNING,
                    );
                }
                return Ok(());
            }

            let computer = scard_core::account::computer_name().unwrap_or_else(|_| ".".into());

            let (sid, domain, username) = match &self.mode {
                TargetMode::BoundUser {
                    sid,
                    domain,
                    username,
                } => (sid.clone(), domain.clone(), username.clone()),
                TargetMode::ExplicitUser => {
                    if typed_username.is_empty() {
                        // SAFETY: Verified non-null above.
                        unsafe {
                            self.fail(
                                ppsz_status,
                                pcpsi,
                                "Enter your local Windows username.".into(),
                                CPSI_WARNING,
                            );
                        }
                        return Ok(());
                    }

                    // Uniform error message + small floor delay prevent local username enumeration
                    // when RDP is exposed without NLA.
                    match scard_core::account::lookup_local_account_by_name(&typed_username) {
                        Ok(info) if scard_core::storage::vault_exists(&info.sid) => {
                            (info.sid, info.domain, info.username)
                        }
                        _ => {
                            std::thread::sleep(std::time::Duration::from_millis(150));
                            // SAFETY: Verified non-null above.
                            unsafe {
                                self.fail(
                                    ppsz_status,
                                    pcpsi,
                                    "Sign-in failed. Verify the local username, RS-Key enrollment, and PIN."
                                        .into(),
                                    CPSI_ERROR,
                                );
                            }
                            return Ok(());
                        }
                    }
                }
            };

            let timeout_ms = match scard_core::storage::read_touch_policy(&sid) {
                Some(TOUCH_POLICY_ALWAYS) | Some(TOUCH_POLICY_CACHED) => TOUCH_HELPER_TIMEOUT_MS,
                _ => DEFAULT_HELPER_TIMEOUT_MS,
            };

            let req = HelperRequest {
                sid,
                username: username.clone(),
                computer,
                pin: pin_bytes,
            };

            let password = match invoke_auth_helper(&req, timeout_ms) {
                HelperResponse::Success { password } => password,
                HelperResponse::Failure { icon, message } => {
                    let cp_icon = match icon {
                        HelperIcon::None => CPSI_NONE,
                        HelperIcon::Warning => CPSI_WARNING,
                        HelperIcon::Error => CPSI_ERROR,
                    };
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(ppsz_status, pcpsi, message, cp_icon);
                    }
                    return Ok(());
                }
            };

            let protected = match protect_password(&password) {
                Ok(protected) => protected,
                Err(error) => {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            format!("CredProtect failed: {}", error.message()),
                            CPSI_ERROR,
                        );
                    }
                    return Ok(());
                }
            };

            let packed = match pack_kerb(&domain, &username, &protected, self.cpus) {
                Ok(packed) => packed,
                Err(error) => {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            format!("KERB packing failed: {}", error.message()),
                            CPSI_ERROR,
                        );
                    }
                    return Ok(());
                }
            };

            let package = match negotiate_package() {
                Ok(package) => package,
                Err(error) => {
                    // SAFETY: Free `packed.pointer` before returning error.
                    unsafe {
                        CoTaskMemFree(Some(packed.pointer as *const c_void));
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            format!("Negotiate package lookup failed: {}", error.message()),
                            CPSI_ERROR,
                        );
                    }
                    return Ok(());
                }
            };

            // SAFETY: Out-pointers verified non-null; ownership of `packed.pointer` transfers to LogonUI.
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
        })
    }

    fn ReportResult(
        &self,
        ntsstatus: windows::Win32::Foundation::NTSTATUS,
        _ntssubstatus: windows::Win32::Foundation::NTSTATUS,
        ppsz_status: *mut PWSTR,
        pcpsi: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> WinResult<()> {
        if ppsz_status.is_null() || pcpsi.is_null() {
            return Err(E_INVALIDARG.into());
        }
        // SAFETY: Out-pointers verified non-null.
        unsafe {
            *ppsz_status = PWSTR::null();
            *pcpsi = CPSI_NONE;
        }

        guard_com(|| {
            const STATUS_LOGON_FAILURE: u32 = 0xC000_006A;
            const STATUS_ACCOUNT_LOCKED_OUT: u32 = 0xC000_0234;
            const STATUS_PASSWORD_EXPIRED: u32 = 0xC000_0071;
            const STATUS_ACCOUNT_DISABLED: u32 = 0xC000_0072;

            let status = ntsstatus.0 as u32;
            let (message, icon) = if status == STATUS_LOGON_FAILURE {
                (
                    "Incorrect password. Check your recovery sheet or re-enroll.",
                    CPSI_ERROR,
                )
            } else if status == STATUS_ACCOUNT_LOCKED_OUT {
                ("The account is locked out.", CPSI_ERROR)
            } else if status == STATUS_PASSWORD_EXPIRED {
                (
                    "The password has expired; sign in with recovery password and re-enroll.",
                    CPSI_WARNING,
                )
            } else if status == STATUS_ACCOUNT_DISABLED {
                ("The account is disabled.", CPSI_ERROR)
            } else {
                ("Sign-in failed.", CPSI_ERROR)
            };
            // SAFETY: Out-pointers verified non-null.
            unsafe {
                self.fail(ppsz_status, pcpsi, message.into(), icon);
            }
            Ok(())
        })
    }
}

impl IRawCredentialProviderCredential2_Impl for Credential_Impl {
    unsafe fn GetUserSid(&self, ppsz_sid: *mut PWSTR) -> HRESULT {
        if ppsz_sid.is_null() {
            return E_INVALIDARG;
        }
        // SAFETY: Verified non-null; always initialize out-pointer to null per COM rules.
        unsafe {
            *ppsz_sid = PWSTR::null();
        }
        match guard_com(|| match &self.mode {
            TargetMode::BoundUser { sid, .. } => {
                let allocated = alloc_pwstr(sid)?;
                // SAFETY: Verified non-null above.
                unsafe {
                    *ppsz_sid = allocated;
                }
                Ok(S_OK)
            }
            // Returning `S_FALSE` (`0x00000001`) with `*ppsz_sid == nullptr` instructs
            // Windows LogonUI to associate this credential with the "Other user" tile.
            TargetMode::ExplicitUser => Ok(S_FALSE),
        }) {
            Ok(hr) => hr,
            Err(err) => err.code(),
        }
    }
}

pub fn field_descriptor(index: u32) -> WinResult<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
    let (label, cpft) = match index {
        SFI_TILEIMAGE => ("RS-Key", CPFT_TILE_IMAGE),
        SFI_LABEL => ("Sign in with RS-Key", CPFT_LARGE_TEXT),
        SFI_USERNAME => ("Username", CPFT_EDIT_TEXT),
        SFI_PIN => ("RS-Key PIN", CPFT_PASSWORD_TEXT),
        SFI_SUBMIT => ("Sign in", CPFT_SUBMIT_BUTTON),
        SFI_STATUS => ("Status", CPFT_SMALL_TEXT),
        _ => return Err(E_INVALIDARG.into()),
    };

    Ok(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
        dwFieldID: index,
        cpft,
        pszLabel: alloc_pwstr(label)?,
        guidFieldType: windows::core::GUID::zeroed(),
    })
}

pub fn field_count() -> u32 {
    FIELD_COUNT
}

/// Generate a crisp 48x48 32-bpp smart-card / security-key `HBITMAP` for the
/// Windows "Sign-in options" button. Ownership of the returned `HBITMAP` transfers
/// to `LogonUI.exe` (`DeleteObject`).
fn create_rskey_tile_bitmap() -> WinResult<HBITMAP> {
    const W: usize = 48;
    const H: usize = 48;
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: W as i32,
            // Top-down DIB
            biHeight: -(H as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            biSizeImage: (W * H * 4) as u32,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut bits_ptr: *mut c_void = std::ptr::null_mut();
    // SAFETY: Allocates a standalone 48x48 32-bit DIB section owned by caller.
    let hbmp = unsafe { CreateDIBSection(None, &bmi, DIB_RGB_COLORS, &mut bits_ptr, None, 0) }?;
    if bits_ptr.is_null() {
        return Err(WinError::from_hresult(E_OUTOFMEMORY));
    }

    // Draw a dark-blue rounded smart-card badge with a gold contact chip & key glyph (BGRA).
    // SAFETY: `bits_ptr` points to `W * H` initialized `u32` pixels.
    let pixels = unsafe { std::slice::from_raw_parts_mut(bits_ptr as *mut u32, W * H) };
    const BG_DARK: u32 = 0xFF1E_3A5F;
    const BORDER: u32 = 0xFF4A_90D9;
    const GOLD: u32 = 0xFFFF_C845;
    const WHITE: u32 = 0xFFF4_F7FA;

    for y in 0..H {
        for x in 0..W {
            let mut color = 0x0000_0000u32;
            // Card body: x in 4..44, y in 10..38
            if (4..44).contains(&x) && (10..38).contains(&y) {
                color = if x == 4 || x == 43 || y == 10 || y == 37 {
                    BORDER
                } else {
                    BG_DARK
                };
            }
            // Gold smart-card chip: x in 9..19, y in 18..28
            if (9..19).contains(&x) && (18..28).contains(&y) {
                color = GOLD;
            }
            // Key ring & shaft on right half of card
            let dx = x as isize - 26;
            let dy = y as isize - 24;
            let dist2 = dx * dx + dy * dy;
            let is_key_ring = (9..=20).contains(&dist2);
            let is_key_shaft = (30..40).contains(&x) && (23..=25).contains(&y);
            let is_key_teeth =
                ((35..=36).contains(&x) || (38..=39).contains(&x)) && (25..=28).contains(&y);
            if is_key_ring || is_key_shaft || is_key_teeth {
                color = WHITE;
            }
            pixels[y * W + x] = color;
        }
    }

    Ok(hbmp)
}

pub fn alloc_pwstr(value: &str) -> WinResult<PWSTR> {
    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| WinError::from_hresult(E_OUTOFMEMORY))?;
    // SAFETY: Allocates `bytes` from COM task memory.
    let pointer = unsafe { CoTaskMemAlloc(bytes) } as *mut u16;
    if pointer.is_null() {
        return Err(WinError::from_hresult(E_OUTOFMEMORY));
    }
    // SAFETY: `pointer` is non-null and holds `wide.len()` elements.
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), pointer, wide.len());
    }
    Ok(PWSTR(pointer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::Interface;
    use windows::Win32::UI::Shell::{ICredentialProviderCredential2, CPUS_LOGON};

    #[test]
    fn explicit_user_credential_returns_s_false_and_null_sid_over_com_vtable() {
        let base: ICredentialProviderCredential = Credential::new_explicit_user(CPUS_LOGON).into();
        // Cast to official Windows `ICredentialProviderCredential2` to verify exact IID & vtable ABI!
        let cred: ICredentialProviderCredential2 = base.cast().unwrap();
        let mut raw_sid = PWSTR(std::ptr::dangling_mut());
        // SAFETY: Direct vtable call mirrors exact `LogonUI.exe` invocation.
        let hr = unsafe { (Interface::vtable(&cred).GetUserSid)(cred.as_raw(), &mut raw_sid) };
        assert_eq!(hr, S_FALSE);
        assert!(raw_sid.is_null());

        // Null out-pointer must return `E_INVALIDARG`.
        // SAFETY: Testing null out-pointer defense.
        let null_hr =
            unsafe { (Interface::vtable(&cred).GetUserSid)(cred.as_raw(), std::ptr::null_mut()) };
        assert_eq!(null_hr, E_INVALIDARG);
    }

    #[test]
    fn bound_user_credential_returns_s_ok_and_allocated_sid() {
        let base: ICredentialProviderCredential = Credential::new_bound(
            "S-1-5-21-999-1001".into(),
            "MYPC".into(),
            "alice".into(),
            CPUS_LOGON,
        )
        .into();
        let cred: ICredentialProviderCredential2 = base.cast().unwrap();
        // SAFETY: Standard COM call; free returned string with `CoTaskMemFree`.
        unsafe {
            let sid_pwstr = cred.GetUserSid().unwrap();
            assert_eq!(sid_pwstr.to_string().unwrap(), "S-1-5-21-999-1001");
            CoTaskMemFree(Some(sid_pwstr.0 as *const c_void));
        }
    }

    #[test]
    fn credential_methods_reject_null_out_pointers_safely() {
        let cred: ICredentialProviderCredential = Credential::new_explicit_user(CPUS_LOGON).into();
        // SAFETY: Testing defensive null handling across COM boundary.
        unsafe {
            let mut state = CPFS_HIDDEN;
            assert_eq!(
                cred.GetFieldState(SFI_USERNAME, std::ptr::null_mut(), std::ptr::null_mut())
                    .unwrap_err()
                    .code(),
                E_INVALIDARG
            );
            let mut inter = CPFIS_NONE;
            cred.GetFieldState(SFI_USERNAME, &mut state, &mut inter)
                .unwrap();
            assert_eq!(state, CPFS_DISPLAY_IN_SELECTED_TILE);
            assert_eq!(inter, CPFIS_FOCUSED);

            // Tile image must be CPFS_DISPLAY_IN_BOTH with a valid HBITMAP so Windows 10/11
            // renders the "Sign-in options" icon bar on both user tiles and "Other user"!
            cred.GetFieldState(SFI_TILEIMAGE, &mut state, &mut inter)
                .unwrap();
            assert_eq!(state, CPFS_DISPLAY_IN_BOTH);
            let hbmp = cred.GetBitmapValue(SFI_TILEIMAGE).unwrap();
            assert!(!hbmp.is_invalid() && !hbmp.0.is_null());
            let _ = windows::Win32::Graphics::Gdi::DeleteObject(hbmp.into());

            assert_eq!(
                cred.GetSerialization(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                )
                .unwrap_err()
                .code(),
                E_INVALIDARG
            );
        }
    }
}
