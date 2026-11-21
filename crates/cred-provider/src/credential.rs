//! Credential object: bound-user and explicit ("Other user") tiles, PIN/username
//! fields, in-place PUK PIN-unblock workflow, isolated helper invocation, and
//! `GetSerialization`.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard};
use windows::core::{
    implement, interface, w, Error as WinError, IUnknownImpl, Ref, Result as WinResult, BOOL,
    HRESULT, PCWSTR, PWSTR,
};
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_OUTOFMEMORY, S_FALSE, S_OK};
use windows::Win32::Graphics::Gdi::{
    CreateDIBSection, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP,
};
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::UI::Shell::{
    ICredentialProviderCredential, ICredentialProviderCredentialEvents,
    ICredentialProviderCredential_Impl, ICredentialProviderCredential_Vtbl, CPFIS_FOCUSED,
    CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_HIDDEN,
    CPFT_COMMAND_LINK, CPFT_EDIT_TEXT, CPFT_LARGE_TEXT, CPFT_PASSWORD_TEXT, CPFT_SMALL_TEXT,
    CPFT_SUBMIT_BUTTON, CPFT_TILE_IMAGE, CPGSR_NO_CREDENTIAL_NOT_FINISHED,
    CPGSR_RETURN_CREDENTIAL_FINISHED, CPSI_ERROR, CPSI_NONE, CPSI_WARNING,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_STATUS_ICON,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO,
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
use scard_core::crypto::constant_time_eq;
use scard_core::ipc::{
    HelperFailureReason, HelperIcon, HelperOperation, HelperRequest, HelperResponse,
};
use scard_core::piv::{TOUCH_POLICY_ALWAYS, TOUCH_POLICY_CACHED};

const SFI_TILEIMAGE: u32 = 0;
const SFI_LABEL: u32 = 1;
const SFI_USERNAME: u32 = 2;
const SFI_PIN: u32 = 3;
const SFI_PUK: u32 = 4;
const SFI_NEW_PIN: u32 = 5;
const SFI_CONFIRM_PIN: u32 = 6;
const SFI_SUBMIT: u32 = 7;
const SFI_STATUS: u32 = 8;
const SFI_TOGGLE_MODE: u32 = 9;
const FIELD_COUNT: u32 = 10;

const LABEL_NORMAL: &str = "Sign in with Familiar Smartcard";
const LABEL_UNBLOCK: &str = "Unblock Familiar Smartcard with PUK";
const LINK_TO_UNBLOCK: &str = "PIN blocked? Unblock with PUK";
const LINK_TO_NORMAL: &str = "Back to normal PIN sign-in";

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
    puk: Zeroizing<String>,
    new_pin: Zeroizing<String>,
    confirm_pin: Zeroizing<String>,
    unblock_mode: bool,
    status: String,
    events: Option<ICredentialProviderCredentialEvents>,
}

impl CredentialMutable {
    fn new() -> Self {
        Self {
            typed_username: String::new(),
            pin: Zeroizing::new(String::new()),
            puk: Zeroizing::new(String::new()),
            new_pin: Zeroizing::new(String::new()),
            confirm_pin: Zeroizing::new(String::new()),
            unblock_mode: false,
            status: String::new(),
            events: None,
        }
    }

    fn clear_secrets(&mut self) {
        self.pin.clear();
        self.puk.clear();
        self.new_pin.clear();
        self.confirm_pin.clear();
    }
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
            inner: Mutex::new(CredentialMutable::new()),
        }
    }

    pub fn new_explicit_user(cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO) -> Self {
        Self {
            mode: TargetMode::ExplicitUser,
            cpus,
            inner: Mutex::new(CredentialMutable::new()),
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

    fn clear_secret_memory(&self) {
        self.lock_inner().clear_secrets();
    }

    fn set_status(&self, text: String) {
        self.lock_inner().status = text;
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.clear_secret_memory();
    }
}

impl Credential_Impl {
    /// Zeroize all internal PIN/PUK buffers AND notify `LogonUI.exe` via
    /// `ICredentialProviderCredentialEvents::SetFieldString` so no password box
    /// on the lock screen ever retains stale `••••••` dots.
    fn clear_secrets_and_notify_ui(&self) {
        let events_opt = {
            let mut guard = self.lock_inner();
            guard.clear_secrets();
            guard.events.clone()
        };
        if let Some(events) = events_opt {
            let this_cpc: ICredentialProviderCredential = self.to_interface();
            // SAFETY: Invoked outside `self.inner` Mutex so synchronous callbacks cannot deadlock.
            unsafe {
                for field in [SFI_PIN, SFI_PUK, SFI_NEW_PIN, SFI_CONFIRM_PIN] {
                    let _ = events.SetFieldString(&this_cpc, field, w!(""));
                }
            }
        }
    }

    /// Switch between normal PIN sign-in and in-place PUK PIN-unblock mode,
    /// updating field visibility, labels, submit button adjacency, and focus.
    fn set_unblock_mode_and_notify_ui(&self, unblock: bool) {
        let (events_opt, needs_username) = {
            let mut guard = self.lock_inner();
            guard.unblock_mode = unblock;
            guard.clear_secrets();
            let needs_user = self.is_explicit_user() && guard.typed_username.is_empty();
            (guard.events.clone(), needs_user)
        };

        if let Some(events) = events_opt {
            let this_cpc: ICredentialProviderCredential = self.to_interface();
            let (pin_state, puk_state, submit_adj, label, toggle_label) = if unblock {
                (
                    CPFS_HIDDEN,
                    CPFS_DISPLAY_IN_SELECTED_TILE,
                    SFI_CONFIRM_PIN,
                    w!("Unblock Familiar Smartcard with PUK"),
                    w!("Back to normal PIN sign-in"),
                )
            } else {
                (
                    CPFS_DISPLAY_IN_SELECTED_TILE,
                    CPFS_HIDDEN,
                    SFI_PIN,
                    w!("Sign in with Familiar Smartcard"),
                    w!("PIN blocked? Unblock with PUK"),
                )
            };

            // SAFETY: Invoked outside `self.inner` Mutex.
            unsafe {
                for field in [SFI_PIN, SFI_PUK, SFI_NEW_PIN, SFI_CONFIRM_PIN] {
                    let _ = events.SetFieldString(&this_cpc, field, w!(""));
                }
                let _ = events.SetFieldString(&this_cpc, SFI_LABEL, label);
                let _ = events.SetFieldString(&this_cpc, SFI_TOGGLE_MODE, toggle_label);
                let _ = events.SetFieldState(&this_cpc, SFI_PIN, pin_state);
                let _ = events.SetFieldState(&this_cpc, SFI_PUK, puk_state);
                let _ = events.SetFieldState(&this_cpc, SFI_NEW_PIN, puk_state);
                let _ = events.SetFieldState(&this_cpc, SFI_CONFIRM_PIN, puk_state);
                let _ = events.SetFieldSubmitButton(&this_cpc, SFI_SUBMIT, submit_adj);

                let _ = events.SetFieldInteractiveState(&this_cpc, SFI_PIN, CPFIS_NONE);
                let _ = events.SetFieldInteractiveState(&this_cpc, SFI_PUK, CPFIS_NONE);
                let _ = events.SetFieldInteractiveState(&this_cpc, SFI_NEW_PIN, CPFIS_NONE);
                let _ = events.SetFieldInteractiveState(&this_cpc, SFI_CONFIRM_PIN, CPFIS_NONE);
                if self.is_explicit_user() {
                    let _ = events.SetFieldInteractiveState(&this_cpc, SFI_USERNAME, CPFIS_NONE);
                }

                let focus_field = if needs_username {
                    SFI_USERNAME
                } else if unblock {
                    SFI_PUK
                } else {
                    SFI_PIN
                };
                let _ = events.SetFieldInteractiveState(&this_cpc, focus_field, CPFIS_FOCUSED);
            }
        }
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
        self.clear_secrets_and_notify_ui();
    }

    fn resolve_target_account(
        &self,
        typed_username: &str,
        ppsz_status: *mut PWSTR,
        pcpsi: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Option<(String, String, String)> {
        match &self.mode {
            TargetMode::BoundUser {
                sid,
                domain,
                username,
            } => Some((sid.clone(), domain.clone(), username.clone())),
            TargetMode::ExplicitUser => {
                if typed_username.is_empty() {
                    // SAFETY: Out-pointers verified non-null by `GetSerialization`.
                    unsafe {
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            "Enter your local Windows username.".into(),
                            CPSI_WARNING,
                        );
                    }
                    return None;
                }

                // Uniform error message + small floor delay prevent local username enumeration
                // when RDP is exposed without NLA.
                match scard_core::account::lookup_local_account_by_name(typed_username) {
                    Ok(info) if scard_core::storage::vault_exists(&info.sid) => {
                        Some((info.sid, info.domain, info.username))
                    }
                    _ => {
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        // SAFETY: Out-pointers verified non-null by `GetSerialization`.
                        unsafe {
                            self.fail(
                                ppsz_status,
                                pcpsi,
                                "Sign-in failed. Verify the local username, Familiar Smartcard enrollment, and credentials."
                                    .into(),
                                CPSI_ERROR,
                            );
                        }
                        None
                    }
                }
            }
        }
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
        guard_com(|| {
            // Clear leftover secret text while preserving `unblock_mode` (so returning
            // from a `PinBlocked` error screen keeps the PUK unblock fields open!).
            self.clear_secrets_and_notify_ui();
            // Never auto-logon.
            Ok(BOOL(0))
        })
    }

    fn SetDeselected(&self) -> WinResult<()> {
        guard_com(|| {
            self.set_unblock_mode_and_notify_ui(false);
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
            let (unblock_mode, explicit_needs_username, status_empty) = {
                let guard = self.lock_inner();
                (
                    guard.unblock_mode,
                    self.is_explicit_user() && guard.typed_username.is_empty(),
                    guard.status.is_empty(),
                )
            };

            let (state, interactive) = match dwfieldid {
                // `CPFS_DISPLAY_IN_BOTH` is required by Windows 10/11 XAML LogonUI so the
                // "Sign-in options" icon bar renders our credential switch button!
                SFI_TILEIMAGE => (CPFS_DISPLAY_IN_BOTH, CPFIS_NONE),
                SFI_LABEL | SFI_SUBMIT | SFI_TOGGLE_MODE => {
                    (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE)
                }
                SFI_USERNAME => {
                    if self.is_explicit_user() {
                        let focus = if explicit_needs_username {
                            CPFIS_FOCUSED
                        } else {
                            CPFIS_NONE
                        };
                        (CPFS_DISPLAY_IN_SELECTED_TILE, focus)
                    } else {
                        (CPFS_HIDDEN, CPFIS_NONE)
                    }
                }
                SFI_PIN => {
                    if unblock_mode {
                        (CPFS_HIDDEN, CPFIS_NONE)
                    } else {
                        let focus = if explicit_needs_username {
                            CPFIS_NONE
                        } else {
                            CPFIS_FOCUSED
                        };
                        (CPFS_DISPLAY_IN_SELECTED_TILE, focus)
                    }
                }
                SFI_PUK => {
                    if unblock_mode {
                        let focus = if explicit_needs_username {
                            CPFIS_NONE
                        } else {
                            CPFIS_FOCUSED
                        };
                        (CPFS_DISPLAY_IN_SELECTED_TILE, focus)
                    } else {
                        (CPFS_HIDDEN, CPFIS_NONE)
                    }
                }
                SFI_NEW_PIN | SFI_CONFIRM_PIN => {
                    if unblock_mode {
                        (CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE)
                    } else {
                        (CPFS_HIDDEN, CPFIS_NONE)
                    }
                }
                SFI_STATUS => {
                    if status_empty {
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
        guard_com(|| {
            let guard = self.lock_inner();
            match dwfieldid {
                SFI_LABEL => alloc_pwstr(if guard.unblock_mode {
                    LABEL_UNBLOCK
                } else {
                    LABEL_NORMAL
                }),
                SFI_USERNAME => alloc_pwstr(&guard.typed_username),
                SFI_PIN => alloc_pwstr(guard.pin.as_str()),
                SFI_PUK => alloc_pwstr(guard.puk.as_str()),
                SFI_NEW_PIN => alloc_pwstr(guard.new_pin.as_str()),
                SFI_CONFIRM_PIN => alloc_pwstr(guard.confirm_pin.as_str()),
                SFI_SUBMIT => alloc_pwstr("Sign in"),
                SFI_STATUS => alloc_pwstr(&guard.status),
                SFI_TOGGLE_MODE => alloc_pwstr(if guard.unblock_mode {
                    LINK_TO_NORMAL
                } else {
                    LINK_TO_UNBLOCK
                }),
                _ => Err(E_NOTIMPL.into()),
            }
        })
    }

    fn GetBitmapValue(&self, dwfieldid: u32) -> WinResult<HBITMAP> {
        guard_com(|| {
            if dwfieldid != SFI_TILEIMAGE {
                return Err(E_INVALIDARG.into());
            }
            create_smartcard_tile_bitmap()
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
            let unblock = self.lock_inner().unblock_mode;
            Ok(if unblock { SFI_CONFIRM_PIN } else { SFI_PIN })
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
            SFI_PIN | SFI_PUK | SFI_NEW_PIN | SFI_CONFIRM_PIN => {
                // SAFETY: `psz` was checked non-null; copy directly into a `Zeroizing` string.
                let raw = Zeroizing::new(unsafe { psz.to_string() }.unwrap_or_default());
                let trimmed = raw.trim();
                if trimmed.len() > 16 {
                    self.set_status("PIN / PUK input is too long.".into());
                    return Ok(());
                }
                let mut guard = self.lock_inner();
                let target = match dwfieldid {
                    SFI_PIN => &mut guard.pin,
                    SFI_PUK => &mut guard.puk,
                    SFI_NEW_PIN => &mut guard.new_pin,
                    _ => &mut guard.confirm_pin,
                };
                target.clear();
                target.push_str(trimmed);
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

    fn CommandLinkClicked(&self, dwfieldid: u32) -> WinResult<()> {
        if dwfieldid != SFI_TOGGLE_MODE {
            return Err(E_NOTIMPL.into());
        }
        guard_com(|| {
            let next_mode = !self.lock_inner().unblock_mode;
            self.set_unblock_mode_and_notify_ui(next_mode);
            Ok(())
        })
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
            let (unblock_mode, typed_username, pin_bytes, puk_bytes, new_pin_bytes, confirm_bytes) = {
                let guard = self.lock_inner();
                (
                    guard.unblock_mode,
                    guard.typed_username.clone(),
                    Zeroizing::new(guard.pin.as_bytes().to_vec()),
                    Zeroizing::new(guard.puk.as_bytes().to_vec()),
                    Zeroizing::new(guard.new_pin.as_bytes().to_vec()),
                    Zeroizing::new(guard.confirm_pin.as_bytes().to_vec()),
                )
            };

            let operation = if unblock_mode {
                if puk_bytes.is_empty() {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            "Enter your Familiar Smartcard PUK (6-8 characters; PIV default is 12345678)."
                                .into(),
                            CPSI_WARNING,
                        );
                    }
                    return Ok(());
                }
                if puk_bytes.len() < 6
                    || puk_bytes.len() > 8
                    || !puk_bytes.iter().all(|&b| (0x21..=0x7E).contains(&b))
                {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            "Familiar Smartcard PUK must be 6-8 printable ASCII characters.".into(),
                            CPSI_WARNING,
                        );
                    }
                    return Ok(());
                }
                if new_pin_bytes.len() < 6
                    || new_pin_bytes.len() > 8
                    || !new_pin_bytes.iter().all(|b| b.is_ascii_digit())
                {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            "New PIV PIN must be 6-8 ASCII digits.".into(),
                            CPSI_WARNING,
                        );
                    }
                    return Ok(());
                }
                if !constant_time_eq(&new_pin_bytes, &confirm_bytes) {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            "New PIN and confirmation PIN do not match.".into(),
                            CPSI_WARNING,
                        );
                    }
                    return Ok(());
                }
                HelperOperation::UnblockAndUnlock {
                    puk: puk_bytes,
                    new_pin: new_pin_bytes,
                }
            } else {
                if pin_bytes.is_empty() {
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(
                            ppsz_status,
                            pcpsi,
                            "Enter your Familiar Smartcard PIN.".into(),
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
                HelperOperation::Unlock { pin: pin_bytes }
            };

            let computer = scard_core::account::computer_name().unwrap_or_else(|_| ".".into());
            let Some((sid, domain, username)) =
                self.resolve_target_account(&typed_username, ppsz_status, pcpsi)
            else {
                return Ok(());
            };

            let timeout_ms = match scard_core::storage::read_touch_policy(&sid) {
                Some(TOUCH_POLICY_ALWAYS) | Some(TOUCH_POLICY_CACHED) => TOUCH_HELPER_TIMEOUT_MS,
                _ => DEFAULT_HELPER_TIMEOUT_MS,
            };

            let req = HelperRequest {
                sid,
                username: username.clone(),
                computer,
                operation,
            };

            let password = match invoke_auth_helper(&req, timeout_ms) {
                HelperResponse::Success { password } => password,
                HelperResponse::Failure {
                    reason,
                    icon,
                    message,
                } => {
                    let cp_icon = match icon {
                        HelperIcon::None => CPSI_NONE,
                        HelperIcon::Warning => CPSI_WARNING,
                        HelperIcon::Error => CPSI_ERROR,
                    };
                    // SAFETY: Verified non-null above.
                    unsafe {
                        self.fail(ppsz_status, pcpsi, message, cp_icon);
                    }
                    // Automatically expand the PUK unblock fields when the card reports
                    // 0 PIN attempts left so returning from OK lets the user unblock immediately!
                    if reason == HelperFailureReason::PinBlocked {
                        self.set_unblock_mode_and_notify_ui(true);
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
            self.set_unblock_mode_and_notify_ui(false);
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
        SFI_TILEIMAGE => ("Familiar Smartcard", CPFT_TILE_IMAGE),
        SFI_LABEL => (LABEL_NORMAL, CPFT_LARGE_TEXT),
        SFI_USERNAME => ("Username", CPFT_EDIT_TEXT),
        SFI_PIN => ("Familiar Smartcard PIN", CPFT_PASSWORD_TEXT),
        SFI_PUK => ("Card PUK (default: 12345678)", CPFT_PASSWORD_TEXT),
        SFI_NEW_PIN => ("New PIN (6-8 digits)", CPFT_PASSWORD_TEXT),
        SFI_CONFIRM_PIN => ("Confirm new PIN", CPFT_PASSWORD_TEXT),
        SFI_SUBMIT => ("Sign in", CPFT_SUBMIT_BUTTON),
        SFI_STATUS => ("Status", CPFT_SMALL_TEXT),
        SFI_TOGGLE_MODE => (LINK_TO_UNBLOCK, CPFT_COMMAND_LINK),
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
fn create_smartcard_tile_bitmap() -> WinResult<HBITMAP> {
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
            if (4..44).contains(&x) && (10..38).contains(&y) {
                color = if x == 4 || x == 43 || y == 10 || y == 37 {
                    BORDER
                } else {
                    BG_DARK
                };
            }
            if (9..19).contains(&x) && (18..28).contains(&y) {
                color = GOLD;
            }
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
        let cred: ICredentialProviderCredential2 = base.cast().unwrap();
        let mut raw_sid = PWSTR(std::ptr::dangling_mut());
        // SAFETY: Direct vtable call mirrors exact `LogonUI.exe` invocation.
        let hr = unsafe { (Interface::vtable(&cred).GetUserSid)(cred.as_raw(), &mut raw_sid) };
        assert_eq!(hr, S_FALSE);
        assert!(raw_sid.is_null());

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

    #[implement(ICredentialProviderCredentialEvents)]
    struct MockCredentialEvents {
        string_updates: std::sync::Arc<Mutex<Vec<(u32, String)>>>,
        state_updates: std::sync::Arc<Mutex<Vec<(u32, CREDENTIAL_PROVIDER_FIELD_STATE)>>>,
        submit_adj: std::sync::Arc<Mutex<Option<u32>>>,
    }

    impl windows::Win32::UI::Shell::ICredentialProviderCredentialEvents_Impl
        for MockCredentialEvents_Impl
    {
        fn SetFieldState(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            dwfieldid: u32,
            cpfs: CREDENTIAL_PROVIDER_FIELD_STATE,
        ) -> WinResult<()> {
            self.state_updates.lock().unwrap().push((dwfieldid, cpfs));
            Ok(())
        }

        fn SetFieldInteractiveState(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            _dwfieldid: u32,
            _cpfis: CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
        ) -> WinResult<()> {
            Ok(())
        }

        fn SetFieldString(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            dwfieldid: u32,
            psz: &PCWSTR,
        ) -> WinResult<()> {
            let val = if psz.is_null() {
                String::new()
            } else {
                // SAFETY: `psz` is a valid NUL-terminated UTF-16 string passed by `Credential`.
                unsafe { psz.to_string() }.unwrap_or_default()
            };
            self.string_updates.lock().unwrap().push((dwfieldid, val));
            Ok(())
        }

        fn SetFieldCheckbox(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            _dwfieldid: u32,
            _bchecked: BOOL,
            _pszlabel: &PCWSTR,
        ) -> WinResult<()> {
            Ok(())
        }

        fn SetFieldBitmap(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            _dwfieldid: u32,
            _hbmp: HBITMAP,
        ) -> WinResult<()> {
            Ok(())
        }

        fn SetFieldComboBoxSelectedItem(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            _dwfieldid: u32,
            _dwselecteditem: u32,
        ) -> WinResult<()> {
            Ok(())
        }

        fn DeleteFieldComboBoxItem(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            _dwfieldid: u32,
            _dwitem: u32,
        ) -> WinResult<()> {
            Ok(())
        }

        fn AppendFieldComboBoxItem(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            _dwfieldid: u32,
            _pszitem: &PCWSTR,
        ) -> WinResult<()> {
            Ok(())
        }

        fn SetFieldSubmitButton(
            &self,
            _pcpc: Ref<'_, ICredentialProviderCredential>,
            _dwfieldid: u32,
            dwadjacentto: u32,
        ) -> WinResult<()> {
            *self.submit_adj.lock().unwrap() = Some(dwadjacentto);
            Ok(())
        }

        fn OnCreatingWindow(&self) -> WinResult<windows::Win32::Foundation::HWND> {
            Err(E_NOTIMPL.into())
        }
    }

    #[test]
    fn failed_login_reselection_and_puk_unblock_toggle_notify_logonui_events() {
        let updates = std::sync::Arc::new(Mutex::new(Vec::new()));
        let state_updates = std::sync::Arc::new(Mutex::new(Vec::new()));
        let submit_adj = std::sync::Arc::new(Mutex::new(None));
        let events: ICredentialProviderCredentialEvents = MockCredentialEvents {
            string_updates: updates.clone(),
            state_updates: state_updates.clone(),
            submit_adj: submit_adj.clone(),
        }
        .into();

        let cred: ICredentialProviderCredential = Credential::new_explicit_user(CPUS_LOGON).into();
        // SAFETY: Standard COM calls in unit test.
        unsafe {
            cred.Advise(&events).unwrap();

            cred.SetStringValue(SFI_USERNAME, w!("__nonexistent_fsc_test_user__"))
                .unwrap();
            cred.SetStringValue(SFI_PIN, w!("123456")).unwrap();

            let mut cpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
            let mut cpcs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION::default();
            let mut status_pwstr = PWSTR::null();
            let mut icon = CPSI_NONE;
            cred.GetSerialization(&mut cpgsr, &mut cpcs, &mut status_pwstr, &mut icon)
                .unwrap();
            assert_eq!(cpgsr, CPGSR_NO_CREDENTIAL_NOT_FINISHED);
            if !status_pwstr.is_null() {
                CoTaskMemFree(Some(status_pwstr.0 as *const c_void));
            }

            let pin_after = cred.GetStringValue(SFI_PIN).unwrap();
            assert_eq!(pin_after.to_string().unwrap(), "");
            CoTaskMemFree(Some(pin_after.0 as *const c_void));
            assert!(updates.lock().unwrap().contains(&(SFI_PIN, String::new())));

            // Clicking the CommandLink toggles into PUK Unblock mode and moves Submit to SFI_CONFIRM_PIN!
            cred.CommandLinkClicked(SFI_TOGGLE_MODE).unwrap();
            assert_eq!(*submit_adj.lock().unwrap(), Some(SFI_CONFIRM_PIN));
            assert_eq!(
                cred.GetSubmitButtonValue(SFI_SUBMIT).unwrap(),
                SFI_CONFIRM_PIN
            );

            let mut puk_state = CPFS_HIDDEN;
            let mut puk_inter = CPFIS_NONE;
            cred.GetFieldState(SFI_PUK, &mut puk_state, &mut puk_inter)
                .unwrap();
            assert_eq!(puk_state, CPFS_DISPLAY_IN_SELECTED_TILE);
            assert_eq!(puk_inter, CPFIS_FOCUSED);

            // Mismatched New PIN vs Confirm PIN rejects cleanly and clears PUK/PIN boxes while staying in unblock mode!
            cred.SetStringValue(SFI_PUK, w!("12345678")).unwrap();
            cred.SetStringValue(SFI_NEW_PIN, w!("654321")).unwrap();
            cred.SetStringValue(SFI_CONFIRM_PIN, w!("000000")).unwrap();
            cred.GetSerialization(&mut cpgsr, &mut cpcs, &mut status_pwstr, &mut icon)
                .unwrap();
            assert_eq!(cpgsr, CPGSR_NO_CREDENTIAL_NOT_FINISHED);
            if !status_pwstr.is_null() {
                CoTaskMemFree(Some(status_pwstr.0 as *const c_void));
            }
            let puk_after = cred.GetStringValue(SFI_PUK).unwrap();
            assert_eq!(puk_after.to_string().unwrap(), "");
            CoTaskMemFree(Some(puk_after.0 as *const c_void));

            // SetSelected preserves unblock_mode so returning from OK keeps PUK fields visible!
            let _ = cred.SetSelected().unwrap();
            assert_eq!(
                cred.GetSubmitButtonValue(SFI_SUBMIT).unwrap(),
                SFI_CONFIRM_PIN
            );

            // Clicking CommandLink again returns to normal PIN mode.
            cred.CommandLinkClicked(SFI_TOGGLE_MODE).unwrap();
            assert_eq!(cred.GetSubmitButtonValue(SFI_SUBMIT).unwrap(), SFI_PIN);

            cred.UnAdvise().unwrap();
        }
    }
}
