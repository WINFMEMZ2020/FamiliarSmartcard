//! Registry storage for per-user vault blobs, touch policy hints, and pinned
//! card `0xF9` attestation roots, plus SDDL ACL enforcement.
//!
//! Security rules:
//! - Every registry key created under `HKLM\SOFTWARE\FamiliarSmartcard` is
//!   atomically created with SDDL `D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)` so
//!   standard local users never inherit read or write access.
//! - No diagnostic log is ever written to world-writable `C:\Windows\Temp`.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::crypto::constant_time_eq;
use crate::dpapi;
use crate::error::{AuthError, Result};
use crate::vault::VaultBlob;
use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use windows::core::{w, BOOL, PCWSTR};
use windows::Win32::Foundation::{
    LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    SE_REGISTRY_KEY,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY, KEY_WRITE, REG_BINARY, REG_DWORD,
    REG_OPTION_NON_VOLATILE, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD,
};

const ROOT_SUBKEY: &str = "SOFTWARE\\FamiliarSmartcard";
const USERS_SUBKEY: &str = "SOFTWARE\\FamiliarSmartcard\\Users";
const ATTESTATION_SUBKEY: &str = "SOFTWARE\\FamiliarSmartcard\\Attestation";
const COOLDOWNS_SUBKEY: &str = "SOFTWARE\\FamiliarSmartcard\\Cooldowns";

/// Safety cooldown enforced before the final (1 remaining) hardware PIN retry.
pub const LAST_ATTEMPT_COOLDOWN_SECS: u64 = 60;

const VALUE_VAULT: &str = "VaultBlob";
const VALUE_VAULT_PENDING: &str = "VaultBlob.pending";
const VALUE_VAULT_BACKUP: &str = "VaultBlob.bak";
const VALUE_TOUCH_POLICY: &str = "TouchPolicy";
const VALUE_CARD_AUTH_9E_PUB: &str = "CardAuth9EPub";
const VALUE_PINNED_F9: &str = "PinnedF9Fingerprint";

const MAX_DPAPI_BLOB: usize = 4096;
const SDDL_REVISION_1: u32 = 1;

/// Protected DACL granting FullControl only to `NT AUTHORITY\SYSTEM` and
/// `BUILTIN\Administrators`, with container & object inheritance.
/// Used exclusively for secret registry hives (`HKLM\SOFTWARE\FamiliarSmartcard`).
const SDDL_SYSTEM_ADMINS_ONLY: PCWSTR = w!("D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)");

/// Hardened `Program Files` binary DACL: FullControl for `SYSTEM` and `Administrators`,
/// ReadAndExecute (`0x1200a9`) only for `Users` (`BU`), `ALL APPLICATION PACKAGES` (`AC`),
/// and `LOCAL SERVICE` (`LS`) so Windows 10/11 XAML `LogonUI.exe` and AppContainer
/// brokers can load the COM DLL without granting write access to non-admins.
const SDDL_PROGRAM_FILES_BINARIES: PCWSTR =
    w!("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;AC)(A;OICI;0x1200a9;;;LS)");

/// Standard COM `HKLM\SOFTWARE\Classes\CLSID` DACL: FullControl for `SYSTEM` and
/// `Administrators`, Read (`KR`) for `Users`, `ALL APPLICATION PACKAGES`, and `LOCAL SERVICE`.
const SDDL_COM_CLSID_READABLE: PCWSTR =
    w!("D:PAI(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;BU)(A;OICI;KR;;;AC)(A;OICI;KR;;;LS)");

struct SecurityDescriptorGuard(PSECURITY_DESCRIPTOR);

impl SecurityDescriptorGuard {
    fn from_sddl(sddl: PCWSTR) -> Result<Self> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: Valid constant SDDL string and out-pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(|e| AuthError::Internal(format!("SDDL conversion failed: {}", e.message())))?;
        Ok(Self(sd))
    }

    fn system_admins_only() -> Result<Self> {
        Self::from_sddl(SDDL_SYSTEM_ADMINS_ONLY)
    }

    fn dacl_ptr(&self) -> Result<*const ACL> {
        let mut present = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = BOOL(0);
        // SAFETY: `self.0` was created by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
        unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
            .map_err(|e| AuthError::Internal(format!("GetSecurityDescriptorDacl failed: {e}")))?;
        if !present.as_bool() || dacl.is_null() {
            return Err(AuthError::Internal("SDDL produced null DACL".into()));
        }
        Ok(dacl as *const ACL)
    }
}

impl Drop for SecurityDescriptorGuard {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            // SAFETY: `self.0` was allocated with `LocalAlloc` by Advapi32.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
            self.0 = PSECURITY_DESCRIPTOR::default();
        }
    }
}

/// Apply hardened `Program Files` binary permissions (`SY`/`BA` FullControl,
/// `BU`/`AC`/`LS` ReadAndExecute) to an installation directory or binary file.
pub fn apply_program_files_binary_acl(path: &Path) -> Result<()> {
    let sd = SecurityDescriptorGuard::from_sddl(SDDL_PROGRAM_FILES_BINARIES)?;
    let dacl = sd.dacl_ptr()?;
    let wide = to_wide(&path.to_string_lossy());
    // SAFETY: `wide` is NUL-terminated and `dacl` outlives the call.
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if err != ERROR_SUCCESS {
        return Err(AuthError::Internal(format!(
            "SetNamedSecurityInfoW failed on {}: 0x{:08X}",
            path.display(),
            err.0
        )));
    }
    Ok(())
}

/// Ensure a COM `HKLM\SOFTWARE\Classes\CLSID\{...}` subkey is readable by LogonUI
/// and AppContainer brokers (`BU`/`AC`/`LS` Read) while writable only by `SY`/`BA`.
pub fn restore_com_clsid_acl(subkey: &str) -> Result<()> {
    let sd = SecurityDescriptorGuard::from_sddl(SDDL_COM_CLSID_READABLE)?;
    let dacl = sd.dacl_ptr()?;
    let object_name = to_wide(&format!("MACHINE\\{subkey}"));
    // SAFETY: `object_name` is NUL-terminated and `dacl` outlives the call.
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(object_name.as_ptr()),
            SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if err != ERROR_SUCCESS {
        return Err(AuthError::Registry(err.0 as i32));
    }
    Ok(())
}

/// Apply the protected `SYSTEM` + `Administrators` DACL to an existing `HKLM` subkey.
pub fn harden_hklm_subkey_acl(subkey: &str) -> Result<()> {
    let sd = SecurityDescriptorGuard::system_admins_only()?;
    let dacl = sd.dacl_ptr()?;
    let object_name = to_wide(&format!("MACHINE\\{subkey}"));
    // SAFETY: `object_name` is NUL-terminated and `dacl` outlives the call.
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(object_name.as_ptr()),
            SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if err != ERROR_SUCCESS {
        return Err(AuthError::Registry(err.0 as i32));
    }
    Ok(())
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn validate_sid_token(sid: &str) -> Result<()> {
    if sid.is_empty()
        || sid.len() > 184
        || !sid.starts_with("S-1-")
        || !sid
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == 'S')
    {
        return Err(AuthError::Vault("malformed SID string".into()));
    }
    Ok(())
}

fn user_subkey_str(sid: &str) -> Result<String> {
    validate_sid_token(sid)?;
    Ok(format!("{USERS_SUBKEY}\\{sid}"))
}

fn entropy_for_sid(sid: &str) -> Vec<u8> {
    format!("FamiliarSmartcard/v1/{sid}").into_bytes()
}

struct RegKeyGuard(HKEY);

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` was opened/created via Win32 Registry API.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

fn create_secured_hklm_key(subkey: &str) -> Result<RegKeyGuard> {
    let sd = SecurityDescriptorGuard::system_admins_only()?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 .0,
        bInheritHandle: BOOL(0),
    };
    let subkey_w = to_wide(subkey);
    let mut key = HKEY::default();
    // SAFETY: `subkey_w` is NUL-terminated; `sa` and `sd` outlive `RegCreateKeyExW`.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_READ | KEY_SET_VALUE | KEY_WOW64_64KEY,
            Some(&sa),
            &mut key,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }
    Ok(RegKeyGuard(key))
}

/// Ensure the root `HKLM\SOFTWARE\FamiliarSmartcard` hierarchy exists and has
/// `SYSTEM` + `Administrators` protected ACLs (even if an unhardened key pre-existed).
pub fn ensure_secured_vault_hierarchy() -> Result<()> {
    let _root = create_secured_hklm_key(ROOT_SUBKEY)?;
    harden_hklm_subkey_acl(ROOT_SUBKEY)?;
    let _users = create_secured_hklm_key(USERS_SUBKEY)?;
    let _att = create_secured_hklm_key(ATTESTATION_SUBKEY)?;
    let _cool = create_secured_hklm_key(COOLDOWNS_SUBKEY)?;
    Ok(())
}

/// Fast existence check used by the Credential Provider to filter unbound user tiles
/// without invoking DPAPI during tile enumeration.
pub fn vault_exists(sid: &str) -> bool {
    let Ok(subkey) = user_subkey_str(sid) else {
        return false;
    };
    let subkey_w = to_wide(&subkey);
    let value_w = to_wide(VALUE_VAULT);
    let mut len = 0u32;
    // SAFETY: Queries value length only.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_BINARY,
            None,
            None,
            Some(&mut len),
        )
    };
    status == ERROR_SUCCESS && len > 0 && (len as usize) <= MAX_DPAPI_BLOB
}

/// Read the optional `TouchPolicy` hint (`0x01` NEVER, `0x02` ALWAYS, `0x03` CACHED)
/// stored alongside the user's vault to select an appropriate helper timeout.
pub fn read_touch_policy(sid: &str) -> Option<u8> {
    let subkey = user_subkey_str(sid).ok()?;
    let subkey_w = to_wide(&subkey);
    let value_w = to_wide(VALUE_TOUCH_POLICY);
    let mut raw = 0u32;
    let mut len = size_of::<u32>() as u32;
    // SAFETY: `raw` is a valid 4-byte buffer for `RRF_RT_REG_DWORD`.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut raw as *mut u32 as *mut c_void),
            Some(&mut len),
        )
    };
    if status == ERROR_SUCCESS {
        u8::try_from(raw).ok()
    } else {
        None
    }
}

pub fn write_touch_policy(sid: &str, touch_policy: u8) -> Result<()> {
    ensure_secured_vault_hierarchy()?;
    let subkey = user_subkey_str(sid)?;
    let key = create_secured_hklm_key(&subkey)?;
    let value_w = to_wide(VALUE_TOUCH_POLICY);
    let dword = (touch_policy as u32).to_le_bytes();
    // SAFETY: `key.0` is open with `KEY_WRITE`; `dword` is 4 bytes.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            PCWSTR(value_w.as_ptr()),
            None,
            REG_DWORD,
            Some(&dword),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }
    Ok(())
}

fn read_raw_reg_binary(subkey: &str, value_name: &str, max_len: usize) -> Result<Option<Vec<u8>>> {
    let subkey_w = to_wide(subkey);
    let value_w = to_wide(value_name);

    let mut len = 0u32;
    // SAFETY: First call queries byte length.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_BINARY,
            None,
            None,
            Some(&mut len),
        )
    };

    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }
    if len == 0 || (len as usize) > max_len {
        return Err(AuthError::Vault(format!(
            "registry blob '{value_name}' exceeds {max_len} bytes or is empty"
        )));
    }

    let mut buffer = vec![0u8; len as usize];
    // SAFETY: `buffer` has `len` bytes capacity.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_BINARY,
            None,
            Some(buffer.as_mut_ptr() as *mut c_void),
            Some(&mut len),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }
    buffer.truncate((len as usize).min(buffer.len()));
    Ok(Some(buffer))
}

fn write_raw_reg_binary(key: HKEY, value_name: &str, bytes: &[u8]) -> Result<()> {
    let value_w = to_wide(value_name);
    // SAFETY: `key` is open with `KEY_WRITE`; `bytes` outlives the call.
    let status =
        unsafe { RegSetValueExW(key, PCWSTR(value_w.as_ptr()), None, REG_BINARY, Some(bytes)) };
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }
    Ok(())
}

fn delete_reg_value_ignore_missing(key: HKEY, value_name: &str) {
    let value_w = to_wide(value_name);
    // SAFETY: `key` is open with `KEY_SET_VALUE`.
    unsafe {
        let _ = RegDeleteValueW(key, PCWSTR(value_w.as_ptr()));
    }
}

pub fn read_vault(sid: &str) -> Result<Option<VaultBlob>> {
    let subkey = user_subkey_str(sid)?;
    let Some(buffer) = read_raw_reg_binary(&subkey, VALUE_VAULT, MAX_DPAPI_BLOB)? else {
        return Ok(None);
    };
    let entropy = entropy_for_sid(sid);
    let encoded = dpapi::unprotect(&buffer, &entropy)?;
    let vault = VaultBlob::decode(&encoded)?;
    Ok(Some(vault))
}

fn encode_and_protect_vault(sid: &str, vault: &VaultBlob) -> Result<(Vec<u8>, Vec<u8>)> {
    let encoded = vault.encode()?;
    let entropy = entropy_for_sid(sid);
    let protected = dpapi::protect(&encoded, &entropy)?;
    if protected.len() > MAX_DPAPI_BLOB {
        return Err(AuthError::Vault(
            "protected vault exceeds 4096 bytes".into(),
        ));
    }
    Ok((encoded, protected))
}

/// Stage a pending vault and back up any existing active vault before rotating
/// the Windows account password.
pub fn stage_pending_vault_with_backup(sid: &str, pending_vault: &VaultBlob) -> Result<()> {
    ensure_secured_vault_hierarchy()?;
    let subkey = user_subkey_str(sid)?;
    let key = create_secured_hklm_key(&subkey)?;

    if let Some(existing) = read_raw_reg_binary(&subkey, VALUE_VAULT, MAX_DPAPI_BLOB)? {
        write_raw_reg_binary(key.0, VALUE_VAULT_BACKUP, &existing)?;
    }
    let (_, protected) = encode_and_protect_vault(sid, pending_vault)?;
    write_raw_reg_binary(key.0, VALUE_VAULT_PENDING, &protected)?;
    Ok(())
}

/// Write `vault` to `VaultBlob`, immediately read it back through DPAPI + decode
/// to verify storage integrity, and clean up `VaultBlob.pending`.
pub fn write_vault(sid: &str, vault: &VaultBlob) -> Result<()> {
    ensure_secured_vault_hierarchy()?;
    let subkey = user_subkey_str(sid)?;
    let key = create_secured_hklm_key(&subkey)?;

    let (expected_encoded, protected) = encode_and_protect_vault(sid, vault)?;
    write_raw_reg_binary(key.0, VALUE_VAULT, &protected)?;

    // Read-back verification guarantees the persisted registry value decrypts cleanly.
    let read_back = read_raw_reg_binary(&subkey, VALUE_VAULT, MAX_DPAPI_BLOB)?
        .ok_or_else(|| AuthError::Vault("vault read-back returned empty".into()))?;
    let unprotected = dpapi::unprotect(&read_back, &entropy_for_sid(sid))?;
    if !constant_time_eq(&unprotected, &expected_encoded) {
        return Err(AuthError::Vault(
            "vault read-back verification mismatch".into(),
        ));
    }
    let _ = VaultBlob::decode(&unprotected)?;

    delete_reg_value_ignore_missing(key.0, VALUE_VAULT_PENDING);
    Ok(())
}

/// Overwrite and delete any residual `VaultBlob.bak` / `VaultBlob.pending` values
/// once a new password rotation or re-bind has been verified via `LogonUserW`,
/// ensuring historical human passwords never persist in the registry.
pub fn purge_vault_backup(sid: &str) -> Result<()> {
    let subkey = user_subkey_str(sid)?;
    let Ok(key) = create_secured_hklm_key(&subkey) else {
        return Ok(());
    };
    if let Ok(Some(existing)) = read_raw_reg_binary(&subkey, VALUE_VAULT_BACKUP, MAX_DPAPI_BLOB) {
        let zeros = vec![0u8; existing.len()];
        let _ = write_raw_reg_binary(key.0, VALUE_VAULT_BACKUP, &zeros);
    }
    delete_reg_value_ignore_missing(key.0, VALUE_VAULT_BACKUP);
    delete_reg_value_ignore_missing(key.0, VALUE_VAULT_PENDING);
    Ok(())
}

/// Read the optional 65-byte uncompressed P-256 public key for PIV slot `0x9E`
/// (`Card Authentication`, `PIN=NEVER`), used to authenticate the physical card
/// BEFORE transmitting the user's plaintext PIN or PUK.
pub fn read_card_auth_9e_pub(sid: &str) -> Result<Option<Vec<u8>>> {
    let subkey = user_subkey_str(sid)?;
    let Some(bytes) = read_raw_reg_binary(&subkey, VALUE_CARD_AUTH_9E_PUB, 133)? else {
        return Ok(None);
    };
    if crate::crypto::p256_public_from_sec1(&bytes).is_err() {
        return Err(AuthError::Vault(
            "corrupted CardAuth9EPub public key in registry".into(),
        ));
    }
    Ok(Some(bytes))
}

/// Persist the verified 65-byte uncompressed P-256 public key for slot `0x9E`.
pub fn write_card_auth_9e_pub(sid: &str, pub_sec1: &[u8]) -> Result<()> {
    let _ = crate::crypto::p256_public_from_sec1(pub_sec1)?;
    ensure_secured_vault_hierarchy()?;
    let subkey = user_subkey_str(sid)?;
    let key = create_secured_hklm_key(&subkey)?;
    write_raw_reg_binary(key.0, VALUE_CARD_AUTH_9E_PUB, pub_sec1)
}

/// Remove any stored `CardAuth9EPub` when re-enrolling with a card that does not
/// have slot `0x9E` provisioned.
pub fn clear_card_auth_9e_pub(sid: &str) -> Result<()> {
    let subkey = user_subkey_str(sid)?;
    let Ok(key) = create_secured_hklm_key(&subkey) else {
        return Ok(());
    };
    delete_reg_value_ignore_missing(key.0, VALUE_CARD_AUTH_9E_PUB);
    Ok(())
}

/// Read the machine-pinned `0xF9` attestation CA public-key SHA-256 fingerprint.
pub fn read_pinned_f9() -> Result<Option<[u8; 32]>> {
    let Some(bytes) = read_raw_reg_binary(ATTESTATION_SUBKEY, VALUE_PINNED_F9, 64)? else {
        return Ok(None);
    };
    if bytes.len() != 32 {
        return Err(AuthError::Attestation(
            "corrupted pinned 0xF9 fingerprint in registry".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

/// Pin the `0xF9` attestation CA public-key SHA-256 fingerprint under secured `HKLM`.
pub fn write_pinned_f9(fingerprint: &[u8; 32]) -> Result<()> {
    ensure_secured_vault_hierarchy()?;
    let key = create_secured_hklm_key(ATTESTATION_SUBKEY)?;
    write_raw_reg_binary(key.0, VALUE_PINNED_F9, fingerprint)
}

/// Clear the pinned `0xF9` attestation CA fingerprint (used after card replacement or PIV reset).
/// Returns `true` if a previously pinned value existed and was removed.
pub fn clear_pinned_f9() -> Result<bool> {
    ensure_secured_vault_hierarchy()?;
    let existed = read_raw_reg_binary(ATTESTATION_SUBKEY, VALUE_PINNED_F9, 64)?.is_some();
    let key = create_secured_hklm_key(ATTESTATION_SUBKEY)?;
    delete_reg_value_ignore_missing(key.0, VALUE_PINNED_F9);
    Ok(existed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CooldownDecision {
    Expired,
    Active {
        remaining_secs: u64,
    },
    ClampBackwardJump {
        clamped_until_unix: u64,
        remaining_secs: u64,
    },
}

fn evaluate_cooldown_deadline(until_unix: u64, now_unix: u64, max_secs: u64) -> CooldownDecision {
    if now_unix >= until_unix {
        return CooldownDecision::Expired;
    }
    let diff = until_unix - now_unix;
    if diff > max_secs {
        // System clock moved backwards; clamp deadline so cooldown never exceeds `max_secs`.
        CooldownDecision::ClampBackwardJump {
            clamped_until_unix: now_unix.saturating_add(max_secs),
            remaining_secs: max_secs,
        }
    } else {
        CooldownDecision::Active {
            remaining_secs: diff,
        }
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn start_named_cooldown(name: &str, duration_secs: u64) -> Result<()> {
    ensure_secured_vault_hierarchy()?;
    let key = create_secured_hklm_key(COOLDOWNS_SUBKEY)?;
    let capped = duration_secs.min(LAST_ATTEMPT_COOLDOWN_SECS);
    let until = unix_now_secs().saturating_add(capped);
    write_raw_reg_binary(key.0, name, &until.to_le_bytes())
}

fn check_named_cooldown(name: &str) -> Result<Option<u64>> {
    let Some(bytes) = read_raw_reg_binary(COOLDOWNS_SUBKEY, name, 16)? else {
        return Ok(None);
    };
    if bytes.len() != 8 {
        let _ = clear_named_cooldown(name);
        return Ok(None);
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes);
    let until = u64::from_le_bytes(raw);
    let now = unix_now_secs();

    match evaluate_cooldown_deadline(until, now, LAST_ATTEMPT_COOLDOWN_SECS) {
        CooldownDecision::Expired => {
            let _ = clear_named_cooldown(name);
            Ok(None)
        }
        CooldownDecision::Active { remaining_secs } => Ok(Some(remaining_secs)),
        CooldownDecision::ClampBackwardJump {
            clamped_until_unix,
            remaining_secs,
        } => {
            if let Ok(key) = create_secured_hklm_key(COOLDOWNS_SUBKEY) {
                let _ = write_raw_reg_binary(key.0, name, &clamped_until_unix.to_le_bytes());
            }
            Ok(Some(remaining_secs))
        }
    }
}

fn clear_named_cooldown(name: &str) -> Result<()> {
    let Ok(key) = create_secured_hklm_key(COOLDOWNS_SUBKEY) else {
        return Ok(());
    };
    delete_reg_value_ignore_missing(key.0, name);
    Ok(())
}

/// Record a mandatory safety cooldown (default 60s) for `card_fingerprint` when
/// the card reaches 1 remaining PIN attempt (`63 C1`), preventing accidental
/// rapid keypresses from locking the hardware card.
pub fn start_last_attempt_cooldown(card_fingerprint: &[u8; 32], duration_secs: u64) -> Result<()> {
    start_named_cooldown(&hex::encode(card_fingerprint), duration_secs)
}

/// Check whether `card_fingerprint` has an active last-attempt PIN cooldown.
/// Returns `Ok(Some(remaining_secs))` if active, or `Ok(None)` if expired/absent.
pub fn check_last_attempt_cooldown(card_fingerprint: &[u8; 32]) -> Result<Option<u64>> {
    check_named_cooldown(&hex::encode(card_fingerprint))
}

/// Clear any active last-attempt PIN cooldown for `card_fingerprint`.
pub fn clear_last_attempt_cooldown(card_fingerprint: &[u8; 32]) -> Result<()> {
    clear_named_cooldown(&hex::encode(card_fingerprint))
}

/// Record a mandatory safety cooldown (default 60s) before the final PUK attempt (`63 C1`),
/// protecting the PIV applet from accidental permanent PUK bricking.
pub fn start_puk_last_attempt_cooldown(
    card_fingerprint: &[u8; 32],
    duration_secs: u64,
) -> Result<()> {
    start_named_cooldown(
        &format!("{}_puk", hex::encode(card_fingerprint)),
        duration_secs,
    )
}

pub fn check_puk_last_attempt_cooldown(card_fingerprint: &[u8; 32]) -> Result<Option<u64>> {
    check_named_cooldown(&format!("{}_puk", hex::encode(card_fingerprint)))
}

pub fn clear_puk_last_attempt_cooldown(card_fingerprint: &[u8; 32]) -> Result<()> {
    clear_named_cooldown(&format!("{}_puk", hex::encode(card_fingerprint)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_builds_valid_dacl() {
        for sddl in [
            SDDL_SYSTEM_ADMINS_ONLY,
            SDDL_PROGRAM_FILES_BINARIES,
            SDDL_COM_CLSID_READABLE,
        ] {
            let sd = SecurityDescriptorGuard::from_sddl(sddl).unwrap();
            let dacl = sd.dacl_ptr().unwrap();
            assert!(!dacl.is_null());
        }
    }

    #[test]
    fn sid_validator_rejects_traversal_and_garbage() {
        assert!(validate_sid_token("S-1-5-21-123456-7890-1001").is_ok());
        assert!(validate_sid_token("").is_err());
        assert!(validate_sid_token("S-1-5-21\\..\\Evil").is_err());
        assert!(validate_sid_token("Administrator").is_err());
    }

    #[test]
    fn cooldown_deadline_handles_expiry_and_backwards_clock_jumps() {
        assert_eq!(
            evaluate_cooldown_deadline(1_060, 1_015, 60),
            CooldownDecision::Active { remaining_secs: 45 }
        );
        assert_eq!(
            evaluate_cooldown_deadline(1_060, 1_060, 60),
            CooldownDecision::Expired
        );
        assert_eq!(
            evaluate_cooldown_deadline(1_060, 1_200, 60),
            CooldownDecision::Expired
        );
        // Backwards jump by 1 hour clamps remaining wait to 60s instead of 3660s!
        assert_eq!(
            evaluate_cooldown_deadline(5_000, 1_000, 60),
            CooldownDecision::ClampBackwardJump {
                clamped_until_unix: 1_060,
                remaining_secs: 60,
            }
        );
    }
}
