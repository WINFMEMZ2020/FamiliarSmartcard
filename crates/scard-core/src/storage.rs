//! Registry storage for per-user vault blobs.
//!
//! The registry value contains a DPAPI machine-scope envelope. The DPAPI
//! entropy is derived from the SID so a blob cannot be transplanted between
//! users. The ACL must be restricted to SYSTEM/Administrators by the installer.

use crate::dpapi;
use crate::error::{AuthError, Result};
use crate::vault::VaultBlob;
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_WOW64_64KEY, KEY_WRITE, REG_BINARY, REG_OPTION_NON_VOLATILE, RRF_RT_REG_BINARY,
};

const REG_PREFIX: &str = "SOFTWARE\\FamiliarSmartcard\\Users\\";
const VALUE_NAME: &str = "VaultBlob";
const MAX_DPAPI_BLOB: usize = 4096;

/// Append a non-secret diagnostic line. Used by the Credential Provider because
/// LogonUI has no console. The file is writable by SYSTEM/Administrators.
pub fn debug_log(message: &str) {
    use std::io::Write;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(r"C:\Windows\Temp\familiar_cp.log")
    {
        let _ = writeln!(file, "{timestamp} {message}");
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn subkey_for_sid(sid: &str) -> Vec<u16> {
    to_wide(&format!("{REG_PREFIX}{sid}"))
}

fn entropy_for_sid(sid: &str) -> Vec<u8> {
    format!("FamiliarSmartcard/v1/{sid}").into_bytes()
}

pub fn read_vault(sid: &str) -> Result<Option<VaultBlob>> {
    let subkey = subkey_for_sid(sid);
    let value = to_wide(VALUE_NAME);
    debug_log(&format!("read_vault sid={sid}"));

    let mut len = 0u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_BINARY,
            None,
            None,
            Some(&mut len),
        )
    };
    debug_log(&format!(
        "read_vault first status=0x{:08X} len={len}",
        status.0
    ));

    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }
    if len as usize > MAX_DPAPI_BLOB {
        return Err(AuthError::Vault("vault blob exceeds 4096 bytes".into()));
    }

    let mut buffer = vec![0u8; len as usize];
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_BINARY,
            None,
            Some(buffer.as_mut_ptr() as *mut c_void),
            Some(&mut len),
        )
    };
    debug_log(&format!(
        "read_vault second status=0x{:08X} len={len}",
        status.0
    ));
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }
    buffer.truncate(len as usize);

    let entropy = entropy_for_sid(sid);
    let encoded = dpapi::unprotect(&buffer, &entropy)?;
    let vault = VaultBlob::decode(&encoded)?;
    debug_log("read_vault dpapi+decode ok");
    Ok(Some(vault))
}

pub fn write_vault(sid: &str, vault: &VaultBlob) -> Result<()> {
    debug_log(&format!("write_vault sid={sid}"));
    let encoded = vault.encode()?;
    let entropy = entropy_for_sid(sid);
    let protected = dpapi::protect(&encoded, &entropy)?;
    if protected.len() > MAX_DPAPI_BLOB {
        return Err(AuthError::Vault(
            "protected vault exceeds 4096 bytes".into(),
        ));
    }

    let subkey = subkey_for_sid(sid);
    let value = to_wide(VALUE_NAME);

    let mut key = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_WOW64_64KEY,
            None,
            &mut key,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }

    let status = unsafe {
        RegSetValueExW(
            key,
            PCWSTR(value.as_ptr()),
            None,
            REG_BINARY,
            Some(&protected),
        )
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    if status != ERROR_SUCCESS {
        return Err(AuthError::Registry(status.0 as i32));
    }
    Ok(())
}
