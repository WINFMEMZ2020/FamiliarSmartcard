//! Pure-Rust installer and Credential Provider registrar.
//!
//! Security & Reliability guarantees:
//! - Verifies all required binaries (`cred_provider.dll` and `familiar-auth-helper.exe`)
//!   exist BEFORE any account password rotation begins.
//! - Applies standard hardened `Program Files` ACLs (`SY`/`BA` FullControl,
//!   `Users`/`ALL APPLICATION PACKAGES`/`LOCAL SERVICE` ReadAndExecute) so Windows 10/11
//!   XAML `LogonUI.exe` can always load the COM DLL while non-admins have zero write access.
//! - Live hot-swaps an in-use `familiar_cred_provider.dll` by renaming the mapped old
//!   file to `.old.<tick>` (scheduled for boot cleanup) and immediately placing the new
//!   DLL at the canonical path — taking effect on the very next lock/RDP session without reboot!

#![deny(unsafe_op_in_unsafe_fn)]

use scard_core::crypto::{constant_time_eq, sha256};
use scard_core::storage::{
    apply_program_files_binary_acl, ensure_secured_vault_hierarchy, restore_com_clsid_acl,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY,
    KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};

const CLSID_STR: &str = "{6E2B7F4A-9C1D-4E8B-9A7F-3D5C1E2B4A60}";
const PROVIDER_NAME: &str = "FamiliarSmartcard";
const DEST_DLL_NAME: &str = "familiar_cred_provider.dll";
const HELPER_EXE_NAME: &str = "familiar-auth-helper.exe";
const ENROLL_EXE_NAME: &str = "familiar-enroll.exe";

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn program_files_install_dir() -> PathBuf {
    let base = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    PathBuf::from(base).join("FamiliarSmartcard")
}

fn find_source_binary(exe_dir: &Path, filename: &str) -> Option<PathBuf> {
    let direct = exe_dir.join(filename);
    if direct.is_file() {
        return Some(direct);
    }
    if let Some(parent) = exe_dir.parent() {
        for sub in ["release", "debug"] {
            let candidate = parent.join(sub).join(filename);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Verify that both `cred_provider.dll` and `familiar-auth-helper.exe` are present
/// before starting any card enrollment or password rotation.
pub fn preflight_check_sources() -> Result<(PathBuf, PathBuf), String> {
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_dir = current_exe
        .parent()
        .ok_or_else(|| "Cannot determine executable directory.".to_string())?;
    let install_dir = program_files_install_dir();
    let dest_dll = install_dir.join(DEST_DLL_NAME);
    let dest_helper = install_dir.join(HELPER_EXE_NAME);

    let src_dll = find_source_binary(exe_dir, "cred_provider.dll")
        .or_else(|| find_source_binary(exe_dir, DEST_DLL_NAME))
        .or_else(|| dest_dll.is_file().then_some(dest_dll))
        .ok_or_else(|| {
            format!(
                "cred_provider.dll was not found in '{}'. Please copy ALL files from dist\\FamiliarSmartcard (familiar-enroll.exe, cred_provider.dll, AND familiar-auth-helper.exe) into the same folder.",
                exe_dir.display()
            )
        })?;

    let src_helper = find_source_binary(exe_dir, HELPER_EXE_NAME)
        .or_else(|| dest_helper.is_file().then_some(dest_helper))
        .ok_or_else(|| {
            format!(
                "{HELPER_EXE_NAME} was not found in '{}'. Please copy ALL files from dist\\FamiliarSmartcard (familiar-enroll.exe, cred_provider.dll, AND familiar-auth-helper.exe) into the same folder.",
                exe_dir.display()
            )
        })?;

    Ok((src_dll, src_helper))
}

fn files_have_identical_hash(a: &Path, b: &Path) -> bool {
    let (Ok(bytes_a), Ok(bytes_b)) = (fs::read(a), fs::read(b)) else {
        return false;
    };
    constant_time_eq(&sha256(&bytes_a), &sha256(&bytes_b))
}

/// Copy `src` to `dest` and apply `Program Files` read+execute ACLs.
/// If `dest` is currently mapped into `LogonUI.exe`, rename `dest` aside to `.old.<ts>`
/// (marking the old file for reboot deletion) so the new file goes live immediately!
fn install_binary_live(src: &Path, dest: &Path) -> Result<(), String> {
    if src == dest {
        apply_program_files_binary_acl(dest).map_err(|e| e.to_string())?;
        return Ok(());
    }
    if dest.is_file() && files_have_identical_hash(src, dest) {
        apply_program_files_binary_acl(dest).map_err(|e| e.to_string())?;
        return Ok(());
    }

    if fs::copy(src, dest).is_ok() {
        apply_program_files_binary_acl(dest).map_err(|e| e.to_string())?;
        return Ok(());
    }

    // `dest` is locked by a running `LogonUI.exe` process. NTFS permits renaming a
    // mapped DLL within the same directory, freeing `dest` for immediate replacement!
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let old_backup = dest.with_extension(format!("old.{stamp}"));
    let dest_w = to_wide(&dest.to_string_lossy());
    let old_w = to_wide(&old_backup.to_string_lossy());

    // SAFETY: Valid NUL-terminated wide paths.
    unsafe {
        MoveFileExW(
            PCWSTR(dest_w.as_ptr()),
            PCWSTR(old_w.as_ptr()),
            MOVEFILE_REPLACE_EXISTING,
        )
    }
    .map_err(|e| {
        format!(
            "Failed to move locked {} aside: {}",
            dest.display(),
            e.message()
        )
    })?;

    // Best-effort cleanup of the renamed old binary on next reboot.
    // SAFETY: Valid NUL-terminated wide path; `PCWSTR::null()` schedules delete on reboot.
    unsafe {
        let _ = MoveFileExW(
            PCWSTR(old_w.as_ptr()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        );
    }

    fs::copy(src, dest).map_err(|e| {
        format!(
            "Failed to copy {} -> {} after moving old binary aside: {e}",
            src.display(),
            dest.display()
        )
    })?;
    apply_program_files_binary_acl(dest).map_err(|e| e.to_string())?;
    Ok(())
}

fn write_reg_sz_64(subkey: &str, value_name: Option<&str>, text: &str) -> Result<(), String> {
    let subkey_w = to_wide(subkey);
    let mut key = HKEY::default();
    // SAFETY: `subkey_w` is NUL-terminated.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_WOW64_64KEY,
            None,
            &mut key,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(format!("RegCreateKeyExW({subkey}) failed: 0x{:08X}", rc.0));
    }

    let name_w = value_name.map(to_wide);
    let name_ptr = match &name_w {
        Some(w) => PCWSTR(w.as_ptr()),
        None => PCWSTR::null(),
    };
    let data_w = to_wide(text);
    // SAFETY: `data_w` is valid UTF-16LE including NUL terminator (`len * 2` bytes).
    let data_bytes =
        unsafe { std::slice::from_raw_parts(data_w.as_ptr() as *const u8, data_w.len() * 2) };
    // SAFETY: `key` is open with `KEY_WRITE`.
    let set_rc = unsafe { RegSetValueExW(key, name_ptr, None, REG_SZ, Some(data_bytes)) };
    // SAFETY: Close handle opened above.
    unsafe {
        let _ = RegCloseKey(key);
    }
    if set_rc != ERROR_SUCCESS {
        return Err(format!(
            "RegSetValueExW({subkey}) failed: 0x{:08X}",
            set_rc.0
        ));
    }
    Ok(())
}

/// Install `familiar_cred_provider.dll` and `familiar-auth-helper.exe` into
/// `C:\Program Files\FamiliarSmartcard\`, harden `HKLM\SOFTWARE\FamiliarSmartcard`,
/// and register the COM Credential Provider so it is immediately active.
pub fn install_and_register() -> Result<String, String> {
    let (src_dll, src_helper) = preflight_check_sources()?;
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;

    let install_dir = program_files_install_dir();
    let dest_dll = install_dir.join(DEST_DLL_NAME);
    let dest_helper = install_dir.join(HELPER_EXE_NAME);
    let dest_enroll = install_dir.join(ENROLL_EXE_NAME);

    fs::create_dir_all(&install_dir)
        .map_err(|e| format!("Failed to create {}: {e}", install_dir.display()))?;
    apply_program_files_binary_acl(&install_dir).map_err(|e| e.to_string())?;

    install_binary_live(&src_dll, &dest_dll)?;
    install_binary_live(&src_helper, &dest_helper)?;
    let _ = install_binary_live(&current_exe, &dest_enroll);

    ensure_secured_vault_hierarchy().map_err(|e| e.to_string())?;

    let cp_subkey = format!(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{CLSID_STR}"
    );
    write_reg_sz_64(&cp_subkey, None, PROVIDER_NAME)?;

    let clsid_root = format!("SOFTWARE\\Classes\\CLSID\\{CLSID_STR}");
    let inproc_subkey = format!("{clsid_root}\\InprocServer32");
    write_reg_sz_64(&inproc_subkey, None, &dest_dll.to_string_lossy())?;
    write_reg_sz_64(&inproc_subkey, Some("ThreadingModel"), "Apartment")?;
    // Ensure COM `Classes\CLSID` has standard `Read` permissions for LogonUI/AppContainer
    // (healing any overly restrictive DACL from an older build) while keeping write restricted to SY/BA.
    let _ = restore_com_clsid_acl(&clsid_root);
    let _ = restore_com_clsid_acl(&inproc_subkey);

    Ok(format!(
        "Installed live to: {}\r\nRegistered CLSID:  {CLSID_STR}\r\nHelper binary:     {}",
        dest_dll.display(),
        dest_helper.display()
    ))
}
