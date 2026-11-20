//! Current interactive-account helpers for the enrollment GUI.

use crate::error::{AuthError, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserGetInfo, USER_INFO_1,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub sid: String,
    pub domain: String,
    pub username: String,
    pub computer: String,
}

/// Resolve the current process user to a SID/domain/username.
///
/// The GUI should eventually use WTS APIs to identify the interactive session
/// user instead of the elevated process token. This helper is the initial
/// bridge until that is wired in.
pub fn current_user() -> Result<UserInfo> {
    let username =
        std::env::var("USERNAME").map_err(|_| AuthError::Internal("USERNAME is not set".into()))?;
    let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| ".".into());
    let computer = std::env::var("COMPUTERNAME").unwrap_or_else(|_| ".".into());

    let qualified = if domain == "." || domain.is_empty() {
        username.clone()
    } else {
        format!("{domain}\\{username}")
    };
    let qualified_w: Vec<u16> = qualified.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type = SID_NAME_USE::default();

    unsafe {
        let _ = LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(qualified_w.as_ptr()),
            None,
            &mut sid_len,
            None,
            &mut domain_len,
            &mut sid_type,
        );
    }

    if sid_len == 0 {
        return Err(AuthError::Internal(
            "LookupAccountNameW returned no SID size".into(),
        ));
    }

    let mut sid = vec![0u8; sid_len as usize];
    let mut domain_buffer = vec![0u16; domain_len.max(1) as usize];
    let status = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(qualified_w.as_ptr()),
            Some(PSID(sid.as_mut_ptr() as *mut core::ffi::c_void)),
            &mut sid_len,
            Some(PWSTR(domain_buffer.as_mut_ptr())),
            &mut domain_len,
            &mut sid_type,
        )
    };
    status.map_err(|error| AuthError::Internal(format!("LookupAccountNameW failed: {error}")))?;

    let mut sid_string = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(
            PSID(sid.as_mut_ptr() as *mut core::ffi::c_void),
            &mut sid_string,
        )
    }
    .map_err(|error| AuthError::Internal(format!("ConvertSidToStringSidW failed: {error}")))?;

    let sid_text = unsafe { sid_string.to_string() }.unwrap_or_default();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_string.0 as *mut core::ffi::c_void)));
    }

    Ok(UserInfo {
        sid: sid_text,
        domain: if domain_len > 0 {
            String::from_utf16_lossy(&domain_buffer[..domain_len as usize])
        } else {
            domain
        },
        username,
        computer,
    })
}

/// Compute the approximate absolute password-set time from
/// `USER_INFO_1::usri1_password_age` (relative seconds).
///
/// The value is intentionally approximate; callers must compare with the
/// static vault value using `vault::password_last_set_matches` (±5 seconds).
pub fn password_last_set(username: &str) -> Result<u64> {
    let username_w: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer: *mut u8 = std::ptr::null_mut();

    let status =
        unsafe { NetUserGetInfo(PCWSTR::null(), PCWSTR(username_w.as_ptr()), 1, &mut buffer) };
    if status != 0 || buffer.is_null() {
        return Err(AuthError::Internal(format!(
            "NetUserGetInfo failed with status {status}"
        )));
    }

    let info = unsafe { &*(buffer as *const USER_INFO_1) };
    let age = info.usri1_password_age as u64;
    unsafe {
        let _ = NetApiBufferFree(Some(buffer as *const core::ffi::c_void));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    Ok(now.saturating_sub(age))
}
