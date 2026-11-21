//! Windows account resolution, Workgroup/cloud-account policy checks, and
//! atomic password rotation helpers.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::error::{AuthError, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGetJoinInformation, NetSetupDomainName, NetUserGetInfo, NetUserModalsGet,
    NetUserSetInfo, NETSETUP_JOIN_STATUS, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1,
    USER_INFO_1003, USER_INFO_1008, USER_INFO_24, USER_MODALS_INFO_3,
};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows::Win32::Security::{
    LookupAccountNameW, LookupAccountSidW, SidTypeUser, PSID, SID_NAME_USE,
};
use windows::Win32::System::RemoteDesktop::{
    WTSDomainName, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName, WTS_CURRENT_SESSION,
};
use windows::Win32::System::WindowsProgramming::GetComputerNameW;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub sid: String,
    pub domain: String,
    pub username: String,
    pub computer: String,
}

#[derive(Debug, Clone)]
pub struct AccountSafetyStatus {
    pub lockout_threshold: u32,
}

/// Resolve the interactive session user to an authoritative `(SID, domain, username, computer)`.
pub fn current_user() -> Result<UserInfo> {
    let username = query_wts_string(WTSUserName)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("USERNAME")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .ok_or_else(|| AuthError::Internal("interactive USERNAME is not available".into()))?;
    let domain = query_wts_string(WTSDomainName)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("USERDOMAIN")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| ".".into());

    let qualified = if domain == "." || domain.is_empty() {
        username
    } else {
        format!("{domain}\\{username}")
    };
    lookup_local_account_by_name(&qualified)
}

/// Resolve a SID string (`S-1-5-21-...`) to its authoritative `(domain, username)` on this machine.
///
/// Used by the Credential Provider so enumerated user tiles always match the exact SAM
/// account name regardless of UPN or display-name formatting.
pub fn lookup_account_by_sid(sid_text: &str) -> Result<UserInfo> {
    let computer = computer_name()?;
    let sid_w: Vec<u16> = sid_text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psid = PSID::default();
    // SAFETY: `sid_w` is NUL-terminated; `psid` is freed with `LocalFree` below.
    unsafe { ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut psid) }
        .map_err(|e| AuthError::Internal(format!("ConvertStringSidToSidW failed: {e}")))?;

    struct SidGuard(PSID);
    impl Drop for SidGuard {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                // SAFETY: Allocated by `ConvertStringSidToSidW`.
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0 .0)));
                }
            }
        }
    }
    let guard = SidGuard(psid);

    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_use = SID_NAME_USE::default();
    // SAFETY: First call queries required buffer lengths.
    unsafe {
        let _ = LookupAccountSidW(
            PCWSTR::null(),
            guard.0,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut sid_use,
        );
    }
    if name_len == 0 || name_len > 1024 || domain_len > 1024 {
        return Err(AuthError::Internal(
            "LookupAccountSidW returned invalid buffer size".into(),
        ));
    }

    let mut name_buf = vec![0u16; name_len as usize];
    let mut domain_buf = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: Buffers match queried sizes.
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            guard.0,
            Some(PWSTR(name_buf.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain_buf.as_mut_ptr())),
            &mut domain_len,
            &mut sid_use,
        )
    }
    .map_err(|e| AuthError::Internal(format!("LookupAccountSidW failed: {e}")))?;

    let username = String::from_utf16_lossy(&name_buf[..name_len as usize]);
    let domain = if domain_len > 0 {
        String::from_utf16_lossy(&domain_buf[..domain_len as usize])
    } else {
        computer.clone()
    };

    Ok(UserInfo {
        sid: sid_text.to_string(),
        domain,
        username,
        computer,
    })
}

/// Resolve a typed username (`alice`, `.\alice`, or `MYPC\alice`) to a local account `UserInfo`.
///
/// Rejects domain/non-local accounts so the "Other user" tile only targets local accounts.
pub fn lookup_local_account_by_name(input: &str) -> Result<UserInfo> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(AuthError::AccountPolicy("invalid username".into()));
    }
    let computer = computer_name()?;

    let normalized = if let Some((dom, user)) = trimmed.rsplit_once('\\') {
        if user.is_empty() {
            return Err(AuthError::AccountPolicy("empty username".into()));
        }
        if !dom.is_empty() && dom != "." && !dom.eq_ignore_ascii_case(&computer) {
            return Err(AuthError::AccountPolicy(
                "only local computer accounts are supported".into(),
            ));
        }
        format!("{computer}\\{user}")
    } else if trimmed.contains('@') {
        return Err(AuthError::AccountPolicy(
            "UPN / cloud accounts are not supported; enter the local username".into(),
        ));
    } else {
        format!("{computer}\\{trimmed}")
    };

    let qualified_w: Vec<u16> = normalized
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type = SID_NAME_USE::default();

    // SAFETY: Queries required SID and domain buffer sizes.
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
    if sid_len == 0 || sid_len > 512 || domain_len > 1024 {
        return Err(AuthError::AccountPolicy(
            "local user account not found".into(),
        ));
    }

    let mut sid = vec![0u8; sid_len as usize];
    let mut domain_buffer = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: `sid` and `domain_buffer` match queried lengths.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(qualified_w.as_ptr()),
            Some(PSID(sid.as_mut_ptr() as *mut core::ffi::c_void)),
            &mut sid_len,
            Some(PWSTR(domain_buffer.as_mut_ptr())),
            &mut domain_len,
            &mut sid_type,
        )
    }
    .map_err(|_| AuthError::AccountPolicy("local user account lookup failed".into()))?;

    if sid_type != SidTypeUser {
        return Err(AuthError::AccountPolicy(
            "target account is not a standard user account".into(),
        ));
    }

    let mut sid_string = PWSTR::null();
    // SAFETY: `sid` contains a valid binary SID from `LookupAccountNameW`.
    unsafe {
        ConvertSidToStringSidW(
            PSID(sid.as_mut_ptr() as *mut core::ffi::c_void),
            &mut sid_string,
        )
    }
    .map_err(|e| AuthError::Internal(format!("ConvertSidToStringSidW failed: {e}")))?;

    // SAFETY: `sid_string` is NUL-terminated and freed via `LocalFree`.
    let sid_text = unsafe { sid_string.to_string() }.unwrap_or_default();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_string.0 as *mut core::ffi::c_void)));
    }

    let resolved_domain = if domain_len > 0 {
        String::from_utf16_lossy(&domain_buffer[..domain_len as usize])
    } else {
        computer.clone()
    };
    if !resolved_domain.eq_ignore_ascii_case(&computer) {
        return Err(AuthError::AccountPolicy(
            "domain accounts are not supported; use a local Workgroup account".into(),
        ));
    }

    // Canonicalize the SAM username via SID reverse lookup so case and aliases match.
    lookup_account_by_sid(&sid_text)
}

/// Enforce Workgroup membership, reject Microsoft/cloud-connected accounts, and
/// inspect the local account lockout threshold.
pub fn verify_local_workgroup_account(username: &str) -> Result<AccountSafetyStatus> {
    let mut name_buf = PWSTR::null();
    let mut join_status = NETSETUP_JOIN_STATUS::default();
    // SAFETY: Queries local machine join status; `name_buf` is freed below.
    let rc = unsafe { NetGetJoinInformation(PCWSTR::null(), &mut name_buf, &mut join_status) };
    if !name_buf.is_null() {
        // SAFETY: Allocated by `NetGetJoinInformation`.
        unsafe {
            let _ = NetApiBufferFree(Some(name_buf.0 as *const core::ffi::c_void));
        }
    }
    if rc == 0 && join_status == NetSetupDomainName {
        return Err(AuthError::AccountPolicy(
            "this computer is joined to an Active Directory domain; FamiliarSmartcard only supports standalone Workgroup machines".into(),
        ));
    }

    // Check USER_INFO_24 to reject Microsoft Accounts / Azure AD / internet identities.
    let username_w: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let mut info24_ptr: *mut u8 = std::ptr::null_mut();
    // SAFETY: `username_w` is NUL-terminated; `info24_ptr` is freed if non-null.
    let status24 = unsafe {
        NetUserGetInfo(
            PCWSTR::null(),
            PCWSTR(username_w.as_ptr()),
            24,
            &mut info24_ptr,
        )
    };
    if status24 == 0 && !info24_ptr.is_null() {
        // SAFETY: `NetUserGetInfo` level 24 succeeded and returned a `USER_INFO_24`.
        let is_cloud =
            unsafe { (*(info24_ptr as *const USER_INFO_24)).usri24_internet_identity }.as_bool();
        unsafe {
            let _ = NetApiBufferFree(Some(info24_ptr as *const core::ffi::c_void));
        }
        if is_cloud {
            return Err(AuthError::AccountPolicy(
                "Microsoft / cloud-connected accounts are not supported; switch to a local Windows account".into(),
            ));
        }
    }

    let mut modals_ptr: *mut u8 = std::ptr::null_mut();
    // SAFETY: Queries local SAM lockout policy (`USER_MODALS_INFO_3`).
    let modals_rc = unsafe { NetUserModalsGet(PCWSTR::null(), 3, &mut modals_ptr) };
    let mut lockout_threshold = 0u32;
    if modals_rc == 0 && !modals_ptr.is_null() {
        // SAFETY: Valid `USER_MODALS_INFO_3` returned by `NetUserModalsGet`.
        lockout_threshold =
            unsafe { (*(modals_ptr as *const USER_MODALS_INFO_3)).usrmod3_lockout_threshold };
        unsafe {
            let _ = NetApiBufferFree(Some(modals_ptr as *const core::ffi::c_void));
        }
    }

    Ok(AccountSafetyStatus { lockout_threshold })
}

/// Atomically set a local user's password via `NetUserSetInfo` (level 1003) and
/// set `UF_DONT_EXPIRE_PASSWD` (level 1008) while preserving existing account flags.
pub fn rotate_local_password_and_disable_expiry(username: &str, new_password: &str) -> Result<()> {
    let username_w: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let mut pw_w: Zeroizing<Vec<u16>> = Zeroizing::new(
        new_password
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect(),
    );

    // Read current flags first so we preserve all existing account bits.
    let mut info1_ptr: *mut u8 = std::ptr::null_mut();
    // SAFETY: Queries `USER_INFO_1` for `username_w`.
    let rc1 = unsafe {
        NetUserGetInfo(
            PCWSTR::null(),
            PCWSTR(username_w.as_ptr()),
            1,
            &mut info1_ptr,
        )
    };
    if rc1 != 0 || info1_ptr.is_null() {
        return Err(AuthError::Internal(format!(
            "NetUserGetInfo(level=1) failed with status {rc1}"
        )));
    }
    // SAFETY: Valid `USER_INFO_1` buffer.
    let existing_flags = unsafe { (*(info1_ptr as *const USER_INFO_1)).usri1_flags };
    unsafe {
        let _ = NetApiBufferFree(Some(info1_ptr as *const core::ffi::c_void));
    }

    let info1003 = USER_INFO_1003 {
        usri1003_password: PWSTR(pw_w.as_mut_ptr()),
    };
    // SAFETY: `username_w` and `pw_w` outlive `NetUserSetInfo`.
    let rc_pw = unsafe {
        NetUserSetInfo(
            PCWSTR::null(),
            PCWSTR(username_w.as_ptr()),
            1003,
            &info1003 as *const USER_INFO_1003 as *const u8,
            None,
        )
    };
    if rc_pw != 0 {
        return Err(AuthError::Internal(format!(
            "NetUserSetInfo(level=1003) password update failed with status {rc_pw}"
        )));
    }

    let info1008 = USER_INFO_1008 {
        usri1008_flags: existing_flags | UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
    };
    // SAFETY: `info1008` is valid for level 1008.
    let rc_flags = unsafe {
        NetUserSetInfo(
            PCWSTR::null(),
            PCWSTR(username_w.as_ptr()),
            1008,
            &info1008 as *const USER_INFO_1008 as *const u8,
            None,
        )
    };
    if rc_flags != 0 {
        return Err(AuthError::Internal(format!(
            "password changed, but setting UF_DONT_EXPIRE_PASSWD failed with status {rc_flags}"
        )));
    }

    Ok(())
}

fn query_wts_string(
    class: windows::Win32::System::RemoteDesktop::WTS_INFO_CLASS,
) -> Option<String> {
    let mut buffer = PWSTR::null();
    let mut bytes = 0u32;
    // SAFETY: Queries current session info; `buffer` is freed with `WTSFreeMemory`.
    unsafe {
        WTSQuerySessionInformationW(None, WTS_CURRENT_SESSION, class, &mut buffer, &mut bytes)
            .ok()?;
    }
    if buffer.is_null() {
        return None;
    }
    // SAFETY: `buffer` is NUL-terminated UTF-16 returned by WTS.
    let value = unsafe { buffer.to_string() }.ok();
    unsafe {
        WTSFreeMemory(buffer.0 as *mut core::ffi::c_void);
    }
    value
}

/// Read the computer name through Win32 rather than relying on environment variables.
pub fn computer_name() -> Result<String> {
    let mut length = 256u32;
    let mut buffer = vec![0u16; length as usize];
    // SAFETY: `buffer` has 256 `u16` elements (`MAX_COMPUTERNAME_LENGTH + 1` is 16).
    unsafe { GetComputerNameW(Some(PWSTR(buffer.as_mut_ptr())), &mut length) }
        .map_err(|error| AuthError::Internal(format!("GetComputerNameW failed: {error}")))?;
    Ok(String::from_utf16_lossy(
        &buffer[..(length as usize).min(buffer.len())],
    ))
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn query_password_age_and_midpoint(username_w: &[u16]) -> Result<(u64, u64)> {
    for _ in 0..2 {
        let before = unix_now_secs();
        let mut buffer: *mut u8 = std::ptr::null_mut();
        // SAFETY: `username_w` is NUL-terminated; `buffer` is freed via `NetApiBufferFree`.
        let status =
            unsafe { NetUserGetInfo(PCWSTR::null(), PCWSTR(username_w.as_ptr()), 1, &mut buffer) };
        if status != 0 || buffer.is_null() {
            return Err(AuthError::Internal(format!(
                "NetUserGetInfo failed with status {status}"
            )));
        }
        // SAFETY: Valid `USER_INFO_1` returned by `NetUserGetInfo`.
        let age = unsafe { (*(buffer as *const USER_INFO_1)).usri1_password_age } as u64;
        unsafe {
            let _ = NetApiBufferFree(Some(buffer as *const core::ffi::c_void));
        }
        let after = unix_now_secs();

        if after.abs_diff(before) <= 2 {
            let midpoint = before / 2 + after / 2 + (before & after & 1);
            return Ok((midpoint, age));
        }
    }

    Err(AuthError::Internal(
        "system clock jumped repeatedly while querying password age".into(),
    ))
}

/// Compute the password-set marker for login / self-test comparison.
///
/// Important Windows SAM quirk: local accounts created during OOBE / `unattend.xml`
/// whose password has never been rotated via SAM password-change APIs have
/// `PasswordLastSet == 0` in SAM, causing `usri1_password_age` to remain `0`
/// permanently. Returning sentinel `0` when `age == 0` prevents `now - 0` from
/// drifting with the wall clock and falsely reporting `PasswordChanged` after 10s.
pub fn password_last_set(username: &str) -> Result<u64> {
    let username_w: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let (midpoint, age) = query_password_age_and_midpoint(&username_w)?;
    if age == 0 {
        return Ok(0);
    }
    Ok(midpoint.saturating_sub(age))
}

/// Compute the static `password_last_set` marker at enrollment / rotation time.
///
/// Distinguishes two `usri1_password_age == 0` states by waiting 1.1s once when `age == 0`:
/// - Just-rotated password (`NetUserSetInfo` <1s ago): `age` advances to `>= 1`,
///   yielding the real Unix timestamp `midpoint - age > 0`.
/// - OOBE / un-aged password (`SAM.PasswordLastSet == 0`): `age` remains `0`,
///   yielding stable sentinel `0` so `Re-bind current password` works indefinitely
///   while still catching any future password change (`0 -> non-zero`).
pub fn password_last_set_for_enrollment(username: &str) -> Result<u64> {
    let username_w: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let (midpoint, age) = query_password_age_and_midpoint(&username_w)?;
    if age > 0 {
        return Ok(midpoint.saturating_sub(age));
    }

    std::thread::sleep(std::time::Duration::from_millis(1100));
    let (midpoint2, age2) = query_password_age_and_midpoint(&username_w)?;
    if age2 > 0 {
        Ok(midpoint2.saturating_sub(age2))
    } else {
        Ok(0)
    }
}
