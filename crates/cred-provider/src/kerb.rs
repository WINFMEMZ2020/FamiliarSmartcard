//! KERB serialization and CredProtect helpers.
//!
//! Mirrors the Microsoft Credential Provider V2 contract: use
//! `KERB_INTERACTIVE_UNLOCK_LOGON` for both logon and unlock, set `MessageType`
//! from the usage scenario, keep `LogonId` zero, protect the password in-process
//! with `CredProtectW` (dynamic two-pass sizing), and zeroize all temporary
//! plaintext/packing buffers.

#![deny(unsafe_op_in_unsafe_fn)]

use windows::core::{PSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, E_INVALIDARG, E_OUTOFMEMORY, HANDLE, LUID,
};
use windows::Win32::Security::Authentication::Identity::{
    KerbInteractiveLogon, KerbWorkstationUnlockLogon, LsaConnectUntrusted,
    LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage, KERB_INTERACTIVE_UNLOCK_LOGON,
    LSA_STRING, LSA_UNICODE_STRING,
};
use windows::Win32::Security::Credentials::{CredProtectW, CRED_PROTECTION_TYPE};
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::Win32::UI::Shell::{CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_USAGE_SCENARIO};
use zeroize::Zeroizing;

pub struct PackedKerb {
    pub pointer: *mut u8,
    pub length: u32,
}

/// Protect a plaintext password with `CredProtectW` using dynamic two-pass buffer sizing.
///
/// The temporary UTF-16 plaintext buffer is held in `Zeroizing` so no plaintext
/// heap allocation lingers in `LogonUI.exe`.
pub fn protect_password(password: &str) -> windows::core::Result<Zeroizing<Vec<u16>>> {
    let mut input: Zeroizing<Vec<u16>> = Zeroizing::new(password.encode_utf16().collect());
    input.push(0);

    let mut cch = 0u32;
    let mut protection = CRED_PROTECTION_TYPE::default();

    // Pass 1: query the exact required character count.
    // SAFETY: `cch == 0` with null output pointer queries the required buffer size.
    let first = unsafe {
        CredProtectW(
            false,
            &input,
            PWSTR::null(),
            &mut cch,
            Some(&mut protection),
        )
    };
    if let Err(err) = first {
        if err.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() || cch == 0 {
            return Err(err);
        }
    }
    if cch == 0 || cch > 32_767 {
        return Err(windows::core::Error::from_hresult(E_INVALIDARG));
    }

    let mut output = Zeroizing::new(vec![0u16; cch as usize]);
    // Pass 2: encrypt into the sized buffer.
    // SAFETY: `output` has `cch` elements capacity.
    unsafe {
        CredProtectW(
            false,
            &input,
            PWSTR(output.as_mut_ptr()),
            &mut cch,
            Some(&mut protection),
        )?;
    }

    let cap = output.len();
    output.truncate((cch as usize).min(cap));
    while output.last() == Some(&0) {
        output.pop();
    }
    Ok(output)
}

/// Look up the `Negotiate` authentication package id.
pub fn negotiate_package() -> windows::core::Result<u32> {
    let mut handle = HANDLE::default();
    // SAFETY: Valid `HANDLE` out-pointer.
    let status = unsafe { LsaConnectUntrusted(&mut handle) };
    if status.0 < 0 {
        return Err(windows::core::Error::from_hresult(
            windows::core::HRESULT::from_nt(status.0),
        ));
    }

    let mut name = b"Negotiate".to_vec();
    let lsa_name = LSA_STRING {
        Length: name.len() as u16,
        MaximumLength: (name.len() + 1) as u16,
        Buffer: PSTR(name.as_mut_ptr()),
    };
    let mut package = 0u32;
    // SAFETY: `handle` is connected and `lsa_name` buffer outlives the call.
    let status = unsafe { LsaLookupAuthenticationPackage(handle, &lsa_name, &mut package) };
    // SAFETY: Always deregister the untrusted LSA connection handle.
    unsafe {
        let _ = LsaDeregisterLogonProcess(handle);
    }
    if status.0 < 0 {
        return Err(windows::core::Error::from_hresult(
            windows::core::HRESULT::from_nt(status.0),
        ));
    }
    Ok(package)
}

/// Pack a `KERB_INTERACTIVE_UNLOCK_LOGON` into a `CoTaskMem` buffer owned by Windows.
///
/// Enforces `u16` byte-length limits on every `LSA_UNICODE_STRING` field so oversized
/// inputs fail closed with `E_INVALIDARG` instead of silently truncating.
pub fn pack_kerb(
    domain: &str,
    username: &str,
    protected_password: &[u16],
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
) -> windows::core::Result<PackedKerb> {
    let domain_bytes: Vec<u8> = domain
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let username_bytes: Vec<u8> = username
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let password_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        protected_password
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect(),
    );

    let domain_len_u16 = u16::try_from(domain_bytes.len())
        .map_err(|_| windows::core::Error::from_hresult(E_INVALIDARG))?;
    let username_len_u16 = u16::try_from(username_bytes.len())
        .map_err(|_| windows::core::Error::from_hresult(E_INVALIDARG))?;
    let password_len_u16 = u16::try_from(password_bytes.len())
        .map_err(|_| windows::core::Error::from_hresult(E_INVALIDARG))?;

    let header = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();
    let total = header
        .checked_add(domain_bytes.len())
        .and_then(|n| n.checked_add(username_bytes.len()))
        .and_then(|n| n.checked_add(password_bytes.len()))
        .ok_or_else(|| windows::core::Error::from_hresult(E_OUTOFMEMORY))?;
    let total_u32 =
        u32::try_from(total).map_err(|_| windows::core::Error::from_hresult(E_OUTOFMEMORY))?;

    let mut buffer = Zeroizing::new(vec![0u8; total]);
    let mut kiul = KERB_INTERACTIVE_UNLOCK_LOGON::default();
    kiul.Logon.MessageType = if cpus == CPUS_UNLOCK_WORKSTATION {
        KerbWorkstationUnlockLogon
    } else {
        KerbInteractiveLogon
    };
    kiul.LogonId = LUID {
        LowPart: 0,
        HighPart: 0,
    };

    let mut offset = header;
    kiul.Logon.LogonDomainName = LSA_UNICODE_STRING {
        Length: domain_len_u16,
        MaximumLength: domain_len_u16,
        Buffer: PWSTR(offset as *mut u16),
    };
    offset += domain_bytes.len();
    kiul.Logon.UserName = LSA_UNICODE_STRING {
        Length: username_len_u16,
        MaximumLength: username_len_u16,
        Buffer: PWSTR(offset as *mut u16),
    };
    offset += username_bytes.len();
    kiul.Logon.Password = LSA_UNICODE_STRING {
        Length: password_len_u16,
        MaximumLength: password_len_u16,
        Buffer: PWSTR(offset as *mut u16),
    };

    // SAFETY: `kiul` is `header` bytes and `buffer` has `total >= header` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(&kiul as *const _ as *const u8, buffer.as_mut_ptr(), header);
    }
    let mut cursor = header;
    buffer[cursor..cursor + domain_bytes.len()].copy_from_slice(&domain_bytes);
    cursor += domain_bytes.len();
    buffer[cursor..cursor + username_bytes.len()].copy_from_slice(&username_bytes);
    cursor += username_bytes.len();
    buffer[cursor..cursor + password_bytes.len()].copy_from_slice(&password_bytes);

    // SAFETY: Allocates `total` bytes from COM task allocator as required by LogonUI.
    let pointer = unsafe { CoTaskMemAlloc(total) } as *mut u8;
    if pointer.is_null() {
        return Err(windows::core::Error::from_hresult(E_OUTOFMEMORY));
    }
    // SAFETY: Both `buffer` and `pointer` are valid non-overlapping regions of `total` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(buffer.as_ptr(), pointer, total);
    }

    Ok(PackedKerb {
        pointer,
        length: total_u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::CPUS_LOGON;

    #[test]
    fn pack_kerb_sets_message_type_and_rejects_u16_overflow() {
        let protected = vec![b'A' as u16, b'B' as u16, b'C' as u16];
        let packed = pack_kerb("MYPC", "alice", &protected, CPUS_LOGON).unwrap();
        assert!(!packed.pointer.is_null());
        let expected_len = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>() + 8 + 10 + 6;
        assert_eq!(packed.length as usize, expected_len);
        // SAFETY: Free test buffer allocated with `CoTaskMemAlloc`.
        unsafe {
            let hdr = &*(packed.pointer as *const KERB_INTERACTIVE_UNLOCK_LOGON);
            assert_eq!(hdr.Logon.MessageType, KerbInteractiveLogon);
            assert_eq!(hdr.Logon.LogonDomainName.Length, 8);
            assert_eq!(hdr.Logon.UserName.Length, 10);
            assert_eq!(hdr.Logon.Password.Length, 6);
            CoTaskMemFree(Some(packed.pointer as *const c_void));
        }

        // Oversized password (> 65535 bytes = > 32767 u16s) must fail closed instead of truncating!
        let huge = vec![0x0041u16; 40_000];
        let err = pack_kerb("MYPC", "alice", &huge, CPUS_LOGON)
            .err()
            .expect("oversized field must fail");
        assert_eq!(err.code(), E_INVALIDARG);
    }
}
