//! KERB serialization and CredProtect helpers.
//!
//! This mirrors the Microsoft Credential Provider sample: use
//! `KERB_INTERACTIVE_UNLOCK_LOGON` for both logon and unlock, set MessageType
//! from the usage scenario, keep LogonId zero, and protect the password with
//! `CredProtectW`.

use windows::core::{PSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::Authentication::Identity::{
    KerbInteractiveLogon, KerbWorkstationUnlockLogon, LsaConnectUntrusted,
    LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage, KERB_INTERACTIVE_UNLOCK_LOGON,
    LSA_STRING, LSA_UNICODE_STRING,
};
use windows::Win32::Security::Credentials::{CredProtectW, CRED_PROTECTION_TYPE};
use windows::Win32::System::Com::CoTaskMemAlloc;
use windows::Win32::UI::Shell::{CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_USAGE_SCENARIO};

use crate::guids::CLSID_FAMILIAR_SMARTCARD;

pub struct PackedKerb {
    pub pointer: *mut u8,
    pub length: u32,
}

/// Protect a plaintext password with `CredProtectW`.
pub fn protect_password(password: &str) -> windows::core::Result<Vec<u16>> {
    let mut input: Vec<u16> = password.encode_utf16().collect();
    input.push(0);

    let mut output = vec![0u16; input.len() + 1024];
    let mut cch = output.len() as u32;
    let mut protection = CRED_PROTECTION_TYPE::default();

    unsafe {
        CredProtectW(
            false,
            &input,
            PWSTR(output.as_mut_ptr()),
            &mut cch,
            Some(&mut protection),
        )?;
    }

    output.truncate(cch as usize);
    while output.last() == Some(&0) {
        output.pop();
    }
    Ok(output)
}

/// Look up the `Negotiate` authentication package id.
pub fn negotiate_package() -> windows::core::Result<u32> {
    let mut handle = HANDLE::default();
    unsafe {
        let status = LsaConnectUntrusted(&mut handle);
        if status.0 < 0 {
            return Err(windows::core::Error::from_hresult(
                windows::core::HRESULT::from_nt(status.0),
            ));
        }
    }

    let mut name = b"Negotiate".to_vec();
    let lsa_name = LSA_STRING {
        Length: name.len() as u16,
        MaximumLength: (name.len() + 1) as u16,
        Buffer: PSTR(name.as_mut_ptr()),
    };
    let mut package = 0u32;
    let status = unsafe { LsaLookupAuthenticationPackage(handle, &lsa_name, &mut package) };
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

/// Pack a `KERB_INTERACTIVE_UNLOCK_LOGON` into a CoTaskMem buffer owned by
/// Windows. The UNICODE_STRING buffers are byte offsets from the structure base.
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
    let password_bytes: Vec<u8> = protected_password
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();

    let header = std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>();
    let total = header + domain_bytes.len() + username_bytes.len() + password_bytes.len();
    if total > u32::MAX as usize {
        return Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_OUTOFMEMORY,
        ));
    }

    let mut buffer = vec![0u8; total];
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
        Length: domain_bytes.len() as u16,
        MaximumLength: domain_bytes.len() as u16,
        Buffer: PWSTR(offset as *mut u16),
    };
    offset += domain_bytes.len();
    kiul.Logon.UserName = LSA_UNICODE_STRING {
        Length: username_bytes.len() as u16,
        MaximumLength: username_bytes.len() as u16,
        Buffer: PWSTR(offset as *mut u16),
    };
    offset += username_bytes.len();
    kiul.Logon.Password = LSA_UNICODE_STRING {
        Length: password_bytes.len() as u16,
        MaximumLength: password_bytes.len() as u16,
        Buffer: PWSTR(offset as *mut u16),
    };

    unsafe {
        std::ptr::copy_nonoverlapping(&kiul as *const _ as *const u8, buffer.as_mut_ptr(), header);
    }
    let mut cursor = header;
    buffer[cursor..cursor + domain_bytes.len()].copy_from_slice(&domain_bytes);
    cursor += domain_bytes.len();
    buffer[cursor..cursor + username_bytes.len()].copy_from_slice(&username_bytes);
    cursor += username_bytes.len();
    buffer[cursor..cursor + password_bytes.len()].copy_from_slice(&password_bytes);

    let pointer = unsafe { CoTaskMemAlloc(total) } as *mut u8;
    if pointer.is_null() {
        return Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_OUTOFMEMORY,
        ));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(buffer.as_ptr(), pointer, total);
    }

    let _ = CLSID_FAMILIAR_SMARTCARD;
    Ok(PackedKerb {
        pointer,
        length: total as u32,
    })
}
