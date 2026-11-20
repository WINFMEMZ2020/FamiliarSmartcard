//! Windows DPAPI (machine scope) wrapper for the outer vault envelope.
//!
//! DPAPI machine scope is not a substitute for the card-bound inner envelope;
//! it prevents a copied registry blob from being useful on another machine.

use crate::error::{AuthError, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    let input = blob(data);
    let entropy_blob = blob(entropy);
    let entropy_ptr = if entropy.is_empty() {
        None
    } else {
        Some(&entropy_blob as *const CRYPT_INTEGER_BLOB)
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            entropy_ptr,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|error| AuthError::Dpapi(error.message()))?;

    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData as _)));
    }
    Ok(result)
}

pub fn unprotect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    let input = blob(data);
    let entropy_blob = blob(entropy);
    let entropy_ptr = if entropy.is_empty() {
        None
    } else {
        Some(&entropy_blob as *const CRYPT_INTEGER_BLOB)
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &input,
            None,
            entropy_ptr,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|error| AuthError::Dpapi(error.message()))?;

    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData as _)));
    }
    Ok(result)
}
