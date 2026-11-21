//! Windows DPAPI (machine scope) wrapper for the outer vault envelope.
//!
//! DPAPI machine scope is not a substitute for the card-bound inner envelope;
//! it prevents a copied registry blob from being useful on another machine.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::error::{AuthError, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroizing;

fn try_blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
    let cb = u32::try_from(data.len())
        .map_err(|_| AuthError::Dpapi("DPAPI input exceeds u32::MAX".into()))?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: cb,
        pbData: data.as_ptr() as *mut u8,
    })
}

unsafe fn scrub_and_local_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        for offset in 0..len {
            // SAFETY: `ptr..ptr + len` is a valid buffer returned by DPAPI via LocalAlloc.
            unsafe {
                std::ptr::write_volatile(ptr.add(offset), 0);
            }
        }
        // SAFETY: `ptr` was allocated with LocalAlloc by Crypt(Un)ProtectData.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(ptr as _)));
        }
    }
}

pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    let input = try_blob(data)?;
    let entropy_blob = try_blob(entropy)?;
    let entropy_ptr = if entropy.is_empty() {
        None
    } else {
        Some(&entropy_blob as *const CRYPT_INTEGER_BLOB)
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `input` and `entropy_blob` outlive the FFI call; `output` is a valid out-struct.
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

    let len = output.cbData as usize;
    let result = if output.pbData.is_null() || len == 0 {
        Vec::new()
    } else {
        // SAFETY: `output.pbData` points to `len` initialized bytes from DPAPI.
        unsafe { std::slice::from_raw_parts(output.pbData, len).to_vec() }
    };
    // SAFETY: `output.pbData` is freed exactly once after copying.
    unsafe {
        scrub_and_local_free(output.pbData, len);
    }
    Ok(result)
}

pub fn unprotect(data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let input = try_blob(data)?;
    let entropy_blob = try_blob(entropy)?;
    let entropy_ptr = if entropy.is_empty() {
        None
    } else {
        Some(&entropy_blob as *const CRYPT_INTEGER_BLOB)
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    // SAFETY: `input` and `entropy_blob` outlive the FFI call; `output` is a valid out-struct.
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

    let len = output.cbData as usize;
    let result = if output.pbData.is_null() || len == 0 {
        Zeroizing::new(Vec::new())
    } else {
        // SAFETY: `output.pbData` points to `len` initialized bytes from DPAPI.
        Zeroizing::new(unsafe { std::slice::from_raw_parts(output.pbData, len).to_vec() })
    };
    // SAFETY: `output.pbData` is scrubbed and freed once.
    unsafe {
        scrub_and_local_free(output.pbData, len);
    }
    Ok(result)
}
