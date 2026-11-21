//! FamiliarSmartcard Credential Provider DLL.
//!
//! Exports the COM in-proc server entry points. Every COM entry point and vtable
//! method is protected against null pointers and Rust panics (`catch_unwind`) so
//! `LogonUI.exe` can never be aborted across the FFI boundary.

#![allow(non_snake_case)]
#![allow(unknown_lints, linker_messages)]
#![deny(unsafe_op_in_unsafe_fn)]

mod com_guard;
mod credential;
mod guids;
mod helper_client;
mod kerb;
mod provider;

use std::ffi::c_void;
use windows::core::{
    implement, IUnknown, Interface, Ref, Result as WinResult, BOOL, GUID, HRESULT,
};
use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_INVALIDARG, E_UNEXPECTED, S_FALSE, S_OK,
};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};

use crate::com_guard::{ensure_silent_panic_hook, guard_com};
use crate::guids::CLSID_FAMILIAR_SMARTCARD;
use crate::provider::Provider;

#[implement(IClassFactory)]
struct ClassFactory;

impl IClassFactory_Impl for ClassFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut c_void,
    ) -> WinResult<()> {
        if ppvobject.is_null() {
            return Err(E_INVALIDARG.into());
        }
        // SAFETY: `ppvobject` was verified non-null; initialize out-pointer per COM rules.
        unsafe {
            *ppvobject = std::ptr::null_mut();
        }
        if riid.is_null() {
            return Err(E_INVALIDARG.into());
        }
        if !punkouter.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        guard_com(|| {
            let provider: IUnknown = Provider::new().into();
            // SAFETY: `riid` and `ppvobject` were verified non-null above.
            let hr = unsafe { provider.query(riid, ppvobject) };
            if hr.is_err() {
                return Err(hr.into());
            }
            Ok(())
        })
    }

    fn LockServer(&self, _flock: BOOL) -> WinResult<()> {
        Ok(())
    }
}

/// # Safety
///
/// Called by COM (`CoGetClassObject`) with valid pointers to `rclsid`, `riid`, and `ppv`.
/// Null pointers are defensively rejected with `E_INVALIDARG`.
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    ensure_silent_panic_hook();

    if !ppv.is_null() {
        // SAFETY: `ppv` is non-null; clear output pointer before any early return.
        unsafe {
            *ppv = std::ptr::null_mut();
        }
    }
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_INVALIDARG;
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: `rclsid` was verified non-null.
        let requested = unsafe { *rclsid };
        if requested != CLSID_FAMILIAR_SMARTCARD {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        let factory: IClassFactory = ClassFactory.into();
        // SAFETY: `riid` and `ppv` were verified non-null.
        let hr = unsafe { factory.query(riid, ppv) };
        if hr.is_err() {
            return hr;
        }
        S_OK
    }));

    result.unwrap_or(E_UNEXPECTED)
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    // Keep the DLL loaded; LogonUI may hold interfaces for the whole session.
    S_FALSE
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::Shell::ICredentialProvider;

    #[test]
    fn dll_get_class_object_rejects_nulls_and_wrong_clsid() {
        let mut out: *mut c_void = std::ptr::dangling_mut();
        let iid = ICredentialProvider::IID;
        // SAFETY: Testing defensive null handling in `DllGetClassObject`.
        unsafe {
            assert_eq!(
                DllGetClassObject(std::ptr::null(), &iid, &mut out),
                E_INVALIDARG
            );
            assert!(out.is_null());

            assert_eq!(
                DllGetClassObject(&CLSID_FAMILIAR_SMARTCARD, std::ptr::null(), &mut out),
                E_INVALIDARG
            );
            assert_eq!(
                DllGetClassObject(&CLSID_FAMILIAR_SMARTCARD, &iid, std::ptr::null_mut()),
                E_INVALIDARG
            );

            let wrong = GUID::from_u128(0x11111111_2222_3333_4444_555555555555);
            assert_eq!(
                DllGetClassObject(&wrong, &iid, &mut out),
                CLASS_E_CLASSNOTAVAILABLE
            );
        }
    }
}
