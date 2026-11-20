//! FamiliarSmartcard Credential Provider DLL.
//!
//! Exports the COM in-proc server entry points. `DllCanUnloadNow` keeps the
//! provider loaded; this is conservative and avoids lifetime races in LogonUI.

#![allow(non_snake_case)]

mod credential;
mod guids;
mod kerb;
mod provider;

use std::ffi::c_void;
use windows::core::{
    implement, IUnknown, Interface, Ref, Result as WinResult, BOOL, GUID, HRESULT,
};
use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, E_INVALIDARG, S_FALSE, S_OK};
use windows::Win32::System::Com::{IClassFactory, IClassFactory_Impl};

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
        // This provider does not support aggregation.
        if !punkouter.is_null() {
            return Err(windows::Win32::Foundation::CLASS_E_NOAGGREGATION.into());
        }

        let provider: IUnknown = Provider::new().into();
        let hr = unsafe { provider.query(riid, ppvobject) };
        if hr.is_err() {
            return Err(hr.into());
        }
        Ok(())
    }

    fn LockServer(&self, _flock: BOOL) -> WinResult<()> {
        // The DLL stays loaded for the lifetime of LogonUI.
        Ok(())
    }
}

#[no_mangle]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    unsafe {
        if rclsid.is_null() || riid.is_null() || ppv.is_null() {
            return E_INVALIDARG;
        }
        if *rclsid != CLSID_FAMILIAR_SMARTCARD {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        let factory: IClassFactory = ClassFactory.into();
        let hr = factory.query(riid, ppv);
        if hr.is_err() {
            return hr;
        }
        S_OK
    }
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    // Keep the DLL loaded; LogonUI may hold interfaces for the whole session.
    S_FALSE
}
