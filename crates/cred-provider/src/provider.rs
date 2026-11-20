//! Credential Provider implementation.

use std::cell::RefCell;
use std::ffi::c_void;
use windows::core::{implement, Ref, Result as WinResult, BOOL, PWSTR};
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL};
use windows::Win32::Storage::EnhancedStorage::PKEY_Identity_QualifiedUserName;
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::UI::Shell::{
    ICredentialProvider, ICredentialProviderCredential, ICredentialProviderEvents,
    ICredentialProviderSetUserArray, ICredentialProviderSetUserArray_Impl,
    ICredentialProviderUserArray, ICredentialProvider_Impl, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    CREDENTIAL_PROVIDER_NO_DEFAULT, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};

use crate::credential::{field_count, field_descriptor, Credential};

#[implement(ICredentialProvider, ICredentialProviderSetUserArray)]
pub struct Provider {
    cpus: RefCell<CREDENTIAL_PROVIDER_USAGE_SCENARIO>,
    users: RefCell<Option<ICredentialProviderUserArray>>,
    credentials: RefCell<Vec<ICredentialProviderCredential>>,
}

impl Provider {
    pub fn new() -> Self {
        Self {
            cpus: RefCell::new(CREDENTIAL_PROVIDER_USAGE_SCENARIO::default()),
            users: RefCell::new(None),
            credentials: RefCell::new(Vec::new()),
        }
    }

    fn rebuild_credentials(&self) {
        let cpus = *self.cpus.borrow();
        let mut result = Vec::new();

        if let Some(users) = self.users.borrow().as_ref() {
            let count = unsafe { users.GetCount() }.unwrap_or(0);
            for index in 0..count {
                let user = match unsafe { users.GetAt(index) } {
                    Ok(user) => user,
                    Err(_) => continue,
                };
                let sid = match unsafe { user.GetSid() } {
                    Ok(sid) => take_pwstr(sid),
                    Err(_) => continue,
                };
                if sid.is_empty() {
                    continue;
                }
                let qualified =
                    match unsafe { user.GetStringValue(&PKEY_Identity_QualifiedUserName) } {
                        Ok(value) => take_pwstr(value),
                        Err(_) => String::new(),
                    };
                let (domain, username) = split_qualified(&qualified);
                let credential: ICredentialProviderCredential =
                    Credential::new(sid, domain, username, cpus).into();
                result.push(credential);
            }
        }

        *self.credentials.borrow_mut() = result;
    }
}

impl ICredentialProvider_Impl for Provider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> WinResult<()> {
        if cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION {
            return Err(E_NOTIMPL.into());
        }
        *self.cpus.borrow_mut() = cpus;
        Ok(())
    }

    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn Advise(
        &self,
        _pcpe: Ref<'_, ICredentialProviderEvents>,
        _upadvisecontext: usize,
    ) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn UnAdvise(&self) -> WinResult<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetFieldDescriptorCount(&self) -> WinResult<u32> {
        Ok(field_count())
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> WinResult<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        let descriptor = field_descriptor(dwindex)?;
        let pointer =
            unsafe { CoTaskMemAlloc(std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>()) }
                as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;
        if pointer.is_null() {
            return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
        }
        unsafe {
            *pointer = descriptor;
        }
        Ok(pointer)
    }

    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut BOOL,
    ) -> WinResult<()> {
        self.rebuild_credentials();
        let count = self.credentials.borrow().len() as u32;
        unsafe {
            *pdwcount = count;
            *pdwdefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
            *pbautologonwithdefault = BOOL(0);
        }
        Ok(())
    }

    fn GetCredentialAt(&self, dwindex: u32) -> WinResult<ICredentialProviderCredential> {
        self.rebuild_credentials();
        let credentials = self.credentials.borrow();
        credentials
            .get(dwindex as usize)
            .cloned()
            .ok_or_else(|| E_INVALIDARG.into())
    }
}

impl ICredentialProviderSetUserArray_Impl for Provider_Impl {
    fn SetUserArray(&self, users: Ref<'_, ICredentialProviderUserArray>) -> WinResult<()> {
        *self.users.borrow_mut() = users.clone();
        Ok(())
    }
}

fn take_pwstr(pointer: PWSTR) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let value = unsafe { pointer.to_string() }.unwrap_or_default();
    unsafe {
        CoTaskMemFree(Some(pointer.0 as *const c_void));
    }
    value
}

fn split_qualified(qualified: &str) -> (String, String) {
    if let Some((domain, username)) = qualified.rsplit_once('\\') {
        (domain.to_string(), username.to_string())
    } else if qualified.is_empty() {
        (
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| ".".into()),
            String::new(),
        )
    } else {
        (
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| ".".into()),
            qualified.to_string(),
        )
    }
}
