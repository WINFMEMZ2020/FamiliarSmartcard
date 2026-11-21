//! Credential Provider implementation.
//!
//! Key behaviors:
//! - Filters enumerated user tiles to ONLY accounts that have a bound RS-Key vault.
//! - Resolves SAM usernames authoritatively by SID (`LookupAccountSidW`) so UPNs
//!   never corrupt AAD or `NetUserGetInfo`.
//! - Automatically emits an `ExplicitUser` ("Other user") credential when the
//!   user array is empty (`GetCount() == 0`) or `CPAO_EMPTY_LOCAL` /
//!   `CPAO_EMPTY_CONNECTED` is requested (common over RDP without cached tiles).
//! - Builds credentials once per `SetUsageScenario` / `SetUserArray` transition
//!   instead of destroying and recreating objects on every `GetCredentialAt` call,
//!   and never holds an internal lock across outgoing COM calls.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard};
use windows::core::{implement, Ref, Result as WinResult, BOOL, PWSTR};
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_OUTOFMEMORY};
use windows::Win32::Storage::EnhancedStorage::PKEY_Identity_QualifiedUserName;
use windows::Win32::System::Com::{CoTaskMemAlloc, CoTaskMemFree};
use windows::Win32::UI::Shell::{
    ICredentialProvider, ICredentialProviderCredential, ICredentialProviderEvents,
    ICredentialProviderSetUserArray, ICredentialProviderSetUserArray_Impl,
    ICredentialProviderUserArray, ICredentialProvider_Impl, CPAO_EMPTY_CONNECTED, CPAO_EMPTY_LOCAL,
    CPUS_LOGON, CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_NO_DEFAULT,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO,
};

use crate::com_guard::guard_com;
use crate::credential::{field_count, field_descriptor, Credential};

struct ProviderState {
    cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    users: Option<ICredentialProviderUserArray>,
    credentials: Vec<ICredentialProviderCredential>,
    dirty: bool,
}

#[implement(ICredentialProvider, ICredentialProviderSetUserArray)]
pub struct Provider {
    state: Mutex<ProviderState>,
}

impl Provider {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ProviderState {
                cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO::default(),
                users: None,
                credentials: Vec::new(),
                dirty: true,
            }),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, ProviderState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ensure_credentials_built(&self) {
        let (cpus, users_opt) = {
            let guard = self.lock_state();
            if !guard.dirty {
                return;
            }
            (guard.cpus, guard.users.clone())
        };

        // Outgoing COM calls on `ICredentialProviderUserArray` happen outside our Mutex
        // so STA message-pump re-entrancy can never deadlock or panic.
        let mut built: Vec<ICredentialProviderCredential> = Vec::new();

        if let Some(users) = users_opt.as_ref() {
            // SAFETY: Valid COM interface pointer provided by LogonUI.
            let count = unsafe { users.GetCount() }.unwrap_or(0);
            // SAFETY: Valid COM interface pointer provided by LogonUI.
            let _ = unsafe { users.GetAccountOptions() }
                .map(|o| (o.0 & (CPAO_EMPTY_LOCAL.0 | CPAO_EMPTY_CONNECTED.0)) != 0)
                .unwrap_or(false);

            for index in 0..count {
                // SAFETY: `index < count`.
                let Ok(user) = (unsafe { users.GetAt(index) }) else {
                    continue;
                };
                // SAFETY: Returns CoTaskMem-allocated SID string.
                let sid = match unsafe { user.GetSid() } {
                    Ok(sid) => take_pwstr(sid),
                    Err(_) => continue,
                };
                if sid.is_empty() || !scard_core::storage::vault_exists(&sid) {
                    continue;
                }

                let (domain, username) = match scard_core::account::lookup_account_by_sid(&sid) {
                    Ok(info) => (info.domain, info.username),
                    Err(_) => {
                        // Fallback if SAM lookup fails transiently.
                        // SAFETY: Queries qualified username string property.
                        let qualified = match unsafe {
                            user.GetStringValue(&PKEY_Identity_QualifiedUserName)
                        } {
                            Ok(v) => take_pwstr(v),
                            Err(_) => String::new(),
                        };
                        split_qualified_fallback(&qualified)
                    }
                };

                if username.is_empty() {
                    continue;
                }

                let credential: ICredentialProviderCredential =
                    Credential::new_bound(sid, domain, username, cpus).into();
                built.push(credential);
            }
        }

        // CRITICAL FOR RDP: Over non-NLA Remote Desktop (`mstsc.exe` sending a `username:s:...`
        // packet via `SetSerialization`), Windows opens `LogonUI.exe` directly on the "Other user"
        // tile EVEN WHEN `users.GetCount() >= 1` and `GetAccountOptions() == CPAO_NONE`!
        // Under "Other user", Windows ONLY displays "Sign-in options" for credentials returning
        // `GetUserSid() -> S_FALSE`. Therefore, we ALWAYS emit one `ExplicitUser` ("Other user")
        // credential during `CPUS_LOGON` (and in `CPUS_UNLOCK_WORKSTATION` if no bound user matched).
        if cpus == CPUS_LOGON || built.is_empty() {
            let other_tile: ICredentialProviderCredential =
                Credential::new_explicit_user(cpus).into();
            built.push(other_tile);
        }

        let mut guard = self.lock_state();
        guard.credentials = built;
        guard.dirty = false;
    }
}

impl ICredentialProvider_Impl for Provider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> WinResult<()> {
        guard_com(|| {
            if cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION {
                return Err(E_NOTIMPL.into());
            }
            let mut guard = self.lock_state();
            guard.cpus = cpus;
            guard.dirty = true;
            Ok(())
        })
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
        Ok(())
    }

    fn UnAdvise(&self) -> WinResult<()> {
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> WinResult<u32> {
        Ok(field_count())
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> WinResult<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        guard_com(|| {
            let descriptor = field_descriptor(dwindex)?;
            // SAFETY: Allocates COM task memory for one `CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR`.
            let pointer = unsafe {
                CoTaskMemAlloc(std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>())
            } as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;
            if pointer.is_null() {
                if !descriptor.pszLabel.is_null() {
                    // SAFETY: Free `pszLabel` so we do not leak it on outer OOM.
                    unsafe {
                        CoTaskMemFree(Some(descriptor.pszLabel.0 as *const c_void));
                    }
                }
                return Err(E_OUTOFMEMORY.into());
            }
            // SAFETY: `pointer` is non-null and properly sized/aligned.
            unsafe {
                *pointer = descriptor;
            }
            Ok(pointer)
        })
    }

    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut BOOL,
    ) -> WinResult<()> {
        if pdwcount.is_null() || pdwdefault.is_null() || pbautologonwithdefault.is_null() {
            return Err(E_INVALIDARG.into());
        }
        // SAFETY: All three out-pointers were verified non-null; initialize safe defaults first.
        unsafe {
            *pdwcount = 0;
            *pdwdefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
            *pbautologonwithdefault = BOOL(0);
        }

        guard_com(|| {
            self.ensure_credentials_built();
            let count = {
                let guard = self.lock_state();
                u32::try_from(guard.credentials.len()).unwrap_or(0)
            };
            // SAFETY: Verified non-null above; never enable default or auto-logon.
            unsafe {
                *pdwcount = count;
                *pdwdefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
                *pbautologonwithdefault = BOOL(0);
            }
            Ok(())
        })
    }

    fn GetCredentialAt(&self, dwindex: u32) -> WinResult<ICredentialProviderCredential> {
        guard_com(|| {
            self.ensure_credentials_built();
            let guard = self.lock_state();
            guard
                .credentials
                .get(dwindex as usize)
                .cloned()
                .ok_or_else(|| E_INVALIDARG.into())
        })
    }
}

impl ICredentialProviderSetUserArray_Impl for Provider_Impl {
    fn SetUserArray(&self, users: Ref<'_, ICredentialProviderUserArray>) -> WinResult<()> {
        guard_com(|| {
            let mut guard = self.lock_state();
            guard.users = users.clone();
            guard.dirty = true;
            Ok(())
        })
    }
}

fn take_pwstr(pointer: PWSTR) -> String {
    if pointer.is_null() {
        return String::new();
    }
    // SAFETY: `pointer` is a NUL-terminated UTF-16 string allocated via `CoTaskMemAlloc`.
    let value = unsafe { pointer.to_string() }.unwrap_or_default();
    unsafe {
        CoTaskMemFree(Some(pointer.0 as *const c_void));
    }
    value
}

fn split_qualified_fallback(qualified: &str) -> (String, String) {
    let default_comp = scard_core::account::computer_name().unwrap_or_else(|_| ".".into());
    if let Some((domain, username)) = qualified.rsplit_once('\\') {
        (domain.to_string(), username.to_string())
    } else if qualified.contains('@') || qualified.is_empty() {
        (default_comp, String::new())
    } else {
        (default_comp, qualified.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::Interface;

    #[test]
    fn provider_null_out_pointers_return_e_invalidarg_and_explicit_tile_is_stable() {
        let provider: ICredentialProvider = Provider::new().into();
        // SAFETY: Testing COM interface methods directly.
        unsafe {
            provider.SetUsageScenario(CPUS_LOGON, 0).unwrap();

            let mut count = 99u32;
            let mut def = 0u32;
            let mut auto = BOOL(1);

            let err = provider
                .GetCredentialCount(std::ptr::null_mut(), &mut def, &mut auto)
                .unwrap_err();
            assert_eq!(err.code(), E_INVALIDARG);

            provider
                .GetCredentialCount(&mut count, &mut def, &mut auto)
                .unwrap();
            // With no user array set under CPUS_LOGON, exactly 1 "Other user" tile is emitted.
            assert_eq!(count, 1);
            assert_eq!(def, CREDENTIAL_PROVIDER_NO_DEFAULT);
            assert_eq!(auto, BOOL(0));

            // Repeated `GetCredentialAt(0)` MUST return the exact same underlying COM identity!
            let c1 = provider.GetCredentialAt(0).unwrap();
            let c2 = provider.GetCredentialAt(0).unwrap();
            assert_eq!(c1.as_raw(), c2.as_raw());
        }
    }
}
