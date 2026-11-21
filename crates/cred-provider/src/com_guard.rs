//! Panic containment and silent hook helpers for COM FFI boundaries.

#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;
use windows::core::Result as WinResult;
use windows::Win32::Foundation::E_UNEXPECTED;

static PANIC_HOOK_INIT: Once = Once::new();

/// Install a silent panic hook once so panics inside `LogonUI.exe` never format
/// or print sensitive values to any stream.
pub fn ensure_silent_panic_hook() {
    PANIC_HOOK_INIT.call_once(|| {
        std::panic::set_hook(Box::new(|_| {}));
    });
}

/// Execute `f` inside `catch_unwind`, converting any Rust panic into `E_UNEXPECTED`.
pub fn guard_com<T, F>(f: F) -> WinResult<T>
where
    F: FnOnce() -> WinResult<T>,
{
    ensure_silent_panic_hook();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => Err(E_UNEXPECTED.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_com_catches_panic_and_returns_e_unexpected() {
        let res: WinResult<u32> = guard_com(|| {
            panic!("simulated internal panic");
        });
        let err = res.unwrap_err();
        assert_eq!(err.code(), E_UNEXPECTED);
    }
}
