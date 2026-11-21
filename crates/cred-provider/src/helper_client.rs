//! Spawns `familiar-auth-helper.exe` in the same Windows Session ID over
//! anonymous pipes and enforces a hard `TerminateProcess` timeout.

#![deny(unsafe_op_in_unsafe_fn)]

use scard_core::ipc::{
    read_framed, write_framed, HelperFailureReason, HelperIcon, HelperRequest, HelperResponse,
    MAX_IPC_FRAME_LEN,
};
use std::io::Cursor;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HMODULE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};

pub const DEFAULT_HELPER_TIMEOUT_MS: u32 = 10_000;
pub const TOUCH_HELPER_TIMEOUT_MS: u32 = 22_000;
const HELPER_EXE_NAME: &str = "familiar-auth-helper.exe";

struct HandleGuard(HANDLE);

impl HandleGuard {
    fn raw(&self) -> HANDLE {
        self.0
    }

    fn close_now(&mut self) {
        if !self.0.is_invalid() && !self.0 .0.is_null() {
            // SAFETY: Owned Win32 handle closed at most once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
            self.0 = HANDLE::default();
        }
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        self.close_now();
    }
}

struct PipeWriter(HANDLE);

impl std::io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0u32;
        let chunk = &buf[..buf.len().min(4096)];
        // SAFETY: `self.0` is a valid write-pipe handle and `chunk` outlives `WriteFile`.
        unsafe {
            windows::Win32::Storage::FileSystem::WriteFile(
                self.0,
                Some(chunk),
                Some(&mut written),
                None,
            )
            .map_err(|e| std::io::Error::other(e.message()))?;
        }
        Ok(written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Locate `familiar-auth-helper.exe` strictly inside the same protected directory
/// as this `familiar_cred_provider.dll` module (`GetModuleFileNameW`), never via `PATH`.
pub fn locate_sibling_helper_exe() -> Result<PathBuf, String> {
    let mut hmod = HMODULE::default();
    let fn_addr = locate_sibling_helper_exe as *const () as *const u16;
    // SAFETY: Queries module handle of the currently loaded DLL from its own code address.
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(fn_addr),
            &mut hmod,
        )
    }
    .map_err(|e| format!("GetModuleHandleExW failed: {}", e.message()))?;

    let mut buf = vec![0u16; 1024];
    // SAFETY: `buf` has 1024 `u16` capacity.
    let len = unsafe { GetModuleFileNameW(Some(hmod), &mut buf) } as usize;
    if len == 0 || len >= buf.len() {
        return Err("GetModuleFileNameW returned invalid path length".into());
    }
    let dll_path = PathBuf::from(String::from_utf16_lossy(&buf[..len]));
    let dir = dll_path
        .parent()
        .ok_or_else(|| "DLL path has no parent directory".to_string())?;
    Ok(dir.join(HELPER_EXE_NAME))
}

fn generic_failure(icon: HelperIcon, message: impl Into<String>) -> HelperResponse {
    HelperResponse::Failure {
        reason: HelperFailureReason::Generic,
        icon,
        message: message.into(),
    }
}

/// Spawn `familiar-auth-helper.exe` next to the DLL and run a single unlock request.
pub fn invoke_auth_helper(req: &HelperRequest, timeout_ms: u32) -> HelperResponse {
    let helper_path = match locate_sibling_helper_exe() {
        Ok(path) => path,
        Err(_) => {
            return generic_failure(
                HelperIcon::Error,
                "Authentication helper path could not be resolved.",
            );
        }
    };
    invoke_auth_helper_at(&helper_path, &[], req, timeout_ms)
}

/// Spawn a specific helper executable path with optional arguments and a hard timeout.
pub fn invoke_auth_helper_at(
    helper_exe: &Path,
    extra_args: &[&str],
    req: &HelperRequest,
    timeout_ms: u32,
) -> HelperResponse {
    if !helper_exe.exists() {
        return generic_failure(
            HelperIcon::Error,
            "Authentication helper executable is missing. Re-run FamiliarSmartcard setup.",
        );
    }

    let encoded_req = match req.encode() {
        Ok(bytes) => bytes,
        Err(_) => {
            return generic_failure(
                HelperIcon::Error,
                "Failed to encode authentication request.",
            );
        }
    };

    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: BOOL(1),
    };

    let mut stdin_read_raw = HANDLE::default();
    let mut stdin_write_raw = HANDLE::default();
    // SAFETY: Creates anonymous pipe with `4096`-byte kernel buffer (> `MAX_IPC_FRAME_LEN`).
    if unsafe { CreatePipe(&mut stdin_read_raw, &mut stdin_write_raw, Some(&sa), 4096) }.is_err() {
        return generic_failure(HelperIcon::Error, "Failed to create helper input pipe.");
    }
    let mut child_stdin_read = HandleGuard(stdin_read_raw);
    let mut parent_stdin_write = HandleGuard(stdin_write_raw);

    let mut stdout_read_raw = HANDLE::default();
    let mut stdout_write_raw = HANDLE::default();
    // SAFETY: Creates anonymous output pipe with `4096`-byte kernel buffer.
    if unsafe { CreatePipe(&mut stdout_read_raw, &mut stdout_write_raw, Some(&sa), 4096) }.is_err()
    {
        return generic_failure(HelperIcon::Error, "Failed to create helper output pipe.");
    }
    let parent_stdout_read = HandleGuard(stdout_read_raw);
    let mut child_stdout_write = HandleGuard(stdout_write_raw);

    // Prevent the child from inheriting the parent's ends of the pipes.
    // SAFETY: Valid pipe handles created above.
    unsafe {
        if SetHandleInformation(
            parent_stdin_write.raw(),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAGS(0),
        )
        .is_err()
            || SetHandleInformation(
                parent_stdout_read.raw(),
                HANDLE_FLAG_INHERIT.0,
                HANDLE_FLAGS(0),
            )
            .is_err()
        {
            return generic_failure(
                HelperIcon::Error,
                "Failed to configure helper pipe inheritance.",
            );
        }
    }

    // Write the entire bounded request frame (`<= 1026` bytes) into the 4096-byte kernel
    // pipe buffer and immediately close the write end so the child observes EOF cleanly.
    if write_framed(PipeWriter(parent_stdin_write.raw()), &encoded_req).is_err() {
        return generic_failure(
            HelperIcon::Error,
            "Failed to send request to authentication helper.",
        );
    }
    parent_stdin_write.close_now();

    let exe_str = helper_exe.to_string_lossy();
    let mut cmd_str = format!("\"{exe_str}\"");
    for arg in extra_args {
        cmd_str.push(' ');
        cmd_str.push_str(arg);
    }
    let exe_w: Vec<u16> = exe_str.encode_utf16().chain(std::iter::once(0)).collect();
    let mut cmd_w: Vec<u16> = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();

    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: child_stdin_read.raw(),
        hStdOutput: child_stdout_write.raw(),
        hStdError: HANDLE::default(),
        ..Default::default()
    };
    let mut proc_info = PROCESS_INFORMATION::default();

    // SAFETY: Spawns child in the exact same Windows Session ID with `CREATE_NO_WINDOW`.
    let spawn_res = unsafe {
        CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            Some(PWSTR(cmd_w.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_NO_WINDOW,
            None,
            None,
            &startup,
            &mut proc_info,
        )
    };

    // Always close child-side pipe handles in the parent immediately after `CreateProcessW`.
    child_stdin_read.close_now();
    child_stdout_write.close_now();

    if spawn_res.is_err() {
        return generic_failure(HelperIcon::Error, "Failed to launch authentication helper.");
    }

    let proc_handle = HandleGuard(proc_info.hProcess);
    let _thread_handle = HandleGuard(proc_info.hThread);

    // Hard timeout wait on the helper process.
    // SAFETY: `proc_handle.raw()` is a valid process handle.
    let wait_status = unsafe { WaitForSingleObject(proc_handle.raw(), timeout_ms) };
    if wait_status == WAIT_TIMEOUT {
        // SAFETY: Hard-kill the hung helper process so `LogonUI.exe` immediately unblocks!
        unsafe {
            let _ = TerminateProcess(proc_handle.raw(), 1);
            let _ = WaitForSingleObject(proc_handle.raw(), 1_000);
        }
        return generic_failure(
            HelperIcon::Warning,
            "Smart card timed out. Check your PIV smart card / RDP redirection, or click Sign-in options to use your recovery password.",
        );
    }
    if wait_status != WAIT_OBJECT_0 {
        return generic_failure(
            HelperIcon::Error,
            "Waiting on authentication helper failed.",
        );
    }

    // Child has exited and write end is closed; `ReadFile` is guaranteed non-blocking.
    let mut raw_out = zeroize::Zeroizing::new(Vec::with_capacity(MAX_IPC_FRAME_LEN + 4));
    let mut chunk = zeroize::Zeroizing::new([0u8; 512]);
    loop {
        let mut read_n = 0u32;
        // SAFETY: `parent_stdout_read` is open and `chunk` is valid.
        let ok = unsafe {
            ReadFile(
                parent_stdout_read.raw(),
                Some(chunk.as_mut()),
                Some(&mut read_n),
                None,
            )
        };
        if ok.is_err() || read_n == 0 {
            break;
        }
        let n = read_n as usize;
        if raw_out.len() + n > MAX_IPC_FRAME_LEN + 4 {
            return generic_failure(
                HelperIcon::Error,
                "Authentication helper returned an oversized response.",
            );
        }
        raw_out.extend_from_slice(&chunk[..n]);
    }

    let Ok(frame) = read_framed(Cursor::new(raw_out.as_slice())) else {
        return generic_failure(
            HelperIcon::Error,
            "Authentication helper exited without a valid response.",
        );
    };

    HelperResponse::decode(&frame).unwrap_or_else(|_| {
        generic_failure(
            HelperIcon::Error,
            "Malformed response from authentication helper.",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn built_helper_path() -> Option<PathBuf> {
        let current = std::env::current_exe().ok()?;
        // `target/debug/deps/cred_provider-...exe` -> `target/debug/familiar-auth-helper.exe`
        let debug_dir = current.parent()?.parent()?;
        let candidate = debug_dir.join("familiar-auth-helper.exe");
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    }

    #[test]
    fn missing_helper_fails_closed_cleanly() {
        let req = HelperRequest {
            sid: "S-1-5-21-1000-1001".into(),
            username: "nobody".into(),
            computer: "LOCAL".into(),
            operation: scard_core::ipc::HelperOperation::Unlock {
                pin: Zeroizing::new(b"123456".to_vec()),
            },
        };
        let resp =
            invoke_auth_helper_at(Path::new(r"C:\nonexistent\no_helper.exe"), &[], &req, 500);
        assert!(matches!(resp, HelperResponse::Failure { .. }));
    }

    #[test]
    fn hung_helper_is_terminated_within_hard_timeout() {
        let Some(helper) = built_helper_path() else {
            return;
        };
        let req = HelperRequest {
            sid: "S-1-5-21-1000-1001".into(),
            username: "nobody".into(),
            computer: "LOCAL".into(),
            operation: scard_core::ipc::HelperOperation::Unlock {
                pin: Zeroizing::new(b"123456".to_vec()),
            },
        };
        let start = std::time::Instant::now();
        let resp = invoke_auth_helper_at(&helper, &["--test-simulate-hang"], &req, 250);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 5,
            "helper was not killed promptly: {elapsed:?}"
        );
        match resp {
            HelperResponse::Failure { icon, message, .. } => {
                assert_eq!(icon, HelperIcon::Warning);
                assert!(message.contains("timed out"));
            }
            HelperResponse::Success { .. } => panic!("hung helper must never succeed"),
        }
    }
}
