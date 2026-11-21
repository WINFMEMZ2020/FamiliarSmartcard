//! Spawns `familiar-auth-helper.exe` in the same Windows Session ID over
//! anonymous pipes, streams real-time `HelperProgress::TouchRequired` events into
//! a cancelable topmost prompt window when hardware touch is required, and enforces
//! a hard `TerminateProcess` timeout.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::touch_dialog::{run_touch_prompt_modal, DialogWaitResult, WM_APP_HELPER_EVENT};
use scard_core::ipc::{
    read_framed, write_framed, HelperFailureReason, HelperIcon, HelperProgress, HelperRequest,
    HelperResponse, HelperStreamFrame,
};
use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HMODULE, HWND,
    LPARAM, WPARAM,
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
use windows::Win32::UI::WindowsAndMessaging::PostMessageW;

pub const DEFAULT_HELPER_TIMEOUT_MS: u32 = 10_000;
pub const TOUCH_HELPER_TIMEOUT_MS: u32 = 25_000;
const HELPER_EXE_NAME: &str = "familiar-auth-helper.exe";

pub enum HelperInvokeOutcome {
    Completed(HelperResponse),
    Cancelled,
}

pub enum StreamEvent {
    Progress(HelperProgress),
    Final(HelperResponse),
    Eof,
}

struct HandleGuard(HANDLE);

impl HandleGuard {
    fn raw(&self) -> HANDLE {
        self.0
    }

    fn take_raw(&mut self) -> isize {
        let v = self.0 .0 as isize;
        self.0 = HANDLE::default();
        v
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

struct PipeReader(HandleGuard);

impl std::io::Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut read_n = 0u32;
        let cap = buf.len().min(4096);
        // SAFETY: `self.0.raw()` is an owned anonymous read-pipe handle and `buf[..cap]` is valid.
        let res = unsafe { ReadFile(self.0.raw(), Some(&mut buf[..cap]), Some(&mut read_n), None) };
        if res.is_err() || read_n == 0 {
            return Ok(0);
        }
        Ok(read_n as usize)
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

/// Spawn `familiar-auth-helper.exe` next to the DLL, showing an interactive cancelable
/// Touch Prompt window if `HelperProgress::TouchRequired` is emitted.
pub fn invoke_auth_helper_interactive<F>(
    req: &HelperRequest,
    timeout_ms: u32,
    on_creating_window: F,
) -> HelperInvokeOutcome
where
    F: FnOnce() -> Option<HWND>,
{
    let helper_path = match locate_sibling_helper_exe() {
        Ok(path) => path,
        Err(_) => {
            return HelperInvokeOutcome::Completed(generic_failure(
                HelperIcon::Error,
                "Authentication helper path could not be resolved.",
            ));
        }
    };
    invoke_auth_helper_interactive_at(&helper_path, &[], req, timeout_ms, on_creating_window)
}

/// Non-interactive convenience wrapper used by headless tests.
#[cfg(test)]
pub fn invoke_auth_helper_at(
    helper_exe: &Path,
    extra_args: &[&str],
    req: &HelperRequest,
    timeout_ms: u32,
) -> HelperResponse {
    match invoke_auth_helper_interactive_at(helper_exe, extra_args, req, timeout_ms, || None) {
        HelperInvokeOutcome::Completed(resp) => resp,
        HelperInvokeOutcome::Cancelled => {
            generic_failure(HelperIcon::Warning, "Sign-in cancelled.")
        }
    }
}

/// Spawn a specific helper executable path with streaming progress + cancelable UI support.
pub fn invoke_auth_helper_interactive_at<F>(
    helper_exe: &Path,
    extra_args: &[&str],
    req: &HelperRequest,
    timeout_ms: u32,
    on_creating_window: F,
) -> HelperInvokeOutcome
where
    F: FnOnce() -> Option<HWND>,
{
    if !helper_exe.exists() {
        return HelperInvokeOutcome::Completed(generic_failure(
            HelperIcon::Error,
            "Authentication helper executable is missing. Re-run FamiliarSmartcard setup.",
        ));
    }

    let encoded_req = match req.encode() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HelperInvokeOutcome::Completed(generic_failure(
                HelperIcon::Error,
                "Failed to encode authentication request.",
            ));
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
        return HelperInvokeOutcome::Completed(generic_failure(
            HelperIcon::Error,
            "Failed to create helper input pipe.",
        ));
    }
    let mut child_stdin_read = HandleGuard(stdin_read_raw);
    let mut parent_stdin_write = HandleGuard(stdin_write_raw);

    let mut stdout_read_raw = HANDLE::default();
    let mut stdout_write_raw = HANDLE::default();
    // SAFETY: Creates anonymous output pipe with `4096`-byte kernel buffer.
    if unsafe { CreatePipe(&mut stdout_read_raw, &mut stdout_write_raw, Some(&sa), 4096) }.is_err()
    {
        return HelperInvokeOutcome::Completed(generic_failure(
            HelperIcon::Error,
            "Failed to create helper output pipe.",
        ));
    }
    let mut parent_stdout_read = HandleGuard(stdout_read_raw);
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
            return HelperInvokeOutcome::Completed(generic_failure(
                HelperIcon::Error,
                "Failed to configure helper pipe inheritance.",
            ));
        }
    }

    // Write the entire bounded request frame (`<= 1026` bytes) into the 4096-byte kernel
    // pipe buffer and immediately close the write end so the child observes EOF cleanly.
    if write_framed(PipeWriter(parent_stdin_write.raw()), &encoded_req).is_err() {
        return HelperInvokeOutcome::Completed(generic_failure(
            HelperIcon::Error,
            "Failed to send request to authentication helper.",
        ));
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

    // Always close child-side pipe handles in the parent immediately after `CreateProcessW`
    // so terminating the child process immediately unblocks the reader thread with EOF!
    child_stdin_read.close_now();
    child_stdout_write.close_now();

    if spawn_res.is_err() {
        return HelperInvokeOutcome::Completed(generic_failure(
            HelperIcon::Error,
            "Failed to launch authentication helper.",
        ));
    }

    let proc_handle = HandleGuard(proc_info.hProcess);
    let _thread_handle = HandleGuard(proc_info.hThread);

    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
    let notify_hwnd = Arc::new(AtomicIsize::new(0));
    let reader_notify = Arc::clone(&notify_hwnd);
    let (tx, rx) = mpsc::channel::<StreamEvent>();
    let stdout_raw = parent_stdout_read.take_raw();

    // Stream IPC frames from the child's stdout pipe on a dedicated reader thread.
    let reader_thread = std::thread::spawn(move || {
        let mut pipe = PipeReader(HandleGuard(HANDLE(stdout_raw as *mut c_void)));
        const MAX_FRAMES: usize = 16;
        for _ in 0..MAX_FRAMES {
            let Ok(raw_frame) = read_framed(&mut pipe) else {
                let _ = tx.send(StreamEvent::Eof);
                wake_dialog(&reader_notify);
                return;
            };
            match HelperStreamFrame::decode(&raw_frame) {
                Ok(HelperStreamFrame::Progress(prog)) => {
                    let _ = tx.send(StreamEvent::Progress(prog));
                    wake_dialog(&reader_notify);
                }
                Ok(HelperStreamFrame::Final(resp)) => {
                    let _ = tx.send(StreamEvent::Final(resp));
                    wake_dialog(&reader_notify);
                    return;
                }
                Err(_) => {
                    let _ = tx.send(StreamEvent::Final(generic_failure(
                        HelperIcon::Error,
                        "Malformed response from authentication helper.",
                    )));
                    wake_dialog(&reader_notify);
                    return;
                }
            }
        }
        let _ = tx.send(StreamEvent::Eof);
        wake_dialog(&reader_notify);
    });

    // Phase A: Wait before opening any GUI window (`Touch=NEVER` and wrong-PIN attempts
    // complete here in ~50ms without ever flashing a window!).
    let outcome = if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(remaining) {
            Ok(StreamEvent::Final(resp)) => {
                // SAFETY: Reap child exit cleanly.
                unsafe {
                    let _ = WaitForSingleObject(proc_handle.raw(), 500);
                }
                HelperInvokeOutcome::Completed(resp)
            }
            Ok(StreamEvent::Progress(HelperProgress::TouchRequired { step, total })) => {
                // Phase B: Card PIN verified and hardware touch is now actively required!
                // Give the user a full `TOUCH_HELPER_TIMEOUT_MS` window from prompt appearance.
                let touch_deadline = deadline.max(
                    Instant::now() + Duration::from_millis(u64::from(TOUCH_HELPER_TIMEOUT_MS)),
                );
                let owner_hwnd = on_creating_window();
                match run_touch_prompt_modal(
                    owner_hwnd,
                    step,
                    total,
                    touch_deadline,
                    &rx,
                    &notify_hwnd,
                ) {
                    DialogWaitResult::Completed(resp) => {
                        unsafe {
                            let _ = WaitForSingleObject(proc_handle.raw(), 500);
                        }
                        HelperInvokeOutcome::Completed(resp)
                    }
                    DialogWaitResult::Cancelled => {
                        kill_helper(&proc_handle);
                        HelperInvokeOutcome::Cancelled
                    }
                    DialogWaitResult::TimedOut => {
                        kill_helper(&proc_handle);
                        HelperInvokeOutcome::Completed(timeout_failure())
                    }
                    DialogWaitResult::PipeBroken => {
                        kill_helper(&proc_handle);
                        HelperInvokeOutcome::Completed(generic_failure(
                            HelperIcon::Error,
                            "Authentication helper exited unexpectedly.",
                        ))
                    }
                }
            }
            Ok(StreamEvent::Eof) | Err(RecvTimeoutError::Disconnected) => {
                kill_helper(&proc_handle);
                HelperInvokeOutcome::Completed(generic_failure(
                    HelperIcon::Error,
                    "Authentication helper exited without a valid response.",
                ))
            }
            Err(RecvTimeoutError::Timeout) => {
                kill_helper(&proc_handle);
                HelperInvokeOutcome::Completed(timeout_failure())
            }
        }
    } else {
        kill_helper(&proc_handle);
        HelperInvokeOutcome::Completed(timeout_failure())
    };

    let _ = reader_thread.join();
    outcome
}

fn wake_dialog(notify_hwnd: &AtomicIsize) {
    let raw = notify_hwnd.load(Ordering::SeqCst);
    if raw != 0 {
        let hwnd = HWND(raw as *mut c_void);
        // SAFETY: Posts benign wakeup message; `raw` is cleared before `DestroyWindow`.
        unsafe {
            let _ = PostMessageW(Some(hwnd), WM_APP_HELPER_EVENT, WPARAM(0), LPARAM(0));
        }
    }
}

fn kill_helper(proc_handle: &HandleGuard) {
    // SAFETY: Hard-kills helper child process and waits briefly for kernel handle cleanup.
    unsafe {
        let _ = TerminateProcess(proc_handle.raw(), 1);
        let _ = WaitForSingleObject(proc_handle.raw(), 1_000);
    }
}

fn timeout_failure() -> HelperResponse {
    generic_failure(
        HelperIcon::Warning,
        "Smart card timed out waiting for response or touch. Try again, or click Sign-in options to use your recovery password.",
    )
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
            explicit_user: false,
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
            explicit_user: false,
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
