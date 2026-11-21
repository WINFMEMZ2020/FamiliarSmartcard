//! Borderless, High-DPI Per-Monitor V2 Hardware Touch Prompt overlay displayed
//! on `WinSta0\Winlogon` during `GetSerialization` whenever `familiar-auth-helper.exe`
//! emits `HelperProgress::TouchRequired { step, total }`.
//!
//! Styling & DPI architecture:
//! - Temporarily enters `DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2` (restoring
//!   the caller thread's prior context via RAII on return) and queries per-window /
//!   system DPI (`96`..`480`), plus live `WM_DPICHANGED` handling.
//! - Borderless `WS_POPUP` window with Windows 11 DWM rounded corners (`DWMWCP_ROUND`)
//!   and explicit `DWMWA_BORDER_COLOR = DWMWA_COLOR_NONE` (`0xFFFFFFFE`) so ZERO
//!   window frame or 1px outline is drawn (with `SetWindowRgn` rounded fallback on Win10).
//! - Flicker-free double-buffered 32-bpp DIB SDF renderer + ClearType `Segoe UI`
//!   typography and custom borderless hover/press `Cancel (Esc)` pill button.

#![deny(unsafe_op_in_unsafe_fn)]

use scard_core::ipc::HelperProgress;
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};
use windows::core::{s, w, HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    FreeLibrary, COLORREF, HINSTANCE, HMODULE, HWND, LPARAM, LRESULT, RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, BitBlt, CreateCompatibleDC, CreateDIBSection, CreateFontW, CreateRoundRectRgn,
    DeleteDC, DeleteObject, DrawTextW, EndPaint, GetDC, GetDeviceCaps, GetStockObject,
    InvalidateRect, ReleaseDC, SelectObject, SetBkMode, SetTextColor, SetWindowRgn, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, DEFAULT_CHARSET,
    DEFAULT_GUI_FONT, DEFAULT_PITCH, DIB_RGB_COLORS, DT_CENTER, DT_NOPREFIX, DT_SINGLELINE,
    DT_VCENTER, FF_DONTCARE, HBRUSH, HDC, HFONT, LOGPIXELSX, OUT_DEFAULT_PRECIS, PAINTSTRUCT,
    SRCCOPY, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::{
    GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    ReleaseCapture, SetCapture, SetFocus, VK_ESCAPE, VK_RETURN, VK_SPACE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
    GetSystemMetrics, GetWindowLongPtrW, IsWindow, KillTimer, LoadCursorW, PostMessageW,
    RegisterClassW, SetCursor, SetForegroundWindow, SetTimer, SetWindowLongPtrW, SetWindowPos,
    ShowWindow, TranslateMessage, GWLP_USERDATA, HWND_TOPMOST, IDC_ARROW, IDC_HAND, MSG,
    SM_CXSCREEN, SM_CYSCREEN, SWP_NOACTIVATE, SWP_NOZORDER, SWP_SHOWWINDOW, SW_SHOW, WM_APP,
    WM_CLOSE, WM_DPICHANGED, WM_ERASEBKGND, WM_KEYDOWN, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE,
    WM_PAINT, WM_SETCURSOR, WM_TIMER, WNDCLASSW, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
    WS_VISIBLE,
};

use crate::helper_client::StreamEvent;

pub const WM_APP_HELPER_EVENT: u32 = WM_APP + 42;
const ID_TIMER_ANIM: usize = 1;

const BASE_WIDTH_DIP: i32 = 432;
const BASE_HEIGHT_DIP: i32 = 236;
const CORNER_RADIUS_DIP: i32 = 14;

const FW_SEMIBOLD_WEIGHT: i32 = 600;
const FW_REGULAR_WEIGHT: i32 = FW_normal_val;

#[allow(non_upper_case_globals)]
const FW_normal_val: i32 = 400;

/// Logical `DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2` handle constant (`(HANDLE)-4`).
const DPI_CONTEXT_PER_MONITOR_V2: isize = -4;

struct DpiThreadGuard {
    prev_context: isize,
    restore_fn: Option<unsafe extern "system" fn(isize) -> isize>,
}

impl DpiThreadGuard {
    fn enter_per_monitor_v2() -> Self {
        // SAFETY: Dynamically resolves `SetThreadDpiAwarenessContext` from loaded `user32.dll`.
        unsafe {
            let set_fn = GetModuleHandleW(w!("user32.dll"))
                .ok()
                .and_then(|h| GetProcAddress(h, s!("SetThreadDpiAwarenessContext")))
                .map(|p| std::mem::transmute::<_, unsafe extern "system" fn(isize) -> isize>(p));
            if let Some(f) = set_fn {
                let prev = f(DPI_CONTEXT_PER_MONITOR_V2);
                if prev != 0 {
                    return Self {
                        prev_context: prev,
                        restore_fn: Some(f),
                    };
                }
            }
            Self {
                prev_context: 0,
                restore_fn: None,
            }
        }
    }
}

impl Drop for DpiThreadGuard {
    fn drop(&mut self) {
        if let (Some(f), prev) = (self.restore_fn, self.prev_context) {
            if prev != 0 {
                // SAFETY: Restores the exact previous thread DPI awareness context.
                unsafe {
                    let _ = f(prev);
                }
            }
        }
    }
}

#[inline]
fn scale_dip(dip: i32, dpi: u32) -> i32 {
    let d = dpi.clamp(96, 576) as i64;
    ((dip as i64 * d + 48) / 96) as i32
}

#[inline]
fn scale_f32(dip: f32, dpi: u32) -> f32 {
    dip * (dpi.clamp(96, 576) as f32 / 96.0)
}

fn query_effective_dpi(hwnd_hint: Option<HWND>) -> u32 {
    // SAFETY: Dynamically resolves Win10+ `GetDpiForWindow` / `GetDpiForSystem` with GDI fallback.
    unsafe {
        if let Ok(user32) = GetModuleHandleW(w!("user32.dll")) {
            if let Some(hwnd) = hwnd_hint.filter(|h| !h.is_invalid() && !h.0.is_null()) {
                if let Some(p) = GetProcAddress(user32, s!("GetDpiForWindow")) {
                    let get_win_dpi: unsafe extern "system" fn(HWND) -> u32 =
                        std::mem::transmute(p);
                    let d = get_win_dpi(hwnd);
                    if (96..=576).contains(&d) {
                        return d;
                    }
                }
            }
            if let Some(p) = GetProcAddress(user32, s!("GetDpiForSystem")) {
                let get_sys_dpi: unsafe extern "system" fn() -> u32 = std::mem::transmute(p);
                let d = get_sys_dpi();
                if (96..=576).contains(&d) {
                    return d;
                }
            }
        }
        let hdc = GetDC(None);
        if !hdc.is_invalid() && !hdc.0.is_null() {
            let d = GetDeviceCaps(Some(hdc), LOGPIXELSX);
            let _ = ReleaseDC(None, hdc);
            if (96..=576).contains(&d) {
                return d as u32;
            }
        }
        96
    }
}

/// Apply Windows 11 DWM borderless rounded corners (`DWMWCP_ROUND` + `DWMWA_BORDER_COLOR = NONE`),
/// falling back to `SetWindowRgn` rounded region on Windows 10 where attribute 33 is absent.
unsafe fn apply_borderless_surface(hwnd: HWND, width: i32, height: i32, dpi: u32) -> bool {
    const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
    const DWMWA_WINDOW_CORNER_PREFERENCE: u32 = 33;
    const DWMWA_BORDER_COLOR: u32 = 34;
    const DWMWCP_ROUND: u32 = 2;
    const DWMWA_COLOR_NONE: u32 = 0xFFFF_FFFE;

    type DwmSetAttrFn = unsafe extern "system" fn(HWND, u32, *const c_void, u32) -> HRESULT;

    // SAFETY: Loads `dwmapi.dll` strictly from `System32` (`LOAD_LIBRARY_SEARCH_SYSTEM32`).
    let dwm_applied = unsafe {
        if let Ok(dwm) = LoadLibraryExW(w!("dwmapi.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) {
            let res = if let Some(proc) = GetProcAddress(dwm, s!("DwmSetWindowAttribute")) {
                let set_attr: DwmSetAttrFn = std::mem::transmute(proc);
                let dark: u32 = 1;
                let _ = set_attr(
                    hwnd,
                    DWMWA_USE_IMMERSIVE_DARK_MODE,
                    &dark as *const _ as *const c_void,
                    size_of::<u32>() as u32,
                );
                let no_border: u32 = DWMWA_COLOR_NONE;
                let _ = set_attr(
                    hwnd,
                    DWMWA_BORDER_COLOR,
                    &no_border as *const _ as *const c_void,
                    size_of::<u32>() as u32,
                );
                let round: u32 = DWMWCP_ROUND;
                set_attr(
                    hwnd,
                    DWMWA_WINDOW_CORNER_PREFERENCE,
                    &round as *const _ as *const c_void,
                    size_of::<u32>() as u32,
                )
                .is_ok()
            } else {
                false
            };
            let _ = FreeLibrary(dwm);
            res
        } else {
            false
        }
    };

    if !dwm_applied {
        let diameter = scale_dip(CORNER_RADIUS_DIP * 2, dpi);
        // SAFETY: Fallback rounded window region on Windows 10; OS owns `rgn` after `SetWindowRgn`.
        unsafe {
            let rgn = CreateRoundRectRgn(0, 0, width + 1, height + 1, diameter, diameter);
            if !rgn.is_invalid() && !rgn.0.is_null() {
                let _ = SetWindowRgn(hwnd, Some(rgn), true);
            }
        }
    }
    dwm_applied
}

struct DialogState {
    dpi: u32,
    dwm_rounded: bool,
    step: u8,
    total: u8,
    started: Instant,
    deadline: Instant,
    total_duration_secs: f32,
    tick: u32,
    cancel_hover: bool,
    cancel_pressed: bool,
    user_cancelled: bool,
}

impl DialogState {
    fn cancel_rect(&self, client_w: i32, client_h: i32) -> RECT {
        let btn_w = scale_dip(140, self.dpi);
        let btn_h = scale_dip(36, self.dpi);
        let bottom_pad = scale_dip(20, self.dpi);
        let left = (client_w - btn_w) / 2;
        let top = (client_h - bottom_pad - btn_h).max(0);
        RECT {
            left,
            top,
            right: left + btn_w,
            bottom: top + btn_h,
        }
    }
}

#[inline]
fn pt_in_rect(r: &RECT, x: i32, y: i32) -> bool {
    x >= r.left && x < r.right && y >= r.top && y < r.bottom
}

pub enum DialogWaitResult {
    Completed(scard_core::ipc::HelperResponse),
    Cancelled,
    TimedOut,
    PipeBroken,
}

fn current_dll_hinstance() -> HINSTANCE {
    let mut hmod = HMODULE::default();
    let addr = current_dll_hinstance as *const () as *const u16;
    // SAFETY: Queries module handle of `familiar_cred_provider.dll` without incrementing refcount.
    let _ = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(addr),
            &mut hmod,
        )
    };
    HINSTANCE(hmod.0)
}

struct FontGuard {
    handle: HFONT,
    owned: bool,
}

impl FontGuard {
    fn create_dip(dip_height: i32, weight: i32, dpi: u32) -> Self {
        let px_height = -scale_dip(dip_height, dpi);
        // SAFETY: Creates ClearType `Segoe UI` font scaled to exact physical pixel height.
        unsafe {
            let f = CreateFontW(
                px_height,
                0,
                0,
                0,
                weight,
                0,
                0,
                0,
                DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                (DEFAULT_PITCH.0 | FF_DONTCARE.0) as u32,
                w!("Segoe UI"),
            );
            if !f.is_invalid() && !f.0.is_null() {
                Self {
                    handle: f,
                    owned: true,
                }
            } else {
                Self {
                    handle: HFONT(GetStockObject(DEFAULT_GUI_FONT).0),
                    owned: false,
                }
            }
        }
    }
}

impl Drop for FontGuard {
    fn drop(&mut self) {
        if self.owned && !self.handle.is_invalid() && !self.handle.0.is_null() {
            // SAFETY: Deletes owned GDI font.
            unsafe {
                let _ = DeleteObject(self.handle.into());
            }
        }
    }
}

fn step_strings(step: u8, total: u8) -> (&'static str, &'static str) {
    if total <= 1 {
        (
            "Touch your security key",
            "Press the blinking button or sensor on your key to sign in",
        )
    } else if step <= 1 {
        (
            "Touch your security key (1 of 2)",
            "Press the blinking button or sensor on your key",
        )
    } else {
        (
            "Confirmed! Touch again (2 of 2)",
            "Almost done — press your security key one more time",
        )
    }
}

/// Display the borderless High-DPI Hardware Touch Prompt overlay and pump messages until
/// `rx` delivers `StreamEvent::Final`, the user clicks `Cancel` (`Esc`), or `deadline` expires.
pub fn run_touch_prompt_modal(
    owner_hwnd: Option<HWND>,
    initial_step: u8,
    initial_total: u8,
    deadline: Instant,
    rx: &Receiver<StreamEvent>,
    notify_hwnd: &AtomicIsize,
) -> DialogWaitResult {
    let _dpi_guard = DpiThreadGuard::enter_per_monitor_v2();

    let hinstance = current_dll_hinstance();
    let class_name = w!("FamiliarTouchOverlayV2");

    let wc = WNDCLASSW {
        lpfnWndProc: Some(touch_wndproc),
        hInstance: hinstance,
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default(),
        hbrBackground: HBRUSH(std::ptr::null_mut()),
        lpszClassName: class_name,
        ..Default::default()
    };
    // SAFETY: Registers window class once per DLL load (`ERROR_CLASS_ALREADY_EXISTS` is benign).
    unsafe {
        let _ = RegisterClassW(&wc);
    }

    let valid_owner = owner_hwnd
        .filter(|&h| !h.is_invalid() && !h.0.is_null() && unsafe { IsWindow(Some(h)) }.as_bool());
    let dpi = query_effective_dpi(valid_owner);
    let width = scale_dip(BASE_WIDTH_DIP, dpi);
    let height = scale_dip(BASE_HEIGHT_DIP, dpi);

    // SAFETY: Queries physical screen dimensions under `PER_MONITOR_AWARE_V2`.
    let (screen_w, screen_h) =
        unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    let pos_x = ((screen_w - width) / 2).max(16);
    let pos_y = ((screen_h - height) / 2).max(16);

    // Borderless `WS_POPUP | WS_VISIBLE` with `WS_EX_TOPMOST | WS_EX_TOOLWINDOW` (zero frame!).
    let Ok(hwnd) = (unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            class_name,
            w!(""),
            WS_POPUP | WS_VISIBLE,
            pos_x,
            pos_y,
            width,
            height,
            valid_owner,
            None,
            Some(hinstance),
            None,
        )
    }) else {
        return wait_headless(deadline, rx);
    };

    let now = Instant::now();
    let total_dur = deadline
        .checked_duration_since(now)
        .unwrap_or(Duration::from_secs(25))
        .as_secs_f32()
        .max(1.0);

    // SAFETY: Configures borderless rounded DWM attributes, stores dialog state, and starts 100ms animation timer.
    let state_ptr = unsafe {
        let dwm_rounded = apply_borderless_surface(hwnd, width, height, dpi);
        let st = Box::into_raw(Box::new(DialogState {
            dpi,
            dwm_rounded,
            step: initial_step,
            total: initial_total,
            started: now,
            deadline,
            total_duration_secs: total_dur,
            tick: 0,
            cancel_hover: false,
            cancel_pressed: false,
            user_cancelled: false,
        }));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, st as isize);

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetWindowPos(
            hwnd,
            Some(HWND_TOPMOST),
            pos_x,
            pos_y,
            width,
            height,
            SWP_SHOWWINDOW,
        );
        let _ = SetForegroundWindow(hwnd);
        let _ = SetFocus(Some(hwnd));
        let _ = InvalidateRect(Some(hwnd), None, false);
        let _ = SetTimer(Some(hwnd), ID_TIMER_ANIM, 100, None);
        st
    };

    notify_hwnd.store(hwnd.0 as isize, Ordering::SeqCst);
    unsafe {
        let _ = PostMessageW(Some(hwnd), WM_APP_HELPER_EVENT, WPARAM(0), LPARAM(0));
    }

    let result = loop {
        if let Some(done) = drain_stream_events(hwnd, rx) {
            break done;
        }
        // SAFETY: `state_ptr` is owned on this thread until cleanup below.
        if unsafe { (*state_ptr).user_cancelled } {
            break DialogWaitResult::Cancelled;
        }
        if Instant::now() >= deadline {
            break DialogWaitResult::TimedOut;
        }

        let mut msg = MSG::default();
        // SAFETY: Standard Win32 message loop for current thread.
        let gm = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        if !gm.as_bool() || gm.0 == -1 {
            break DialogWaitResult::Cancelled;
        }
        if msg.message == WM_KEYDOWN {
            let vk = msg.wParam.0 as u16;
            if vk == VK_ESCAPE.0 || vk == VK_RETURN.0 || vk == VK_SPACE.0 {
                break DialogWaitResult::Cancelled;
            }
        }
        // SAFETY: Dispatches message to `touch_wndproc`.
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    };

    notify_hwnd.store(0, Ordering::SeqCst);
    // SAFETY: Releases capture, timer, window, and heap state cleanly.
    unsafe {
        let _ = ReleaseCapture();
        let _ = KillTimer(Some(hwnd), ID_TIMER_ANIM);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if IsWindow(Some(hwnd)).as_bool() {
            let _ = DestroyWindow(hwnd);
        }
        drop(Box::from_raw(state_ptr));
    }

    result
}

fn drain_stream_events(hwnd: HWND, rx: &Receiver<StreamEvent>) -> Option<DialogWaitResult> {
    let mut updated = false;
    loop {
        match rx.try_recv() {
            Ok(StreamEvent::Progress(HelperProgress::TouchRequired { step, total })) => {
                // SAFETY: Mutates state owned by this UI thread.
                unsafe {
                    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut DialogState;
                    if let Some(st) = ptr.as_mut() {
                        st.step = step;
                        st.total = total;
                        updated = true;
                    }
                }
            }
            Ok(StreamEvent::Final(resp)) => return Some(DialogWaitResult::Completed(resp)),
            Ok(StreamEvent::Eof) => return Some(DialogWaitResult::PipeBroken),
            Err(TryRecvError::Empty) => {
                if updated {
                    unsafe {
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                return None;
            }
            Err(TryRecvError::Disconnected) => return Some(DialogWaitResult::PipeBroken),
        }
    }
}

fn wait_headless(deadline: Instant, rx: &Receiver<StreamEvent>) -> DialogWaitResult {
    loop {
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            return DialogWaitResult::TimedOut;
        };
        match rx.recv_timeout(rem) {
            Ok(StreamEvent::Progress(_)) => continue,
            Ok(StreamEvent::Final(resp)) => return DialogWaitResult::Completed(resp),
            Ok(StreamEvent::Eof) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return DialogWaitResult::PipeBroken;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return DialogWaitResult::TimedOut,
        }
    }
}

// ---------------------------------------------------------------------------
// Subpixel Anti-Aliased SDF Primitives & Double-Buffered ClearType Renderer
// ---------------------------------------------------------------------------

#[inline]
fn sd_round_rect(px: f32, py: f32, cx: f32, cy: f32, half_w: f32, half_h: f32, r: f32) -> f32 {
    let dx = (px - cx).abs() - (half_w - r).max(0.0);
    let dy = (py - cy).abs() - (half_h - r).max(0.0);
    let out_d = (dx.max(0.0) * dx.max(0.0) + dy.max(0.0) * dy.max(0.0)).sqrt();
    let in_d = dx.max(dy).min(0.0);
    out_d + in_d - r
}

#[inline]
fn blend_argb(dst: u32, src_rgb: (u8, u8, u8), alpha: f32) -> u32 {
    let a = alpha.clamp(0.0, 1.0);
    if a <= 0.001 {
        return dst;
    }
    if a >= 0.999 {
        return 0xFF00_0000
            | ((src_rgb.0 as u32) << 16)
            | ((src_rgb.1 as u32) << 8)
            | (src_rgb.2 as u32);
    }
    let dr = ((dst >> 16) & 0xFF) as f32;
    let dg = ((dst >> 8) & 0xFF) as f32;
    let db = (dst & 0xFF) as f32;
    let inv = 1.0 - a;
    let r = (src_rgb.0 as f32 * a + dr * inv).round() as u32;
    let g = (src_rgb.1 as f32 * a + dg * inv).round() as u32;
    let b = (src_rgb.2 as f32 * a + db * inv).round() as u32;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

fn fill_sdf_round_rect(
    pixels: &mut [u32],
    stride: usize,
    height: usize,
    rect: RECT,
    radius: f32,
    rgb: (u8, u8, u8),
    opacity: f32,
) {
    let x0 = rect.left.max(0) as usize;
    let y0 = rect.top.max(0) as usize;
    let x1 = (rect.right.max(0) as usize).min(stride);
    let y1 = (rect.bottom.max(0) as usize).min(height);
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let cx = (rect.left + rect.right) as f32 * 0.5;
    let cy = (rect.top + rect.bottom) as f32 * 0.5;
    let hw = (rect.right - rect.left) as f32 * 0.5;
    let hh = (rect.bottom - rect.top) as f32 * 0.5;

    for y in y0..y1 {
        let py = y as f32 + 0.5;
        let row = &mut pixels[y * stride..y * stride + stride];
        for (x, cell) in row.iter_mut().enumerate().take(x1).skip(x0) {
            let px = x as f32 + 0.5;
            let dist = sd_round_rect(px, py, cx, cy, hw, hh, radius);
            let cov = (0.5 - dist).clamp(0.0, 1.0) * opacity;
            if cov > 0.0 {
                *cell = blend_argb(*cell, rgb, cov);
            }
        }
    }
}

fn draw_key_emblem(
    pixels: &mut [u32],
    w: usize,
    h: usize,
    dpi: u32,
    step: u8,
    total: u8,
    tick: u32,
) {
    let cx = w as f32 * 0.5;
    let cy = scale_f32(44.0, dpi);
    // Smooth sinusoidal pulse (period = 16 ticks = 1.6s)
    let phase = (tick as f32 * std::f32::consts::TAU / 16.0).sin() * 0.5 + 0.5;

    let accent = if total >= 2 && step >= 2 {
        (34u8, 197u8, 94u8) // Emerald green once first press is confirmed!
    } else {
        (56u8, 189u8, 248u8) // Crisp sky-cyan touch glow
    };

    let outer_r = scale_f32(25.0 + 3.5 * phase, dpi);
    let inner_r = scale_f32(20.0, dpi);
    let ring_thick = scale_f32(2.0, dpi);
    let pad = (outer_r + 3.0).ceil() as isize;
    let x0 = ((cx as isize - pad).max(0)) as usize;
    let x1 = ((cx as isize + pad).min(w as isize)) as usize;
    let y0 = ((cy as isize - pad).max(0)) as usize;
    let y1 = ((cy as isize + pad).min(h as isize)) as usize;

    for y in y0..y1 {
        let py = y as f32 + 0.5;
        for x in x0..x1 {
            let px = x as f32 + 0.5;
            let d = ((px - cx) * (px - cx) + (py - cy) * (py - cy)).sqrt();

            // Soft outer breathing halo
            let halo_cov = (0.5 - (d - outer_r)).clamp(0.0, 1.0) * (0.18 + 0.14 * phase);
            if halo_cov > 0.0 {
                pixels[y * w + x] = blend_argb(pixels[y * w + x], accent, halo_cov);
            }

            // Crisp inner badge disc
            let disc_cov = (0.5 - (d - inner_r)).clamp(0.0, 1.0);
            if disc_cov > 0.0 {
                pixels[y * w + x] = blend_argb(pixels[y * w + x], (36, 45, 64), disc_cov);
            }

            // Crisp accent ring around disc
            let ring_d = (d - inner_r).abs() - ring_thick * 0.5;
            let ring_cov = (0.5 - ring_d).clamp(0.0, 1.0) * 0.92;
            if ring_cov > 0.0 {
                pixels[y * w + x] = blend_argb(pixels[y * w + x], accent, ring_cov);
            }
        }
    }

    // Draw crisp anti-aliased security key glyph inside the badge
    let head_cx = cx - scale_f32(5.0, dpi);
    let head_r = scale_f32(5.2, dpi);
    let hole_r = scale_f32(2.1, dpi);
    let gold = (251u8, 191u8, 36u8);

    for y in y0..y1 {
        let py = y as f32 + 0.5;
        for x in x0..x1 {
            let px = x as f32 + 0.5;
            let dh = ((px - head_cx) * (px - head_cx) + (py - cy) * (py - cy)).sqrt();
            let ring_cov =
                (0.5 - (dh - head_r)).clamp(0.0, 1.0) * (0.5 + (dh - hole_r)).clamp(0.0, 1.0);
            if ring_cov > 0.0 {
                pixels[y * w + x] = blend_argb(pixels[y * w + x], gold, ring_cov);
            }
        }
    }

    // Key shaft & teeth
    let shaft = RECT {
        left: (cx - scale_f32(1.0, dpi)).round() as i32,
        top: (cy - scale_f32(1.4, dpi)).round() as i32,
        right: (cx + scale_f32(10.5, dpi)).round() as i32,
        bottom: (cy + scale_f32(1.4, dpi)).round() as i32,
    };
    fill_sdf_round_rect(pixels, w, h, shaft, scale_f32(1.0, dpi), gold, 1.0);

    for tooth_x in [4.5f32, 8.2f32] {
        let tooth = RECT {
            left: (cx + scale_f32(tooth_x, dpi)).round() as i32,
            top: (cy + scale_f32(0.8, dpi)).round() as i32,
            right: (cx + scale_f32(tooth_x + 2.0, dpi)).round() as i32,
            bottom: (cy + scale_f32(4.5, dpi)).round() as i32,
        };
        fill_sdf_round_rect(pixels, w, h, tooth, scale_f32(0.8, dpi), gold, 1.0);
    }
}

unsafe fn paint_overlay(hwnd: HWND, hdc: HDC, st: &DialogState) {
    let mut rc = RECT::default();
    // SAFETY: Queries client bounds.
    if unsafe { GetClientRect(hwnd, &mut rc) }.is_err() {
        return;
    }
    let w = (rc.right - rc.left).max(1) as usize;
    let h = (rc.bottom - rc.top).max(1) as usize;

    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w as i32,
            biHeight: -(h as i32), // Top-down 32-bpp DIB
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            biSizeImage: (w * h * 4) as u32,
            ..Default::default()
        },
        ..Default::default()
    };

    // SAFETY: Creates offscreen memory DC + 32-bpp DIB section for flicker-free rendering.
    unsafe {
        let mem_dc = CreateCompatibleDC(Some(hdc));
        if mem_dc.is_invalid() || mem_dc.0.is_null() {
            return;
        }
        let mut bits_ptr: *mut c_void = std::ptr::null_mut();
        let Ok(dib) = CreateDIBSection(Some(mem_dc), &bmi, DIB_RGB_COLORS, &mut bits_ptr, None, 0)
        else {
            let _ = DeleteDC(mem_dc);
            return;
        };
        if bits_ptr.is_null() {
            let _ = DeleteObject(dib.into());
            let _ = DeleteDC(mem_dc);
            return;
        }
        let old_bmp = SelectObject(mem_dc, dib.into());

        {
            let pixels = std::slice::from_raw_parts_mut(bits_ptr as *mut u32, w * h);
            // Smooth subtle vertical dark-slate surface (borderless, matches Windows 11 dark UI)
            for y in 0..h {
                let t = y as f32 / (h.max(1) as f32);
                let r = (30.0 - 4.0 * t).round() as u32;
                let g = (36.0 - 5.0 * t).round() as u32;
                let b = (50.0 - 6.0 * t).round() as u32;
                let col = 0xFF00_0000 | (r << 16) | (g << 8) | b;
                pixels[y * w..(y + 1) * w].fill(col);
            }

            // 1. Pulsing security-key badge at top center
            draw_key_emblem(pixels, w, h, st.dpi, st.step, st.total, st.tick);

            // 2. Step pills / time progress bar
            let bar_y = scale_dip(146, st.dpi);
            let bar_h = scale_dip(4, st.dpi).max(2);
            let bar_r = bar_h as f32 * 0.5;
            if st.total >= 2 {
                let pill_w = scale_dip(104, st.dpi);
                let gap = scale_dip(10, st.dpi);
                let total_w = pill_w * 2 + gap;
                let start_x = (w as i32 - total_w) / 2;
                let p1 = RECT {
                    left: start_x,
                    top: bar_y,
                    right: start_x + pill_w,
                    bottom: bar_y + bar_h,
                };
                let p2 = RECT {
                    left: start_x + pill_w + gap,
                    top: bar_y,
                    right: start_x + total_w,
                    bottom: bar_y + bar_h,
                };
                let c1 = if st.step >= 2 {
                    (34, 197, 94)
                } else {
                    (56, 189, 248)
                };
                let c2 = if st.step >= 2 {
                    (56, 189, 248)
                } else {
                    (58, 68, 88)
                };
                fill_sdf_round_rect(pixels, w, h, p1, bar_r, c1, 1.0);
                fill_sdf_round_rect(pixels, w, h, p2, bar_r, c2, 1.0);
            } else {
                let bar_w = scale_dip(220, st.dpi);
                let start_x = (w as i32 - bar_w) / 2;
                let track = RECT {
                    left: start_x,
                    top: bar_y,
                    right: start_x + bar_w,
                    bottom: bar_y + bar_h,
                };
                fill_sdf_round_rect(pixels, w, h, track, bar_r, (55, 65, 84), 1.0);

                let rem_frac = st
                    .deadline
                    .checked_duration_since(Instant::now())
                    .map(|d| (d.as_secs_f32() / st.total_duration_secs).clamp(0.0, 1.0))
                    .unwrap_or(0.0);
                let fill_w = ((bar_w as f32) * rem_frac).round() as i32;
                if fill_w > 2 {
                    let active = RECT {
                        left: start_x,
                        top: bar_y,
                        right: start_x + fill_w,
                        bottom: bar_y + bar_h,
                    };
                    fill_sdf_round_rect(pixels, w, h, active, bar_r, (56, 189, 248), 1.0);
                }
            }

            // 3. Borderless rounded Cancel pill button
            let btn_rc = st.cancel_rect(w as i32, h as i32);
            let btn_rgb = if st.cancel_pressed {
                (71, 85, 105)
            } else if st.cancel_hover {
                (58, 70, 92)
            } else {
                (44, 53, 72)
            };
            fill_sdf_round_rect(pixels, w, h, btn_rc, scale_f32(8.0, st.dpi), btn_rgb, 1.0);
        }

        // 4. Crisp ClearType Typography over DIB
        let _ = SetBkMode(mem_dc, TRANSPARENT);
        let font_title = FontGuard::create_dip(20, FW_SEMIBOLD_WEIGHT, st.dpi);
        let font_sub = FontGuard::create_dip(14, FW_REGULAR_WEIGHT, st.dpi);
        let font_small = FontGuard::create_dip(12, FW_REGULAR_WEIGHT, st.dpi);
        let font_btn = FontGuard::create_dip(14, FW_SEMIBOLD_WEIGHT, st.dpi);

        let (title_text, sub_text) = step_strings(st.step, st.total);
        let secs_left = st
            .deadline
            .checked_duration_since(Instant::now())
            .map(|d| d.as_secs().saturating_add(1))
            .unwrap_or(0);
        let timer_text = format!("{secs_left}s remaining");

        draw_centered_line(
            mem_dc,
            font_title.handle,
            COLORREF(0x00FC_FAF8), // #F8FAFC (BGR)
            title_text,
            0,
            scale_dip(78, st.dpi),
            w as i32,
            scale_dip(108, st.dpi),
        );
        draw_centered_line(
            mem_dc,
            font_sub.handle,
            COLORREF(0x00E1_D5CB), // #CBD5E1 (BGR)
            sub_text,
            scale_dip(16, st.dpi),
            scale_dip(110, st.dpi),
            w as i32 - scale_dip(16, st.dpi),
            scale_dip(136, st.dpi),
        );
        draw_centered_line(
            mem_dc,
            font_small.handle,
            COLORREF(0x00B8_A394), // #94A3B8 (BGR)
            &timer_text,
            0,
            scale_dip(154, st.dpi),
            w as i32,
            scale_dip(174, st.dpi),
        );

        let btn_rc = st.cancel_rect(w as i32, h as i32);
        draw_centered_line(
            mem_dc,
            font_btn.handle,
            COLORREF(0x00F9_F5F1), // #F1F5F9 (BGR)
            "Cancel  (Esc)",
            btn_rc.left,
            btn_rc.top,
            btn_rc.right,
            btn_rc.bottom,
        );

        let _ = BitBlt(hdc, 0, 0, w as i32, h as i32, Some(mem_dc), 0, 0, SRCCOPY);
        let _ = SelectObject(mem_dc, old_bmp);
        let _ = DeleteObject(dib.into());
        let _ = DeleteDC(mem_dc);
    }
    let _ = st.started;
}

#[allow(clippy::too_many_arguments)]
unsafe fn draw_centered_line(
    hdc: HDC,
    font: HFONT,
    color: COLORREF,
    text: &str,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) {
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    let mut rc = RECT {
        left,
        top,
        right,
        bottom,
    };
    // SAFETY: Selects font, sets text color, draws single-line centered ClearType text, and restores font.
    unsafe {
        let prev = SelectObject(hdc, font.into());
        let _ = SetTextColor(hdc, color);
        let _ = DrawTextW(
            hdc,
            &mut wide,
            &mut rc,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
        );
        let _ = SelectObject(hdc, prev);
    }
}

#[inline]
fn unpack_mouse_xy(lparam: LPARAM) -> (i32, i32) {
    let x = (lparam.0 & 0xFFFF) as i16 as i32;
    let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
    (x, y)
}

extern "system" fn touch_wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: Window procedure invoked on owning UI thread.
    unsafe {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut DialogState;
        match msg {
            WM_ERASEBKGND => LRESULT(1),
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                if let Some(st) = ptr.as_ref() {
                    paint_overlay(hwnd, hdc, st);
                }
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_TIMER => {
                if let Some(st) = ptr.as_mut() {
                    st.tick = st.tick.wrapping_add(1);
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                LRESULT(0)
            }
            WM_DPICHANGED => {
                if let Some(st) = ptr.as_mut() {
                    let new_dpi = ((wparam.0 >> 16) & 0xFFFF) as u32;
                    if (96..=576).contains(&new_dpi) {
                        st.dpi = new_dpi;
                    }
                    let suggested = lparam.0 as *const RECT;
                    if !suggested.is_null() {
                        let r = *suggested;
                        let w = r.right - r.left;
                        let h = r.bottom - r.top;
                        let _ = SetWindowPos(
                            hwnd,
                            None,
                            r.left,
                            r.top,
                            w,
                            h,
                            SWP_NOZORDER | SWP_NOACTIVATE,
                        );
                        if !st.dwm_rounded {
                            let diameter = scale_dip(CORNER_RADIUS_DIP * 2, st.dpi);
                            let rgn = CreateRoundRectRgn(0, 0, w + 1, h + 1, diameter, diameter);
                            if !rgn.is_invalid() && !rgn.0.is_null() {
                                let _ = SetWindowRgn(hwnd, Some(rgn), true);
                            }
                        }
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }
            WM_SETCURSOR => {
                if let Some(st) = ptr.as_ref() {
                    let cursor_id = if st.cancel_hover { IDC_HAND } else { IDC_ARROW };
                    if let Ok(cur) = LoadCursorW(None, cursor_id) {
                        let _ = SetCursor(Some(cur));
                        return LRESULT(1);
                    }
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
            WM_MOUSEMOVE => {
                if let Some(st) = ptr.as_mut() {
                    let mut rc = RECT::default();
                    let _ = GetClientRect(hwnd, &mut rc);
                    let (mx, my) = unpack_mouse_xy(lparam);
                    let over = pt_in_rect(&st.cancel_rect(rc.right, rc.bottom), mx, my);
                    if over != st.cancel_hover {
                        st.cancel_hover = over;
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }
            WM_LBUTTONDOWN => {
                if let Some(st) = ptr.as_mut() {
                    let mut rc = RECT::default();
                    let _ = GetClientRect(hwnd, &mut rc);
                    let (mx, my) = unpack_mouse_xy(lparam);
                    if pt_in_rect(&st.cancel_rect(rc.right, rc.bottom), mx, my) {
                        st.cancel_pressed = true;
                        let _ = SetCapture(hwnd);
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }
            WM_LBUTTONUP => {
                if let Some(st) = ptr.as_mut() {
                    let was_pressed = st.cancel_pressed;
                    st.cancel_pressed = false;
                    if was_pressed {
                        let _ = ReleaseCapture();
                        let mut rc = RECT::default();
                        let _ = GetClientRect(hwnd, &mut rc);
                        let (mx, my) = unpack_mouse_xy(lparam);
                        if pt_in_rect(&st.cancel_rect(rc.right, rc.bottom), mx, my) {
                            st.user_cancelled = true;
                        }
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }
            WM_CLOSE => {
                if let Some(st) = ptr.as_mut() {
                    st.user_cancelled = true;
                }
                LRESULT(0)
            }
            WM_APP_HELPER_EVENT => LRESULT(0),
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_dpi_scaling_and_sdf_button_hit_test_are_exact() {
        assert_eq!(scale_dip(432, 96), 432); // 100%
        assert_eq!(scale_dip(432, 144), 648); // 150%
        assert_eq!(scale_dip(432, 192), 864); // 200%
        assert_eq!(scale_dip(432, 240), 1080); // 250%

        let now = Instant::now();
        let st = DialogState {
            dpi: 192,
            dwm_rounded: true,
            step: 1,
            total: 2,
            started: now,
            deadline: now + Duration::from_secs(20),
            total_duration_secs: 20.0,
            tick: 0,
            cancel_hover: false,
            cancel_pressed: false,
            user_cancelled: false,
        };
        let cw = scale_dip(BASE_WIDTH_DIP, 192);
        let ch = scale_dip(BASE_HEIGHT_DIP, 192);
        let btn = st.cancel_rect(cw, ch);
        assert_eq!(btn.right - btn.left, 280);
        assert_eq!(btn.bottom - btn.top, 72);
        assert!(pt_in_rect(
            &btn,
            (btn.left + btn.right) / 2,
            (btn.top + btn.bottom) / 2
        ));
        assert!(!pt_in_rect(&btn, 10, 10));
    }
}
