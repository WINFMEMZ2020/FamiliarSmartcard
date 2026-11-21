//! Modal Win32 dialog for unblocking a locked PIV PIN with PUK (`00 2C 00 80`)
//! and changing the card's PUK (`00 24 00 81`).
//!
//! All user-visible strings are strictly English per project policy.

#![deny(unsafe_op_in_unsafe_fn)]

use scard_core::crypto::constant_time_eq;
use scard_core::storage::clear_last_attempt_cooldown;
use scard_core::{change_card_puk, unblock_card_pin, AuthError};
use std::ffi::c_void;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetStockObject, COLOR_WINDOW, DEFAULT_GUI_FONT, HBRUSH, HFONT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, IsWindow, LoadCursorW, MessageBoxW,
    PostMessageW, RegisterClassW, SendMessageW, SetForegroundWindow, SetWindowLongPtrW,
    SetWindowTextW, ShowWindow, TranslateMessage, CW_USEDEFAULT, GWLP_USERDATA, HMENU, IDC_ARROW,
    MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_YESNO, MSG, SW_SHOW,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_NULL, WM_SETFONT,
    WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};
use zeroize::Zeroizing;

const ID_BTN_UNBLOCK_PIN: usize = 3001;
const ID_BTN_CHANGE_PUK: usize = 3002;
const ID_BTN_CLOSE: usize = 3003;

const EM_SETPASSWORDCHAR: u32 = 0x00CC;
const PASSWORD_CHAR: usize = 0x25CF;

struct PukDialogState {
    status_lbl: HWND,
    unblock_puk: HWND,
    unblock_new_pin: HWND,
    unblock_confirm_pin: HWND,
    chg_cur_puk: HWND,
    chg_new_puk: HWND,
    chg_confirm_puk: HWND,
    log: String,
    closed: bool,
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn scrub_hwnd(hwnd: HWND) {
    if !hwnd.0.is_null() {
        let mask = w!("0000000000000000");
        let empty = w!("");
        // SAFETY: Overwrites internal Win32 Edit buffer before clearing.
        unsafe {
            let _ = SetWindowTextW(hwnd, mask);
            let _ = SetWindowTextW(hwnd, empty);
        }
    }
}

unsafe fn read_hwnd_zeroizing(hwnd: HWND) -> Zeroizing<String> {
    // SAFETY: Queries edit control length.
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    if len <= 0 {
        return Zeroizing::new(String::new());
    }
    let mut buf = Zeroizing::new(vec![0u16; len as usize + 1]);
    // SAFETY: `buf` has `len + 1` capacity.
    let copied = unsafe { GetWindowTextW(hwnd, buf.as_mut_slice()) };
    let valid = copied.max(0) as usize;
    Zeroizing::new(String::from_utf16_lossy(&buf[..valid]))
}

fn valid_pin(pin: &str) -> bool {
    (6..=8).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit())
}

fn valid_puk(puk: &str) -> bool {
    (6..=8).contains(&puk.len()) && puk.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

fn format_puk_error(err: &AuthError) -> String {
    match err {
        AuthError::PukIncorrect(rem) => {
            format!("Incorrect PUK ({rem} PUK attempt(s) remaining on card).")
        }
        AuthError::PukBlocked => {
            "Card PUK is permanently blocked (0 attempts left). A PIV applet reset is required."
                .into()
        }
        other => other.to_string(),
    }
}

/// Show the modal PIN Unblock & PUK Management dialog.
/// Returns `Some(summary_log)` if one or more card actions succeeded.
pub fn show_puk_management_dialog(parent: HWND) -> Option<String> {
    // SAFETY: Standard Win32 modal dialog creation and message loop.
    unsafe {
        let Ok(instance) = GetModuleHandleW(None) else {
            return None;
        };
        let hinstance = windows::Win32::Foundation::HINSTANCE(instance.0);
        let class_name = w!("FamiliarPukModalClass");

        let wc = WNDCLASSW {
            lpfnWndProc: Some(puk_modal_wndproc),
            hInstance: hinstance,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as *mut c_void),
            lpszClassName: class_name,
            ..Default::default()
        };
        let _ = RegisterClassW(&wc);

        let _ = EnableWindow(parent, false);

        let title = to_wide("Familiar Smartcard — PIN Unblock & PUK Management");
        let Ok(modal) = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            PCWSTR(title.as_ptr()),
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            660,
            490,
            Some(parent),
            None,
            Some(hinstance),
            None,
        ) else {
            let _ = EnableWindow(parent, true);
            return None;
        };

        let font = HFONT(GetStockObject(DEFAULT_GUI_FONT).0);

        let status_lbl = make_child(
            modal,
            w!("STATIC"),
            "Unblocking or changing PIN/PUK preserves your 0x9D key — existing Windows vaults do NOT need re-enrollment.",
            20,
            14,
            605,
            34,
            WINDOW_STYLE(0),
            0,
            font,
        );

        // --- Section 1: Unblock PIN with PUK ---
        let _ = make_child(
            modal,
            w!("STATIC"),
            "1. Unblock Blocked PIV PIN with PUK (resets PIN retries to 3):",
            20,
            56,
            605,
            20,
            WINDOW_STYLE(0),
            0,
            font,
        );

        let _ = make_child(
            modal,
            w!("STATIC"),
            "Card PUK (default: 12345678)",
            20,
            84,
            210,
            22,
            WINDOW_STYLE(0),
            0,
            font,
        );
        let unblock_puk = make_password_edit(modal, 240, 82, 180, 24, font);

        let _ = make_child(
            modal,
            w!("STATIC"),
            "New PIV PIN (6-8 digits)",
            20,
            114,
            210,
            22,
            WINDOW_STYLE(0),
            0,
            font,
        );
        let unblock_new_pin = make_password_edit(modal, 240, 112, 180, 24, font);

        let _ = make_child(
            modal,
            w!("STATIC"),
            "Confirm New PIV PIN",
            20,
            144,
            210,
            22,
            WINDOW_STYLE(0),
            0,
            font,
        );
        let unblock_confirm_pin = make_password_edit(modal, 240, 142, 180, 24, font);

        let _ = make_child(
            modal,
            w!("BUTTON"),
            "Unblock PIN & Reset Retries",
            240,
            174,
            220,
            32,
            WS_TABSTOP,
            ID_BTN_UNBLOCK_PIN,
            font,
        );

        // --- Section 2: Change Card PUK ---
        let _ = make_child(
            modal,
            w!("STATIC"),
            "2. Change Card PUK (replace factory default 12345678 with your own 6-8 char PUK):",
            20,
            226,
            605,
            20,
            WINDOW_STYLE(0),
            0,
            font,
        );

        let _ = make_child(
            modal,
            w!("STATIC"),
            "Current PUK",
            20,
            254,
            210,
            22,
            WINDOW_STYLE(0),
            0,
            font,
        );
        let chg_cur_puk = make_password_edit(modal, 240, 252, 180, 24, font);

        let _ = make_child(
            modal,
            w!("STATIC"),
            "New PUK (6-8 ASCII chars)",
            20,
            284,
            210,
            22,
            WINDOW_STYLE(0),
            0,
            font,
        );
        let chg_new_puk = make_password_edit(modal, 240, 282, 180, 24, font);

        let _ = make_child(
            modal,
            w!("STATIC"),
            "Confirm New PUK",
            20,
            314,
            210,
            22,
            WINDOW_STYLE(0),
            0,
            font,
        );
        let chg_confirm_puk = make_password_edit(modal, 240, 312, 180, 24, font);

        let _ = make_child(
            modal,
            w!("BUTTON"),
            "Change Card PUK",
            240,
            344,
            220,
            32,
            WS_TABSTOP,
            ID_BTN_CHANGE_PUK,
            font,
        );

        let _ = make_child(
            modal,
            w!("BUTTON"),
            "Close",
            510,
            402,
            115,
            34,
            WS_TABSTOP,
            ID_BTN_CLOSE,
            font,
        );

        let state = Box::new(PukDialogState {
            status_lbl,
            unblock_puk,
            unblock_new_pin,
            unblock_confirm_pin,
            chg_cur_puk,
            chg_new_puk,
            chg_confirm_puk,
            log: String::new(),
            closed: false,
        });
        let state_ptr = Box::into_raw(state);
        SetWindowLongPtrW(modal, GWLP_USERDATA, state_ptr as isize);

        let _ = ShowWindow(modal, SW_SHOW);

        let mut msg = MSG::default();
        while !(*state_ptr).closed && IsWindow(Some(modal)).as_bool() {
            let ret = GetMessageW(&mut msg, None, 0, 0);
            if !ret.as_bool() {
                break;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if IsWindow(Some(modal)).as_bool() {
            scrub_all(&*state_ptr);
            SetWindowLongPtrW(modal, GWLP_USERDATA, 0);
            let _ = DestroyWindow(modal);
        }
        let result_log = (*state_ptr).log.clone();
        drop(Box::from_raw(state_ptr));

        let _ = EnableWindow(parent, true);
        let _ = SetForegroundWindow(parent);

        if result_log.is_empty() {
            None
        } else {
            Some(result_log)
        }
    }
}

unsafe fn scrub_all(st: &PukDialogState) {
    // SAFETY: Scrubs all child Edit controls.
    unsafe {
        scrub_hwnd(st.unblock_puk);
        scrub_hwnd(st.unblock_new_pin);
        scrub_hwnd(st.unblock_confirm_pin);
        scrub_hwnd(st.chg_cur_puk);
        scrub_hwnd(st.chg_new_puk);
        scrub_hwnd(st.chg_confirm_puk);
    }
}

unsafe fn set_lbl(hwnd: HWND, text: &str) {
    let wtext = to_wide(text);
    // SAFETY: Updates child STATIC label.
    unsafe {
        let _ = SetWindowTextW(hwnd, PCWSTR(wtext.as_ptr()));
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn make_child(
    parent: HWND,
    class: PCWSTR,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    extra: WINDOW_STYLE,
    id: usize,
    font: HFONT,
) -> HWND {
    let wide = to_wide(text);
    let menu = if id == 0 {
        None
    } else {
        Some(HMENU(id as *mut c_void))
    };
    // SAFETY: Creates standard Win32 child control.
    unsafe {
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            PCWSTR(wide.as_ptr()),
            WS_CHILD | WS_VISIBLE | extra,
            x,
            y,
            w,
            h,
            Some(parent),
            menu,
            None,
            None,
        )
        .unwrap_or_default();
        let _ = SendMessageW(
            hwnd,
            WM_SETFONT,
            Some(WPARAM(font.0 as usize)),
            Some(LPARAM(1)),
        );
        hwnd
    }
}

unsafe fn make_password_edit(parent: HWND, x: i32, y: i32, w: i32, h: i32, font: HFONT) -> HWND {
    // SAFETY: Creates password-masked Edit control.
    unsafe {
        let hwnd = make_child(
            parent,
            w!("EDIT"),
            "",
            x,
            y,
            w,
            h,
            WS_BORDER | WS_TABSTOP,
            0,
            font,
        );
        let _ = SendMessageW(
            hwnd,
            EM_SETPASSWORDCHAR,
            Some(WPARAM(PASSWORD_CHAR)),
            Some(LPARAM(0)),
        );
        hwnd
    }
}

extern "system" fn puk_modal_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: Modal dialog window procedure on main UI thread.
    unsafe {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PukDialogState;
        match msg {
            WM_COMMAND if !ptr.is_null() => {
                let st = &mut *ptr;
                let id = wparam.0 & 0xFFFF;
                match id {
                    ID_BTN_UNBLOCK_PIN => handle_unblock_pin(hwnd, st),
                    ID_BTN_CHANGE_PUK => handle_change_puk(hwnd, st),
                    ID_BTN_CLOSE => {
                        st.closed = true;
                        let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
                    }
                    _ => {}
                }
                LRESULT(0)
            }
            WM_CLOSE => {
                if !ptr.is_null() {
                    (*ptr).closed = true;
                    let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
                }
                LRESULT(0)
            }
            WM_DESTROY => LRESULT(0),
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn handle_unblock_pin(hwnd: HWND, st: &mut PukDialogState) {
    let puk = unsafe { read_hwnd_zeroizing(st.unblock_puk) };
    let new_pin = unsafe { read_hwnd_zeroizing(st.unblock_new_pin) };
    let confirm_pin = unsafe { read_hwnd_zeroizing(st.unblock_confirm_pin) };

    if !valid_puk(&puk) {
        unsafe {
            set_lbl(
                st.status_lbl,
                "PUK must be 6-8 printable ASCII characters (factory default: 12345678).",
            );
        }
        return;
    }
    if !valid_pin(&new_pin) {
        unsafe {
            set_lbl(st.status_lbl, "New PIV PIN must be 6-8 ASCII digits.");
        }
        return;
    }
    if !constant_time_eq(new_pin.as_bytes(), confirm_pin.as_bytes()) {
        unsafe {
            set_lbl(
                st.status_lbl,
                "New PIV PIN and confirmation PIN do not match.",
            );
        }
        return;
    }

    match unblock_card_pin(None, None, puk.as_bytes(), new_pin.as_bytes()) {
        Ok(fp_opt) => {
            if let Some(fp) = fp_opt {
                let _ = clear_last_attempt_cooldown(&fp);
            }
            unsafe {
                scrub_hwnd(st.unblock_puk);
                scrub_hwnd(st.unblock_new_pin);
                scrub_hwnd(st.unblock_confirm_pin);
                set_lbl(
                    st.status_lbl,
                    "Success: PIV PIN unblocked and retry counter reset to 3.",
                );
                let _ = MessageBoxW(
                    Some(hwnd),
                    w!("The smart card PIV PIN was unblocked and its retry counter has been restored to 3.\r\n\r\nYour existing Windows vault remains valid with the new PIN."),
                    w!("PIN Unblocked"),
                    MB_OK | MB_ICONINFORMATION,
                );
            }
            st.log.push_str(
                "PIN Unblock: succeeded (retry counter reset to 3; existing vault remains valid).\r\n",
            );
        }
        Err(err) => {
            let msg = format_puk_error(&err);
            unsafe {
                scrub_hwnd(st.unblock_puk);
                set_lbl(st.status_lbl, &msg);
                let wide = to_wide(&msg);
                let _ = MessageBoxW(
                    Some(hwnd),
                    PCWSTR(wide.as_ptr()),
                    w!("PIN Unblock Failed"),
                    MB_OK | MB_ICONERROR,
                );
            }
        }
    }
}

unsafe fn handle_change_puk(hwnd: HWND, st: &mut PukDialogState) {
    let cur_puk = unsafe { read_hwnd_zeroizing(st.chg_cur_puk) };
    let new_puk = unsafe { read_hwnd_zeroizing(st.chg_new_puk) };
    let confirm_puk = unsafe { read_hwnd_zeroizing(st.chg_confirm_puk) };

    if !valid_puk(&cur_puk) || !valid_puk(&new_puk) {
        unsafe {
            set_lbl(
                st.status_lbl,
                "Both Current PUK and New PUK must be 6-8 printable ASCII characters.",
            );
        }
        return;
    }
    if !constant_time_eq(new_puk.as_bytes(), confirm_puk.as_bytes()) {
        unsafe {
            set_lbl(st.status_lbl, "New PUK and confirmation PUK do not match.");
        }
        return;
    }

    let confirm = unsafe {
        MessageBoxW(
            Some(hwnd),
            w!("Make sure you have written down the new PUK offline before proceeding!\r\n\r\nIf you forget both your PIN and your PUK, the PIV applet on the smart card will have to be wiped.\r\n\r\nProceed with changing the card PUK?"),
            w!("Confirm Change Card PUK"),
            MB_YESNO | MB_ICONWARNING,
        )
    };
    if confirm.0 != 6 {
        return;
    }

    match change_card_puk(None, cur_puk.as_bytes(), new_puk.as_bytes()) {
        Ok(()) => {
            unsafe {
                scrub_hwnd(st.chg_cur_puk);
                scrub_hwnd(st.chg_new_puk);
                scrub_hwnd(st.chg_confirm_puk);
                set_lbl(st.status_lbl, "Success: PIV card PUK updated.");
                let _ = MessageBoxW(
                    Some(hwnd),
                    w!("The smart card PUK has been updated. Keep your new PUK stored safely offline."),
                    w!("Card PUK Updated"),
                    MB_OK | MB_ICONINFORMATION,
                );
            }
            st.log
                .push_str("Change PUK: succeeded (custom PUK active on card).\r\n");
        }
        Err(err) => {
            let msg = format_puk_error(&err);
            unsafe {
                scrub_hwnd(st.chg_cur_puk);
                set_lbl(st.status_lbl, &msg);
                let wide = to_wide(&msg);
                let _ = MessageBoxW(
                    Some(hwnd),
                    PCWSTR(wide.as_ptr()),
                    w!("Change PUK Failed"),
                    MB_OK | MB_ICONERROR,
                );
            }
        }
    }
}
