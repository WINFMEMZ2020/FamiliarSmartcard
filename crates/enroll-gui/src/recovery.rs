//! Modal Win32 Recovery Sheet confirmation dialog and optional GDI direct printer.
//!
//! Security rules:
//! - Displayed BEFORE `NetUserSetInfo` modifies the real OS password.
//! - Never offers `.txt` or `.pdf` file export.
//! - Requires the user to type the last 6 non-hyphen characters of the generated
//!   password and check the offline-storage confirmation checkbox.

#![deny(unsafe_op_in_unsafe_fn)]

use scard_core::crypto::verify_recovery_tail;
use std::ffi::c_void;
use std::mem::size_of;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    DeleteDC, GetDeviceCaps, GetStockObject, TextOutW, ANSI_FIXED_FONT, COLOR_WINDOW,
    DEFAULT_GUI_FONT, HBRUSH, HDC, HFONT, LOGPIXELSY,
};
use windows::Win32::Storage::Xps::{EndDoc, EndPage, StartDocW, StartPage, DOCINFOW};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::Dialogs::{
    PrintDlgW, PD_NOPAGENUMS, PD_NOSELECTION, PD_RETURNDC, PD_USEDEVMODECOPIESANDCOLLATE, PRINTDLGW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, IsWindow, LoadCursorW, MessageBoxW,
    RegisterClassW, SendMessageW, SetForegroundWindow, SetWindowLongPtrW, SetWindowTextW,
    ShowWindow, TranslateMessage, BM_GETCHECK, BS_AUTOCHECKBOX, CW_USEDEFAULT, ES_AUTOVSCROLL,
    ES_MULTILINE, ES_READONLY, GWLP_USERDATA, HMENU, IDC_ARROW, MB_ICONINFORMATION, MB_ICONWARNING,
    MB_OK, MB_YESNO, MSG, SW_SHOW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_DESTROY,
    WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_POPUP, WS_SYSMENU, WS_TABSTOP,
    WS_VISIBLE,
};
use zeroize::Zeroizing;

const ID_PRINT: usize = 2001;
const ID_CONFIRM: usize = 2002;
const ID_CANCEL: usize = 2003;
const ID_CHECKBOX: usize = 2004;

const BST_CHECKED: usize = 1;

pub struct RecoverySheet<'a> {
    pub computer: &'a str,
    pub domain: &'a str,
    pub username: &'a str,
    pub sid: &'a str,
    pub card_name: &'a str,
    pub card_fingerprint_hex: &'a str,
    pub password: &'a str,
    pub created_utc_unix: u64,
}

struct ModalState {
    expected_password: Zeroizing<String>,
    printable_lines: Vec<Zeroizing<String>>,
    pw_box: HWND,
    tail_edit: HWND,
    checkbox: HWND,
    confirmed: bool,
    closed: bool,
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn scrub_hwnd_text(hwnd: HWND) {
    if !hwnd.0.is_null() {
        let mask = w!("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        let empty = w!("");
        // SAFETY: Valid child Edit control handle.
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

/// Show a modal recovery-sheet confirmation dialog.
/// Returns `true` ONLY if the user typed the last 6 non-hyphen characters and
/// checked the offline storage confirmation checkbox.
pub fn confirm_recovery_sheet(parent: HWND, sheet: &RecoverySheet<'_>) -> bool {
    let summary_text = format!(
        "Computer:        {}\r\n\
         Local Account:   {}\\{}\r\n\
         Account SID:     {}\r\n\
         RS-Key Card:     {}\r\n\
         9D Fingerprint:  {}\r\n\
         Generated (UTC): {} (Unix epoch)",
        sheet.computer,
        sheet.domain,
        sheet.username,
        sheet.sid,
        sheet.card_name,
        sheet.card_fingerprint_hex,
        sheet.created_utc_unix
    );

    let printable_lines = vec![
        Zeroizing::new("FAMILIARSMARTCARD EMERGENCY RECOVERY SHEET (KEEP OFFLINE)".into()),
        Zeroizing::new("==========================================================".into()),
        Zeroizing::new(String::new()),
        Zeroizing::new(format!("Computer:        {}", sheet.computer)),
        Zeroizing::new(format!(
            "Local Account:   {}\\{}",
            sheet.domain, sheet.username
        )),
        Zeroizing::new(format!("Account SID:     {}", sheet.sid)),
        Zeroizing::new(format!("RS-Key Card:     {}", sheet.card_name)),
        Zeroizing::new(format!("9D Fingerprint:  {}", sheet.card_fingerprint_hex)),
        Zeroizing::new(format!(
            "Generated (UTC): {} (Unix seconds)",
            sheet.created_utc_unix
        )),
        Zeroizing::new(String::new()),
        Zeroizing::new(
            "Windows Recovery Password (enter WITHOUT hyphens? NO — include hyphens!):".into(),
        ),
        Zeroizing::new(format!("  {}", sheet.password)),
        Zeroizing::new(String::new()),
        Zeroizing::new("Note: Include the hyphens (-) exactly as printed when signing in".into()),
        Zeroizing::new("with the native Windows password option.".into()),
    ];

    unsafe {
        let Ok(instance) = GetModuleHandleW(None) else {
            return false;
        };
        let hinstance = windows::Win32::Foundation::HINSTANCE(instance.0);
        let class_name = w!("FamiliarRecoveryModalClass");

        let wc = WNDCLASSW {
            lpfnWndProc: Some(modal_wndproc),
            hInstance: hinstance,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as *mut c_void),
            lpszClassName: class_name,
            ..Default::default()
        };
        let _ = RegisterClassW(&wc);

        let _ = EnableWindow(parent, false);

        let title = to_wide("Step 2 of 2: Verify Offline Recovery Sheet");
        let Ok(modal) = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            PCWSTR(title.as_ptr()),
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            720,
            510,
            Some(parent),
            None,
            Some(hinstance),
            None,
        ) else {
            let _ = EnableWindow(parent, true);
            return false;
        };

        let ui_font = HFONT(GetStockObject(DEFAULT_GUI_FONT).0);
        let mono_font = HFONT(GetStockObject(ANSI_FIXED_FONT).0);

        let warn = make_child(
            modal,
            w!("STATIC"),
            "WRITE DOWN OR PRINT THIS PASSWORD NOW. Your Windows password has NOT been changed yet. \
             Never save this password to a local file. Include the hyphens (-) if signing in with Windows password.",
            20,
            16,
            665,
            40,
            WINDOW_STYLE(0),
            0,
        );
        apply_font(warn, ui_font);

        let info_box = make_child(
            modal,
            w!("EDIT"),
            &summary_text,
            20,
            62,
            665,
            116,
            WS_BORDER
                | WINDOW_STYLE(ES_MULTILINE as u32 | ES_READONLY as u32 | ES_AUTOVSCROLL as u32),
            0,
        );
        apply_font(info_box, mono_font);

        let pw_label = make_child(
            modal,
            w!("STATIC"),
            "Generated 36-character recovery password (include hyphens when signing in):",
            20,
            188,
            665,
            20,
            WINDOW_STYLE(0),
            0,
        );
        apply_font(pw_label, ui_font);

        let pw_box = make_child(
            modal,
            w!("EDIT"),
            sheet.password,
            20,
            212,
            665,
            34,
            WS_BORDER | WINDOW_STYLE(ES_READONLY as u32),
            0,
        );
        apply_font(pw_box, mono_font);

        let print_btn = make_child(
            modal,
            w!("BUTTON"),
            "Print recovery sheet...",
            20,
            256,
            190,
            30,
            WS_TABSTOP,
            ID_PRINT,
        );
        apply_font(print_btn, ui_font);

        let tail_label = make_child(
            modal,
            w!("STATIC"),
            "Type the LAST 6 characters of the password above to prove you recorded it:",
            20,
            302,
            500,
            22,
            WINDOW_STYLE(0),
            0,
        );
        apply_font(tail_label, ui_font);

        let tail_edit = make_child(
            modal,
            w!("EDIT"),
            "",
            525,
            299,
            160,
            26,
            WS_BORDER | WS_TABSTOP,
            0,
        );
        apply_font(tail_edit, mono_font);

        let checkbox = make_child(
            modal,
            w!("BUTTON"),
            "I stored this recovery sheet offline and kept native password sign-in enabled.",
            20,
            340,
            665,
            26,
            WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
            ID_CHECKBOX,
        );
        apply_font(checkbox, ui_font);

        let confirm_btn = make_child(
            modal,
            w!("BUTTON"),
            "Confirm & Rotate Windows Password",
            20,
            390,
            290,
            40,
            WS_TABSTOP,
            ID_CONFIRM,
        );
        apply_font(confirm_btn, ui_font);

        let cancel_btn = make_child(
            modal,
            w!("BUTTON"),
            "Cancel (Keep Existing Password)",
            330,
            390,
            250,
            40,
            WS_TABSTOP,
            ID_CANCEL,
        );
        apply_font(cancel_btn, ui_font);

        let state = Box::new(ModalState {
            expected_password: Zeroizing::new(sheet.password.to_string()),
            printable_lines,
            pw_box,
            tail_edit,
            checkbox,
            confirmed: false,
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

        let confirmed = (*state_ptr).confirmed;
        if IsWindow(Some(modal)).as_bool() {
            scrub_hwnd_text((*state_ptr).pw_box);
            scrub_hwnd_text((*state_ptr).tail_edit);
            SetWindowLongPtrW(modal, GWLP_USERDATA, 0);
            let _ = DestroyWindow(modal);
        }
        drop(Box::from_raw(state_ptr));

        let _ = EnableWindow(parent, true);
        let _ = SetForegroundWindow(parent);
        confirmed
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
    extra_style: WINDOW_STYLE,
    id: usize,
) -> HWND {
    let wide = to_wide(text);
    let menu = if id == 0 {
        None
    } else {
        Some(HMENU(id as *mut c_void))
    };
    // SAFETY: Creates standard Win32 child control.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            PCWSTR(wide.as_ptr()),
            WS_CHILD | WS_VISIBLE | extra_style,
            x,
            y,
            w,
            h,
            Some(parent),
            menu,
            None,
            None,
        )
        .unwrap_or_default()
    }
}

unsafe fn apply_font(hwnd: HWND, font: HFONT) {
    // SAFETY: Standard `WM_SETFONT` dispatch.
    unsafe {
        let _ = SendMessageW(
            hwnd,
            WM_SETFONT,
            Some(WPARAM(font.0 as usize)),
            Some(LPARAM(1)),
        );
    }
}

extern "system" fn modal_wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: Win32 window procedure for the recovery modal dialog.
    unsafe {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut ModalState;
        match msg {
            WM_COMMAND if !ptr.is_null() => {
                let st = &mut *ptr;
                let id = wparam.0 & 0xFFFF;
                match id {
                    ID_PRINT => {
                        print_recovery_sheet(hwnd, &st.printable_lines);
                    }
                    ID_CONFIRM => {
                        let typed = read_hwnd_zeroizing(st.tail_edit);
                        if !verify_recovery_tail(&st.expected_password, &typed) {
                            let _ = MessageBoxW(
                                Some(hwnd),
                                w!("The last 6 characters do not match the recovery password. Please check carefully."),
                                w!("Verification Failed"),
                                MB_OK | MB_ICONWARNING,
                            );
                            return LRESULT(0);
                        }
                        let checked = SendMessageW(
                            st.checkbox,
                            BM_GETCHECK,
                            Some(WPARAM(0)),
                            Some(LPARAM(0)),
                        )
                        .0 as usize
                            == BST_CHECKED;
                        if !checked {
                            let _ = MessageBoxW(
                                Some(hwnd),
                                w!("Please check the confirmation box after storing the recovery sheet offline."),
                                w!("Confirmation Required"),
                                MB_OK | MB_ICONWARNING,
                            );
                            return LRESULT(0);
                        }
                        scrub_hwnd_text(st.pw_box);
                        scrub_hwnd_text(st.tail_edit);
                        st.confirmed = true;
                        st.closed = true;
                    }
                    ID_CANCEL => {
                        scrub_hwnd_text(st.pw_box);
                        scrub_hwnd_text(st.tail_edit);
                        st.confirmed = false;
                        st.closed = true;
                    }
                    _ => {}
                }
                LRESULT(0)
            }
            WM_CLOSE => {
                if !ptr.is_null() {
                    let st = &mut *ptr;
                    scrub_hwnd_text(st.pw_box);
                    scrub_hwnd_text(st.tail_edit);
                    st.confirmed = false;
                    st.closed = true;
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                if !ptr.is_null() {
                    (*ptr).closed = true;
                }
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn print_recovery_sheet(hwnd: HWND, lines: &[Zeroizing<String>]) {
    // SAFETY: Standard Win32 MessageBox prompt warning about print spoolers and PDF printers.
    let proceed = unsafe {
        MessageBoxW(
            Some(hwnd),
            w!("Print directly to a physical printer only.\r\n\r\nDo NOT select 'Microsoft Print to PDF' or save to disk, and be aware that Windows Print Spooler may temporarily cache print jobs on disk.\r\n\r\nContinue to printer selection?"),
            w!("Print Spooler Security Notice"),
            MB_YESNO | MB_ICONWARNING,
        )
    };
    if proceed.0 != 6 {
        // IDYES == 6
        return;
    }

    let mut pd = PRINTDLGW {
        lStructSize: size_of::<PRINTDLGW>() as u32,
        hwndOwner: hwnd,
        Flags: PD_RETURNDC | PD_NOPAGENUMS | PD_NOSELECTION | PD_USEDEVMODECOPIESANDCOLLATE,
        nCopies: 1,
        ..Default::default()
    };

    // SAFETY: Displays standard Win32 Print Dialog.
    if !unsafe { PrintDlgW(&mut pd) }.as_bool() || pd.hDC.is_invalid() {
        return;
    }
    let hdc: HDC = pd.hDC;

    let doc_name = to_wide("FamiliarSmartcard Recovery Sheet");
    let di = DOCINFOW {
        cbSize: size_of::<DOCINFOW>() as i32,
        lpszDocName: PCWSTR(doc_name.as_ptr()),
        ..Default::default()
    };

    // SAFETY: Prints lines to `hdc` and releases the printer DC.
    unsafe {
        if StartDocW(hdc, &di) > 0 {
            if StartPage(hdc) > 0 {
                let dpi_y = GetDeviceCaps(Some(hdc), LOGPIXELSY).max(72);
                let line_step = (dpi_y * 14) / 72;
                let margin_x = (dpi_y * 3) / 4;
                let mut y = (dpi_y * 3) / 4;

                for line in lines {
                    let wide: Zeroizing<Vec<u16>> = Zeroizing::new(line.encode_utf16().collect());
                    let _ = TextOutW(hdc, margin_x, y, &wide);
                    y += line_step;
                }
                let _ = EndPage(hdc);
            }
            let _ = EndDoc(hdc);
            let _ = MessageBoxW(
                Some(hwnd),
                w!("Recovery sheet sent to printer. Verify the physical printout before confirming."),
                w!("FamiliarSmartcard"),
                MB_OK | MB_ICONINFORMATION,
            );
        }
        let _ = DeleteDC(hdc);
    }
}
