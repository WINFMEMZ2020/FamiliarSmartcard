//! Minimal native Win32 enrollment/diagnostics GUI.
//!
//! Stage 1: card probe, reader/ATR/slot metadata. Enrollment and vault
//! self-test will be added after the CP/provisioning path is stable.

use std::ffi::c_void;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetStockObject, COLOR_WINDOW, DEFAULT_GUI_FONT, HBRUSH, HFONT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowLongPtrW, LoadCursorW,
    LoadIconW, PostQuitMessage, RegisterClassW, SendMessageW, SetWindowLongPtrW, SetWindowTextW,
    ShowWindow, TranslateMessage, CW_USEDEFAULT, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY,
    GWLP_USERDATA, HMENU, IDC_ARROW, IDI_APPLICATION, MSG, SW_SHOW, WINDOW_EX_STYLE, WM_COMMAND,
    WM_CREATE, WM_DESTROY, WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW,
    WS_VISIBLE, WS_VSCROLL,
};

const ID_PROBE: usize = 1001;
const ID_CLEAR: usize = 1002;

const WINDOW_TITLE: &str = "FamiliarSmartcard Setup and Diagnostics";

struct AppState {
    output: HWND,
}

fn main() -> windows::core::Result<()> {
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let hinstance = HINSTANCE(instance.0);

        let class_name = w!("FamiliarSmartcardGui");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            hIcon: LoadIconW(None, IDI_APPLICATION)?,
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as *mut c_void),
            lpszClassName: class_name,
            ..Default::default()
        };
        if RegisterClassW(&wc) == 0 {
            return Err(windows::core::Error::from_thread());
        }

        let title = to_wide(WINDOW_TITLE);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            PCWSTR(title.as_ptr()),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            760,
            560,
            None,
            None,
            Some(hinstance),
            None,
        )?;

        let _ = ShowWindow(hwnd, SW_SHOW);

        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    Ok(())
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                create_controls(hwnd);
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = (wparam.0 & 0xFFFF) as usize;
                match id {
                    ID_PROBE => probe_and_show(hwnd),
                    ID_CLEAR => {
                        if let Some(state) = state(hwnd) {
                            let _ = SetWindowTextW(state.output, PCWSTR::null());
                        }
                    }
                    _ => {}
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn create_controls(hwnd: HWND) {
    let font = HFONT(GetStockObject(DEFAULT_GUI_FONT).0);

    let label = create_control(
        hwnd,
        w!("STATIC"),
        "RS-Key / PIV Diagnostics",
        20,
        16,
        400,
        24,
        0,
    );
    let _ = SendMessageW(
        label,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );

    let probe = create_control(
        hwnd,
        w!("BUTTON"),
        "Probe card",
        20,
        52,
        130,
        32,
        ID_PROBE as isize,
    );
    let _ = SendMessageW(
        probe,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );

    let clear = create_control(
        hwnd,
        w!("BUTTON"),
        "Clear output",
        160,
        52,
        130,
        32,
        ID_CLEAR as isize,
    );
    let _ = SendMessageW(
        clear,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );

    let style = WS_CHILD
        | WS_VISIBLE
        | WS_BORDER
        | WS_VSCROLL
        | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(
            ES_MULTILINE as u32 | ES_AUTOVSCROLL as u32 | ES_READONLY as u32,
        );

    let output = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        w!("EDIT"),
        PCWSTR::null(),
        style,
        20,
        100,
        700,
        410,
        Some(hwnd),
        None,
        None,
        None,
    )
    .unwrap_or_default();

    let _ = SendMessageW(
        output,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );

    let state = Box::new(AppState { output });
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);
}

unsafe fn create_control(
    parent: HWND,
    class: PCWSTR,
    text: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    id: isize,
) -> HWND {
    let text = to_wide(text);
    let menu = if id == 0 {
        None
    } else {
        Some(HMENU(id as *mut c_void))
    };
    CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class,
        PCWSTR(text.as_ptr()),
        WS_CHILD | WS_VISIBLE,
        x,
        y,
        width,
        height,
        Some(parent),
        menu,
        None,
        None,
    )
    .unwrap_or_default()
}

unsafe fn state(hwnd: HWND) -> Option<&'static AppState> {
    let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const AppState;
    pointer.as_ref()
}

unsafe fn probe_and_show(hwnd: HWND) {
    let Some(state) = state(hwnd) else {
        return;
    };

    let text = match scard_core::probe_readers() {
        Ok(readers) if readers.is_empty() => "No smart card reader found.\r\n".to_string(),
        Ok(readers) => format_readers(&readers),
        Err(error) => format!("Probe failed: {error}\r\n"),
    };

    let wide = to_wide(&text);
    let _ = SetWindowTextW(state.output, PCWSTR(wide.as_ptr()));
}

fn format_readers(readers: &[scard_core::ReaderProbe]) -> String {
    let mut out = String::new();
    for reader in readers {
        out.push_str(&format!("Reader: {}\r\n", reader.reader));
        out.push_str(&format!("  ATR: {}\r\n", reader.atr_hex));
        if reader.piv_selected {
            out.push_str(&format!(
                "  PIV: selected, card: {}\r\n",
                reader.card_name.as_deref().unwrap_or("(unknown)")
            ));
            out.push_str(&format!(
                "  Algorithms: {}\r\n",
                hex::encode(&reader.algorithms)
            ));
        } else {
            out.push_str("  PIV: not selected\r\n");
        }
        if let Some(error) = &reader.error {
            out.push_str(&format!("  Error: {error}\r\n"));
        }
        for slot in &reader.slots {
            out.push_str(&format!(
                "  Slot 0x{:02X}: {}{}\r\n",
                slot.slot,
                if slot.has_key {
                    "key present"
                } else {
                    "no key"
                },
                if slot.metadata_hex.is_empty() {
                    String::new()
                } else {
                    format!(", metadata={}", slot.metadata_hex)
                }
            ));
        }
        out.push_str("\r\n");
    }
    out
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
