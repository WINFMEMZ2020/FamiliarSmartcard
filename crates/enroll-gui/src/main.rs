//! Native Win32 enrollment and diagnostics GUI.
//!
//! All user-visible strings are English by project policy. The initial flow
//! binds the current Windows password to the PIV 9D key without changing the
//! account password; a later two-phase flow will add random-password rotation.

use std::ffi::c_void;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetStockObject, COLOR_WINDOW, DEFAULT_GUI_FONT, HBRUSH, HFONT,
};
use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowLongPtrW,
    GetWindowTextLengthW, GetWindowTextW, LoadCursorW, LoadIconW, PostQuitMessage, RegisterClassW,
    SendMessageW, SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage, CW_USEDEFAULT,
    ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, GWLP_USERDATA, HMENU, IDC_ARROW, IDI_APPLICATION,
    MSG, SW_SHOW, WINDOW_EX_STYLE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_SETFONT, WNDCLASSW,
    WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
};
use zeroize::Zeroizing;

const ID_PROBE: usize = 1001;
const ID_CLEAR: usize = 1002;
const ID_BIND: usize = 1003;
const ID_SELFTEST: usize = 1004;

const WINDOW_TITLE: &str = "FamiliarSmartcard Setup and Diagnostics";
const EM_SETPASSWORDCHAR: u32 = 0x00CC;
const PASSWORD_CHAR: usize = 0x25CF; // bullet

struct AppState {
    output: HWND,
    pin: HWND,
    password: HWND,
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
            820,
            660,
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
                    ID_BIND => bind_account(hwnd),
                    ID_SELFTEST => self_test(hwnd),
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
                let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState;
                if !pointer.is_null() {
                    drop(Box::from_raw(pointer));
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn create_controls(hwnd: HWND) {
    let font = HFONT(GetStockObject(DEFAULT_GUI_FONT).0);

    let title = create_control(
        hwnd,
        w!("STATIC"),
        "RS-Key / PIV enrollment and diagnostics",
        20,
        16,
        600,
        24,
        0,
    );
    set_font(title, font);

    let pin_label = create_control(
        hwnd,
        w!("STATIC"),
        "PIV PIN (6-8 digits)",
        20,
        52,
        180,
        22,
        0,
    );
    set_font(pin_label, font);
    let pin = create_control(hwnd, w!("EDIT"), "", 210, 50, 180, 24, 0);
    let _ = SendMessageW(
        pin,
        EM_SETPASSWORDCHAR,
        Some(WPARAM(PASSWORD_CHAR)),
        Some(LPARAM(0)),
    );
    set_font(pin, font);

    let password_label = create_control(hwnd, w!("STATIC"), "Windows password", 20, 86, 180, 22, 0);
    set_font(password_label, font);
    let password = create_control(hwnd, w!("EDIT"), "", 210, 84, 360, 24, 0);
    let _ = SendMessageW(
        password,
        EM_SETPASSWORDCHAR,
        Some(WPARAM(PASSWORD_CHAR)),
        Some(LPARAM(0)),
    );
    set_font(password, font);

    let probe = create_control(
        hwnd,
        w!("BUTTON"),
        "Probe card",
        20,
        126,
        130,
        32,
        ID_PROBE as isize,
    );
    set_font(probe, font);
    let bind = create_control(
        hwnd,
        w!("BUTTON"),
        "Bind current account",
        160,
        126,
        190,
        32,
        ID_BIND as isize,
    );
    set_font(bind, font);
    let selftest = create_control(
        hwnd,
        w!("BUTTON"),
        "Self-test",
        360,
        126,
        120,
        32,
        ID_SELFTEST as isize,
    );
    set_font(selftest, font);
    let clear = create_control(
        hwnd,
        w!("BUTTON"),
        "Clear output",
        490,
        126,
        130,
        32,
        ID_CLEAR as isize,
    );
    set_font(clear, font);

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
        176,
        760,
        430,
        Some(hwnd),
        None,
        None,
        None,
    )
    .unwrap_or_default();
    set_font(output, font);

    let state = Box::new(AppState {
        output,
        pin,
        password,
    });
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
        WS_CHILD | WS_VISIBLE | WS_BORDER,
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

unsafe fn set_font(hwnd: HWND, font: HFONT) {
    let _ = SendMessageW(
        hwnd,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );
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

    set_output(state.output, &text);
}

unsafe fn bind_account(hwnd: HWND) {
    let Some(state) = state(hwnd) else {
        return;
    };

    let pin = read_edit(state.pin);
    let password = read_edit(state.password);
    if !valid_pin(&pin) {
        set_output(state.output, "PIV PIN must be 6-8 digits.\r\n");
        return;
    }
    if password.is_empty() {
        set_output(state.output, "Enter the Windows password.\r\n");
        return;
    }

    let user = match scard_core::current_user() {
        Ok(user) => user,
        Err(error) => {
            set_output(state.output, &format!("Account lookup failed: {error}\r\n"));
            return;
        }
    };

    if let Err(error) = validate_windows_password(&user, &password) {
        set_output(
            state.output,
            &format!(
                "Windows password validation failed: {error}\r\n\
                 No vault was written and the account password was not changed.\r\n"
            ),
        );
        return;
    }

    let password_last_set = scard_core::account::password_last_set(&user.username).unwrap_or(0);

    let result = match scard_core::enroll(
        None,
        &password,
        &user.sid,
        &user.username,
        &user.computer,
        password_last_set,
    ) {
        Ok(result) => result,
        Err(error) => {
            set_output(state.output, &format!("Enrollment failed: {error}\r\n"));
            return;
        }
    };

    if let Err(error) = scard_core::storage::write_vault(&user.sid, &result.vault) {
        set_output(state.output, &format!("Vault write failed: {error}\r\n"));
        return;
    }

    let fingerprint = hex::encode(result.card_pub_fingerprint);
    set_output(
        state.output,
        &format!(
            "Bound account: {}\\{}\r\nSID: {}\r\nCard: {}\r\nFingerprint: {}\r\n\
             Vault written. The Windows account password was not changed.\r\n",
            user.domain,
            user.username,
            user.sid,
            result.card_name.as_deref().unwrap_or("(unknown)"),
            fingerprint
        ),
    );
}

unsafe fn self_test(hwnd: HWND) {
    let Some(state) = state(hwnd) else {
        return;
    };

    let pin = read_edit(state.pin);
    let expected_password = read_edit(state.password);
    if !valid_pin(&pin) {
        set_output(state.output, "PIV PIN must be 6-8 digits.\r\n");
        return;
    }

    let user = match scard_core::current_user() {
        Ok(user) => user,
        Err(error) => {
            set_output(state.output, &format!("Account lookup failed: {error}\r\n"));
            return;
        }
    };

    let vault = match scard_core::storage::read_vault(&user.sid) {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            set_output(state.output, "No vault is bound to this account.\r\n");
            return;
        }
        Err(error) => {
            set_output(state.output, &format!("Vault read failed: {error}\r\n"));
            return;
        }
    };

    let mut pin_bytes = Zeroizing::new(pin.as_bytes().to_vec());
    let decrypted = match scard_core::unlock(
        vault,
        &user.sid,
        &user.username,
        &user.computer,
        None,
        &mut pin_bytes,
    ) {
        Ok(password) => password,
        Err(error) => {
            set_output(state.output, &format!("Self-test failed: {error}\r\n"));
            return;
        }
    };

    if !expected_password.is_empty() && decrypted.as_str() != expected_password.as_str() {
        set_output(
            state.output,
            "Self-test failed: decrypted password does not match the entered password.\r\n",
        );
        return;
    }

    set_output(
        state.output,
        "Self-test succeeded: the vault was decrypted by the RS-Key.\r\n",
    );
}

fn validate_windows_password(user: &scard_core::UserInfo, password: &str) -> Result<(), String> {
    let username: Vec<u16> = user
        .username
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let domain: Vec<u16> = user
        .domain
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let password_w: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();
    let mut token = HANDLE::default();

    let result = unsafe {
        LogonUserW(
            PCWSTR(username.as_ptr()),
            PCWSTR(domain.as_ptr()),
            PCWSTR(password_w.as_ptr()),
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    if let Err(error) = result {
        return Err(error.message());
    }
    unsafe {
        let _ = CloseHandle(token);
    }
    Ok(())
}

unsafe fn read_edit(hwnd: HWND) -> Zeroizing<String> {
    let length = GetWindowTextLengthW(hwnd);
    if length <= 0 {
        return Zeroizing::new(String::new());
    }
    let mut buffer = vec![0u16; length as usize + 1];
    let copied = GetWindowTextW(hwnd, &mut buffer);
    buffer.truncate(copied.max(0) as usize);
    Zeroizing::new(String::from_utf16_lossy(&buffer))
}

fn valid_pin(pin: &str) -> bool {
    (6..=8).contains(&pin.len()) && pin.chars().all(|c| c.is_ascii_digit())
}

unsafe fn set_output(output: HWND, text: &str) {
    let wide = to_wide(text);
    let _ = SetWindowTextW(output, PCWSTR(wide.as_ptr()));
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
