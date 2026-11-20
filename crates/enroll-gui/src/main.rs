//! Friendly native Win32 setup and diagnostics for FamiliarSmartcard.
//!
//! Double-clicking the executable requests elevation (UAC), auto-detects the
//! RS-Key, and the primary button performs the whole flow:
//! detect card -> validate password -> bind vault -> self-test -> register CP.
//!
//! All user-visible strings are English by project policy.

use std::ffi::c_void;
use std::mem::size_of;
use std::process::Command;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetStockObject, COLOR_WINDOW, DEFAULT_GUI_FONT, HBRUSH, HFONT,
};
use windows::Win32::Security::{
    GetTokenInformation, LogonUserW, TokenElevation, LOGON32_LOGON_NETWORK,
    LOGON32_PROVIDER_DEFAULT, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowLongPtrW,
    GetWindowTextLengthW, GetWindowTextW, LoadCursorW, LoadIconW, MessageBoxW, PostQuitMessage,
    RegisterClassW, SendMessageW, SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage,
    CW_USEDEFAULT, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, GWLP_USERDATA, HMENU, IDC_ARROW,
    IDI_APPLICATION, MB_ICONERROR, MB_OK, MSG, SW_SHOW, SW_SHOWNORMAL, WINDOW_EX_STYLE, WM_COMMAND,
    WM_CREATE, WM_DESTROY, WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW,
    WS_VISIBLE, WS_VSCROLL,
};
use zeroize::Zeroizing;

const ID_SETUP: usize = 1001;
const ID_PROBE: usize = 1002;
const ID_SELFTEST: usize = 1003;
const ID_REGISTER: usize = 1004;
const ID_CLEAR: usize = 1005;

const WINDOW_TITLE: &str = "FamiliarSmartcard";
const EM_SETPASSWORDCHAR: u32 = 0x00CC;
const PASSWORD_CHAR: usize = 0x25CF;

struct AppState {
    status: HWND,
    output: HWND,
    pin: HWND,
    password: HWND,
}

fn main() -> windows::core::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|argument| argument == "--probe") {
        return probe_cli();
    }
    if args.get(1).map(String::as_str) == Some("--card-selftest") {
        let pin = args.get(2).map(String::as_str).unwrap_or("123456");
        return card_selftest(pin);
    }

    if !is_elevated() {
        return relaunch_elevated();
    }

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
            860,
            700,
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

fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

fn relaunch_elevated() -> windows::core::Result<()> {
    let exe = std::env::current_exe().map_err(|error| {
        windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            format!("Cannot locate executable: {error}"),
        )
    })?;
    let exe_w = to_wide(&exe.to_string_lossy());
    let result = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize <= 32 {
        unsafe {
            let _ = MessageBoxW(
                None,
                w!("Administrator rights are required to bind the account and register the provider."),
                w!("FamiliarSmartcard"),
                MB_OK | MB_ICONERROR,
            );
        }
    }
    Ok(())
}

fn probe_cli() -> windows::core::Result<()> {
    match scard_core::probe_readers() {
        Ok(readers) if readers.is_empty() => println!("No smart card reader found."),
        Ok(readers) => print!("{}", format_readers(&readers)),
        Err(error) => {
            eprintln!("Probe failed: {error}");
            return Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ));
        }
    }
    Ok(())
}

fn card_selftest(pin: &str) -> windows::core::Result<()> {
    const TEST_PASSWORD: &str = "FamiliarSmartcard-SelfTest-Only";
    const TEST_SID: &str = "S-1-5-21-0";
    const TEST_USER: &str = "selftest";
    const TEST_COMPUTER: &str = "SELFTEST";

    let enrolled = scard_core::enroll(None, TEST_PASSWORD, TEST_SID, TEST_USER, TEST_COMPUTER, 0)
        .map_err(|error| {
        windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            format!("Enrollment self-test failed: {error}"),
        )
    })?;

    let mut pin_bytes = Zeroizing::new(pin.as_bytes().to_vec());
    let decrypted = scard_core::unlock(
        enrolled.vault,
        TEST_SID,
        TEST_USER,
        TEST_COMPUTER,
        None,
        &mut pin_bytes,
    )
    .map_err(|error| {
        windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            format!("Unlock self-test failed: {error}"),
        )
    })?;

    if decrypted.as_str() != TEST_PASSWORD {
        return Err(windows::core::Error::new(
            windows::Win32::Foundation::E_FAIL,
            "Card self-test decrypted an unexpected password.",
        ));
    }

    println!("Card self-test succeeded.");
    println!(
        "Fingerprint: {}",
        hex::encode(enrolled.card_pub_fingerprint)
    );
    println!(
        "Card: {}",
        enrolled.card_name.as_deref().unwrap_or("(unknown)")
    );
    Ok(())
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                create_controls(hwnd);
                auto_probe(hwnd);
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = (wparam.0 & 0xFFFF) as usize;
                match id {
                    ID_SETUP => setup_account(hwnd),
                    ID_PROBE => probe_and_show(hwnd),
                    ID_SELFTEST => self_test(hwnd),
                    ID_REGISTER => register_provider(hwnd),
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

    let title = create_control(hwnd, w!("STATIC"), "FamiliarSmartcard", 20, 16, 600, 26, 0);
    set_font(title, font);

    let subtitle = create_control(
        hwnd,
        w!("STATIC"),
        "Sign in with your RS-Key. Keep the native password as recovery.",
        20,
        44,
        760,
        22,
        0,
    );
    set_font(subtitle, font);

    let status = create_control(
        hwnd,
        w!("STATIC"),
        "Checking for RS-Key...",
        20,
        74,
        760,
        22,
        0,
    );
    set_font(status, font);

    let pin_label = create_control(
        hwnd,
        w!("STATIC"),
        "PIV PIN (6-8 digits)",
        20,
        108,
        180,
        22,
        0,
    );
    set_font(pin_label, font);
    let pin = create_control(hwnd, w!("EDIT"), "", 210, 106, 180, 24, 0);
    let _ = SendMessageW(
        pin,
        EM_SETPASSWORDCHAR,
        Some(WPARAM(PASSWORD_CHAR)),
        Some(LPARAM(0)),
    );
    set_font(pin, font);

    let password_label =
        create_control(hwnd, w!("STATIC"), "Windows password", 20, 142, 180, 22, 0);
    set_font(password_label, font);
    let password = create_control(hwnd, w!("EDIT"), "", 210, 140, 360, 24, 0);
    let _ = SendMessageW(
        password,
        EM_SETPASSWORDCHAR,
        Some(WPARAM(PASSWORD_CHAR)),
        Some(LPARAM(0)),
    );
    set_font(password, font);

    let setup = create_control(
        hwnd,
        w!("BUTTON"),
        "Set up this account",
        20,
        182,
        220,
        40,
        ID_SETUP as isize,
    );
    set_font(setup, font);
    let probe = create_control(
        hwnd,
        w!("BUTTON"),
        "Probe card",
        260,
        182,
        120,
        32,
        ID_PROBE as isize,
    );
    set_font(probe, font);
    let selftest = create_control(
        hwnd,
        w!("BUTTON"),
        "Self-test",
        390,
        182,
        110,
        32,
        ID_SELFTEST as isize,
    );
    set_font(selftest, font);
    let register = create_control(
        hwnd,
        w!("BUTTON"),
        "Register provider",
        510,
        182,
        150,
        32,
        ID_REGISTER as isize,
    );
    set_font(register, font);
    let clear = create_control(
        hwnd,
        w!("BUTTON"),
        "Clear output",
        670,
        182,
        110,
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
        236,
        800,
        410,
        Some(hwnd),
        None,
        None,
        None,
    )
    .unwrap_or_default();
    set_font(output, font);

    let state = Box::new(AppState {
        status,
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

fn key_present(readers: &[scard_core::ReaderProbe]) -> bool {
    readers.iter().any(|reader| {
        reader
            .slots
            .iter()
            .any(|slot| slot.slot == 0x9D && slot.has_key)
    })
}

unsafe fn set_status(hwnd: HWND, text: &str) {
    if let Some(state) = state(hwnd) {
        let wide = to_wide(text);
        let _ = SetWindowTextW(state.status, PCWSTR(wide.as_ptr()));
    }
}

unsafe fn auto_probe(hwnd: HWND) {
    match scard_core::probe_readers() {
        Ok(readers) if readers.is_empty() => {
            set_status(hwnd, "No RS-Key detected. Insert it and click Probe card.");
        }
        Ok(readers) if key_present(&readers) => {
            set_status(hwnd, "RS-Key detected. PIV 9D key is ready.");
        }
        Ok(_) => {
            set_status(
                hwnd,
                "RS-Key detected, but PIV 9D has no key. Provision the card first.",
            );
        }
        Err(error) => {
            set_status(hwnd, &format!("Card probe failed: {error}"));
        }
    }
}

unsafe fn probe_and_show(hwnd: HWND) {
    let Some(state) = state(hwnd) else {
        return;
    };

    let (status, text) = match scard_core::probe_readers() {
        Ok(readers) if readers.is_empty() => (
            "No RS-Key detected.".to_string(),
            "No smart card reader found.\r\n".to_string(),
        ),
        Ok(readers) => {
            let status = if key_present(&readers) {
                "RS-Key detected. PIV 9D key is ready.".to_string()
            } else {
                "RS-Key detected, but PIV 9D has no key.".to_string()
            };
            (status, format_readers(&readers))
        }
        Err(error) => (
            format!("Card probe failed: {error}"),
            format!("Probe failed: {error}\r\n"),
        ),
    };

    let status_w = to_wide(&status);
    let _ = SetWindowTextW(state.status, PCWSTR(status_w.as_ptr()));
    let output_w = to_wide(&text);
    let _ = SetWindowTextW(state.output, PCWSTR(output_w.as_ptr()));
}

unsafe fn setup_account(hwnd: HWND) {
    let Some(state) = state(hwnd) else {
        return;
    };

    let pin = read_edit(state.pin);
    let password = read_edit(state.password);
    if !valid_pin(&pin) {
        set_status(hwnd, "PIV PIN must be 6-8 digits.");
        return;
    }
    if password.is_empty() {
        set_status(hwnd, "Enter the current Windows password.");
        return;
    }

    set_status(hwnd, "Detecting RS-Key...");
    let readers = match scard_core::probe_readers() {
        Ok(readers) => readers,
        Err(error) => {
            set_status(hwnd, &format!("Card probe failed: {error}"));
            return;
        }
    };
    if !key_present(&readers) {
        set_status(
            hwnd,
            "PIV 9D key not found. Provision the card before setup.",
        );
        return;
    }

    set_status(hwnd, "Resolving the interactive account...");
    let user = match scard_core::current_user() {
        Ok(user) => user,
        Err(error) => {
            set_status(hwnd, &format!("Account lookup failed: {error}"));
            return;
        }
    };

    set_status(hwnd, "Validating the Windows password...");
    if let Err(error) = validate_windows_password(&user, &password) {
        set_status(
            hwnd,
            &format!("Windows password validation failed: {error}"),
        );
        return;
    }

    set_status(hwnd, "Binding the vault to the RS-Key...");
    let password_last_set = match scard_core::account::password_last_set(&user.username) {
        Ok(value) => value,
        Err(error) => {
            set_status(hwnd, &format!("Password timestamp lookup failed: {error}"));
            return;
        }
    };

    let enrolled = match scard_core::enroll(
        None,
        &password,
        &user.sid,
        &user.username,
        &user.computer,
        password_last_set,
    ) {
        Ok(enrolled) => enrolled,
        Err(error) => {
            set_status(hwnd, &format!("Enrollment failed: {error}"));
            return;
        }
    };

    if let Err(error) = scard_core::storage::write_vault(&user.sid, &enrolled.vault) {
        set_status(hwnd, &format!("Vault write failed: {error}"));
        return;
    }

    set_status(hwnd, "Running the self-test...");
    if let Err(error) = self_test_internal(&pin, &password, &user) {
        set_status(hwnd, &format!("Self-test failed: {error}"));
        return;
    }

    set_status(hwnd, "Registering the sign-in provider...");
    let register_result = register_provider_internal();

    let fingerprint = hex::encode(enrolled.card_pub_fingerprint);
    let mut message = format!(
        "Setup complete.\r\n\
         Account: {}\\{}\r\n\
         SID: {}\r\n\
         Card: {}\r\n\
         Fingerprint: {}\r\n\
         Self-test: succeeded\r\n",
        user.domain,
        user.username,
        user.sid,
        enrolled.card_name.as_deref().unwrap_or("(unknown)"),
        fingerprint
    );
    let status = match register_result {
        Ok(output) => {
            message.push_str("Sign-in provider: registered.\r\n");
            if !output.trim().is_empty() {
                message.push_str(&output);
                message.push_str("\r\n");
            }
            "Setup complete. Lock the screen and sign in with RS-Key."
        }
        Err(error) => {
            message.push_str(&format!("Sign-in provider: not registered ({error}).\r\n"));
            "Account bound, but provider registration failed."
        }
    };

    let message_w = to_wide(&message);
    let _ = SetWindowTextW(state.output, PCWSTR(message_w.as_ptr()));
    set_status(hwnd, status);
    let _ = SetWindowTextW(state.password, PCWSTR::null());
    let _ = SetWindowTextW(state.pin, PCWSTR::null());
}

unsafe fn self_test(hwnd: HWND) {
    let Some(state) = state(hwnd) else {
        return;
    };
    let pin = read_edit(state.pin);
    let expected = read_edit(state.password);
    if !valid_pin(&pin) {
        set_status(hwnd, "PIV PIN must be 6-8 digits.");
        return;
    }

    let user = match scard_core::current_user() {
        Ok(user) => user,
        Err(error) => {
            set_status(hwnd, &format!("Account lookup failed: {error}"));
            return;
        }
    };

    match self_test_internal(&pin, &expected, &user) {
        Ok(()) => {
            set_status(hwnd, "Self-test succeeded: the RS-Key decrypted the vault.");
        }
        Err(error) => {
            set_status(hwnd, &format!("Self-test failed: {error}"));
        }
    }
}

fn self_test_internal(
    pin: &str,
    expected_password: &str,
    user: &scard_core::UserInfo,
) -> Result<(), String> {
    let vault = scard_core::storage::read_vault(&user.sid)
        .map_err(|error| format!("Vault read failed: {error}"))?
        .ok_or_else(|| "No vault is bound to this account.".to_string())?;

    let mut pin_bytes = Zeroizing::new(pin.as_bytes().to_vec());
    let decrypted = scard_core::unlock(
        vault,
        &user.sid,
        &user.username,
        &user.computer,
        None,
        &mut pin_bytes,
    )
    .map_err(|error| format!("Unlock failed: {error}"))?;

    if !expected_password.is_empty() && decrypted.as_str() != expected_password {
        return Err("Decrypted password does not match the entered password.".into());
    }
    Ok(())
}

unsafe fn register_provider(hwnd: HWND) {
    match register_provider_internal() {
        Ok(output) => {
            set_status(hwnd, "Sign-in provider registered.");
            if let Some(state) = state(hwnd) {
                let text = if output.trim().is_empty() {
                    "Sign-in provider registered.\r\n".to_string()
                } else {
                    output
                };
                let wide = to_wide(&text);
                let _ = SetWindowTextW(state.output, PCWSTR(wide.as_ptr()));
            }
        }
        Err(error) => {
            set_status(hwnd, &format!("Provider registration failed: {error}"));
        }
    }
}

fn register_provider_internal() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let directory = exe
        .parent()
        .ok_or_else(|| "Cannot determine the application directory.".to_string())?;
    let script = directory.join("register_cp.ps1");
    let dll = directory.join("cred_provider.dll");

    if !script.exists() {
        return Err(format!("{} was not found.", script.display()));
    }
    if !dll.exists() {
        return Err(format!("{} was not found.", dll.display()));
    }

    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(script.as_os_str())
        .arg("-DllPath")
        .arg(dll.as_os_str())
        .output()
        .map_err(|error| format!("Cannot start PowerShell: {error}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(format!(
            "register_cp.ps1 failed.\r\n{}\r\n{}",
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(stdout)
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
