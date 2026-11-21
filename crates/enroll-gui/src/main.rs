//! Native Win32 setup, two-phase recovery-password rotation, attestation
//! management, and diagnostics for FamiliarSmartcard.
//!
//! All user-visible strings (GUI and CLI) are strictly English per project policy.

#![deny(unsafe_op_in_unsafe_fn)]

mod installer;
mod puk_dialog;
mod recovery;

use recovery::{confirm_recovery_sheet, RecoverySheet};
use scard_core::account::{
    password_last_set, password_last_set_for_enrollment, rotate_local_password_and_disable_expiry,
    verify_local_workgroup_account, UserInfo,
};
use scard_core::crypto::generate_recovery_password;
use scard_core::enroll::{
    change_card_puk, enroll_with_options, repin_connected_card_attestation, unblock_card_pin,
    AttestationPolicy, EnrollOptions,
};
use scard_core::piv::{
    MgmtKeyMetadata, PinPukMetadata, ALG_3DES, ALG_AES_128, ALG_AES_192, ALG_AES_256,
    ORIGIN_GENERATED, ORIGIN_IMPORTED, PIN_POLICY_ALWAYS, PIN_POLICY_NEVER, PIN_POLICY_ONCE,
    TOUCH_POLICY_ALWAYS, TOUCH_POLICY_CACHED, TOUCH_POLICY_NEVER,
};
use scard_core::storage::{
    clear_card_auth_9e_pub, clear_last_attempt_cooldown, clear_pinned_f9, purge_vault_backup,
    read_card_auth_9e_pub, read_pinned_f9, read_vault, stage_pending_vault_with_backup,
    write_card_auth_9e_pub, write_touch_policy, write_vault,
};
use scard_core::{
    card_has_9d_key, parse_mgmt_key_hex, provision_card, CardProvisionOptions, VaultBlob,
};
use std::ffi::c_void;
use std::mem::size_of;
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
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowLongPtrW,
    GetWindowTextLengthW, GetWindowTextW, LoadCursorW, LoadIconW, MessageBoxW, PostMessageW,
    PostQuitMessage, RegisterClassW, SendMessageW, SetWindowLongPtrW, SetWindowTextW, ShowWindow,
    TranslateMessage, CW_USEDEFAULT, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, GWLP_USERDATA,
    HMENU, IDC_ARROW, IDI_APPLICATION, MB_ICONERROR, MB_ICONWARNING, MB_OK, MB_YESNO, MSG, SW_SHOW,
    SW_SHOWNORMAL, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_COMMAND, WM_CREATE, WM_DESTROY,
    WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE,
    WS_VSCROLL,
};
use zeroize::Zeroizing;

const ID_SETUP_ROTATE: usize = 1001;
const ID_REBIND_EXISTING: usize = 1002;
const ID_PROBE: usize = 1003;
const ID_SELFTEST: usize = 1004;
const ID_REPIN_ROOT: usize = 1005;
const ID_REGISTER: usize = 1006;
const ID_CLEAR: usize = 1007;
const ID_MANAGE_PUK: usize = 1008;
const ID_RADIO_KEEP_KEY: usize = 1009;
const ID_RADIO_TOUCH_CACHED: usize = 1010;
const ID_RADIO_TOUCH_ALWAYS: usize = 1011;
const ID_RADIO_TOUCH_NEVER: usize = 1012;
const ID_CHK_PROVISION_9E: usize = 1013;

const WM_WORKER_RESULT: u32 = WM_APP + 10;
const WM_WORKER_STATUS: u32 = WM_APP + 11;

const WINDOW_TITLE: &str = "Familiar Smartcard — Setup & Diagnostics";
const EM_SETPASSWORDCHAR: u32 = 0x00CC;
const PASSWORD_CHAR: usize = 0x25CF;
const BM_GETCHECK: u32 = 0x00F0;
const BM_SETCHECK: u32 = 0x00F1;
const BST_UNCHECKED: usize = 0;
const BST_CHECKED: usize = 1;
const STYLE_AUTOCHECKBOX: WINDOW_STYLE = WINDOW_STYLE(0x0003);
const STYLE_AUTORADIO: WINDOW_STYLE = WINDOW_STYLE(0x0009);
const STYLE_GROUP: WINDOW_STYLE = WINDOW_STYLE(0x0002_0000);

struct AppState {
    status: HWND,
    output: HWND,
    pin: HWND,
    password: HWND,
    radio_keep: HWND,
    radio_touch_cached: HWND,
    radio_touch_always: HWND,
    radio_touch_never: HWND,
    chk_9e: HWND,
    mgmt_cur: HWND,
    mgmt_new: HWND,
    buttons: [HWND; 8],
    user_touched_provision_mode: bool,
    busy: bool,
}

struct ProvisionPlan {
    touch_policy_9d: u8,
    provision_9e: bool,
    current_mgmt_hex: Zeroizing<String>,
    new_mgmt_hex: Zeroizing<String>,
}

struct PreparedRotation {
    user: UserInfo,
    new_password: Zeroizing<String>,
    dek: Zeroizing<[u8; 32]>,
    candidate_vault: VaultBlob,
    card_name: String,
    fingerprint_hex: String,
    f9_status: String,
    touch_policy: u8,
    pin_is_default: bool,
    puk_is_default: bool,
    card_auth_9e_pub: Option<Vec<u8>>,
    mgmt_rotated: bool,
}

enum WorkerOutcome {
    ProbeDone {
        status: String,
        output: Option<String>,
        piv_card_without_9d: bool,
    },
    SimpleDone {
        status: String,
        output: Option<String>,
        clear_secrets: bool,
        critical_modal_error: Option<String>,
    },
    RotationCandidateReady(Box<PreparedRotation>),
}

fn main() -> windows::core::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(flag) = args.get(1).map(String::as_str) {
        match flag {
            "--help" | "-h" => {
                print_cli_help();
                return Ok(());
            }
            "--probe" => return probe_cli(),
            "--card-selftest" => {
                let Some(pin) = args.get(2).map(String::as_str) else {
                    eprintln!("Usage: familiar-enroll.exe --card-selftest <PIN>\n");
                    return Err(windows::core::Error::from_hresult(
                        windows::Win32::Foundation::E_INVALIDARG,
                    ));
                };
                return card_selftest_cli(pin);
            }
            "--repin-attestation" => return repin_attestation_cli(),
            "--clear-attestation" => return clear_attestation_cli(),
            "--unblock-pin" => {
                let Some((puk, new_pin)) = args.get(2).zip(args.get(3)) else {
                    eprintln!("Usage: familiar-enroll.exe --unblock-pin <PUK> <NEW-PIN>\n");
                    return Err(windows::core::Error::from_hresult(
                        windows::Win32::Foundation::E_INVALIDARG,
                    ));
                };
                return unblock_pin_cli(puk, new_pin);
            }
            "--change-puk" => {
                let Some((cur_puk, new_puk)) = args.get(2).zip(args.get(3)) else {
                    eprintln!("Usage: familiar-enroll.exe --change-puk <CURRENT-PUK> <NEW-PUK>\n");
                    return Err(windows::core::Error::from_hresult(
                        windows::Win32::Foundation::E_INVALIDARG,
                    ));
                };
                return change_puk_cli(cur_puk, new_puk);
            }
            "--provision-card" => {
                return provision_card_cli(&args[2..]);
            }
            _ => {
                eprintln!("Unknown option: {flag}\n");
                print_cli_help();
                return Err(windows::core::Error::from_hresult(
                    windows::Win32::Foundation::E_INVALIDARG,
                ));
            }
        }
    }

    if !is_elevated() {
        return relaunch_elevated();
    }

    // SAFETY: Standard Win32 GUI initialization and message loop.
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
            920,
            830,
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

fn print_cli_help() {
    println!(
        "Familiar Smartcard — PIV Smart Card Setup & Diagnostics\n\n\
         Usage:\n\
         \x20 familiar-enroll.exe                                Launch elevated Win32 setup GUI\n\
         \x20 familiar-enroll.exe --probe                        Read-only reader, PIN/PUK, 0x9B/0x9D policy & 0xF9 attestation probe\n\
         \x20 familiar-enroll.exe --provision-card <cached|always|never> [--no-9e] [--pin <PIN>] [--mgmt-key <HEX>] [--new-mgmt-key <HEX>]\n\
         \x20                                                    Generate on-card P-256 0x9D key (1-touch CACHED, 2-touch ALWAYS, or NEVER)\n\
         \x20 familiar-enroll.exe --card-selftest <PIN>          Stateless card ECDH/AES-GCM self-test (no registry writes)\n\
         \x20 familiar-enroll.exe --unblock-pin <PUK> <NEW-PIN>  Unblock PIV PIN via PUK (00 2C 00 80) and reset retries to 3\n\
         \x20 familiar-enroll.exe --change-puk <CUR> <NEW>       Change card PUK via 00 24 00 81 (PIV default: 12345678)\n\
         \x20 familiar-enroll.exe --repin-attestation            Verify & re-pin connected card's 0xF9 root in HKLM (Admin)\n\
         \x20 familiar-enroll.exe --clear-attestation            Clear pinned 0xF9 root from HKLM (Admin)\n"
    );
}

fn is_elevated() -> bool {
    // SAFETY: Queries process elevation token status and closes token handle.
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
    // SAFETY: Requests UAC elevation via `ShellExecuteW("runas")`.
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
        // SAFETY: Displays standard Win32 error box.
        unsafe {
            let _ = MessageBoxW(
                None,
                w!("Administrator rights are required to manage vaults and register the sign-in provider."),
                w!("Familiar Smartcard"),
                MB_OK | MB_ICONERROR,
            );
        }
    }
    Ok(())
}

fn probe_cli() -> windows::core::Result<()> {
    let pinned_f9 = read_pinned_f9().ok().flatten().map(hex::encode);
    match scard_core::probe_readers() {
        Ok(readers) if readers.is_empty() => println!("No smart card reader found."),
        Ok(readers) => print!("{}", format_readers(&readers, pinned_f9.as_deref())),
        Err(error) => {
            eprintln!("Probe failed: {error}");
            return Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ));
        }
    }
    Ok(())
}

fn card_selftest_cli(pin: &str) -> windows::core::Result<()> {
    if !valid_pin(pin) {
        eprintln!("Invalid PIN format: PIV PIN must be 6-8 ASCII digits.");
        return Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_INVALIDARG,
        ));
    }

    const TEST_PASSWORD: &str = "FamiliarSmartcard-SelfTest-Only";
    const TEST_SID: &str = "S-1-5-21-0";
    const TEST_USER: &str = "selftest";
    const TEST_COMPUTER: &str = "SELFTEST";

    let enrolled = scard_core::enroll(None, TEST_PASSWORD, TEST_SID, TEST_USER, TEST_COMPUTER, 0)
        .map_err(|error| {
        eprintln!("Enrollment self-test failed: {error}");
        windows::core::Error::from_hresult(windows::Win32::Foundation::E_FAIL)
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
        eprintln!("Unlock self-test failed: {error}");
        windows::core::Error::from_hresult(windows::Win32::Foundation::E_FAIL)
    })?;

    if decrypted.as_str() != TEST_PASSWORD {
        eprintln!("Card self-test decrypted an unexpected password.");
        return Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_FAIL,
        ));
    }

    println!("Card self-test succeeded.");
    println!(
        "9D Fingerprint: {}",
        hex::encode(enrolled.card_pub_fingerprint)
    );
    if let Some(f9) = enrolled.f9_fingerprint {
        println!("0xF9 Root:      {} (verified)", hex::encode(f9));
    }
    println!(
        "Card:           {}",
        enrolled.card_name.as_deref().unwrap_or("(unknown)")
    );
    Ok(())
}

fn repin_attestation_cli() -> windows::core::Result<()> {
    if !is_elevated() {
        eprintln!("Administrator privileges are required to update HKLM attestation pinning.");
        return Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_ACCESSDENIED,
        ));
    }
    match repin_connected_card_attestation(None) {
        Ok(fp) => {
            println!("Successfully verified 0x9D/0xF9 attestation and pinned new card root:");
            println!("  Pinned 0xF9 SHA-256: {}", hex::encode(fp));
            Ok(())
        }
        Err(error) => {
            eprintln!("Re-pin attestation failed: {error}");
            Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ))
        }
    }
}

fn clear_attestation_cli() -> windows::core::Result<()> {
    if !is_elevated() {
        eprintln!("Administrator privileges are required to clear HKLM attestation pinning.");
        return Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_ACCESSDENIED,
        ));
    }
    match clear_pinned_f9() {
        Ok(true) => {
            println!("Cleared previously pinned 0xF9 attestation root from HKLM.");
            Ok(())
        }
        Ok(false) => {
            println!("No pinned 0xF9 attestation root was present in HKLM.");
            Ok(())
        }
        Err(error) => {
            eprintln!("Clear attestation failed: {error}");
            Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ))
        }
    }
}

fn unblock_pin_cli(puk_arg: &str, new_pin_arg: &str) -> windows::core::Result<()> {
    let puk = Zeroizing::new(puk_arg.as_bytes().to_vec());
    let new_pin = Zeroizing::new(new_pin_arg.as_bytes().to_vec());
    let (expected_fp, expected_9e) = match scard_core::current_user() {
        Ok(u) => (
            read_vault(&u.sid)
                .ok()
                .flatten()
                .map(|v| v.card_pub_fingerprint),
            read_card_auth_9e_pub(&u.sid).ok().flatten(),
        ),
        Err(_) => (None, None),
    };
    match unblock_card_pin(
        None,
        expected_fp.as_ref(),
        expected_9e.as_deref(),
        false,
        &puk,
        &new_pin,
    ) {
        Ok(fp_opt) => {
            if let Some(fp) = fp_opt {
                let _ = clear_last_attempt_cooldown(&fp);
            }
            println!("Successfully unblocked PIV PIN and restored retry counter to 3.");
            println!("Existing Windows vaults remain valid with the new PIN.");
            Ok(())
        }
        Err(error) => {
            eprintln!("Unblock PIN failed: {error}");
            Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ))
        }
    }
}

fn change_puk_cli(cur_puk_arg: &str, new_puk_arg: &str) -> windows::core::Result<()> {
    let cur_puk = Zeroizing::new(cur_puk_arg.as_bytes().to_vec());
    let new_puk = Zeroizing::new(new_puk_arg.as_bytes().to_vec());
    match change_card_puk(None, &cur_puk, &new_puk) {
        Ok(()) => {
            println!("Successfully updated PIV card PUK. Keep the new PUK stored offline.");
            Ok(())
        }
        Err(error) => {
            eprintln!("Change PUK failed: {error}");
            Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ))
        }
    }
}

fn provision_card_cli(rest: &[String]) -> windows::core::Result<()> {
    let Some(touch_str) = rest.first().map(String::as_str) else {
        eprintln!(
            "Usage: familiar-enroll.exe --provision-card <cached|always|never> [--no-9e] [--pin <PIN>] [--mgmt-key <HEX>] [--new-mgmt-key <HEX>]\n"
        );
        return Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_INVALIDARG,
        ));
    };
    let touch_policy_9d = if touch_str.eq_ignore_ascii_case("cached") {
        TOUCH_POLICY_CACHED
    } else if touch_str.eq_ignore_ascii_case("always") {
        TOUCH_POLICY_ALWAYS
    } else if touch_str.eq_ignore_ascii_case("never") {
        TOUCH_POLICY_NEVER
    } else {
        eprintln!(
            "Invalid touch policy '{touch_str}': expected 'cached' (1 touch), 'always' (2 touches), or 'never'.\n"
        );
        return Err(windows::core::Error::from_hresult(
            windows::Win32::Foundation::E_INVALIDARG,
        ));
    };

    let mut provision_9e = true;
    let mut pin_opt: Option<Zeroizing<Vec<u8>>> = None;
    let mut cur_mgmt: Option<Zeroizing<String>> = None;
    let mut new_mgmt: Option<Zeroizing<String>> = None;

    let mut idx = 1usize;
    while idx < rest.len() {
        match rest[idx].as_str() {
            "--no-9e" => {
                provision_9e = false;
                idx += 1;
            }
            "--pin" => {
                let Some(val) = rest.get(idx + 1) else {
                    eprintln!("Missing value after --pin\n");
                    return Err(windows::core::Error::from_hresult(
                        windows::Win32::Foundation::E_INVALIDARG,
                    ));
                };
                if !valid_pin(val) {
                    eprintln!("Invalid PIN format: PIV PIN must be 6-8 ASCII digits.\n");
                    return Err(windows::core::Error::from_hresult(
                        windows::Win32::Foundation::E_INVALIDARG,
                    ));
                }
                pin_opt = Some(Zeroizing::new(val.as_bytes().to_vec()));
                idx += 2;
            }
            "--mgmt-key" => {
                let Some(val) = rest.get(idx + 1) else {
                    eprintln!("Missing value after --mgmt-key\n");
                    return Err(windows::core::Error::from_hresult(
                        windows::Win32::Foundation::E_INVALIDARG,
                    ));
                };
                cur_mgmt = Some(Zeroizing::new(val.clone()));
                idx += 2;
            }
            "--new-mgmt-key" => {
                let Some(val) = rest.get(idx + 1) else {
                    eprintln!("Missing value after --new-mgmt-key\n");
                    return Err(windows::core::Error::from_hresult(
                        windows::Win32::Foundation::E_INVALIDARG,
                    ));
                };
                new_mgmt = Some(Zeroizing::new(val.clone()));
                idx += 2;
            }
            other => {
                eprintln!("Unknown --provision-card option: {other}\n");
                return Err(windows::core::Error::from_hresult(
                    windows::Win32::Foundation::E_INVALIDARG,
                ));
            }
        }
    }

    match provision_card(&CardProvisionOptions {
        reader: None,
        pin: pin_opt.as_deref().map(Vec::as_slice),
        touch_policy_9d,
        provision_9e,
        current_mgmt_key_hex: cur_mgmt.as_deref().map(String::as_str),
        new_mgmt_key_hex: new_mgmt.as_deref().map(String::as_str),
    }) {
        Ok(res) => {
            println!("Successfully provisioned PIV smart card keys:");
            println!(
                "  Card:             {}",
                res.card_name.as_deref().unwrap_or("(unknown)")
            );
            println!("  Slot 0x9D SHA256: {}", hex::encode(res.fingerprint_9d));
            println!(
                "  Slot 0x9D Policy: ECC P-256, PIN=ALWAYS, Touch={}",
                format_touch_policy(Some(res.touch_policy_9d))
            );
            println!(
                "  Slot 0x9E Guard:  {}",
                if res.pub_9e_sec1.is_some() {
                    "provisioned (ECC P-256, PIN=NEVER, Touch=NEVER)"
                } else {
                    "skipped (--no-9e)"
                }
            );
            println!(
                "  0x9B Mgmt Key:    alg={} ({})",
                format_mgmt_alg(Some(res.mgmt_alg_used)),
                if res.mgmt_key_rotated {
                    "ROTATED — keep your new hex Management Key stored offline!"
                } else {
                    "unchanged"
                }
            );
            println!(
                "\nIMPORTANT: Run 'familiar-enroll.exe' to Set up or Re-bind this account to the newly generated 0x9D key."
            );
            Ok(())
        }
        Err(error) => {
            eprintln!("Card provisioning failed: {error}");
            Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_FAIL,
            ))
        }
    }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: Main Win32 window procedure.
    unsafe {
        match msg {
            WM_CREATE => {
                create_controls(hwnd);
                spawn_probe_worker(hwnd, false);
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = wparam.0 & 0xFFFF;
                match id {
                    ID_RADIO_KEEP_KEY
                    | ID_RADIO_TOUCH_CACHED
                    | ID_RADIO_TOUCH_ALWAYS
                    | ID_RADIO_TOUCH_NEVER => {
                        if let Some(st) = state_mut(hwnd) {
                            st.user_touched_provision_mode = true;
                        }
                        sync_provision_controls_enabled(hwnd);
                    }
                    ID_SETUP_ROTATE => start_setup_with_rotation(hwnd),
                    ID_REBIND_EXISTING => start_rebind_existing_password(hwnd),
                    ID_PROBE => spawn_probe_worker(hwnd, true),
                    ID_SELFTEST => start_self_test(hwnd),
                    ID_MANAGE_PUK => {
                        if !state_mut(hwnd).map(|s| s.busy).unwrap_or(true) {
                            if let Some(log) = puk_dialog::show_puk_management_dialog(hwnd) {
                                set_status(hwnd, "Card PIN / PUK operation completed.");
                                set_output(hwnd, &log);
                            }
                        }
                    }
                    ID_REPIN_ROOT => start_repin_card_root(hwnd),
                    ID_REGISTER => start_register_provider(hwnd),
                    ID_CLEAR => {
                        if let Some(st) = state_mut(hwnd) {
                            let _ = SetWindowTextW(st.output, PCWSTR::null());
                        }
                    }
                    _ => {}
                }
                LRESULT(0)
            }
            WM_WORKER_STATUS => {
                let ptr = lparam.0 as *mut String;
                if !ptr.is_null() {
                    let msg_text = *Box::from_raw(ptr);
                    set_status(hwnd, &msg_text);
                }
                LRESULT(0)
            }
            WM_WORKER_RESULT => {
                let ptr = lparam.0 as *mut WorkerOutcome;
                if !ptr.is_null() {
                    let outcome = *Box::from_raw(ptr);
                    handle_worker_outcome(hwnd, outcome);
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState;
                if !pointer.is_null() {
                    let st = Box::from_raw(pointer);
                    scrub_edit_control(st.pin);
                    scrub_edit_control(st.password);
                    scrub_edit_control(st.mgmt_cur);
                    scrub_edit_control(st.mgmt_new);
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
    // SAFETY: Standard Win32 child control creation.
    unsafe {
        let font = HFONT(GetStockObject(DEFAULT_GUI_FONT).0);

        let title = create_control(
            hwnd,
            w!("STATIC"),
            "Familiar Smartcard — Local Account PIV Setup",
            20,
            12,
            840,
            22,
            0,
        );
        set_font(title, font);

        let subtitle = create_control(
            hwnd,
            w!("STATIC"),
            "Recommended: generate a 36-char offline recovery password and bind it to your PIV 9D smart card.",
            20,
            36,
            860,
            20,
            0,
        );
        set_font(subtitle, font);

        let status = create_control(
            hwnd,
            w!("STATIC"),
            "Checking for PIV smart card in background...",
            20,
            60,
            860,
            22,
            0,
        );
        set_font(status, font);

        let pin_label = create_control(
            hwnd,
            w!("STATIC"),
            "PIV PIN (6-8 digits)",
            20,
            92,
            180,
            22,
            0,
        );
        set_font(pin_label, font);
        let pin = create_control(hwnd, w!("EDIT"), "", 210, 90, 180, 24, 0);
        let _ = SendMessageW(
            pin,
            EM_SETPASSWORDCHAR,
            Some(WPARAM(PASSWORD_CHAR)),
            Some(LPARAM(0)),
        );
        set_font(pin, font);

        let password_label = create_control(
            hwnd,
            w!("STATIC"),
            "Current Windows password",
            20,
            124,
            180,
            22,
            0,
        );
        set_font(password_label, font);
        let password = create_control(hwnd, w!("EDIT"), "", 210, 122, 380, 24, 0);
        let _ = SendMessageW(
            password,
            EM_SETPASSWORDCHAR,
            Some(WPARAM(PASSWORD_CHAR)),
            Some(LPARAM(0)),
        );
        set_font(password, font);

        // Integrated Card Key & Touch Policy controls (applied during Set up / Re-bind)
        let prov_label = create_control(
            hwnd,
            w!("STATIC"),
            "Card Key & Touch Policy (applied during Set up / Re-bind):",
            20,
            156,
            860,
            20,
            0,
        );
        set_font(prov_label, font);

        let radio_keep = create_check_control(
            hwnd,
            "Keep existing 0x9D card key",
            20,
            178,
            260,
            22,
            STYLE_AUTORADIO | STYLE_GROUP,
            ID_RADIO_KEEP_KEY as isize,
            font,
        );
        let _ = SendMessageW(
            radio_keep,
            BM_SETCHECK,
            Some(WPARAM(BST_CHECKED)),
            Some(LPARAM(0)),
        );

        let radio_touch_cached = create_check_control(
            hwnd,
            "New 0x9D: Touch = CACHED (1 touch — Recommended)",
            305,
            178,
            430,
            22,
            STYLE_AUTORADIO,
            ID_RADIO_TOUCH_CACHED as isize,
            font,
        );

        let radio_touch_always = create_check_control(
            hwnd,
            "New 0x9D: Touch = ALWAYS (strict 2 touches)",
            20,
            202,
            280,
            22,
            STYLE_AUTORADIO,
            ID_RADIO_TOUCH_ALWAYS as isize,
            font,
        );

        let radio_touch_never = create_check_control(
            hwnd,
            "New 0x9D: Touch = NEVER (PIN only, no touch)",
            305,
            202,
            390,
            22,
            STYLE_AUTORADIO,
            ID_RADIO_TOUCH_NEVER as isize,
            font,
        );

        let chk_9e = create_check_control(
            hwnd,
            "Also generate Slot 0x9E anti-phishing key (PIN=NEVER, Touch=NEVER)",
            20,
            228,
            510,
            22,
            STYLE_AUTOCHECKBOX | STYLE_GROUP,
            ID_CHK_PROVISION_9E as isize,
            font,
        );
        let _ = SendMessageW(
            chk_9e,
            BM_SETCHECK,
            Some(WPARAM(BST_CHECKED)),
            Some(LPARAM(0)),
        );

        let mgmt_cur_lbl = create_control(
            hwnd,
            w!("STATIC"),
            "0x9B Mgmt Key (blank=default)",
            20,
            256,
            215,
            22,
            0,
        );
        set_font(mgmt_cur_lbl, font);
        let mgmt_cur = create_control(hwnd, w!("EDIT"), "", 240, 254, 195, 24, 0);
        let _ = SendMessageW(
            mgmt_cur,
            EM_SETPASSWORDCHAR,
            Some(WPARAM(PASSWORD_CHAR)),
            Some(LPARAM(0)),
        );
        set_font(mgmt_cur, font);

        let mgmt_new_lbl = create_control(
            hwnd,
            w!("STATIC"),
            "Rotate 0x9B to (opt. hex)",
            450,
            256,
            185,
            22,
            0,
        );
        set_font(mgmt_new_lbl, font);
        let mgmt_new = create_control(hwnd, w!("EDIT"), "", 640, 254, 240, 24, 0);
        set_font(mgmt_new, font);

        // Row 1: Primary enrollment vs Advanced/Rescue re-bind
        let btn_setup = create_control(
            hwnd,
            w!("BUTTON"),
            "Set up & rotate password (Recommended)",
            20,
            288,
            290,
            38,
            ID_SETUP_ROTATE as isize,
        );
        set_font(btn_setup, font);

        let btn_rebind = create_control(
            hwnd,
            w!("BUTTON"),
            "Re-bind current password (Advanced / Rescue)",
            322,
            288,
            305,
            38,
            ID_REBIND_EXISTING as isize,
        );
        set_font(btn_rebind, font);

        // Row 2: Diagnostics, PIN/PUK Recovery, Attestation Pinning, Provider Registration
        let btn_probe = create_control(
            hwnd,
            w!("BUTTON"),
            "Probe card",
            20,
            334,
            105,
            30,
            ID_PROBE as isize,
        );
        set_font(btn_probe, font);

        let btn_selftest = create_control(
            hwnd,
            w!("BUTTON"),
            "Self-test vault",
            133,
            334,
            120,
            30,
            ID_SELFTEST as isize,
        );
        set_font(btn_selftest, font);

        let btn_puk = create_control(
            hwnd,
            w!("BUTTON"),
            "Unblock PIN / PUK...",
            261,
            334,
            165,
            30,
            ID_MANAGE_PUK as isize,
        );
        set_font(btn_puk, font);

        let btn_repin = create_control(
            hwnd,
            w!("BUTTON"),
            "Re-pin card root",
            434,
            334,
            140,
            30,
            ID_REPIN_ROOT as isize,
        );
        set_font(btn_repin, font);

        let btn_register = create_control(
            hwnd,
            w!("BUTTON"),
            "Register provider",
            582,
            334,
            145,
            30,
            ID_REGISTER as isize,
        );
        set_font(btn_register, font);

        let btn_clear = create_control(
            hwnd,
            w!("BUTTON"),
            "Clear output",
            735,
            334,
            115,
            30,
            ID_CLEAR as isize,
        );
        set_font(btn_clear, font);

        let out_style = WS_CHILD
            | WS_VISIBLE
            | WS_BORDER
            | WS_VSCROLL
            | WINDOW_STYLE(ES_MULTILINE as u32 | ES_AUTOVSCROLL as u32 | ES_READONLY as u32);

        let output = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("EDIT"),
            PCWSTR::null(),
            out_style,
            20,
            372,
            860,
            400,
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
            radio_keep,
            radio_touch_cached,
            radio_touch_always,
            radio_touch_never,
            chk_9e,
            mgmt_cur,
            mgmt_new,
            buttons: [
                btn_setup,
                btn_rebind,
                btn_probe,
                btn_selftest,
                btn_puk,
                btn_repin,
                btn_register,
                btn_clear,
            ],
            user_touched_provision_mode: false,
            busy: false,
        });
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);
        sync_provision_controls_enabled(hwnd);
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_check_control(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    extra_style: WINDOW_STYLE,
    id: isize,
    font: HFONT,
) -> HWND {
    let wide = to_wide(text);
    // SAFETY: Standard Win32 radio/checkbox BUTTON creation without WS_BORDER.
    unsafe {
        let ctrl = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("BUTTON"),
            PCWSTR(wide.as_ptr()),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | extra_style,
            x,
            y,
            width,
            height,
            Some(parent),
            Some(HMENU(id as *mut c_void)),
            None,
            None,
        )
        .unwrap_or_default();
        set_font(ctrl, font);
        ctrl
    }
}

unsafe fn is_checked(hwnd: HWND) -> bool {
    // SAFETY: Queries Win32 button check state.
    unsafe {
        SendMessageW(hwnd, BM_GETCHECK, Some(WPARAM(0)), Some(LPARAM(0))).0 == BST_CHECKED as isize
    }
}

unsafe fn sync_provision_controls_enabled(hwnd: HWND) {
    // SAFETY: Enables/disables provisioning options based on radio state and busy flag.
    unsafe {
        let Some(st) = state_mut(hwnd) else {
            return;
        };
        let provisioning = !st.busy
            && (is_checked(st.radio_touch_cached)
                || is_checked(st.radio_touch_always)
                || is_checked(st.radio_touch_never));
        let _ = EnableWindow(st.radio_keep, !st.busy);
        let _ = EnableWindow(st.radio_touch_cached, !st.busy);
        let _ = EnableWindow(st.radio_touch_always, !st.busy);
        let _ = EnableWindow(st.radio_touch_never, !st.busy);
        let _ = EnableWindow(st.chk_9e, provisioning);
        let _ = EnableWindow(st.mgmt_cur, provisioning);
        let _ = EnableWindow(st.mgmt_new, provisioning);
    }
}

#[allow(clippy::too_many_arguments)]
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
    let tab = if id != 0 || class == w!("EDIT") {
        WS_TABSTOP
    } else {
        WINDOW_STYLE(0)
    };
    // SAFETY: Standard Win32 control creation.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            PCWSTR(text.as_ptr()),
            WS_CHILD | WS_VISIBLE | WS_BORDER | tab,
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
}

unsafe fn set_font(hwnd: HWND, font: HFONT) {
    // SAFETY: Standard `WM_SETFONT` message.
    unsafe {
        let _ = SendMessageW(
            hwnd,
            WM_SETFONT,
            Some(WPARAM(font.0 as usize)),
            Some(LPARAM(1)),
        );
    }
}

unsafe fn state_mut(hwnd: HWND) -> Option<&'static mut AppState> {
    // SAFETY: Accessed exclusively on the main Win32 UI thread.
    unsafe {
        let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState;
        pointer.as_mut()
    }
}

unsafe fn set_busy(hwnd: HWND, busy: bool, status_text: &str) {
    // SAFETY: UI thread updates busy flag, button enable state, and status label.
    unsafe {
        if let Some(st) = state_mut(hwnd) {
            st.busy = busy;
            for &btn in &st.buttons {
                let _ = EnableWindow(btn, !busy);
            }
            let wide = to_wide(status_text);
            let _ = SetWindowTextW(st.status, PCWSTR(wide.as_ptr()));
        }
        sync_provision_controls_enabled(hwnd);
    }
}

unsafe fn set_status(hwnd: HWND, text: &str) {
    // SAFETY: UI thread updates status text.
    unsafe {
        if let Some(st) = state_mut(hwnd) {
            let wide = to_wide(text);
            let _ = SetWindowTextW(st.status, PCWSTR(wide.as_ptr()));
        }
    }
}

unsafe fn set_output(hwnd: HWND, text: &str) {
    // SAFETY: UI thread updates output edit control.
    unsafe {
        if let Some(st) = state_mut(hwnd) {
            let wide = to_wide(text);
            let _ = SetWindowTextW(st.output, PCWSTR(wide.as_ptr()));
        }
    }
}

fn post_status(hwnd_raw: isize, status_text: impl Into<String>) {
    let boxed = Box::into_raw(Box::new(status_text.into()));
    let hwnd = HWND(hwnd_raw as *mut c_void);
    // SAFETY: Posts heap-allocated status `String` to main UI thread; freed on receipt.
    unsafe {
        if PostMessageW(
            Some(hwnd),
            WM_WORKER_STATUS,
            WPARAM(0),
            LPARAM(boxed as isize),
        )
        .is_err()
        {
            drop(Box::from_raw(boxed));
        }
    }
}

fn post_outcome(hwnd_raw: isize, outcome: WorkerOutcome) {
    let boxed = Box::into_raw(Box::new(outcome));
    let hwnd = HWND(hwnd_raw as *mut c_void);
    // SAFETY: Posts heap-allocated `WorkerOutcome` pointer to main UI thread; freed on receipt.
    unsafe {
        if PostMessageW(
            Some(hwnd),
            WM_WORKER_RESULT,
            WPARAM(0),
            LPARAM(boxed as isize),
        )
        .is_err()
        {
            drop(Box::from_raw(boxed));
        }
    }
}

fn compliant_9d_present(readers: &[scard_core::ReaderProbe]) -> (bool, Option<String>) {
    let mut first_policy_err = None;
    for reader in readers {
        for slot in &reader.slots {
            if slot.slot == 0x9D && slot.has_key {
                if slot.policy_valid_for_9d {
                    return (true, None);
                }
                if first_policy_err.is_none() {
                    first_policy_err = slot.policy_error.clone();
                }
            }
        }
    }
    (false, first_policy_err)
}

unsafe fn spawn_probe_worker(hwnd: HWND, update_output: bool) {
    // SAFETY: Checks busy state on UI thread before spawning background worker.
    unsafe {
        if state_mut(hwnd).map(|s| s.busy).unwrap_or(true) {
            return;
        }
        set_busy(hwnd, true, "Probing smart card readers...");
    }
    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || {
        let pinned_f9 = read_pinned_f9().ok().flatten().map(hex::encode);
        let outcome = match scard_core::probe_readers() {
            Ok(readers) if readers.is_empty() => WorkerOutcome::ProbeDone {
                status: "No PIV smart card detected. Insert your card (or enable Smart Cards in RDP) and click Probe card.".into(),
                output: update_output.then(|| "No smart card reader found.\r\n".into()),
                piv_card_without_9d: false,
            },
            Ok(readers) => {
                let any_piv = readers.iter().any(|r| r.piv_selected);
                let any_9d_key = readers
                    .iter()
                    .flat_map(|r| r.slots.iter())
                    .any(|s| s.slot == 0x9D && s.has_key);
                let (ready, policy_err) = compliant_9d_present(&readers);
                let status = if ready {
                    "PIV smart card detected. Slot 0x9D is ready (or choose New 0x9D below to change Touch policy).".into()
                } else if let Some(err) = policy_err {
                    format!("PIV smart card detected, but slot 0x9D failed policy check: {err} — select New 0x9D below to re-provision.")
                } else if any_piv {
                    "New/empty PIV smart card detected — 'New 0x9D: Touch = CACHED (1 touch)' selected for one-step setup.".into()
                } else {
                    "Smart card reader detected, but no PIV card is present.".into()
                };
                let output = update_output.then(|| format_readers(&readers, pinned_f9.as_deref()));
                WorkerOutcome::ProbeDone {
                    status,
                    output,
                    piv_card_without_9d: any_piv && !any_9d_key,
                }
            }
            Err(error) => WorkerOutcome::ProbeDone {
                status: format!("Card probe failed: {error}"),
                output: update_output.then(|| format!("Probe failed: {error}\r\n")),
                piv_card_without_9d: false,
            },
        };
        post_outcome(hwnd_raw, outcome);
    });
}

/// Read and validate the integrated Card Key & Touch Policy controls, asking for
/// explicit confirmation if rotating `0x9B` or overwriting an existing `0x9D` key.
/// Returns `Ok(None)` when `"Keep existing 0x9D card key"` is selected, `Ok(Some(plan))`
/// when provisioning is confirmed, or `Err(None)` when the user cancels confirmation.
unsafe fn read_and_confirm_provision_plan(
    hwnd: HWND,
) -> Result<Option<ProvisionPlan>, Option<String>> {
    let (touch_cached, touch_always, touch_never, provision_9e, current_mgmt_hex, new_mgmt_hex) = unsafe {
        let Some(st) = state_mut(hwnd) else {
            return Err(None);
        };
        (
            is_checked(st.radio_touch_cached),
            is_checked(st.radio_touch_always),
            is_checked(st.radio_touch_never),
            is_checked(st.chk_9e),
            read_edit(st.mgmt_cur),
            read_edit(st.mgmt_new),
        )
    };

    if !touch_cached && !touch_always && !touch_never {
        return Ok(None);
    }

    let touch_policy_9d = if touch_cached {
        TOUCH_POLICY_CACHED
    } else if touch_always {
        TOUCH_POLICY_ALWAYS
    } else {
        TOUCH_POLICY_NEVER
    };

    if !current_mgmt_hex.trim().is_empty() {
        if let Err(e) = parse_mgmt_key_hex(&current_mgmt_hex) {
            return Err(Some(e.to_string()));
        }
    }
    if !new_mgmt_hex.trim().is_empty() {
        if let Err(e) = parse_mgmt_key_hex(&new_mgmt_hex) {
            return Err(Some(format!("Invalid new 0x9B Management Key: {e}")));
        }
        let rot_confirm = unsafe {
            MessageBoxW(
                Some(hwnd),
                w!("You entered a new hex key in 'Rotate 0x9B to'.\r\n\r\n\
                    Make sure you have saved this 0x9B Management Key offline! Without it, future PIV key generation on this card will require resetting the PIV applet.\r\n\r\n\
                    Proceed with rotating the card's 0x9B Management Key?"),
                w!("Confirm 0x9B Management Key Rotation"),
                MB_YESNO | MB_ICONWARNING,
            )
        };
        if rot_confirm.0 != 6 {
            return Err(None);
        }
    }

    if card_has_9d_key(None) {
        let policy_name = match touch_policy_9d {
            TOUCH_POLICY_CACHED => "CACHED (1 physical touch per sign-in + immediate reset)",
            TOUCH_POLICY_ALWAYS => "ALWAYS (strict 2 physical touches per sign-in)",
            _ => "NEVER (PIN only)",
        };
        let warn_msg = format!(
            "Slot 0x9D on the connected smart card ALREADY contains a key.\r\n\r\n\
             Generating a new 0x9D key with Touch Policy = {policy_name} will permanently overwrite the existing key on this card.\r\n\
             Any OTHER computers or tools bound to the old key on this card will need re-enrollment.\r\n\r\n\
             Overwrite the existing card key and continue?"
        );
        let warn_w = to_wide(&warn_msg);
        let overwrite_confirm = unsafe {
            MessageBoxW(
                Some(hwnd),
                PCWSTR(warn_w.as_ptr()),
                w!("Confirm Overwriting Existing Card Key"),
                MB_YESNO | MB_ICONWARNING,
            )
        };
        if overwrite_confirm.0 != 6 {
            return Err(None);
        }
    }

    Ok(Some(ProvisionPlan {
        touch_policy_9d,
        provision_9e,
        current_mgmt_hex,
        new_mgmt_hex,
    }))
}

unsafe fn start_setup_with_rotation(hwnd: HWND) {
    let (pin, current_password) = unsafe {
        let Some(st) = state_mut(hwnd) else {
            return;
        };
        if st.busy {
            return;
        }
        (read_edit(st.pin), read_edit(st.password))
    };

    if !valid_pin(&pin) {
        unsafe { set_status(hwnd, "PIV PIN must be 6-8 ASCII digits.") };
        return;
    }
    if current_password.is_empty() {
        unsafe {
            set_status(
                hwnd,
                "Enter your current Windows password to authorize setup.",
            )
        };
        return;
    }

    let provision_plan = match unsafe { read_and_confirm_provision_plan(hwnd) } {
        Ok(plan) => plan,
        Err(Some(msg)) => {
            unsafe { set_status(hwnd, &msg) };
            return;
        }
        Err(None) => return,
    };

    unsafe {
        set_busy(
            hwnd,
            true,
            "Phase 1/2: Validating account, checking card policy & running card self-test...",
        );
    }

    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || {
        let res: Result<PreparedRotation, String> = (|| {
            // Pre-flight check binary package & Windows password BEFORE touching the smart card!
            installer::preflight_check_sources()?;

            let user =
                scard_core::current_user().map_err(|e| format!("Account lookup failed: {e}"))?;
            let _ = verify_local_workgroup_account(&user.username).map_err(|e| e.to_string())?;
            validate_windows_password(&user, &current_password)
                .map_err(|e| format!("Current Windows password is incorrect: {e}"))?;

            let mut mgmt_rotated = false;
            if let Some(plan) = &provision_plan {
                post_status(
                    hwnd_raw,
                    format!(
                        "Phase 1/2: Provisioning on-card ECC P-256 key (Touch = {})...",
                        format_touch_policy(Some(plan.touch_policy_9d))
                    ),
                );
                let prov_res = provision_card(&CardProvisionOptions {
                    reader: None,
                    pin: Some(pin.as_bytes()),
                    touch_policy_9d: plan.touch_policy_9d,
                    provision_9e: plan.provision_9e,
                    current_mgmt_key_hex: Some(plan.current_mgmt_hex.as_str())
                        .filter(|s| !s.trim().is_empty()),
                    new_mgmt_key_hex: Some(plan.new_mgmt_hex.as_str())
                        .filter(|s| !s.trim().is_empty()),
                })
                .map_err(|e| format!("Card key provisioning failed: {e}"))?;
                mgmt_rotated = prov_res.mgmt_key_rotated;
            }

            let new_password = generate_recovery_password();
            let placeholder_ts = password_last_set(&user.username).map_err(|e| e.to_string())?;

            let enrolled = enroll_with_options(&EnrollOptions {
                reader: None,
                password: &new_password,
                sid: &user.sid,
                username: &user.username,
                computer: &user.computer,
                password_last_set: placeholder_ts,
                attestation_policy: AttestationPolicy::EnforceOrPinFirstUse,
            })
            .map_err(|e| format!("Card enrollment failed: {e}"))?;

            if enrolled.touch_policy == TOUCH_POLICY_CACHED {
                post_status(
                    hwnd_raw,
                    "ACTION REQUIRED: Press your blinking security key ONCE now (Touch=CACHED self-test)...",
                );
            } else if enrolled.touch_policy == TOUCH_POLICY_ALWAYS {
                post_status(
                    hwnd_raw,
                    "ACTION REQUIRED: Press your blinking security key TWICE now (Touch=ALWAYS self-test)...",
                );
            }

            // Mandatory Phase B card self-test BEFORE touching the real Windows password!
            let mut pin_bytes = Zeroizing::new(pin.as_bytes().to_vec());
            let decrypted = scard_core::unlock(
                enrolled.vault.clone(),
                &user.sid,
                &user.username,
                &user.computer,
                None,
                &mut pin_bytes,
            )
            .map_err(|e| format!("Card self-test failed (Windows password NOT changed): {e}"))?;

            if !scard_core::crypto::constant_time_eq(decrypted.as_bytes(), new_password.as_bytes())
            {
                return Err(
                    "Card self-test decrypted mismatch (Windows password NOT changed).".into(),
                );
            }

            let f9_status = match (enrolled.f9_fingerprint, enrolled.f9_newly_pinned) {
                (Some(fp), true) => format!("{} (verified & newly pinned)", hex::encode(fp)),
                (Some(fp), false) => format!("{} (verified against pinned root)", hex::encode(fp)),
                (None, _) => "(card did not return 0xF9 attestation)".into(),
            };

            Ok(PreparedRotation {
                user,
                new_password,
                dek: enrolled.dek,
                candidate_vault: enrolled.vault,
                card_name: enrolled
                    .card_name
                    .unwrap_or_else(|| "(unknown PIV card)".into()),
                fingerprint_hex: hex::encode(enrolled.card_pub_fingerprint),
                f9_status,
                touch_policy: enrolled.touch_policy,
                pin_is_default: enrolled.pin_is_default,
                puk_is_default: enrolled.puk_is_default,
                card_auth_9e_pub: enrolled.card_auth_9e_pub,
                mgmt_rotated,
            })
        })();

        match res {
            Ok(prepared) => post_outcome(
                hwnd_raw,
                WorkerOutcome::RotationCandidateReady(Box::new(prepared)),
            ),
            Err(err) => post_outcome(
                hwnd_raw,
                WorkerOutcome::SimpleDone {
                    status: err.clone(),
                    output: Some(format!("{err}\r\n")),
                    clear_secrets: false,
                    critical_modal_error: None,
                },
            ),
        }
    });
}

unsafe fn commit_confirmed_rotation(hwnd: HWND, prepared: PreparedRotation) {
    unsafe {
        set_busy(
            hwnd,
            true,
            "Phase 2/2: Rotating Windows password, committing vault & registering provider...",
        );
    }
    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || {
        let user = &prepared.user;

        // CRITICAL SAFETY ORDER: Install and register the Credential Provider binaries
        // FIRST, BEFORE rotating the Windows password! If installation fails for any
        // reason, the user's original Windows password remains 100% untouched!
        let install_summary = match installer::install_and_register() {
            Ok(summary) => summary,
            Err(err) => {
                post_outcome(
                    hwnd_raw,
                    WorkerOutcome::SimpleDone {
                        status:
                            "Provider installation failed — your Windows password was NOT changed."
                                .into(),
                        output: Some(format!(
                            "Credential Provider installation failed (your Windows password was NOT modified):\r\n{err}\r\n"
                        )),
                        clear_secrets: false,
                        critical_modal_error: None,
                    },
                );
                return;
            }
        };

        if let Err(e) = stage_pending_vault_with_backup(&user.sid, &prepared.candidate_vault) {
            post_outcome(
                hwnd_raw,
                WorkerOutcome::SimpleDone {
                    status: format!("Staging pending vault failed (password NOT changed): {e}"),
                    output: None,
                    clear_secrets: false,
                    critical_modal_error: None,
                },
            );
            return;
        }

        if let Err(e) =
            rotate_local_password_and_disable_expiry(&user.username, &prepared.new_password)
        {
            post_outcome(
                hwnd_raw,
                WorkerOutcome::SimpleDone {
                    status: format!("Windows password rotation failed: {e}"),
                    output: Some(format!("Password rotation failed: {e}\r\n")),
                    clear_secrets: false,
                    critical_modal_error: None,
                },
            );
            return;
        }

        // From this point on, the OS password IS `prepared.new_password` (which the user
        // verified on their offline recovery sheet), and the Credential Provider is ALREADY
        // installed. Re-bind AAD with the new timestamp using the retained `Zeroizing` DEK.
        let commit_res: Result<(), String> = (|| {
            let new_last_set =
                password_last_set_for_enrollment(&user.username).map_err(|e| e.to_string())?;
            let final_vault = prepared
                .candidate_vault
                .reencrypt_password_with_dek(
                    &prepared.dek,
                    &prepared.new_password,
                    &user.sid,
                    &user.username,
                    &user.computer,
                    new_last_set,
                )
                .map_err(|e| e.to_string())?;

            write_vault(&user.sid, &final_vault).map_err(|e| e.to_string())?;
            write_touch_policy(&user.sid, prepared.touch_policy).map_err(|e| e.to_string())?;
            if let Some(pub_9e) = &prepared.card_auth_9e_pub {
                write_card_auth_9e_pub(&user.sid, pub_9e).map_err(|e| e.to_string())?;
            } else {
                let _ = clear_card_auth_9e_pub(&user.sid);
            }
            validate_windows_password(user, &prepared.new_password)
                .map_err(|e| format!("Post-rotation LogonUserW check failed: {e}"))?;
            // Scrub and purge historical `VaultBlob.bak` once the new password & vault are verified!
            let _ = purge_vault_backup(&user.sid);
            Ok(())
        })();

        match commit_res {
            Ok(()) => {
                let guard_9e = if prepared.card_auth_9e_pub.is_some() {
                    "enabled (slot 0x9E P-256 PIN=NEVER verified)"
                } else {
                    "not configured (optional: provision slot 0x9E P-256 PIN=NEVER)"
                };
                let mut report = format!(
                    "Setup and password rotation complete.\r\n\
                     Account:        {}\\{}\r\n\
                     SID:            {}\r\n\
                     Card:           {}\r\n\
                     9D Fingerprint: {}\r\n\
                     9D Touch:       {}\r\n\
                     0xF9 Root:      {}\r\n\
                     Pre-PIN 0x9E:   {}\r\n\
                     Card Self-Test: succeeded\r\n\
                     Password:       rotated to 36-char recovery password (180-bit entropy, never expires)\r\n\
                     {}\r\n",
                    user.domain,
                    user.username,
                    user.sid,
                    prepared.card_name,
                    prepared.fingerprint_hex,
                    format_touch_policy(Some(prepared.touch_policy)),
                    prepared.f9_status,
                    guard_9e,
                    install_summary
                );
                if prepared.mgmt_rotated {
                    report.push_str(
                        "\r\n0x9B MGMT KEY ROTATED: Keep your new hex 0x9B Management Key stored safely offline.\r\n",
                    );
                }
                if prepared.pin_is_default || prepared.puk_is_default {
                    report.push_str(
                        "\r\nSECURITY WARNING: Your smart card PIN (123456) and/or PUK (12345678) is still set to the factory default!\r\n\
                         Click 'Unblock PIN / PUK...' to set a custom PUK and PIN before production deployment.\r\n",
                    );
                }
                if prepared.touch_policy == TOUCH_POLICY_NEVER {
                    report.push_str(
                        "\r\nADVISORY: Slot 0x9D has Touch Policy = NEVER. If you connect to remote hosts via RDP smart-card redirection,\r\n\
                         provisioning 0x9D with Touch Policy = ALWAYS prevents remote processes from invoking your card without physical touch.\r\n",
                    );
                }
                post_outcome(
                    hwnd_raw,
                    WorkerOutcome::SimpleDone {
                        status:
                            "Setup complete. Lock the screen and sign in with Familiar Smartcard."
                                .into(),
                        output: Some(report),
                        clear_secrets: true,
                        critical_modal_error: None,
                    },
                );
            }
            Err(err) => {
                let critical = format!(
                    "CRITICAL NOTICE: Your Windows password HAS ALREADY BEEN UPDATED to the recovery sheet password you just verified, \
                     but finalizing the vault or provider registration encountered an error:\r\n\r\n{err}\r\n\r\n\
                     Keep your recovery sheet safe! Use that recovery password (including hyphens) to sign in and click 'Re-bind current password'."
                );
                post_outcome(
                    hwnd_raw,
                    WorkerOutcome::SimpleDone {
                        status:
                            "Password rotated, but vault/provider finalization failed — see alert."
                                .into(),
                        output: Some(format!("{critical}\r\n")),
                        clear_secrets: true,
                        critical_modal_error: Some(critical),
                    },
                );
            }
        }
    });
}

unsafe fn start_rebind_existing_password(hwnd: HWND) {
    let (pin, password) = unsafe {
        let Some(st) = state_mut(hwnd) else {
            return;
        };
        if st.busy {
            return;
        }
        (read_edit(st.pin), read_edit(st.password))
    };

    if !valid_pin(&pin) {
        unsafe { set_status(hwnd, "PIV PIN must be 6-8 ASCII digits.") };
        return;
    }
    if password.is_empty() {
        unsafe { set_status(hwnd, "Enter the current Windows password to re-bind.") };
        return;
    }

    let provision_plan = match unsafe { read_and_confirm_provision_plan(hwnd) } {
        Ok(plan) => plan,
        Err(Some(msg)) => {
            unsafe { set_status(hwnd, &msg) };
            return;
        }
        Err(None) => return,
    };

    // Explicit security warning per project design.
    let confirm = unsafe {
        MessageBoxW(
            Some(hwnd),
            w!("Re-binding an existing password WITHOUT rotating to a high-entropy random recovery password is NOT RECOMMENDED for production.\r\n\r\n\
                Because the native Windows password provider stays enabled as a recovery path, a weak or reused password can still be guessed at the lock screen (especially over non-NLA RDP).\r\n\r\n\
                Only use this option when re-binding an already-rotated recovery password or inside isolated test environments.\r\n\r\n\
                Proceed with re-binding the current password?"),
            w!("Security Warning — Re-bind Existing Password"),
            MB_YESNO | MB_ICONWARNING,
        )
    };
    if confirm.0 != 6 {
        return;
    }

    unsafe {
        set_busy(
            hwnd,
            true,
            "Re-binding current password, running card self-test & registering provider...",
        );
    }

    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || {
        let res: Result<String, String> = (|| {
            // Install and register provider binaries & validate Windows password BEFORE touching the card!
            let install_summary = installer::install_and_register()?;

            let user =
                scard_core::current_user().map_err(|e| format!("Account lookup failed: {e}"))?;
            let safety =
                verify_local_workgroup_account(&user.username).map_err(|e| e.to_string())?;
            validate_windows_password(&user, &password)
                .map_err(|e| format!("Windows password validation failed: {e}"))?;
            let last_set =
                password_last_set_for_enrollment(&user.username).map_err(|e| e.to_string())?;

            let mut mgmt_rotated = false;
            if let Some(plan) = &provision_plan {
                post_status(
                    hwnd_raw,
                    format!(
                        "Provisioning on-card ECC P-256 key (Touch = {})...",
                        format_touch_policy(Some(plan.touch_policy_9d))
                    ),
                );
                let prov_res = provision_card(&CardProvisionOptions {
                    reader: None,
                    pin: Some(pin.as_bytes()),
                    touch_policy_9d: plan.touch_policy_9d,
                    provision_9e: plan.provision_9e,
                    current_mgmt_key_hex: Some(plan.current_mgmt_hex.as_str())
                        .filter(|s| !s.trim().is_empty()),
                    new_mgmt_key_hex: Some(plan.new_mgmt_hex.as_str())
                        .filter(|s| !s.trim().is_empty()),
                })
                .map_err(|e| format!("Card key provisioning failed: {e}"))?;
                mgmt_rotated = prov_res.mgmt_key_rotated;
            }

            let enrolled = enroll_with_options(&EnrollOptions {
                reader: None,
                password: &password,
                sid: &user.sid,
                username: &user.username,
                computer: &user.computer,
                password_last_set: last_set,
                attestation_policy: AttestationPolicy::EnforceOrPinFirstUse,
            })
            .map_err(|e| format!("Enrollment failed: {e}"))?;

            stage_pending_vault_with_backup(&user.sid, &enrolled.vault)
                .map_err(|e| format!("Vault staging failed: {e}"))?;
            write_vault(&user.sid, &enrolled.vault)
                .map_err(|e| format!("Vault write failed: {e}"))?;
            write_touch_policy(&user.sid, enrolled.touch_policy)
                .map_err(|e| format!("Touch policy write failed: {e}"))?;
            if let Some(pub_9e) = &enrolled.card_auth_9e_pub {
                write_card_auth_9e_pub(&user.sid, pub_9e)
                    .map_err(|e| format!("0x9E key write failed: {e}"))?;
            } else {
                let _ = clear_card_auth_9e_pub(&user.sid);
            }

            if enrolled.touch_policy == TOUCH_POLICY_CACHED {
                post_status(
                    hwnd_raw,
                    "ACTION REQUIRED: Press your blinking security key ONCE now (Touch=CACHED self-test)...",
                );
            } else if enrolled.touch_policy == TOUCH_POLICY_ALWAYS {
                post_status(
                    hwnd_raw,
                    "ACTION REQUIRED: Press your blinking security key TWICE now (Touch=ALWAYS self-test)...",
                );
            }

            self_test_internal(&pin, &password, &user)?;
            let _ = purge_vault_backup(&user.sid);

            let f9_status = match (enrolled.f9_fingerprint, enrolled.f9_newly_pinned) {
                (Some(fp), true) => format!("{} (verified & newly pinned)", hex::encode(fp)),
                (Some(fp), false) => format!("{} (verified against pinned root)", hex::encode(fp)),
                (None, _) => "(card did not return 0xF9 attestation)".into(),
            };
            let guard_9e = if enrolled.card_auth_9e_pub.is_some() {
                "enabled (slot 0x9E P-256 PIN=NEVER verified)"
            } else {
                "not configured (optional: provision slot 0x9E P-256 PIN=NEVER)"
            };

            let mut msg = format!(
                "Re-bind complete (existing password kept).\r\n\
                 Account:        {}\\{}\r\n\
                 SID:            {}\r\n\
                 Card:           {}\r\n\
                 9D Fingerprint: {}\r\n\
                 9D Touch:       {}\r\n\
                 0xF9 Root:      {}\r\n\
                 Pre-PIN 0x9E:   {}\r\n\
                 Self-Test:      succeeded\r\n\
                 {}\r\n",
                user.domain,
                user.username,
                user.sid,
                enrolled.card_name.as_deref().unwrap_or("(unknown)"),
                hex::encode(enrolled.card_pub_fingerprint),
                format_touch_policy(Some(enrolled.touch_policy)),
                f9_status,
                guard_9e,
                install_summary
            );
            if mgmt_rotated {
                msg.push_str(
                    "\r\n0x9B MGMT KEY ROTATED: Keep your new hex 0x9B Management Key stored safely offline.\r\n",
                );
            }
            if safety.lockout_threshold == 0 {
                msg.push_str(
                    "\r\nSECURITY NOTE: Account Lockout Threshold is 0 while keeping an existing password.\r\n\
                     Prefer 'Set up & rotate password' (180-bit random password, which needs no lockout threshold and avoids sole-admin DoS).\r\n\
                     If you manually enable account lockout (`net accounts /lockoutthreshold:5 /lockoutduration:10`), never set permanent lockout on a sole admin account.\r\n",
                );
            }
            if enrolled.pin_is_default || enrolled.puk_is_default {
                msg.push_str(
                    "\r\nSECURITY WARNING: Your smart card PIN (123456) and/or PUK (12345678) is still set to the factory default!\r\n\
                     Click 'Unblock PIN / PUK...' to set a custom PUK and PIN before production deployment.\r\n",
                );
            }
            if enrolled.touch_policy == TOUCH_POLICY_NEVER {
                msg.push_str(
                    "\r\nADVISORY: Slot 0x9D has Touch Policy = NEVER. Consider Touch Policy = ALWAYS when using RDP smart-card redirection.\r\n",
                );
            }
            Ok(msg)
        })();

        match res {
            Ok(report) => post_outcome(
                hwnd_raw,
                WorkerOutcome::SimpleDone {
                    status: "Account re-bound and provider registered. Lock the screen to test."
                        .into(),
                    output: Some(report),
                    clear_secrets: true,
                    critical_modal_error: None,
                },
            ),
            Err(err) => post_outcome(
                hwnd_raw,
                WorkerOutcome::SimpleDone {
                    status: err.clone(),
                    output: Some(format!("{err}\r\n")),
                    clear_secrets: false,
                    critical_modal_error: None,
                },
            ),
        }
    });
}

unsafe fn start_self_test(hwnd: HWND) {
    let (pin, expected) = unsafe {
        let Some(st) = state_mut(hwnd) else {
            return;
        };
        if st.busy {
            return;
        }
        (read_edit(st.pin), read_edit(st.password))
    };

    if !valid_pin(&pin) {
        unsafe { set_status(hwnd, "PIV PIN must be 6-8 ASCII digits.") };
        return;
    }

    unsafe {
        set_busy(
            hwnd,
            true,
            "Running stored-vault Familiar Smartcard unlock self-test...",
        )
    };
    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || {
        let res = scard_core::current_user()
            .map_err(|e| format!("Account lookup failed: {e}"))
            .and_then(|user| self_test_internal(&pin, &expected, &user));
        match res {
            Ok(()) => post_outcome(
                hwnd_raw,
                WorkerOutcome::SimpleDone {
                    status: "Self-test succeeded: Familiar Smartcard unlocked and verified the bound vault."
                        .into(),
                    output: None,
                    clear_secrets: false,
                    critical_modal_error: None,
                },
            ),
            Err(err) => post_outcome(
                hwnd_raw,
                WorkerOutcome::SimpleDone {
                    status: format!("Self-test failed: {err}"),
                    output: Some(format!("Self-test failed: {err}\r\n")),
                    clear_secrets: false,
                    critical_modal_error: None,
                },
            ),
        }
    });
}

unsafe fn start_repin_card_root(hwnd: HWND) {
    unsafe {
        if state_mut(hwnd).map(|s| s.busy).unwrap_or(true) {
            return;
        }
    }

    let confirm = unsafe {
        MessageBoxW(
            Some(hwnd),
            w!("Replace the machine-pinned 0xF9 attestation root with the currently connected PIV smart card?\r\n\r\n\
                Only do this after replacing your physical smart card, factory-resetting its PIV applet, \
                or regenerating its device attestation key."),
            w!("Confirm Re-pin Card Attestation Root"),
            MB_YESNO | MB_ICONWARNING,
        )
    };
    if confirm.0 != 6 {
        return;
    }

    unsafe {
        set_busy(
            hwnd,
            true,
            "Verifying 0x9D/0xF9 attestation chain and pinning root...",
        )
    };
    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || match repin_connected_card_attestation(None) {
        Ok(fp) => {
            let hex_fp = hex::encode(fp);
            post_outcome(
                hwnd_raw,
                WorkerOutcome::SimpleDone {
                    status: "Pinned new 0xF9 card attestation root in HKLM.".into(),
                    output: Some(format!(
                        "Verified 0x9D/0xF9 attestation signature and updated HKLM pin:\r\n  Pinned 0xF9 SHA-256: {hex_fp}\r\n"
                    )),
                    clear_secrets: false,
                    critical_modal_error: None,
                },
            );
        }
        Err(err) => post_outcome(
            hwnd_raw,
            WorkerOutcome::SimpleDone {
                status: format!("Re-pin failed: {err}"),
                output: Some(format!("Re-pin card root failed: {err}\r\n")),
                clear_secrets: false,
                critical_modal_error: None,
            },
        ),
    });
}

unsafe fn start_register_provider(hwnd: HWND) {
    unsafe {
        if state_mut(hwnd).map(|s| s.busy).unwrap_or(true) {
            return;
        }
        set_busy(
            hwnd,
            true,
            "Installing binaries and registering Credential Provider...",
        );
    }
    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || match installer::install_and_register() {
        Ok(summary) => post_outcome(
            hwnd_raw,
            WorkerOutcome::SimpleDone {
                status: "Sign-in provider installed and registered.".into(),
                output: Some(format!("{summary}\r\n")),
                clear_secrets: false,
                critical_modal_error: None,
            },
        ),
        Err(err) => post_outcome(
            hwnd_raw,
            WorkerOutcome::SimpleDone {
                status: format!("Provider registration failed: {err}"),
                output: Some(format!("Provider registration failed:\r\n{err}\r\n")),
                clear_secrets: false,
                critical_modal_error: None,
            },
        ),
    });
}

unsafe fn handle_worker_outcome(hwnd: HWND, outcome: WorkerOutcome) {
    // SAFETY: Invoked on main UI thread from `WM_WORKER_RESULT`.
    unsafe {
        match outcome {
            WorkerOutcome::ProbeDone {
                status,
                output,
                piv_card_without_9d,
            } => {
                if piv_card_without_9d {
                    if let Some(st) = state_mut(hwnd) {
                        if !st.user_touched_provision_mode {
                            let _ = SendMessageW(
                                st.radio_keep,
                                BM_SETCHECK,
                                Some(WPARAM(BST_UNCHECKED)),
                                Some(LPARAM(0)),
                            );
                            let _ = SendMessageW(
                                st.radio_touch_always,
                                BM_SETCHECK,
                                Some(WPARAM(BST_UNCHECKED)),
                                Some(LPARAM(0)),
                            );
                            let _ = SendMessageW(
                                st.radio_touch_never,
                                BM_SETCHECK,
                                Some(WPARAM(BST_UNCHECKED)),
                                Some(LPARAM(0)),
                            );
                            let _ = SendMessageW(
                                st.radio_touch_cached,
                                BM_SETCHECK,
                                Some(WPARAM(BST_CHECKED)),
                                Some(LPARAM(0)),
                            );
                        }
                    }
                }
                set_busy(hwnd, false, &status);
                if let Some(text) = output {
                    set_output(hwnd, &text);
                }
            }
            WorkerOutcome::SimpleDone {
                status,
                output,
                clear_secrets,
                critical_modal_error,
            } => {
                if clear_secrets {
                    // After successful enrollment, switch radio back to Keep existing key
                    // so subsequent actions do not re-overwrite the newly enrolled key.
                    if let Some(st) = state_mut(hwnd) {
                        scrub_edit_control(st.pin);
                        scrub_edit_control(st.password);
                        scrub_edit_control(st.mgmt_cur);
                        scrub_edit_control(st.mgmt_new);
                        let _ = SendMessageW(
                            st.radio_touch_cached,
                            BM_SETCHECK,
                            Some(WPARAM(BST_UNCHECKED)),
                            Some(LPARAM(0)),
                        );
                        let _ = SendMessageW(
                            st.radio_touch_always,
                            BM_SETCHECK,
                            Some(WPARAM(BST_UNCHECKED)),
                            Some(LPARAM(0)),
                        );
                        let _ = SendMessageW(
                            st.radio_touch_never,
                            BM_SETCHECK,
                            Some(WPARAM(BST_UNCHECKED)),
                            Some(LPARAM(0)),
                        );
                        let _ = SendMessageW(
                            st.radio_keep,
                            BM_SETCHECK,
                            Some(WPARAM(BST_CHECKED)),
                            Some(LPARAM(0)),
                        );
                    }
                }
                set_busy(hwnd, false, &status);
                if let Some(text) = output {
                    set_output(hwnd, &text);
                }
                if let Some(alert) = critical_modal_error {
                    let alert_w = to_wide(&alert);
                    let _ = MessageBoxW(
                        Some(hwnd),
                        PCWSTR(alert_w.as_ptr()),
                        w!("Familiar Smartcard — Action Required"),
                        MB_OK | MB_ICONERROR,
                    );
                }
            }
            WorkerOutcome::RotationCandidateReady(prepared) => {
                set_busy(
                    hwnd,
                    false,
                    "Card self-test passed! Record and confirm your recovery sheet to apply.",
                );
                let sheet = RecoverySheet {
                    computer: &prepared.user.computer,
                    domain: &prepared.user.domain,
                    username: &prepared.user.username,
                    sid: &prepared.user.sid,
                    card_name: &prepared.card_name,
                    card_fingerprint_hex: &prepared.fingerprint_hex,
                    password: &prepared.new_password,
                    created_utc_unix: prepared.candidate_vault.created_at,
                };
                if confirm_recovery_sheet(hwnd, &sheet) {
                    commit_confirmed_rotation(hwnd, *prepared);
                } else {
                    drop(prepared);
                    set_status(
                        hwnd,
                        "Setup cancelled at recovery confirmation. Your Windows password was NOT changed.",
                    );
                }
            }
        }
    }
}

fn self_test_internal(pin: &str, expected_password: &str, user: &UserInfo) -> Result<(), String> {
    let vault = read_vault(&user.sid)
        .map_err(|error| format!("Vault read failed: {error}"))?
        .ok_or_else(|| "No vault is bound to this account.".to_string())?;

    let current_ts =
        password_last_set(&user.username).map_err(|e| format!("Timestamp lookup failed: {e}"))?;
    if !scard_core::vault::password_last_set_matches(vault.password_last_set, current_ts) {
        return Err(
            "The Windows password has changed since enrollment; re-enrollment is required.".into(),
        );
    }

    let pin_bytes = Zeroizing::new(pin.as_bytes().to_vec());
    let connected =
        scard_core::AuthPipeline::start(vault, &user.sid, &user.username, &user.computer)
            .and_then(|loaded| loaded.connect_card(None))
            .map_err(|error| format!("Card connection failed: {error}"))?;
    if let Ok(Some(pub_9e)) = read_card_auth_9e_pub(&user.sid) {
        connected
            .verify_pre_pin_card_auth(&pub_9e)
            .map_err(|error| {
                format!("Pre-PIN 0x9E hardware anti-phishing check failed: {error}")
            })?;
    }
    let strict_two_touches = connected.detected_touch_policy() == TOUCH_POLICY_ALWAYS;
    let decrypted = connected
        .verify_pin(&pin_bytes)
        .and_then(|v| {
            if strict_two_touches {
                v.prove_freshness()
                    .and_then(|f| f.verify_pin_for_unwrap(&pin_bytes))
                    .and_then(|u| u.unwrap_dek())
            } else {
                v.unwrap_dek_blinded_single_touch()
            }
        })
        .and_then(|k| k.decrypt_credential())
        .map(|c| c.into_password())
        .map_err(|error| format!("Unlock failed: {error}"))?;

    if !expected_password.is_empty()
        && !scard_core::crypto::constant_time_eq(decrypted.as_bytes(), expected_password.as_bytes())
    {
        return Err("Decrypted vault password does not match the entered password.".into());
    }
    Ok(())
}

fn validate_windows_password(user: &UserInfo, password: &str) -> Result<(), String> {
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
    let password_w: Zeroizing<Vec<u16>> =
        Zeroizing::new(password.encode_utf16().chain(std::iter::once(0)).collect());
    let mut token = HANDLE::default();

    // SAFETY: Validates credentials against local LSA without creating an interactive profile.
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
    // SAFETY: Close returned logon token immediately.
    unsafe {
        let _ = CloseHandle(token);
    }
    Ok(())
}

unsafe fn scrub_edit_control(hwnd: HWND) {
    if !hwnd.0.is_null() {
        let dummy = w!("00000000000000000000000000000000");
        // SAFETY: Overwrites internal Win32 Edit control buffer before clearing.
        unsafe {
            let _ = SetWindowTextW(hwnd, dummy);
            let _ = SetWindowTextW(hwnd, PCWSTR::null());
        }
    }
}

unsafe fn read_edit(hwnd: HWND) -> Zeroizing<String> {
    // SAFETY: Queries edit control length and copies into a `Zeroizing<Vec<u16>>`.
    unsafe {
        let length = GetWindowTextLengthW(hwnd);
        if length <= 0 {
            return Zeroizing::new(String::new());
        }
        let mut buffer = Zeroizing::new(vec![0u16; length as usize + 1]);
        let copied = GetWindowTextW(hwnd, buffer.as_mut_slice());
        let valid = copied.max(0) as usize;
        Zeroizing::new(String::from_utf16_lossy(&buffer[..valid]))
    }
}

fn valid_pin(pin: &str) -> bool {
    (6..=8).contains(&pin.len()) && pin.chars().all(|c| c.is_ascii_digit())
}

fn format_pin_policy(slot: u8, v: Option<u8>) -> &'static str {
    match v {
        Some(PIN_POLICY_NEVER) if slot == 0x9D => "NEVER (rejected for 0x9D)",
        Some(PIN_POLICY_NEVER) => "NEVER",
        Some(PIN_POLICY_ONCE) if slot == 0x9D => "ONCE (rejected for 0x9D)",
        Some(PIN_POLICY_ONCE) => "ONCE",
        Some(PIN_POLICY_ALWAYS) => "ALWAYS",
        Some(_) => "unknown",
        None => "n/a",
    }
}

fn format_touch_policy(v: Option<u8>) -> &'static str {
    match v {
        Some(TOUCH_POLICY_NEVER) => "NEVER",
        Some(TOUCH_POLICY_ALWAYS) => "ALWAYS (2 touches)",
        Some(TOUCH_POLICY_CACHED) => "CACHED (1 touch + reset)",
        Some(_) => "unknown",
        None => "n/a",
    }
}

fn format_origin(v: Option<u8>) -> &'static str {
    match v {
        Some(ORIGIN_GENERATED) => "On-card",
        Some(ORIGIN_IMPORTED) => "Imported (rejected)",
        Some(_) => "unknown",
        None => "n/a",
    }
}

fn format_mgmt_alg(v: Option<u8>) -> &'static str {
    match v {
        Some(ALG_3DES) => "3DES (24B)",
        Some(ALG_AES_128) => "AES-128 (16B)",
        Some(ALG_AES_192) => "AES-192 (24B)",
        Some(ALG_AES_256) => "AES-256 (32B)",
        Some(_) => "unknown",
        None => "n/a",
    }
}

fn format_mgmt_line(meta: &Option<MgmtKeyMetadata>) -> String {
    let Some(m) = meta else {
        return "  Mgmt Key (0x9B): metadata not reported\r\n".into();
    };
    let def_note = match m.is_default {
        Some(true) => " [FACTORY DEFAULT 010203...08 — rotation optional]",
        Some(false) => " [custom / PIN-protected]",
        None => "",
    };
    format!(
        "  Mgmt Key (0x9B): alg={}{def_note}\r\n",
        format_mgmt_alg(m.algorithm)
    )
}

fn format_pin_puk_line(label: &str, default_val: &str, meta: &Option<PinPukMetadata>) -> String {
    let Some(m) = meta else {
        return format!("  {label}: not reported\r\n");
    };
    let retries = match (m.remaining_retries, m.total_retries) {
        (Some(0), Some(tot)) => format!("0/{tot} (BLOCKED)"),
        (Some(0), None) => "0 (BLOCKED)".into(),
        (Some(rem), Some(tot)) => format!("{rem}/{tot} attempts remaining"),
        (Some(rem), None) => format!("{rem} attempt(s) remaining"),
        (None, _) => "retries unknown".into(),
    };
    let def_note = match m.is_default {
        Some(true) => format!(" [FACTORY DEFAULT {default_val} — change recommended]"),
        Some(false) => " [custom]".into(),
        None => String::new(),
    };
    format!("  {label}: {retries}{def_note}\r\n")
}

fn format_readers(readers: &[scard_core::ReaderProbe], pinned_f9: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(pin_hex) = pinned_f9 {
        out.push_str(&format!("Machine-pinned 0xF9 root: {pin_hex}\r\n\r\n"));
    } else {
        out.push_str(
            "Machine-pinned 0xF9 root: (not pinned yet — will pin on first enrollment)\r\n\r\n",
        );
    }

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
            out.push_str(&format_pin_puk_line(
                "PIN Status",
                "123456",
                &reader.pin_metadata,
            ));
            out.push_str(&format_pin_puk_line(
                "PUK Status",
                "12345678",
                &reader.puk_metadata,
            ));
            out.push_str(&format_mgmt_line(&reader.mgmt_metadata));
            match (&reader.f9_fingerprint_hex, reader.attestation_verified) {
                (Some(f9_hex), true) => {
                    let pin_match = match pinned_f9 {
                        Some(p) if p.eq_ignore_ascii_case(f9_hex) => "matches machine pin",
                        Some(_) => "MISMATCH with machine pin (run Re-pin card root if expected)",
                        None => "verified (unpinned)",
                    };
                    out.push_str(&format!("  0xF9 Attestation: {f9_hex} ({pin_match})\r\n"));
                }
                _ => {
                    out.push_str("  0xF9 Attestation: not available\r\n");
                }
            }
        } else {
            out.push_str("  PIV: not selected\r\n");
        }
        if let Some(error) = &reader.error {
            out.push_str(&format!("  Error: {error}\r\n"));
        }
        for slot in &reader.slots {
            if slot.has_key {
                let policy_desc = if let Some(pol) = &slot.policy {
                    format!(
                        " [alg=0x{:02X}, pin={}, touch={}, origin={}]",
                        pol.algorithm.unwrap_or(0),
                        format_pin_policy(slot.slot, pol.pin_policy),
                        format_touch_policy(pol.touch_policy),
                        format_origin(pol.origin)
                    )
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "  Slot 0x{:02X}: key present{policy_desc}\r\n",
                    slot.slot
                ));
                if let Some(err) = &slot.policy_error {
                    out.push_str(&format!("    Policy error: {err}\r\n"));
                }
            } else {
                out.push_str(&format!("  Slot 0x{:02X}: no key\r\n", slot.slot));
            }
        }
        out.push_str("\r\n");
    }
    out
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
