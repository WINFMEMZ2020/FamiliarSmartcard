//! Same-session isolated authentication helper (`familiar-auth-helper.exe`).
//!
//! Spawned by `familiar_cred_provider.dll` inside `LogonUI.exe` with `CREATE_NO_WINDOW`
//! and anonymous `stdin`/`stdout` pipes. Running in the same interactive or RDP
//! session allows `SCardEstablishContext(SCARD_SCOPE_USER)` to access client
//! smart-card readers redirected over RDP while allowing `LogonUI.exe` to
//! enforce a hard `TerminateProcess` timeout if PC/SC hangs.

#![forbid(unsafe_code)]

use scard_core::ipc::{read_framed, write_framed, HelperIcon, HelperRequest, HelperResponse};
use scard_core::AuthError;
use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Install a silent panic hook so no internal state or stack value is ever
    // written to standard streams.
    std::panic::set_hook(Box::new(|_| {}));

    // Optional deterministic hang mode used ONLY by automated timeout tests.
    if let Some(hang_arg) = std::env::args().nth(1) {
        if hang_arg == "--test-simulate-hang" {
            std::thread::sleep(std::time::Duration::from_secs(30));
            return ExitCode::from(2);
        }
    }

    let response = match std::panic::catch_unwind(run_once) {
        Ok(resp) => resp,
        Err(_) => HelperResponse::Failure {
            icon: HelperIcon::Error,
            message: "Authentication helper encountered an unexpected internal error.".into(),
        },
    };

    if let Ok(encoded) = response.encode() {
        let stdout = io::stdout();
        let _ = write_framed(stdout.lock(), &encoded);
    }

    ExitCode::SUCCESS
}

fn run_once() -> HelperResponse {
    let stdin = io::stdin();
    let raw_req = match read_framed(stdin.lock()) {
        Ok(frame) => frame,
        Err(_) => {
            return HelperResponse::Failure {
                icon: HelperIcon::Error,
                message: "Failed to read authentication request from LogonUI.".into(),
            };
        }
    };

    let mut req = match HelperRequest::decode(&raw_req) {
        Ok(req) => req,
        Err(_) => {
            return HelperResponse::Failure {
                icon: HelperIcon::Error,
                message: "Malformed authentication request.".into(),
            };
        }
    };

    let vault = match scard_core::storage::read_vault(&req.sid) {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            return HelperResponse::Failure {
                icon: HelperIcon::Error,
                message: "This account is not bound to an RS-Key.".into(),
            };
        }
        Err(error) => {
            return HelperResponse::Failure {
                icon: HelperIcon::Error,
                message: format_user_error(&error),
            };
        }
    };

    let current_last_set = match scard_core::account::password_last_set(&req.username) {
        Ok(value) => value,
        Err(_) => {
            return HelperResponse::Failure {
                icon: HelperIcon::Error,
                message: "Could not verify local account state.".into(),
            };
        }
    };

    if !scard_core::vault::password_last_set_matches(vault.password_last_set, current_last_set) {
        return HelperResponse::Failure {
            icon: HelperIcon::Error,
            message:
                "The Windows password has changed; sign in with your recovery password and re-enroll."
                    .into(),
        };
    }

    match scard_core::unlock(
        vault,
        &req.sid,
        &req.username,
        &req.computer,
        None,
        &mut req.pin,
    ) {
        Ok(password) => HelperResponse::Success { password },
        Err(error) => HelperResponse::Failure {
            icon: icon_for_error(&error),
            message: format_user_error(&error),
        },
    }
}

fn icon_for_error(error: &AuthError) -> HelperIcon {
    match error {
        AuthError::NoReader | AuthError::NoCard | AuthError::CardBusy | AuthError::Timeout => {
            HelperIcon::Warning
        }
        _ => HelperIcon::Error,
    }
}

fn format_user_error(error: &AuthError) -> String {
    match error {
        AuthError::NoReader => {
            "No smart card reader detected. Insert your RS-Key (or enable Smart Cards in RDP)."
                .into()
        }
        AuthError::NoCard => "No RS-Key present in reader.".into(),
        AuthError::CardBusy => {
            "RS-Key is busy in another application. Close other smart-card apps and try again."
                .into()
        }
        AuthError::Timeout => "Smart card operation timed out or was cancelled.".into(),
        AuthError::WrongCard => "The connected key does not match the enrolled RS-Key.".into(),
        AuthError::PinIncorrect(rem) => {
            format!("Incorrect RS-Key PIN ({rem} attempt(s) remaining).")
        }
        AuthError::PinBlocked => {
            "RS-Key PIN is blocked. Use your recovery password or unblock with PUK.".into()
        }
        AuthError::Apdu {
            sw1: 0x69,
            sw2: 0x82,
        } => "Card security status not satisfied (touch confirmation may have timed out).".into(),
        other => other.to_string(),
    }
}
