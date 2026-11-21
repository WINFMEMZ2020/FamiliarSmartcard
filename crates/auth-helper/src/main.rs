//! Same-session isolated authentication helper (`familiar-auth-helper.exe`).
//!
//! Spawned by `familiar_cred_provider.dll` inside `LogonUI.exe` with `CREATE_NO_WINDOW`
//! and anonymous `stdin`/`stdout` pipes. Running in the same interactive or RDP
//! session allows `SCardEstablishContext(SCARD_SCOPE_USER)` to access client
//! smart-card readers redirected over RDP while allowing `LogonUI.exe` to
//! enforce a hard `TerminateProcess` timeout if PC/SC hangs.

#![forbid(unsafe_code)]

use scard_core::ipc::{
    read_framed, write_framed, HelperFailureReason, HelperIcon, HelperOperation, HelperRequest,
    HelperResponse,
};
use scard_core::storage::{
    check_last_attempt_cooldown, clear_last_attempt_cooldown, start_last_attempt_cooldown,
    LAST_ATTEMPT_COOLDOWN_SECS,
};
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
            reason: HelperFailureReason::Generic,
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
                reason: HelperFailureReason::Generic,
                icon: HelperIcon::Error,
                message: "Failed to read authentication request from LogonUI.".into(),
            };
        }
    };

    let req = match HelperRequest::decode(&raw_req) {
        Ok(req) => req,
        Err(_) => {
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: HelperIcon::Error,
                message: "Malformed authentication request.".into(),
            };
        }
    };

    let vault = match scard_core::storage::read_vault(&req.sid) {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: HelperIcon::Error,
                message: "This account is not bound to an RS-Key.".into(),
            };
        }
        Err(error) => {
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: HelperIcon::Error,
                message: format_user_error(&error),
            };
        }
    };

    let current_last_set = match scard_core::account::password_last_set(&req.username) {
        Ok(value) => value,
        Err(_) => {
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: HelperIcon::Error,
                message: "Could not verify local account state.".into(),
            };
        }
    };

    if !scard_core::vault::password_last_set_matches(vault.password_last_set, current_last_set) {
        return HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: HelperIcon::Error,
            message:
                "The Windows password has changed; sign in with your recovery password and re-enroll."
                    .into(),
        };
    }

    match req.operation {
        HelperOperation::Unlock { mut pin } => {
            handle_unlock(vault, &req.sid, &req.username, &req.computer, &mut pin)
        }
        HelperOperation::UnblockAndUnlock { puk, mut new_pin } => handle_unblock_and_unlock(
            vault,
            &req.sid,
            &req.username,
            &req.computer,
            &puk,
            &mut new_pin,
        ),
    }
}

fn handle_unlock(
    vault: scard_core::VaultBlob,
    sid: &str,
    username: &str,
    computer: &str,
    pin: &mut zeroize::Zeroizing<Vec<u8>>,
) -> HelperResponse {
    // Enforce the 60s safety cooldown before allowing the final (3rd) PIN attempt.
    if let Ok(Some(rem_secs)) = check_last_attempt_cooldown(&vault.card_pub_fingerprint) {
        match scard_core::query_card_pin_remaining(None, &vault.card_pub_fingerprint) {
            Ok(Some(0)) => {
                let _ = clear_last_attempt_cooldown(&vault.card_pub_fingerprint);
                return HelperResponse::Failure {
                    reason: HelperFailureReason::PinBlocked,
                    icon: HelperIcon::Error,
                    message: "RS-Key PIN is blocked (0 attempts left). Enter your PUK and a new PIN to unblock and sign in.".into(),
                };
            }
            Ok(Some(r)) if r > 1 => {
                // Card was already unblocked/verified elsewhere; clear stale cooldown.
                let _ = clear_last_attempt_cooldown(&vault.card_pub_fingerprint);
            }
            Ok(_) => {
                return HelperResponse::Failure {
                    reason: HelperFailureReason::CooldownActive,
                    icon: HelperIcon::Warning,
                    message: format!(
                        "Final PIN attempt safety cooldown active ({rem_secs}s remaining). Only 1 hardware attempt left — double-check your PIN, or click 'PIN blocked? Unblock with PUK'."
                    ),
                };
            }
            Err(error) => {
                return HelperResponse::Failure {
                    reason: HelperFailureReason::Generic,
                    icon: icon_for_error(&error),
                    message: format_user_error(&error),
                };
            }
        }
    }

    let card_fp = vault.card_pub_fingerprint;
    match scard_core::unlock(vault, sid, username, computer, None, pin) {
        Ok(password) => {
            let _ = clear_last_attempt_cooldown(&card_fp);
            HelperResponse::Success { password }
        }
        Err(AuthError::PinIncorrect(1)) => {
            let _ = start_last_attempt_cooldown(&card_fp, LAST_ATTEMPT_COOLDOWN_SECS);
            HelperResponse::Failure {
                reason: HelperFailureReason::CooldownActive,
                icon: HelperIcon::Warning,
                message: format!(
                    "Incorrect RS-Key PIN — ONLY 1 ATTEMPT REMAINING before hardware lock! Waiting {LAST_ATTEMPT_COOLDOWN_SECS}s safety cooldown before your final try."
                ),
            }
        }
        Err(AuthError::PinIncorrect(0)) | Err(AuthError::PinBlocked) => {
            let _ = clear_last_attempt_cooldown(&card_fp);
            HelperResponse::Failure {
                reason: HelperFailureReason::PinBlocked,
                icon: HelperIcon::Error,
                message: "RS-Key PIN is blocked (0 attempts left). Enter your PUK and a new PIN to unblock and sign in.".into(),
            }
        }
        Err(error) => HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: icon_for_error(&error),
            message: format_user_error(&error),
        },
    }
}

fn handle_unblock_and_unlock(
    vault: scard_core::VaultBlob,
    sid: &str,
    username: &str,
    computer: &str,
    puk: &zeroize::Zeroizing<Vec<u8>>,
    new_pin: &mut zeroize::Zeroizing<Vec<u8>>,
) -> HelperResponse {
    let card_fp = vault.card_pub_fingerprint;
    if let Err(error) =
        scard_core::unblock_card_pin(None, Some(&card_fp), puk.as_slice(), new_pin.as_slice())
    {
        return match error {
            AuthError::PukIncorrect(rem) => HelperResponse::Failure {
                reason: HelperFailureReason::PukIncorrect,
                icon: HelperIcon::Error,
                message: format!("Incorrect RS-Key PUK ({rem} PUK attempt(s) remaining)."),
            },
            AuthError::PukBlocked => HelperResponse::Failure {
                reason: HelperFailureReason::PukBlocked,
                icon: HelperIcon::Error,
                message: "RS-Key PUK is permanently blocked. Sign in with your Windows password and reset the PIV applet.".into(),
            },
            other => HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: icon_for_error(&other),
                message: format_user_error(&other),
            },
        };
    }

    let _ = clear_last_attempt_cooldown(&card_fp);

    match scard_core::unlock(vault, sid, username, computer, None, new_pin) {
        Ok(password) => HelperResponse::Success { password },
        Err(error) => HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: icon_for_error(&error),
            message: format!(
                "RS-Key PIN was unblocked, but completing sign-in failed: {}",
                format_user_error(&error)
            ),
        },
    }
}

fn icon_for_error(error: &AuthError) -> HelperIcon {
    match error {
        AuthError::NoReader
        | AuthError::NoCard
        | AuthError::CardBusy
        | AuthError::Timeout
        | AuthError::LastAttemptCooldown { .. } => HelperIcon::Warning,
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
            "RS-Key PIN is blocked. Enter your PUK and a new PIN to unblock.".into()
        }
        AuthError::PukIncorrect(rem) => {
            format!("Incorrect RS-Key PUK ({rem} PUK attempt(s) remaining).")
        }
        AuthError::PukBlocked => {
            "RS-Key PUK is permanently blocked. Sign in with your Windows password.".into()
        }
        AuthError::Apdu {
            sw1: 0x69,
            sw2: 0x82,
        } => "Card security status not satisfied (touch confirmation may have timed out).".into(),
        other => other.to_string(),
    }
}
