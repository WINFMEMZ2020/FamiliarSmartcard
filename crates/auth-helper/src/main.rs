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
    check_last_attempt_cooldown, clear_last_attempt_cooldown, read_card_auth_9e_pub,
    start_last_attempt_cooldown, LAST_ATTEMPT_COOLDOWN_SECS,
};
use scard_core::AuthError;
use std::io;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const EXPLICIT_USER_UNIFORM_FLOOR: Duration = Duration::from_millis(220);
const EXPLICIT_USER_UNIFORM_MSG: &str =
    "Sign-in failed. Verify the local username, Familiar Smartcard enrollment, and credentials.";

fn main() -> ExitCode {
    // Install a silent panic hook so no internal state or stack value is ever
    // written to standard streams.
    std::panic::set_hook(Box::new(|_| {}));

    // Deterministic hang hook compiled ONLY in debug/test builds (`cargo test`),
    // completely stripped from `--release` production binaries.
    #[cfg(debug_assertions)]
    if let Some(hang_arg) = std::env::args().nth(1) {
        if hang_arg == "--test-simulate-hang" {
            std::thread::sleep(Duration::from_secs(30));
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

fn uniform_explicit_failure(started: Instant) -> HelperResponse {
    if let Some(rem) = EXPLICIT_USER_UNIFORM_FLOOR.checked_sub(started.elapsed()) {
        std::thread::sleep(rem);
    }
    HelperResponse::Failure {
        reason: HelperFailureReason::Generic,
        icon: HelperIcon::Error,
        message: EXPLICIT_USER_UNIFORM_MSG.into(),
    }
}

fn run_once() -> HelperResponse {
    let started = Instant::now();
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

    // ANTI-ENUMERATION FOR "OTHER USER" (`explicit_user == true`):
    // Check whether a PIV smart card is present in the session BEFORE looking up the
    // username! Callers without a card receive the exact same reader/card warning for
    // both existent and non-existent usernames; callers with an unrelated dummy card
    // receive the exact same 220ms-padded generic failure whether the username exists or not.
    let (sid, domain, username) = if req.explicit_user {
        if let Err(card_err) = scard_core::ensure_piv_card_present_in_session() {
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: icon_for_error(&card_err),
                message: format_user_error(&card_err),
            };
        }
        match scard_core::account::lookup_local_account_by_name(&req.username) {
            Ok(info) => (info.sid, info.domain, info.username),
            Err(_) => return uniform_explicit_failure(started),
        }
    } else {
        let resolved_domain = scard_core::account::lookup_account_by_sid(&req.sid)
            .map(|u| u.domain)
            .unwrap_or_else(|_| req.computer.clone());
        (req.sid.clone(), resolved_domain, req.username.clone())
    };

    let vault = match scard_core::storage::read_vault(&sid) {
        Ok(Some(vault)) => vault,
        Ok(None) => {
            if req.explicit_user {
                return uniform_explicit_failure(started);
            }
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: HelperIcon::Error,
                message: "This account is not bound to Familiar Smartcard.".into(),
            };
        }
        Err(error) => {
            if req.explicit_user {
                return uniform_explicit_failure(started);
            }
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: HelperIcon::Error,
                message: format_user_error(&error),
            };
        }
    };

    let opt_9e_pub = read_card_auth_9e_pub(&sid).ok().flatten();

    match req.operation {
        HelperOperation::Unlock { mut pin } => handle_unlock(
            vault,
            &sid,
            &domain,
            &username,
            &req.computer,
            opt_9e_pub.as_deref(),
            req.explicit_user,
            started,
            &mut pin,
        ),
        HelperOperation::UnblockAndUnlock { puk, mut new_pin } => handle_unblock_and_unlock(
            vault,
            &sid,
            &domain,
            &username,
            &req.computer,
            opt_9e_pub.as_deref(),
            req.explicit_user,
            started,
            &puk,
            &mut new_pin,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_unlock(
    vault: scard_core::VaultBlob,
    sid: &str,
    domain: &str,
    username: &str,
    computer: &str,
    opt_9e_pub: Option<&[u8]>,
    explicit_user: bool,
    started: Instant,
    pin: &mut zeroize::Zeroizing<Vec<u8>>,
) -> HelperResponse {
    let card_fp = vault.card_pub_fingerprint;
    let stored_pw_last_set = vault.password_last_set;

    let connected = match scard_core::AuthPipeline::start(vault, sid, username, computer)
        .and_then(|loaded| loaded.connect_card(None))
    {
        Ok(c) => c,
        Err(AuthError::WrongCard) if explicit_user => return uniform_explicit_failure(started),
        Err(error) => {
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: icon_for_error(&error),
                message: format_user_error(&error),
            };
        }
    };

    // Phase 4 Pre-PIN Hardware Anti-Phishing: when slot `0x9E` (`PIN=NEVER`) was bound
    // during enrollment, challenge `0x9E` BEFORE sending `VERIFY PIN` or revealing account state!
    if let Some(pub_9e) = opt_9e_pub {
        if let Err(err) = connected.verify_pre_pin_card_auth(pub_9e) {
            if explicit_user {
                return uniform_explicit_failure(started);
            }
            return HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: icon_for_error(&err),
                message: format_user_error(&err),
            };
        }
    }

    // Card identity is now matched! Verify static password-last-set marker.
    let Ok(current_last_set) = scard_core::account::password_last_set(username) else {
        return HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: HelperIcon::Error,
            message: "Could not verify local account state.".into(),
        };
    };
    if !scard_core::vault::password_last_set_matches(stored_pw_last_set, current_last_set) {
        return HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: HelperIcon::Error,
            message:
                "The Windows password has changed; sign in with your recovery password and re-enroll."
                    .into(),
        };
    }

    // Enforce the 60s safety cooldown INSIDE the exclusive PC/SC card transaction!
    if let Ok(Some(rem_secs)) = check_last_attempt_cooldown(&card_fp) {
        match connected.query_pin_remaining() {
            Ok(Some(0)) => {
                let _ = clear_last_attempt_cooldown(&card_fp);
                return HelperResponse::Failure {
                    reason: HelperFailureReason::PinBlocked,
                    icon: HelperIcon::Error,
                    message: "Familiar Smartcard PIN is blocked (0 attempts left). Enter your PUK and a new PIN to unblock and sign in.".into(),
                };
            }
            Ok(Some(r)) if r > 1 => {
                let _ = clear_last_attempt_cooldown(&card_fp);
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

    let unlock_res = connected
        .verify_pin(pin)
        .and_then(|v| v.prove_freshness())
        .and_then(|f| f.verify_pin_for_unwrap(pin))
        .and_then(|u| u.unwrap_dek())
        .and_then(|k| k.decrypt_credential())
        .map(|cred| cred.into_password());

    match unlock_res {
        Ok(password) => {
            let _ = clear_last_attempt_cooldown(&card_fp);
            HelperResponse::Success {
                domain: domain.to_string(),
                username: username.to_string(),
                password,
            }
        }
        Err(AuthError::PinIncorrect(1)) => {
            let _ = start_last_attempt_cooldown(&card_fp, LAST_ATTEMPT_COOLDOWN_SECS);
            HelperResponse::Failure {
                reason: HelperFailureReason::CooldownActive,
                icon: HelperIcon::Warning,
                message: format!(
                    "Incorrect Familiar Smartcard PIN — ONLY 1 ATTEMPT REMAINING before hardware lock! Waiting {LAST_ATTEMPT_COOLDOWN_SECS}s safety cooldown before your final try."
                ),
            }
        }
        Err(AuthError::PinIncorrect(0)) | Err(AuthError::PinBlocked) => {
            let _ = clear_last_attempt_cooldown(&card_fp);
            HelperResponse::Failure {
                reason: HelperFailureReason::PinBlocked,
                icon: HelperIcon::Error,
                message: "Familiar Smartcard PIN is blocked (0 attempts left). Enter your PUK and a new PIN to unblock and sign in.".into(),
            }
        }
        Err(error) => HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: icon_for_error(&error),
            message: format_user_error(&error),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_unblock_and_unlock(
    vault: scard_core::VaultBlob,
    sid: &str,
    domain: &str,
    username: &str,
    computer: &str,
    opt_9e_pub: Option<&[u8]>,
    explicit_user: bool,
    started: Instant,
    puk: &zeroize::Zeroizing<Vec<u8>>,
    new_pin: &mut zeroize::Zeroizing<Vec<u8>>,
) -> HelperResponse {
    let card_fp = vault.card_pub_fingerprint;
    let stored_pw_last_set = vault.password_last_set;

    if let Err(error) = scard_core::unblock_card_pin(
        None,
        Some(&card_fp),
        opt_9e_pub,
        true,
        puk.as_slice(),
        new_pin.as_slice(),
    ) {
        if matches!(error, AuthError::WrongCard) && explicit_user {
            return uniform_explicit_failure(started);
        }
        return match error {
            AuthError::PukIncorrect(1) => HelperResponse::Failure {
                reason: HelperFailureReason::CooldownActive,
                icon: HelperIcon::Warning,
                message: format!(
                    "Incorrect Familiar Smartcard PUK — ONLY 1 PUK ATTEMPT REMAINING before permanent applet lock! Waiting {LAST_ATTEMPT_COOLDOWN_SECS}s safety cooldown."
                ),
            },
            AuthError::PukIncorrect(rem) => HelperResponse::Failure {
                reason: HelperFailureReason::PukIncorrect,
                icon: HelperIcon::Error,
                message: format!(
                    "Incorrect Familiar Smartcard PUK ({rem} PUK attempt(s) remaining)."
                ),
            },
            AuthError::LastAttemptCooldown { remaining_secs } => HelperResponse::Failure {
                reason: HelperFailureReason::CooldownActive,
                icon: HelperIcon::Warning,
                message: format!(
                    "Final PUK attempt safety cooldown active ({remaining_secs}s remaining). Only 1 PUK attempt left before permanent card lock!"
                ),
            },
            AuthError::PukBlocked => HelperResponse::Failure {
                reason: HelperFailureReason::PukBlocked,
                icon: HelperIcon::Error,
                message: "Familiar Smartcard PUK is permanently blocked. Sign in with your Windows password and reset the PIV applet.".into(),
            },
            other => HelperResponse::Failure {
                reason: HelperFailureReason::Generic,
                icon: icon_for_error(&other),
                message: format_user_error(&other),
            },
        };
    }

    let _ = clear_last_attempt_cooldown(&card_fp);

    let Ok(current_last_set) = scard_core::account::password_last_set(username) else {
        return HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: HelperIcon::Error,
            message: "Could not verify local account state.".into(),
        };
    };
    if !scard_core::vault::password_last_set_matches(stored_pw_last_set, current_last_set) {
        return HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: HelperIcon::Error,
            message:
                "Familiar Smartcard PIN was unblocked, but the Windows password has changed; sign in with your recovery password and re-enroll."
                    .into(),
        };
    }

    match scard_core::unlock(vault, sid, username, computer, None, new_pin) {
        Ok(password) => HelperResponse::Success {
            domain: domain.to_string(),
            username: username.to_string(),
            password,
        },
        Err(error) => HelperResponse::Failure {
            reason: HelperFailureReason::Generic,
            icon: icon_for_error(&error),
            message: format!(
                "Familiar Smartcard PIN was unblocked, but completing sign-in failed: {}",
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
            "No smart card reader detected. Insert your Familiar Smartcard (or enable Smart Cards in RDP)."
                .into()
        }
        AuthError::NoCard => "No PIV smart card present in reader.".into(),
        AuthError::CardBusy => {
            "Smart card is busy in another application. Close other smart-card apps and try again."
                .into()
        }
        AuthError::Timeout => "Smart card operation timed out or was cancelled.".into(),
        AuthError::WrongCard => {
            "The connected card does not match the enrolled Familiar Smartcard.".into()
        }
        AuthError::PinIncorrect(rem) => {
            format!("Incorrect Familiar Smartcard PIN ({rem} attempt(s) remaining).")
        }
        AuthError::PinBlocked => {
            "Familiar Smartcard PIN is blocked. Enter your PUK and a new PIN to unblock.".into()
        }
        AuthError::PukIncorrect(rem) => {
            format!("Incorrect Familiar Smartcard PUK ({rem} PUK attempt(s) remaining).")
        }
        AuthError::PukBlocked => {
            "Familiar Smartcard PUK is permanently blocked. Sign in with your Windows password."
                .into()
        }
        AuthError::Apdu {
            sw1: 0x69,
            sw2: 0x82,
        } => "Card security status not satisfied (touch confirmation may have timed out).".into(),
        other => other.to_string(),
    }
}
