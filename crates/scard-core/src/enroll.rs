//! Enrollment: bind a Windows local-account password to a PIV 9D P-256 key.
//!
//! Security invariants:
//! - `Eph_Priv_enroll` exists only on the stack and is consumed by one ECDH.
//! - Only `Eph_Pub_enroll`, the wrapped DEK, and the encrypted password are
//!   persisted in `VaultBlob`.
//! - Slot `0x9D` must pass `validate_slot_9d_policy` (`ECCP256`, `PIN ALWAYS`,
//!   `On-card` origin).
//! - When the card supports `00 F9` attestation, `0x9D` is verified against the
//!   card's `0xF9` CA certificate and checked against (or pinned into) `HKLM`.

#![forbid(unsafe_code)]

use crate::attestation::verify_slot_attestation;
use crate::crypto::{
    aes_gcm_encrypt, constant_time_eq, hkdf_sha256, p256_generate_ephemeral, p256_public_from_sec1,
    p256_public_to_sec1, p256_shared_secret, random_key, random_nonce, random_salt, sha256,
};
use crate::error::{AuthError, Result};
use crate::pcsc::{ScardContext, SCARD_LEAVE_CARD};
use crate::piv::{
    validate_slot_9d_policy, PivSession, KEY_REF_PIN, SLOT_KEY_MANAGEMENT, TOUCH_POLICY_NEVER,
};
use crate::storage::{read_pinned_f9, write_pinned_f9};
use crate::vault::{
    aad_password, aad_wrap, pad_password, AadPasswordParams, VaultBlob, ALG_P256, APP_PIV,
    VAULT_VERSION,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPolicy {
    /// Do not touch registry pinning (used for stateless `--card-selftest`).
    SelfTestOnly,
    /// Enforce existing pinned `0xF9` root if present; pin on first enrollment.
    EnforceOrPinFirstUse,
    /// Explicitly overwrite the pinned `0xF9` root with the connected card's `0xF9` CA.
    RepinCurrentCard,
}

pub struct EnrollOptions<'a> {
    pub reader: Option<&'a str>,
    pub password: &'a str,
    pub sid: &'a str,
    pub username: &'a str,
    pub computer: &'a str,
    pub password_last_set: u64,
    pub attestation_policy: AttestationPolicy,
}

pub struct EnrollResult {
    pub vault: VaultBlob,
    /// Retained in `Zeroizing` memory ONLY during two-phase rotation so Phase D
    /// can re-bind `AAD_password` after `NetUserSetInfo` without touching the card twice.
    pub dek: Zeroizing<[u8; 32]>,
    pub card_name: Option<String>,
    pub card_pub_fingerprint: [u8; 32],
    pub card_pub_sec1: Vec<u8>,
    pub touch_policy: u8,
    pub f9_fingerprint: Option<[u8; 32]>,
    pub f9_newly_pinned: bool,
}

/// Enroll `password` for a local account using the first usable, policy-compliant PIV card.
pub fn enroll_with_options(opts: &EnrollOptions<'_>) -> Result<EnrollResult> {
    let context = ScardContext::new()?;
    let readers = match opts.reader {
        Some(reader) => vec![reader.to_string()],
        None => context.list_readers()?,
    };
    if readers.is_empty() {
        return Err(AuthError::NoReader);
    }

    let mut last_error = None;

    for reader_name in readers {
        let mut card = match context.connect(&reader_name) {
            Ok(card) => card,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };

        if let Err(error) = card.begin_transaction() {
            last_error = Some(error);
            continue;
        }

        let attempt: Result<EnrollResult> = (|| {
            let session = PivSession::new(&card);
            let selected = session.select()?;

            // When the PIV card exposes `00 F7` slot metadata, enforce `ECCP256`,
            // `PIN ALWAYS`, and `On-card` origin. On pure NIST SP 800-73-4 PIV smart cards
            // without vendor `00 F7` metadata, fall back to the standard `5F C1 0B` X.509
            // certificate for slot `0x9D` (matching `typestate.rs` unlock behavior).
            let (touch_policy, card_pub_sec1) =
                if let Some(metadata) = session.get_metadata(SLOT_KEY_MANAGEMENT)? {
                    let parsed_meta = metadata.parse();
                    validate_slot_9d_policy(&parsed_meta)?;
                    let tp = parsed_meta.touch_policy.unwrap_or(TOUCH_POLICY_NEVER);
                    let pk = match parsed_meta.public_key_sec1 {
                        Some(pk) => pk,
                        None => session.read_ec_public_key(SLOT_KEY_MANAGEMENT)?,
                    };
                    (tp, pk)
                } else {
                    (
                        TOUCH_POLICY_NEVER,
                        session.read_ec_public_key(SLOT_KEY_MANAGEMENT)?,
                    )
                };
            let card_pub = p256_public_from_sec1(&card_pub_sec1)?;
            let fingerprint = sha256(&card_pub_sec1);

            // Verify `0x9D` on-card attestation against `0xF9` if supported by the card.
            let mut f9_fingerprint = None;
            let mut f9_newly_pinned = false;
            if let (Some(slot_cert_der), Some(f9_cert_der)) = (
                session.attest_slot(SLOT_KEY_MANAGEMENT)?,
                session.read_attestation_ca_cert()?,
            ) {
                let verified =
                    verify_slot_attestation(&slot_cert_der, &f9_cert_der, &card_pub_sec1)?;
                let current_f9 = verified.f9_public_key_fingerprint;
                f9_fingerprint = Some(current_f9);

                match opts.attestation_policy {
                    AttestationPolicy::SelfTestOnly => {}
                    AttestationPolicy::EnforceOrPinFirstUse => {
                        if let Some(pinned) = read_pinned_f9()? {
                            if !constant_time_eq(&pinned, &current_f9) {
                                return Err(AuthError::Attestation(format!(
                                    "card 0xF9 attestation root ({}) does not match pinned root ({}). \
                                     If you replaced or reset your PIV smart card, run Re-pin Card Root first.",
                                    hex::encode(current_f9),
                                    hex::encode(pinned)
                                )));
                            }
                        } else {
                            write_pinned_f9(&current_f9)?;
                            f9_newly_pinned = true;
                        }
                    }
                    AttestationPolicy::RepinCurrentCard => {
                        write_pinned_f9(&current_f9)?;
                        f9_newly_pinned = true;
                    }
                }
            } else if opts.attestation_policy == AttestationPolicy::RepinCurrentCard {
                return Err(AuthError::Attestation(
                    "connected card did not return 0x9D/0xF9 attestation certificates".into(),
                ));
            }

            let dek = random_key();
            let salt = random_salt();
            let nonce = random_nonce();
            let wrap_nonce = random_nonce();

            let padded_password = pad_password(opts.password)?;
            let password_aad = aad_password(&AadPasswordParams {
                version: VAULT_VERSION,
                app: APP_PIV,
                slot: SLOT_KEY_MANAGEMENT,
                alg: ALG_P256,
                fingerprint: &fingerprint,
                sid: opts.sid,
                username: opts.username,
                computer: opts.computer,
                password_last_set: opts.password_last_set,
            });
            let (ciphertext, tag) = aes_gcm_encrypt(
                dek.as_ref(),
                &nonce,
                padded_password.as_ref(),
                &password_aad,
            )?;

            let (ephemeral_secret, ephemeral_public) = p256_generate_ephemeral();
            let ephemeral_public_sec1 = p256_public_to_sec1(&ephemeral_public);
            let shared = p256_shared_secret(ephemeral_secret, &card_pub);
            let kek = hkdf_sha256(shared.as_ref(), &salt, b"FamiliarSmartcard/v1/wrap")?;
            let wrap_aad = aad_wrap(
                VAULT_VERSION,
                APP_PIV,
                SLOT_KEY_MANAGEMENT,
                ALG_P256,
                &fingerprint,
                opts.sid,
            );
            let (wrapped_dek, wrap_tag) =
                aes_gcm_encrypt(kek.as_ref(), &wrap_nonce, dek.as_ref(), &wrap_aad)?;

            let vault = VaultBlob {
                version: VAULT_VERSION,
                app: APP_PIV,
                slot: SLOT_KEY_MANAGEMENT,
                alg: ALG_P256,
                card_pub_fingerprint: fingerprint,
                eph_pub_enroll: ephemeral_public_sec1,
                wrapped_dek,
                wrap_nonce,
                wrap_tag,
                salt,
                nonce,
                ciphertext,
                tag,
                password_last_set: opts.password_last_set,
                created_at: unix_now(),
            };

            Ok(EnrollResult {
                vault,
                dek,
                card_name: selected.card_name,
                card_pub_fingerprint: fingerprint,
                card_pub_sec1,
                touch_policy,
                f9_fingerprint,
                f9_newly_pinned,
            })
        })();

        match attempt {
            Ok(result) => {
                // Enrollment did not verify a PIN; leave card undisturbed.
                let _ = card.end_transaction(SCARD_LEAVE_CARD);
                let _ = card.disconnect(SCARD_LEAVE_CARD);
                return Ok(result);
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or(AuthError::NoCard))
}

/// Probe the connected card's `0x9D`/`0xF9` attestation chain and pin its `0xF9`
/// public-key fingerprint in `HKLM` without altering any user vault.
pub fn repin_connected_card_attestation(reader: Option<&str>) -> Result<[u8; 32]> {
    let context = ScardContext::new()?;
    let readers = match reader {
        Some(r) => vec![r.to_string()],
        None => context.list_readers()?,
    };
    if readers.is_empty() {
        return Err(AuthError::NoReader);
    }

    let mut last_error = None;
    for reader_name in readers {
        let mut card = match context.connect(&reader_name) {
            Ok(c) => c,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = card.begin_transaction() {
            last_error = Some(e);
            continue;
        }
        let check: Result<[u8; 32]> = (|| {
            let session = PivSession::new(&card);
            session.select()?;
            let pub_9d = session.read_ec_public_key(SLOT_KEY_MANAGEMENT)?;
            let slot_cert = session.attest_slot(SLOT_KEY_MANAGEMENT)?.ok_or_else(|| {
                AuthError::Attestation("card did not return a slot 0x9D attestation cert".into())
            })?;
            let f9_cert = session.read_attestation_ca_cert()?.ok_or_else(|| {
                AuthError::Attestation("card did not return a slot 0xF9 attestation CA cert".into())
            })?;
            let verified = verify_slot_attestation(&slot_cert, &f9_cert, &pub_9d)?;
            write_pinned_f9(&verified.f9_public_key_fingerprint)?;
            Ok(verified.f9_public_key_fingerprint)
        })();

        match check {
            Ok(fp) => {
                let _ = card.end_transaction(SCARD_LEAVE_CARD);
                let _ = card.disconnect(SCARD_LEAVE_CARD);
                return Ok(fp);
            }
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or(AuthError::NoCard))
}

/// Backwards-compatible enrollment helper (used by `--card-selftest` or default policy).
pub fn enroll(
    reader: Option<&str>,
    password: &str,
    sid: &str,
    username: &str,
    computer: &str,
    password_last_set: u64,
) -> Result<EnrollResult> {
    enroll_with_options(&EnrollOptions {
        reader,
        password,
        sid,
        username,
        computer,
        password_last_set,
        attestation_policy: AttestationPolicy::SelfTestOnly,
    })
}

/// Read-only query of remaining PIV PIN attempts on the enrolled PIV smart card matching
/// `expected_fingerprint`. Leaves non-matching and matching cards undisturbed (`SCARD_LEAVE_CARD`).
pub fn query_card_pin_remaining(
    reader: Option<&str>,
    expected_fingerprint: &[u8; 32],
) -> Result<Option<u8>> {
    let context = ScardContext::new()?;
    let readers = match reader {
        Some(r) => vec![r.to_string()],
        None => context.list_readers()?,
    };
    if readers.is_empty() {
        return Err(AuthError::NoReader);
    }

    let mut last_error = None;
    for reader_name in readers {
        let mut card = match context.connect(&reader_name) {
            Ok(c) => c,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = card.begin_transaction() {
            last_error = Some(e);
            continue;
        }
        let check: Result<Option<u8>> = (|| {
            let session = PivSession::new(&card);
            session.select()?;
            let pub_9d = session.read_ec_public_key(SLOT_KEY_MANAGEMENT)?;
            if !constant_time_eq(&sha256(&pub_9d), expected_fingerprint) {
                return Err(AuthError::WrongCard);
            }
            Ok(session
                .get_pin_puk_metadata(KEY_REF_PIN)?
                .and_then(|m| m.remaining_retries))
        })();

        let _ = card.end_transaction(SCARD_LEAVE_CARD);
        let _ = card.disconnect(SCARD_LEAVE_CARD);

        match check {
            Ok(rem) => return Ok(rem),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or(AuthError::NoCard))
}

/// Unblock a PIV card's Application PIN using `puk` and set `new_pin` (`00 2C 00 80`).
///
/// When `expected_fingerprint` is `Some`, only the enrolled PIV smart card matching that
/// slot `0x9D` public-key fingerprint is targeted so PUK attempts are never sent
/// to an unrelated smart card. Returns the slot `0x9D` fingerprint if present.
pub fn unblock_card_pin(
    reader: Option<&str>,
    expected_fingerprint: Option<&[u8; 32]>,
    puk: &[u8],
    new_pin: &[u8],
) -> Result<Option<[u8; 32]>> {
    // Validate input lengths/charset before touching any reader.
    let _ = crate::piv::pad_puk_bytes(puk)?;
    let _ = crate::piv::pad_pin_bytes(new_pin)?;

    let context = ScardContext::new()?;
    let readers = match reader {
        Some(r) => vec![r.to_string()],
        None => context.list_readers()?,
    };
    if readers.is_empty() {
        return Err(AuthError::NoReader);
    }

    let mut last_error = None;
    for reader_name in readers {
        let mut card = match context.connect(&reader_name) {
            Ok(c) => c,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = card.begin_transaction() {
            last_error = Some(e);
            continue;
        }

        let attempt: Result<Option<[u8; 32]>> = (|| {
            let session = PivSession::new(&card);
            session.select()?;

            let fp_opt = match session.read_ec_public_key(SLOT_KEY_MANAGEMENT) {
                Ok(pub_9d) => Some(sha256(&pub_9d)),
                Err(_) if expected_fingerprint.is_none() => None,
                Err(e) => return Err(e),
            };

            if let Some(expected) = expected_fingerprint {
                let actual = fp_opt.ok_or(AuthError::WrongCard)?;
                if !constant_time_eq(&actual, expected) {
                    return Err(AuthError::WrongCard);
                }
            }

            session.reset_pin_with_puk(puk, new_pin)?;
            Ok(fp_opt)
        })();

        match attempt {
            Ok(fp_opt) => return Ok(fp_opt),
            // Terminal PUK errors on the matched card must stop immediately!
            Err(e @ AuthError::PukIncorrect(_)) | Err(e @ AuthError::PukBlocked) => return Err(e),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or(AuthError::NoCard))
}

/// Change a PIV card's PUK (`00 24 00 81`) from `current_puk` to `new_puk`.
pub fn change_card_puk(reader: Option<&str>, current_puk: &[u8], new_puk: &[u8]) -> Result<()> {
    let _ = crate::piv::pad_puk_bytes(current_puk)?;
    let _ = crate::piv::pad_puk_bytes(new_puk)?;

    let context = ScardContext::new()?;
    let readers = match reader {
        Some(r) => vec![r.to_string()],
        None => context.list_readers()?,
    };
    if readers.is_empty() {
        return Err(AuthError::NoReader);
    }

    let mut last_error = None;
    for reader_name in readers {
        let mut card = match context.connect(&reader_name) {
            Ok(c) => c,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = card.begin_transaction() {
            last_error = Some(e);
            continue;
        }

        let attempt: Result<()> = (|| {
            let session = PivSession::new(&card);
            session.select()?;
            session.change_puk(current_puk, new_puk)
        })();

        match attempt {
            Ok(()) => return Ok(()),
            Err(e @ AuthError::PukIncorrect(_)) | Err(e @ AuthError::PukBlocked) => return Err(e),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or(AuthError::NoCard))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
