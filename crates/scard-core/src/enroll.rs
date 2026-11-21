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
    aes_gcm_encrypt, constant_time_eq, hkdf_sha256, is_all_zero, p256_generate_ephemeral,
    p256_public_from_sec1, p256_public_to_sec1, p256_shared_secret, random_key, random_nonce,
    random_salt, sha256,
};
use crate::error::{AuthError, Result};
use crate::pcsc::{ScardContext, SCARD_LEAVE_CARD};
use crate::piv::{
    validate_slot_9d_policy, ApduTransport, PivSession, ALG_ECC_P256, KEY_REF_PIN, KEY_REF_PUK,
    ORIGIN_GENERATED, PIN_POLICY_NEVER, SLOT_CARD_AUTH, SLOT_KEY_MANAGEMENT, TOUCH_POLICY_NEVER,
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
    pub pin_is_default: bool,
    pub puk_is_default: bool,
    /// Optional on-card P-256 `0x9E` (`Card Authentication`, `PIN=NEVER`) public key,
    /// verified via live pre-PIN ECDH (and `0xF9` same-chip attestation when available).
    pub card_auth_9e_pub: Option<Vec<u8>>,
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

            let pin_is_default = session
                .get_pin_puk_metadata(KEY_REF_PIN)
                .ok()
                .flatten()
                .and_then(|m| m.is_default)
                .unwrap_or(false);
            let puk_is_default = session
                .get_pin_puk_metadata(KEY_REF_PUK)
                .ok()
                .flatten()
                .and_then(|m| m.is_default)
                .unwrap_or(false);

            // Verify `0x9D` on-card attestation against `0xF9` if supported by the card,
            // and NEVER allow an unattested card to bypass an already-pinned HKLM root!
            let f9_cert_opt = session.read_attestation_ca_cert()?;
            let current_f9_opt = if let (Some(slot_cert_der), Some(f9_cert_der)) = (
                session.attest_slot(SLOT_KEY_MANAGEMENT)?,
                f9_cert_opt.as_ref(),
            ) {
                let verified =
                    verify_slot_attestation(&slot_cert_der, f9_cert_der, &card_pub_sec1)?;
                Some(verified.f9_public_key_fingerprint)
            } else {
                None
            };

            let (f9_fingerprint, f9_newly_pinned) = enforce_attestation_policy(
                opts.attestation_policy,
                current_f9_opt,
                read_pinned_f9,
                write_pinned_f9,
            )?;

            // Phase 4: Probe optional slot `0x9E` (`Card Authentication`, `PIN=NEVER`)
            // and run a live pre-PIN ECDH challenge to enable Evil-Maid PIN protection.
            let card_auth_9e_pub =
                probe_and_verify_optional_9e(&session, current_f9_opt.and(f9_cert_opt.as_deref()));

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
                pin_is_default,
                puk_is_default,
                card_auth_9e_pub,
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

/// Pure policy evaluator for `0xF9` attestation pinning (unit-tested without touching HKLM).
fn enforce_attestation_policy<FRead, FWrite>(
    policy: AttestationPolicy,
    current_f9: Option<[u8; 32]>,
    read_pinned: FRead,
    write_pinned: FWrite,
) -> Result<(Option<[u8; 32]>, bool)>
where
    FRead: FnOnce() -> Result<Option<[u8; 32]>>,
    FWrite: FnOnce(&[u8; 32]) -> Result<()>,
{
    match (policy, current_f9) {
        (AttestationPolicy::SelfTestOnly, f9) => Ok((f9, false)),
        (AttestationPolicy::EnforceOrPinFirstUse, Some(cur)) => {
            if let Some(pinned) = read_pinned()? {
                if !constant_time_eq(&pinned, &cur) {
                    return Err(AuthError::Attestation(format!(
                        "card 0xF9 attestation root ({}) does not match pinned root ({}). \
                         If you replaced or reset your PIV smart card, run Re-pin Card Root first.",
                        hex::encode(cur),
                        hex::encode(pinned)
                    )));
                }
                Ok((Some(cur), false))
            } else {
                write_pinned(&cur)?;
                Ok((Some(cur), true))
            }
        }
        (AttestationPolicy::EnforceOrPinFirstUse, None) => {
            // CRITICAL: If this machine ALREADY has a pinned `0xF9` root, an unattested/emulated
            // PIV card that omits `00 F9` MUST NOT bypass the machine pin!
            if let Some(pinned) = read_pinned()? {
                return Err(AuthError::Attestation(format!(
                    "machine requires 0xF9 card attestation (pinned root {}), \
                     but the connected card returned no attestation. Run --clear-attestation as Admin only if intentionally migrating to an unattested card.",
                    hex::encode(pinned)
                )));
            }
            Ok((None, false))
        }
        (AttestationPolicy::RepinCurrentCard, Some(cur)) => {
            write_pinned(&cur)?;
            Ok((Some(cur), true))
        }
        (AttestationPolicy::RepinCurrentCard, None) => Err(AuthError::Attestation(
            "connected card did not return 0x9D/0xF9 attestation certificates".into(),
        )),
    }
}

/// Probe slot `0x9E` (`Card Authentication`) for an optional `ECC P-256`, `PIN=NEVER`
/// on-card key, verify same-chip `0xF9` attestation when `0x9D` was attested, and execute
/// a live pre-PIN ECDH challenge so enrollment only enables `0x9E` when proven working.
fn probe_and_verify_optional_9e<T: ApduTransport>(
    session: &PivSession<'_, T>,
    attested_f9_cert_der: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let pub_9e = match session.get_metadata(SLOT_CARD_AUTH) {
        Ok(Some(meta)) => {
            let pol = meta.parse();
            if pol.algorithm != Some(ALG_ECC_P256)
                || pol.pin_policy != Some(PIN_POLICY_NEVER)
                || pol.origin != Some(ORIGIN_GENERATED)
            {
                return None;
            }
            match pol.public_key_sec1 {
                Some(pk) => pk,
                None => session.read_ec_public_key(SLOT_CARD_AUTH).ok()?,
            }
        }
        Ok(None) => session.read_ec_public_key(SLOT_CARD_AUTH).ok()?,
        Err(_) => return None,
    };

    let parsed_pub = p256_public_from_sec1(&pub_9e).ok()?;

    // If the card attested `0x9D` via `0xF9`, require `0x9E` to be attested by the
    // exact same `0xF9` chip root so an external imported key is never accepted.
    if let Some(f9_der) = attested_f9_cert_der {
        let cert_9e = session.attest_slot(SLOT_CARD_AUTH).ok().flatten()?;
        verify_slot_attestation(&cert_9e, f9_der, &pub_9e).ok()?;
    }

    // Live pre-PIN dynamic ECDH self-test (no PIN verified!).
    let (eph_sec, eph_pub) = p256_generate_ephemeral();
    let eph_pub_sec1 = p256_public_to_sec1(&eph_pub);
    let actual = Zeroizing::new(
        session
            .general_authenticate_ecdh(SLOT_CARD_AUTH, ALG_ECC_P256, &eph_pub_sec1)
            .ok()?,
    );
    if actual.len() != 32 || is_all_zero(&actual) {
        return None;
    }
    let expected = p256_shared_secret(eph_sec, &parsed_pub);
    if !constant_time_eq(actual.as_slice(), &expected[..]) {
        return None;
    }

    Some(pub_9e)
}

/// Execute a pre-PIN dynamic P-256 ECDH challenge against slot `0x9E` (`PIN=NEVER`)
/// BEFORE sending `VERIFY PIN` (`00 20`) or `RESET RETRY COUNTER` (`00 2C`), blocking
/// Evil-Maid fake cards from capturing the user's plaintext PIN or PUK.
pub fn verify_pre_pin_9e_challenge<T: ApduTransport>(
    transport: &T,
    expected_9e_pub_sec1: &[u8],
) -> Result<()> {
    let expected_pub = p256_public_from_sec1(expected_9e_pub_sec1)?;
    let session = PivSession::new(transport);
    let actual_pub_sec1 = session
        .read_ec_public_key(SLOT_CARD_AUTH)
        .map_err(|_| AuthError::WrongCard)?;
    if !constant_time_eq(&actual_pub_sec1, expected_9e_pub_sec1) {
        return Err(AuthError::WrongCard);
    }

    let (eph_sec, eph_pub) = p256_generate_ephemeral();
    let eph_pub_sec1 = p256_public_to_sec1(&eph_pub);
    let actual = Zeroizing::new(
        session
            .general_authenticate_ecdh(SLOT_CARD_AUTH, ALG_ECC_P256, &eph_pub_sec1)
            .map_err(|_| AuthError::WrongCard)?,
    );
    if actual.len() != 32 || is_all_zero(&actual) {
        return Err(AuthError::WrongCard);
    }
    let expected = p256_shared_secret(eph_sec, &expected_pub);
    if !constant_time_eq(actual.as_slice(), &expected[..]) {
        return Err(AuthError::WrongCard);
    }
    Ok(())
}

/// Core transport-generic PUK PIN-unblock implementation (`00 2C 00 80`).
///
/// Security guarantees:
/// - Verifies `expected_fingerprint` (and optional `expected_9e_pub` dynamic challenge!)
///   BEFORE issuing `RESET RETRY COUNTER`, so a wrong or Evil-Maid fake card never
///   receives the user's PUK!
/// - When `require_pin_blocked` is `true` (used on the unauthenticated Windows Lock Screen),
///   strictly fails closed unless `remaining_retries == Some(0)` (`BLOCKED`).
pub fn unblock_pin_with_transport<T: ApduTransport>(
    transport: &T,
    expected_fingerprint: Option<&[u8; 32]>,
    expected_9e_pub: Option<&[u8]>,
    require_pin_blocked: bool,
    puk: &[u8],
    new_pin: &[u8],
) -> Result<Option<[u8; 32]>> {
    let _ = crate::piv::pad_puk_bytes(puk)?;
    let _ = crate::piv::pad_pin_bytes(new_pin)?;

    let session = PivSession::new(transport);
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

    if let Some(pub_9e) = expected_9e_pub {
        verify_pre_pin_9e_challenge(transport, pub_9e)?;
    }

    if require_pin_blocked {
        // Strict Fail-Closed: ONLY proceed on Lock Screen when PIN retry counter is
        // positively confirmed to be 0 (`BLOCKED`). `Ok(None)` is rejected!
        let confirmed_blocked = session
            .get_pin_puk_metadata(KEY_REF_PIN)?
            .and_then(|m| m.remaining_retries)
            == Some(0);
        if !confirmed_blocked {
            return Err(AuthError::CardPolicy(
                "card PIN is not confirmed blocked; sign in with your PIN (or unblock via familiar-enroll on desktop)"
                    .into(),
            ));
        }
    }

    session.reset_pin_with_puk(puk, new_pin)?;
    Ok(fp_opt)
}

/// Unblock a PIV card's Application PIN using `puk` and set `new_pin` (`00 2C 00 80`).
pub fn unblock_card_pin(
    reader: Option<&str>,
    expected_fingerprint: Option<&[u8; 32]>,
    expected_9e_pub: Option<&[u8]>,
    require_pin_blocked: bool,
    puk: &[u8],
    new_pin: &[u8],
) -> Result<Option<[u8; 32]>> {
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

        // Check PUK 60s safety cooldown INSIDE the exclusive PC/SC transaction!
        if let Some(expected_fp) = expected_fingerprint {
            if let Ok(Some(rem_secs)) = crate::storage::check_puk_last_attempt_cooldown(expected_fp)
            {
                return Err(AuthError::LastAttemptCooldown {
                    remaining_secs: rem_secs,
                });
            }
        }

        let attempt = unblock_pin_with_transport(
            &card,
            expected_fingerprint,
            expected_9e_pub,
            require_pin_blocked,
            puk,
            new_pin,
        );

        match attempt {
            Ok(fp_opt) => {
                if let Some(fp) = fp_opt {
                    let _ = crate::storage::clear_puk_last_attempt_cooldown(&fp);
                }
                return Ok(fp_opt);
            }
            Err(AuthError::PukIncorrect(1)) => {
                if let Some(expected_fp) = expected_fingerprint {
                    let _ = crate::storage::start_puk_last_attempt_cooldown(
                        expected_fp,
                        crate::storage::LAST_ATTEMPT_COOLDOWN_SECS,
                    );
                }
                return Err(AuthError::PukIncorrect(1));
            }
            // Terminal errors on the matched card must stop immediately!
            Err(e @ AuthError::PukIncorrect(_))
            | Err(e @ AuthError::PukBlocked)
            | Err(e @ AuthError::CardPolicy(_)) => return Err(e),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_f9_root_rejects_unattested_and_mismatched_cards() {
        let pinned_root = [0xAAu8; 32];
        let other_root = [0xBBu8; 32];

        // 1. Unattested card (`None`) MUST NOT bypass an already-pinned HKLM root!
        let unattested_err = enforce_attestation_policy(
            AttestationPolicy::EnforceOrPinFirstUse,
            None,
            || Ok(Some(pinned_root)),
            |_| panic!("must not overwrite pin"),
        )
        .unwrap_err();
        assert!(matches!(unattested_err, AuthError::Attestation(_)));

        // 2. Different physical security key (`other_root`) is rejected!
        let mismatch_err = enforce_attestation_policy(
            AttestationPolicy::EnforceOrPinFirstUse,
            Some(other_root),
            || Ok(Some(pinned_root)),
            |_| panic!("must not overwrite pin"),
        )
        .unwrap_err();
        assert!(matches!(mismatch_err, AuthError::Attestation(_)));

        // 3. Matching `0xF9` root succeeds without rewriting HKLM.
        let (matched, newly_pinned) = enforce_attestation_policy(
            AttestationPolicy::EnforceOrPinFirstUse,
            Some(pinned_root),
            || Ok(Some(pinned_root)),
            |_| panic!("must not rewrite existing pin"),
        )
        .unwrap();
        assert_eq!(matched, Some(pinned_root));
        assert!(!newly_pinned);
    }
}
