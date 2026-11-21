//! Compile-time authentication pipeline.
//!
//! Each state owns the previous state. A caller cannot construct
//! `KeyUnwrapped` without going through `PinVerified` -> `FreshnessProven` ->
//! `PinVerifiedForUnwrap`. Errors consume the current state; if PIN
//! verification was attempted, the card handle is dropped and reset.

#![forbid(unsafe_code)]

use crate::crypto::{
    aes_gcm_decrypt, constant_time_eq, hkdf_sha256, is_all_zero, p256_generate_ephemeral,
    p256_public_from_sec1, p256_public_to_sec1, p256_shared_secret, sha256,
};
use crate::error::{AuthError, Result};
use crate::pcsc::{ScardCard, ScardContext};
use crate::piv::{
    validate_slot_9d_policy, ApduTransport, PivSession, ALG_ECC_P256, KEY_REF_PIN,
    SLOT_KEY_MANAGEMENT,
};
use crate::vault::{aad_password, aad_wrap, unpad_password, AadPasswordParams, VaultBlob};
use zeroize::Zeroizing;

struct CardState<T: ApduTransport> {
    vault: VaultBlob,
    sid: String,
    username: String,
    computer: String,
    // Field order matters: `card` MUST drop before `_context`!
    card: T,
    _context: Option<ScardContext>,
    card_pub_sec1: Vec<u8>,
}

pub struct AuthPipeline;

pub struct VaultLoaded {
    vault: VaultBlob,
    sid: String,
    username: String,
    computer: String,
}

pub struct CardConnected<T: ApduTransport = ScardCard>(CardState<T>);
pub struct PinVerified<T: ApduTransport = ScardCard>(CardState<T>);
pub struct FreshnessProven<T: ApduTransport = ScardCard>(CardState<T>);
pub struct PinVerifiedForUnwrap<T: ApduTransport = ScardCard>(CardState<T>);

pub struct KeyUnwrapped {
    vault: VaultBlob,
    sid: String,
    username: String,
    computer: String,
    dek: Zeroizing<[u8; 32]>,
}

pub struct CredentialDecrypted {
    password: Zeroizing<String>,
}

impl AuthPipeline {
    pub fn start(
        vault: VaultBlob,
        sid: impl Into<String>,
        username: impl Into<String>,
        computer: impl Into<String>,
    ) -> Result<VaultLoaded> {
        Ok(VaultLoaded {
            vault,
            sid: sid.into(),
            username: username.into(),
            computer: computer.into(),
        })
    }
}

impl VaultLoaded {
    pub fn vault(&self) -> &VaultBlob {
        &self.vault
    }

    /// Connect to an arbitrary `ApduTransport` (used by deterministic unit and replay tests).
    pub fn connect_with_transport<T: ApduTransport>(
        self,
        transport: T,
    ) -> Result<CardConnected<T>> {
        let session = PivSession::new(&transport);
        session.select()?;

        if self.vault.slot == SLOT_KEY_MANAGEMENT {
            if let Some(meta) = session.get_metadata(self.vault.slot)? {
                let policy = meta.parse();
                validate_slot_9d_policy(&policy)?;
            }
        }

        let card_pub_sec1 = session.read_ec_public_key(self.vault.slot)?;
        let _ = p256_public_from_sec1(&card_pub_sec1)?;
        if !constant_time_eq(&sha256(&card_pub_sec1), &self.vault.card_pub_fingerprint) {
            return Err(AuthError::WrongCard);
        }

        Ok(CardConnected(CardState {
            vault: self.vault,
            sid: self.sid,
            username: self.username,
            computer: self.computer,
            card: transport,
            _context: None,
            card_pub_sec1,
        }))
    }

    /// Connect to the enrolled physical/RDP-redirected card and verify its fingerprint
    /// and mandatory `0x9D` security policy.
    ///
    /// Non-matching cards are released with `SCARD_LEAVE_CARD` (because `pin_attempted`
    /// has not been set yet), leaving any other smart cards on the system undisturbed.
    pub fn connect_card(self, reader: Option<&str>) -> Result<CardConnected<ScardCard>> {
        let mut context = Some(ScardContext::new()?);
        let readers = match reader {
            Some(reader) => vec![reader.to_string()],
            None => context
                .as_ref()
                .ok_or_else(|| AuthError::Internal("missing PC/SC context".into()))?
                .list_readers()?,
        };

        if readers.is_empty() {
            return Err(AuthError::NoReader);
        }

        let mut last_error = None;

        for reader_name in readers {
            let mut card = match context
                .as_ref()
                .ok_or_else(|| AuthError::Internal("missing PC/SC context".into()))?
                .connect(&reader_name)
            {
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

            let check_result: Result<Vec<u8>> = (|| {
                let session = PivSession::new(&card);
                session.select()?;
                if self.vault.slot == SLOT_KEY_MANAGEMENT {
                    if let Some(meta) = session.get_metadata(self.vault.slot)? {
                        validate_slot_9d_policy(&meta.parse())?;
                    }
                }
                let pub_sec1 = session.read_ec_public_key(self.vault.slot)?;
                let _ = p256_public_from_sec1(&pub_sec1)?;
                if !constant_time_eq(&sha256(&pub_sec1), &self.vault.card_pub_fingerprint) {
                    return Err(AuthError::WrongCard);
                }
                Ok(pub_sec1)
            })();

            let card_pub_sec1 = match check_result {
                Ok(pub_sec1) => pub_sec1,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };

            let context = context
                .take()
                .ok_or_else(|| AuthError::Internal("missing PC/SC context".into()))?;

            return Ok(CardConnected(CardState {
                vault: self.vault,
                sid: self.sid,
                username: self.username,
                computer: self.computer,
                card,
                _context: Some(context),
                card_pub_sec1,
            }));
        }

        Err(last_error.unwrap_or(AuthError::NoCard))
    }
}

impl<T: ApduTransport> CardConnected<T> {
    pub fn card_fingerprint(&self) -> &[u8; 32] {
        &self.0.vault.card_pub_fingerprint
    }

    /// Read-only query of remaining PIV PIN attempts inside the active PC/SC transaction.
    pub fn query_pin_remaining(&self) -> Result<Option<u8>> {
        let session = PivSession::new(&self.0.card);
        Ok(session
            .get_pin_puk_metadata(KEY_REF_PIN)?
            .and_then(|m| m.remaining_retries))
    }

    /// Execute an optional Pre-PIN dynamic ECDH challenge against PIV slot `0x9E`
    /// (`Card Authentication`, `PIN=NEVER`) BEFORE sending `VERIFY PIN`, preventing
    /// Evil-Maid fake cards from capturing the user's plaintext PIN.
    pub fn verify_pre_pin_card_auth(&self, expected_9e_pub_sec1: &[u8]) -> Result<()> {
        crate::enroll::verify_pre_pin_9e_challenge(&self.0.card, expected_9e_pub_sec1)
    }

    /// First VERIFY. Required because the PIV 9D key uses PIN policy ALWAYS.
    /// If this fails (`63 CX`), execution halts immediately so only 1 retry is consumed.
    pub fn verify_pin(self, pin: &Zeroizing<Vec<u8>>) -> Result<PinVerified<T>> {
        {
            let session = PivSession::new(&self.0.card);
            session.verify_pin(pin.as_slice())?;
        }
        Ok(PinVerified(self.0))
    }
}

impl<T: ApduTransport> PinVerified<T> {
    /// Fresh ECDH key confirmation. This is the anti-replay gate.
    pub fn prove_freshness(self) -> Result<FreshnessProven<T>> {
        let state = self.0;
        {
            let session = PivSession::new(&state.card);

            let (ephemeral_secret, ephemeral_public) = p256_generate_ephemeral();
            let ephemeral_public_sec1 = p256_public_to_sec1(&ephemeral_public);

            let actual = Zeroizing::new(session.general_authenticate_ecdh(
                state.vault.slot,
                ALG_ECC_P256,
                &ephemeral_public_sec1,
            )?);

            if actual.len() != 32 || is_all_zero(&actual) {
                return Err(AuthError::Crypto(
                    "invalid ECDH shared secret from card".into(),
                ));
            }

            let card_public = p256_public_from_sec1(&state.card_pub_sec1)?;
            let expected = p256_shared_secret(ephemeral_secret, &card_public);

            if !constant_time_eq(actual.as_slice(), &expected[..]) {
                return Err(AuthError::WrongCard);
            }
        }
        Ok(FreshnessProven(state))
    }
}

impl<T: ApduTransport> FreshnessProven<T> {
    /// Second VERIFY. The first ECDH consumed the ALWAYS-policy PIN.
    pub fn verify_pin_for_unwrap(
        self,
        pin: &Zeroizing<Vec<u8>>,
    ) -> Result<PinVerifiedForUnwrap<T>> {
        let state = self.0;
        {
            let session = PivSession::new(&state.card);
            session.verify_pin(pin.as_slice())?;
        }
        Ok(PinVerifiedForUnwrap(state))
    }
}

impl<T: ApduTransport> PinVerifiedForUnwrap<T> {
    /// Static ECDH with the enrollment public key, HKDF, and DEK unwrap.
    pub fn unwrap_dek(self) -> Result<KeyUnwrapped> {
        let state = self.0;
        let dek = {
            let session = PivSession::new(&state.card);

            let shared = Zeroizing::new(session.general_authenticate_ecdh(
                state.vault.slot,
                ALG_ECC_P256,
                &state.vault.eph_pub_enroll,
            )?);

            if shared.len() != 32 || is_all_zero(&shared) {
                return Err(AuthError::Crypto(
                    "invalid ECDH shared secret from card".into(),
                ));
            }

            let kek = hkdf_sha256(&shared, &state.vault.salt, b"FamiliarSmartcard/v1/wrap")?;
            let aad = aad_wrap(
                state.vault.version,
                state.vault.app,
                state.vault.slot,
                state.vault.alg,
                &state.vault.card_pub_fingerprint,
                &state.sid,
            );

            let dek_bytes = aes_gcm_decrypt(
                &kek[..],
                &state.vault.wrap_nonce,
                &state.vault.wrapped_dek,
                &state.vault.wrap_tag,
                &aad,
            )?;

            if dek_bytes.len() != 32 {
                return Err(AuthError::Crypto("unexpected DEK length".into()));
            }

            let mut dek = Zeroizing::new([0u8; 32]);
            dek.copy_from_slice(&dek_bytes);
            dek
        };

        // Dropping `state.card` here triggers `SCARD_RESET_CARD` before `_context` drops.
        Ok(KeyUnwrapped {
            vault: state.vault,
            sid: state.sid,
            username: state.username,
            computer: state.computer,
            dek,
        })
    }
}

impl KeyUnwrapped {
    /// Decrypt and unpad the Windows password.
    pub fn decrypt_credential(self) -> Result<CredentialDecrypted> {
        let aad = aad_password(&AadPasswordParams {
            version: self.vault.version,
            app: self.vault.app,
            slot: self.vault.slot,
            alg: self.vault.alg,
            fingerprint: &self.vault.card_pub_fingerprint,
            sid: &self.sid,
            username: &self.username,
            computer: &self.computer,
            password_last_set: self.vault.password_last_set,
        });

        let padded = aes_gcm_decrypt(
            &self.dek[..],
            &self.vault.nonce,
            &self.vault.ciphertext,
            &self.vault.tag,
            &aad,
        )?;

        let password = unpad_password(&padded)?;
        Ok(CredentialDecrypted { password })
    }
}

impl CredentialDecrypted {
    pub fn as_str(&self) -> &str {
        self.password.as_str()
    }

    pub fn into_password(self) -> Zeroizing<String> {
        self.password
    }
}

/// Convenience one-shot pipeline over PC/SC.
pub fn unlock(
    vault: VaultBlob,
    sid: &str,
    username: &str,
    computer: &str,
    reader: Option<&str>,
    pin: &mut Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<String>> {
    let credential = AuthPipeline::start(vault, sid, username, computer)?
        .connect_card(reader)?
        .verify_pin(pin)?
        .prove_freshness()?
        .verify_pin_for_unwrap(pin)?
        .unwrap_dek()?
        .decrypt_credential()?;
    Ok(credential.into_password())
}

/// Convenience one-shot pipeline over a custom `ApduTransport` (for mock/replay tests).
pub fn unlock_with_transport<T: ApduTransport>(
    vault: VaultBlob,
    sid: &str,
    username: &str,
    computer: &str,
    transport: T,
    pin: &Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<String>> {
    let credential = AuthPipeline::start(vault, sid, username, computer)?
        .connect_with_transport(transport)?
        .verify_pin(pin)?
        .prove_freshness()?
        .verify_pin_for_unwrap(pin)?
        .unwrap_dek()?
        .decrypt_credential()?;
    Ok(credential.into_password())
}

impl<T: ApduTransport + ?Sized> ApduTransport for &T {
    fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        (**self).transmit_apdu(apdu)
    }

    fn mark_pin_attempted(&self) {
        (**self).mark_pin_attempted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{aes_gcm_encrypt, random_key, random_nonce, random_salt};
    use crate::piv::{tlv, ORIGIN_GENERATED, PIN_POLICY_ALWAYS, TOUCH_POLICY_NEVER};
    use crate::vault::{pad_password, ALG_P256, APP_PIV, VAULT_VERSION};
    use p256::ecdh::diffie_hellman;
    use p256::SecretKey;
    use std::cell::RefCell;

    struct SimulatedPivCard {
        secret_key: SecretKey,
        advertised_public_sec1: Vec<u8>,
        secret_key_9e: Option<SecretKey>,
        advertised_9e_public_sec1: Option<Vec<u8>>,
        hide_pin_metadata: bool,
        pin: RefCell<Vec<u8>>,
        puk: Vec<u8>,
        remaining_retries: RefCell<u8>,
        remaining_puk_retries: RefCell<u8>,
        pin_verified_once: RefCell<bool>,
        verify_calls: RefCell<usize>,
        reset_retry_calls: RefCell<usize>,
        replay_override: Option<[u8; 32]>,
        pin_policy: u8,
    }

    impl SimulatedPivCard {
        fn new(pin: &[u8], replay_override: Option<[u8; 32]>, pin_policy: u8) -> Self {
            Self::with_key_byte(0x42, pin, b"87654321", replay_override, pin_policy)
        }

        fn with_key_byte(
            seed_byte: u8,
            pin: &[u8],
            puk: &[u8],
            replay_override: Option<[u8; 32]>,
            pin_policy: u8,
        ) -> Self {
            let secret_key = SecretKey::from_bytes((&[seed_byte; 32]).into()).unwrap();
            let advertised_public_sec1 = p256_public_to_sec1(&secret_key.public_key());
            Self {
                secret_key,
                advertised_public_sec1,
                secret_key_9e: None,
                advertised_9e_public_sec1: None,
                hide_pin_metadata: false,
                pin: RefCell::new(pin.to_vec()),
                puk: puk.to_vec(),
                remaining_retries: RefCell::new(3),
                remaining_puk_retries: RefCell::new(3),
                pin_verified_once: RefCell::new(false),
                verify_calls: RefCell::new(0),
                reset_retry_calls: RefCell::new(0),
                replay_override,
                pin_policy,
            }
        }
    }

    impl ApduTransport for SimulatedPivCard {
        fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>> {
            match (apdu[0], apdu[1]) {
                // SELECT PIV
                (0x00, 0xA4) => Ok(vec![
                    0x50, 0x07, b'P', b'I', b'V', b'C', b'a', b'r', b'd', 0x90, 0x00,
                ]),
                // GET METADATA (slot 0x9D, slot 0x9E, or PIN 0x80)
                (0x00, 0xF7) => {
                    if apdu[3] == KEY_REF_PIN {
                        if self.hide_pin_metadata {
                            return Ok(vec![0x6D, 0x00]);
                        }
                        let rem = *self.remaining_retries.borrow();
                        let mut meta = tlv(0x05, &[0x00])?;
                        meta.extend_from_slice(&tlv(0x06, &[3, rem])?);
                        meta.extend_from_slice(&[0x90, 0x00]);
                        return Ok(meta);
                    }
                    if apdu[3] == crate::piv::SLOT_CARD_AUTH {
                        let Some(pk_9e) = &self.advertised_9e_public_sec1 else {
                            return Ok(vec![0x6A, 0x88]);
                        };
                        let mut meta = Vec::new();
                        meta.extend_from_slice(&tlv(0x01, &[ALG_ECC_P256])?);
                        meta.extend_from_slice(&tlv(
                            0x02,
                            &[crate::piv::PIN_POLICY_NEVER, TOUCH_POLICY_NEVER],
                        )?);
                        meta.extend_from_slice(&tlv(0x03, &[ORIGIN_GENERATED])?);
                        let pk_inner = tlv(0x86, pk_9e)?;
                        meta.extend_from_slice(&tlv(0x04, &pk_inner)?);
                        meta.extend_from_slice(&[0x90, 0x00]);
                        return Ok(meta);
                    }
                    let mut meta = Vec::new();
                    meta.extend_from_slice(&tlv(0x01, &[ALG_ECC_P256])?);
                    meta.extend_from_slice(&tlv(0x02, &[self.pin_policy, TOUCH_POLICY_NEVER])?);
                    meta.extend_from_slice(&tlv(0x03, &[ORIGIN_GENERATED])?);
                    let pk_inner = tlv(0x86, &self.advertised_public_sec1)?;
                    meta.extend_from_slice(&tlv(0x04, &pk_inner)?);
                    meta.extend_from_slice(&[0x90, 0x00]);
                    Ok(meta)
                }
                // VERIFY PIN (empty status check vs 8-byte verify)
                (0x00, 0x20) => {
                    if apdu.len() <= 5 {
                        if self.hide_pin_metadata {
                            return Ok(vec![0x90, 0x00]);
                        }
                        let rem = *self.remaining_retries.borrow();
                        return if rem == 0 {
                            Ok(vec![0x69, 0x83])
                        } else {
                            Ok(vec![0x63, 0xC0 | rem])
                        };
                    }
                    *self.verify_calls.borrow_mut() += 1;
                    if *self.remaining_retries.borrow() == 0 {
                        return Ok(vec![0x69, 0x83]);
                    }
                    let mut expected = [0xFFu8; 8];
                    let cur_pin = self.pin.borrow();
                    expected[..cur_pin.len()].copy_from_slice(&cur_pin);
                    if apdu[5..13] == expected {
                        *self.remaining_retries.borrow_mut() = 3;
                        *self.pin_verified_once.borrow_mut() = true;
                        Ok(vec![0x90, 0x00])
                    } else {
                        let mut rem = self.remaining_retries.borrow_mut();
                        *rem = rem.saturating_sub(1);
                        Ok(vec![0x63, 0xC0 | *rem])
                    }
                }
                // RESET RETRY COUNTER (PUK Unblock 00 2C 00 80)
                (0x00, 0x2C) => {
                    *self.reset_retry_calls.borrow_mut() += 1;
                    if *self.remaining_puk_retries.borrow() == 0 {
                        return Ok(vec![0x69, 0x83]);
                    }
                    let mut expected_puk = [0xFFu8; 8];
                    expected_puk[..self.puk.len()].copy_from_slice(&self.puk);
                    if apdu[5..13] == expected_puk {
                        let new_pin: Vec<u8> = apdu[13..21]
                            .iter()
                            .copied()
                            .take_while(|&b| b != 0xFF)
                            .collect();
                        *self.pin.borrow_mut() = new_pin;
                        *self.remaining_retries.borrow_mut() = 3;
                        *self.remaining_puk_retries.borrow_mut() = 3;
                        Ok(vec![0x90, 0x00])
                    } else {
                        let mut rem = self.remaining_puk_retries.borrow_mut();
                        *rem = rem.saturating_sub(1);
                        Ok(vec![0x63, 0xC0 | *rem])
                    }
                }
                // GENERAL AUTHENTICATE ECDH (slot 0x9D requires PIN; slot 0x9E is PIN=NEVER)
                (0x00, 0x87) => {
                    let slot = apdu[3];
                    let active_secret = if slot == crate::piv::SLOT_CARD_AUTH {
                        let Some(sec_9e) = &self.secret_key_9e else {
                            return Ok(vec![0x6A, 0x88]);
                        };
                        sec_9e
                    } else {
                        if !*self.pin_verified_once.borrow() {
                            return Ok(vec![0x69, 0x82]);
                        }
                        // Consume ALWAYS PIN immediately
                        *self.pin_verified_once.borrow_mut() = false;
                        &self.secret_key
                    };

                    let outer = crate::piv::find_tlv(&apdu[5..], 0x7C).unwrap();
                    let peer_bytes = crate::piv::find_tlv(outer, 0x85).unwrap();
                    let shared_bytes = if let Some(replayed) = self.replay_override {
                        replayed
                    } else {
                        let peer_pub = p256_public_from_sec1(peer_bytes)?;
                        let shared =
                            diffie_hellman(active_secret.to_nonzero_scalar(), peer_pub.as_affine());
                        let mut out = [0u8; 32];
                        out.copy_from_slice(shared.raw_secret_bytes());
                        out
                    };
                    let inner = tlv(0x82, &shared_bytes)?;
                    let mut resp = tlv(0x7C, &inner)?;
                    resp.extend_from_slice(&[0x90, 0x00]);
                    Ok(resp)
                }
                _ => Ok(vec![0x6D, 0x00]),
            }
        }
    }

    fn build_test_vault(card_pub_sec1: &[u8], password: &str) -> VaultBlob {
        let card_pub = p256_public_from_sec1(card_pub_sec1).unwrap();
        let fingerprint = sha256(card_pub_sec1);
        let dek = random_key();
        let salt = random_salt();
        let nonce = random_nonce();
        let wrap_nonce = random_nonce();
        let padded = pad_password(password).unwrap();
        let pw_aad = aad_password(&AadPasswordParams {
            version: VAULT_VERSION,
            app: APP_PIV,
            slot: SLOT_KEY_MANAGEMENT,
            alg: ALG_P256,
            fingerprint: &fingerprint,
            sid: "S-1-5-21-100",
            username: "alice",
            computer: "WORKSTATION",
            password_last_set: 1700000000,
        });
        let (ciphertext, tag) =
            aes_gcm_encrypt(dek.as_ref(), &nonce, padded.as_ref(), &pw_aad).unwrap();

        let (eph_sec, eph_pub) = p256_generate_ephemeral();
        let eph_pub_sec1 = p256_public_to_sec1(&eph_pub);
        let shared = p256_shared_secret(eph_sec, &card_pub);
        let kek = hkdf_sha256(shared.as_ref(), &salt, b"FamiliarSmartcard/v1/wrap").unwrap();
        let w_aad = aad_wrap(
            VAULT_VERSION,
            APP_PIV,
            SLOT_KEY_MANAGEMENT,
            ALG_P256,
            &fingerprint,
            "S-1-5-21-100",
        );
        let (wrapped_dek, wrap_tag) =
            aes_gcm_encrypt(kek.as_ref(), &wrap_nonce, dek.as_ref(), &w_aad).unwrap();

        VaultBlob {
            version: VAULT_VERSION,
            app: APP_PIV,
            slot: SLOT_KEY_MANAGEMENT,
            alg: ALG_P256,
            card_pub_fingerprint: fingerprint,
            eph_pub_enroll: eph_pub_sec1,
            wrapped_dek,
            wrap_nonce,
            wrap_tag,
            salt,
            nonce,
            ciphertext,
            tag,
            password_last_set: 1700000000,
            created_at: 1700000000,
        }
    }

    #[test]
    fn full_typestate_unlock_succeeds_and_consumes_pin_twice() {
        let card = SimulatedPivCard::new(b"123456", None, PIN_POLICY_ALWAYS);
        let vault = build_test_vault(&card.advertised_public_sec1, "2345-6789-ABCD-EFGH");
        let pin = Zeroizing::new(b"123456".to_vec());

        let pw = unlock_with_transport(vault, "S-1-5-21-100", "alice", "WORKSTATION", &card, &pin)
            .unwrap();
        assert_eq!(pw.as_str(), "2345-6789-ABCD-EFGH");
        assert_eq!(*card.verify_calls.borrow(), 2);
    }

    #[test]
    fn wrong_pin_stops_after_first_verify_and_decrements_only_once() {
        let card = SimulatedPivCard::new(b"123456", None, PIN_POLICY_ALWAYS);
        let vault = build_test_vault(&card.advertised_public_sec1, "secret");
        let bad_pin = Zeroizing::new(b"999999".to_vec());

        let err = unlock_with_transport(
            vault,
            "S-1-5-21-100",
            "alice",
            "WORKSTATION",
            &card,
            &bad_pin,
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::PinIncorrect(2)));
        assert_eq!(*card.verify_calls.borrow(), 1);
    }

    #[test]
    fn static_replay_card_is_blocked_at_freshness_gate() {
        let card = SimulatedPivCard::new(b"123456", Some([0xAA; 32]), PIN_POLICY_ALWAYS);
        let vault = build_test_vault(&card.advertised_public_sec1, "secret");
        let pin = Zeroizing::new(b"123456".to_vec());

        let err = unlock_with_transport(vault, "S-1-5-21-100", "alice", "WORKSTATION", &card, &pin)
            .unwrap_err();
        assert!(matches!(err, AuthError::WrongCard));
        // Stopped before second VERIFY!
        assert_eq!(*card.verify_calls.borrow(), 1);
    }

    #[test]
    fn all_zero_shared_secret_is_rejected() {
        let card = SimulatedPivCard::new(b"123456", Some([0x00; 32]), PIN_POLICY_ALWAYS);
        let vault = build_test_vault(&card.advertised_public_sec1, "secret");
        let pin = Zeroizing::new(b"123456".to_vec());

        let err = unlock_with_transport(vault, "S-1-5-21-100", "alice", "WORKSTATION", &card, &pin)
            .unwrap_err();
        assert!(matches!(err, AuthError::Crypto(_)));
    }

    #[test]
    fn card_with_pin_once_policy_is_rejected_before_verify() {
        let card = SimulatedPivCard::new(b"123456", None, crate::piv::PIN_POLICY_ONCE);
        let vault = build_test_vault(&card.advertised_public_sec1, "secret");
        let pin = Zeroizing::new(b"123456".to_vec());

        let err = unlock_with_transport(vault, "S-1-5-21-100", "alice", "WORKSTATION", &card, &pin)
            .unwrap_err();
        assert!(matches!(err, AuthError::CardPolicy(_)));
        assert_eq!(*card.verify_calls.borrow(), 0);
    }

    #[test]
    fn wrong_security_key_cannot_login_or_puk_reset_and_never_receives_pin_or_puk() {
        let enrolled_card =
            SimulatedPivCard::with_key_byte(0x42, b"123456", b"87654321", None, PIN_POLICY_ALWAYS);
        let vault = build_test_vault(&enrolled_card.advertised_public_sec1, "REAL-WINDOWS-SECRET");

        // 1. Different physical security key (`0x99`): rejected BEFORE `VERIFY PIN`!
        let wrong_card =
            SimulatedPivCard::with_key_byte(0x99, b"123456", b"12345678", None, PIN_POLICY_ALWAYS);
        let pin = Zeroizing::new(b"123456".to_vec());
        let login_err = unlock_with_transport(
            vault.clone(),
            "S-1-5-21-100",
            "alice",
            "WORKSTATION",
            &wrong_card,
            &pin,
        )
        .unwrap_err();
        assert!(matches!(login_err, AuthError::WrongCard));
        assert_eq!(
            *wrong_card.verify_calls.borrow(),
            0,
            "wrong key must NEVER receive VERIFY PIN"
        );

        // 2. Wrong physical key (`0x99`, even if blocked!) attempting lock-screen PUK unblock:
        //    rejected BEFORE `RESET RETRY COUNTER (00 2C)`!
        *wrong_card.remaining_retries.borrow_mut() = 0;
        let puk_err = crate::enroll::unblock_pin_with_transport(
            &wrong_card,
            Some(&vault.card_pub_fingerprint),
            None,
            true,
            b"12345678",
            b"654321",
        )
        .unwrap_err();
        assert!(matches!(puk_err, AuthError::WrongCard));
        assert_eq!(
            *wrong_card.reset_retry_calls.borrow(),
            0,
            "wrong key must NEVER receive 00 2C PUK unblock"
        );

        // 3. Even on the REAL enrolled card, if its PIN is NOT blocked (`remaining == 3`),
        //    lock-screen PUK unblock (`require_pin_blocked = true`) is rejected before `00 2C`!
        let unblocked_err = crate::enroll::unblock_pin_with_transport(
            &enrolled_card,
            Some(&vault.card_pub_fingerprint),
            None,
            true,
            b"87654321",
            b"654321",
        )
        .unwrap_err();
        assert!(matches!(unblocked_err, AuthError::CardPolicy(_)));
        assert_eq!(*enrolled_card.reset_retry_calls.borrow(), 0);

        // 4. Rogue card spoofing `enrolled_card`'s public key in metadata while holding `0x99` private key:
        //    caught deterministically at `prove_freshness` ECDH anti-replay gate!
        let mut spoof_card =
            SimulatedPivCard::with_key_byte(0x99, b"123456", b"12345678", None, PIN_POLICY_ALWAYS);
        spoof_card.advertised_public_sec1 = enrolled_card.advertised_public_sec1.clone();
        let spoof_err = unlock_with_transport(
            vault.clone(),
            "S-1-5-21-100",
            "alice",
            "WORKSTATION",
            &spoof_card,
            &pin,
        )
        .unwrap_err();
        assert!(matches!(spoof_err, AuthError::WrongCard));
        assert_eq!(*spoof_card.verify_calls.borrow(), 1);

        // 5. When the REAL enrolled card IS blocked (`remaining == 0`), PUK unblock with the
        //    correct PUK succeeds and the new PIN unlocks the existing vault without re-enrollment!
        *enrolled_card.remaining_retries.borrow_mut() = 0;
        let fp = crate::enroll::unblock_pin_with_transport(
            &enrolled_card,
            Some(&vault.card_pub_fingerprint),
            None,
            true,
            b"87654321",
            b"654321",
        )
        .unwrap();
        assert_eq!(fp, Some(vault.card_pub_fingerprint));
        let new_pin = Zeroizing::new(b"654321".to_vec());
        let unlocked_pw = unlock_with_transport(
            vault,
            "S-1-5-21-100",
            "alice",
            "WORKSTATION",
            &enrolled_card,
            &new_pin,
        )
        .unwrap();
        assert_eq!(unlocked_pw.as_str(), "REAL-WINDOWS-SECRET");
    }

    #[test]
    fn pre_pin_9e_blocks_evil_maid_pin_phishing_and_lockscreen_puk_fails_closed_on_none() {
        let mut real_card =
            SimulatedPivCard::with_key_byte(0x42, b"123456", b"87654321", None, PIN_POLICY_ALWAYS);
        let sec_9e = SecretKey::from_bytes((&[0x55u8; 32]).into()).unwrap();
        let pub_9e = p256_public_to_sec1(&sec_9e.public_key());
        real_card.secret_key_9e = Some(sec_9e);
        real_card.advertised_9e_public_sec1 = Some(pub_9e.clone());
        let vault = build_test_vault(&real_card.advertised_public_sec1, "SECRET-PW");

        // Evil-Maid fake card clones BOTH `0x9D` and `0x9E` public keys, hoping to record
        // the user's plaintext PIN or PUK!
        let mut evil_maid =
            SimulatedPivCard::with_key_byte(0x99, b"123456", b"87654321", None, PIN_POLICY_ALWAYS);
        evil_maid.advertised_public_sec1 = real_card.advertised_public_sec1.clone();
        evil_maid.secret_key_9e = Some(SecretKey::from_bytes((&[0x77u8; 32]).into()).unwrap());
        evil_maid.advertised_9e_public_sec1 = Some(pub_9e.clone());

        // Pre-PIN `0x9E` challenge rejects `evil_maid` BEFORE `verify_pin` is ever called!
        let connected = AuthPipeline::start(vault.clone(), "S-1-5-21-100", "alice", "WORKSTATION")
            .unwrap()
            .connect_with_transport(&evil_maid)
            .unwrap();
        let err = connected.verify_pre_pin_card_auth(&pub_9e).unwrap_err();
        assert!(matches!(err, AuthError::WrongCard));
        assert_eq!(
            *evil_maid.verify_calls.borrow(),
            0,
            "Evil-Maid fake card must receive ZERO VERIFY PIN commands when 0x9E is bound"
        );

        // Pre-PUK `0x9E` challenge ALSO blocks `evil_maid` BEFORE `00 2C` PUK is ever sent!
        *evil_maid.remaining_retries.borrow_mut() = 0;
        let puk_err = crate::enroll::unblock_pin_with_transport(
            &evil_maid,
            Some(&vault.card_pub_fingerprint),
            Some(&pub_9e),
            true,
            b"87654321",
            b"654321",
        )
        .unwrap_err();
        assert!(matches!(puk_err, AuthError::WrongCard));
        assert_eq!(*evil_maid.reset_retry_calls.borrow(), 0);

        // Real card passes `0x9E` pre-PIN challenge!
        let real_conn = AuthPipeline::start(vault.clone(), "S-1-5-21-100", "alice", "WORKSTATION")
            .unwrap()
            .connect_with_transport(&real_card)
            .unwrap();
        real_conn.verify_pre_pin_card_auth(&pub_9e).unwrap();

        // Fail-closed test: if a card omits PIN retry metadata (`Ok(None)`), Lock-Screen
        // PUK unblock (`require_pin_blocked = true`) MUST reject it!
        real_card.hide_pin_metadata = true;
        let none_meta_err = crate::enroll::unblock_pin_with_transport(
            &real_card,
            Some(&vault.card_pub_fingerprint),
            Some(&pub_9e),
            true,
            b"87654321",
            b"654321",
        )
        .unwrap_err();
        assert!(matches!(none_meta_err, AuthError::CardPolicy(_)));
        assert_eq!(*real_card.reset_retry_calls.borrow(), 0);
    }
}
