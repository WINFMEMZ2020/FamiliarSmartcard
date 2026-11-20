//! Compile-time authentication pipeline.
//!
//! Each state owns the previous state. A caller cannot construct
//! `KeyUnwrapped` without going through `PinVerified` -> `FreshnessProven` ->
//! `PinVerifiedForUnwrap`. Errors consume the current state; the card handle is
//! dropped and reset.

use crate::crypto::{
    aes_gcm_decrypt, constant_time_eq, hkdf_sha256, is_all_zero, p256_generate_ephemeral,
    p256_public_from_sec1, p256_public_to_sec1, p256_shared_secret, sha256,
};
use crate::error::{AuthError, Result};
use crate::pcsc::{ScardCard, ScardContext};
use crate::piv::{PivSession, ALG_ECC_P256};
use crate::vault::{aad_password, aad_wrap, unpad_password, VaultBlob};
use zeroize::Zeroizing;

/// Internal state carried by the card-bound typestate stages.
struct CardState {
    vault: VaultBlob,
    sid: String,
    username: String,
    computer: String,
    // Field order matters: the card must drop before the context.
    card: ScardCard,
    _context: ScardContext,
    card_pub_sec1: Vec<u8>,
}

pub struct AuthPipeline;

pub struct VaultLoaded {
    vault: VaultBlob,
    sid: String,
    username: String,
    computer: String,
}

pub struct CardConnected(CardState);
pub struct PinVerified(CardState);
pub struct FreshnessProven(CardState);
pub struct PinVerifiedForUnwrap(CardState);

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

    /// Connect to the enrolled card and verify its public-key fingerprint.
    ///
    /// If `reader` is `None`, all readers are tried and the one whose card
    /// matches the vault fingerprint is selected.
    pub fn connect_card(self, reader: Option<&str>) -> Result<CardConnected> {
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

            let session = PivSession::new(&card);
            if let Err(error) = session.select() {
                last_error = Some(error);
                continue;
            }

            let card_pub_sec1 = match session.read_ec_public_key(self.vault.slot) {
                Ok(public_key) => public_key,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };

            if sha256(&card_pub_sec1) != self.vault.card_pub_fingerprint {
                last_error = Some(AuthError::WrongCard);
                continue;
            }

            drop(session);
            let context = context
                .take()
                .ok_or_else(|| AuthError::Internal("missing PC/SC context".into()))?;

            return Ok(CardConnected(CardState {
                vault: self.vault,
                sid: self.sid,
                username: self.username,
                computer: self.computer,
                card,
                _context: context,
                card_pub_sec1,
            }));
        }

        Err(last_error.unwrap_or(AuthError::NoCard))
    }
}

impl CardConnected {
    /// First VERIFY. Required because the PIV 9D key uses PIN policy ALWAYS.
    pub fn verify_pin(self, pin: &mut Zeroizing<Vec<u8>>) -> Result<PinVerified> {
        let session = PivSession::new(&self.0.card);
        session.verify_pin(pin.as_slice())?;
        Ok(PinVerified(self.0))
    }
}

impl PinVerified {
    /// Fresh ECDH key confirmation. This is the anti-replay gate.
    pub fn prove_freshness(self) -> Result<FreshnessProven> {
        let state = self.0;
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

        Ok(FreshnessProven(state))
    }
}

impl FreshnessProven {
    /// Second VERIFY. The first ECDH consumed the ALWAYS-policy PIN.
    pub fn verify_pin_for_unwrap(
        self,
        pin: &mut Zeroizing<Vec<u8>>,
    ) -> Result<PinVerifiedForUnwrap> {
        let state = self.0;
        let session = PivSession::new(&state.card);
        session.verify_pin(pin.as_slice())?;
        Ok(PinVerifiedForUnwrap(state))
    }
}

impl PinVerifiedForUnwrap {
    /// Static ECDH with the enrollment public key, HKDF, and DEK unwrap.
    pub fn unwrap_dek(self) -> Result<KeyUnwrapped> {
        let state = self.0;
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
        let aad = aad_password(
            self.vault.version,
            self.vault.app,
            self.vault.slot,
            self.vault.alg,
            &self.vault.card_pub_fingerprint,
            &self.sid,
            &self.username,
            &self.computer,
            self.vault.password_last_set,
        );

        let padded = aes_gcm_decrypt(
            &self.dek[..],
            &self.vault.nonce,
            &self.vault.ciphertext,
            &self.vault.tag,
            &aad,
        )?;

        let password = unpad_password(&padded)?;
        Ok(CredentialDecrypted {
            password: Zeroizing::new(password),
        })
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

/// Convenience one-shot pipeline used by the GUI self-test.
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
