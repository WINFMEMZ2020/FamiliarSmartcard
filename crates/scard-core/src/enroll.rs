//! Enrollment: bind a Windows local-account password to a PIV 9D P-256 key.
//!
//! Security invariants:
//! - `Eph_Priv_enroll` exists only on the stack and is consumed by one ECDH.
//! - Only `Eph_Pub_enroll`, the wrapped DEK, and the encrypted password are
//!   persisted.
//! - The card must already contain an on-card-generated 9D P-256 key.

use crate::crypto::{
    aes_gcm_encrypt, hkdf_sha256, p256_generate_ephemeral, p256_public_from_sec1,
    p256_public_to_sec1, p256_shared_secret, random_key, random_nonce, random_salt, sha256,
};
use crate::error::{AuthError, Result};
use crate::pcsc::{ScardContext, SCARD_RESET_CARD};
use crate::piv::{PivSession, SLOT_KEY_MANAGEMENT};
use crate::vault::{
    aad_password, aad_wrap, pad_password, VaultBlob, ALG_P256, APP_PIV, VAULT_VERSION,
};

pub struct EnrollResult {
    pub vault: VaultBlob,
    pub card_name: Option<String>,
    pub card_pub_fingerprint: [u8; 32],
    pub card_pub_sec1: Vec<u8>,
}

/// Enroll `password` for a local account using the first usable PIV card.
///
/// The card must already have a 9D P-256 key. This function does not verify a
/// PIN and does not generate key material on the card; provisioning is a
/// separate, explicit step.
pub fn enroll(
    reader: Option<&str>,
    password: &str,
    sid: &str,
    username: &str,
    computer: &str,
    password_last_set: u64,
) -> Result<EnrollResult> {
    let context = ScardContext::new()?;
    let readers = match reader {
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

        let session = PivSession::new(&card);
        let selected = match session.select() {
            Ok(selected) => selected,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };

        let card_pub_sec1 = match session.read_ec_public_key(SLOT_KEY_MANAGEMENT) {
            Ok(public_key) => public_key,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };

        let card_pub = match p256_public_from_sec1(&card_pub_sec1) {
            Ok(public_key) => public_key,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };

        let fingerprint = sha256(&card_pub_sec1);

        // Encrypt the Windows password under a random DEK.
        let dek = random_key();
        let salt = random_salt();
        let nonce = random_nonce();
        let wrap_nonce = random_nonce();

        let padded_password = pad_password(password)?;
        let password_aad = aad_password(
            VAULT_VERSION,
            APP_PIV,
            SLOT_KEY_MANAGEMENT,
            ALG_P256,
            &fingerprint,
            sid,
            username,
            computer,
            password_last_set,
        );
        let (ciphertext, tag) =
            aes_gcm_encrypt(dek.as_ref(), &nonce, &padded_password, &password_aad)?;

        // Wrap the DEK under a KEK derived from the card public key.
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
            sid,
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
            password_last_set,
            created_at: unix_now(),
        };

        drop(session);
        let _ = card.end_transaction(SCARD_RESET_CARD);
        let _ = card.disconnect(SCARD_RESET_CARD);

        return Ok(EnrollResult {
            vault,
            card_name: selected.card_name,
            card_pub_fingerprint: fingerprint,
            card_pub_sec1,
        });
    }

    Err(last_error.unwrap_or(AuthError::NoCard))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
