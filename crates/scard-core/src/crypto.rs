//! Cryptographic primitives for the vault.
//!
//! - P-256 ECDH (ephemeral or static peer public key)
//! - HKDF-SHA256
//! - AES-256-GCM (detached tag)
//! - constant-time comparison
//! - zeroization helpers

use crate::error::{AuthError, Result};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Fill a fixed-size array from the OS CSPRNG.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    Zeroizing::new(random_array::<KEY_LEN>())
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    random_array::<NONCE_LEN>()
}

pub fn random_salt() -> [u8; 32] {
    random_array::<32>()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HKDF-SHA256 with a 32-byte output.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, out.as_mut())
        .map_err(|_| AuthError::Crypto("HKDF expand failed".into()))?;
    Ok(out)
}

/// AES-256-GCM with a detached 16-byte tag.
pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AuthError::Crypto("invalid AES-256-GCM key length".into()))?;
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&Nonce::from(*nonce), aad, &mut buffer)
        .map_err(|_| AuthError::Crypto("AES-256-GCM encryption failed".into()))?;
    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(&tag[..]);
    Ok((buffer, tag_bytes))
}

/// AES-256-GCM authenticated decryption. Any tag/AAD mismatch is terminal.
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AuthError::Crypto("invalid AES-256-GCM key length".into()))?;
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(
            &Nonce::from(*nonce),
            aad,
            &mut buffer,
            &Tag::from(*tag),
        )
        .map_err(|_| AuthError::Crypto("AES-256-GCM authentication failed".into()))?;
    Ok(Zeroizing::new(buffer))
}

/// Generate an ephemeral P-256 key pair.
///
/// The caller must discard the secret after the single ECDH operation. For the
/// enrollment key pair, only the public key may be persisted.
pub fn p256_generate_ephemeral() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random(&mut OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// ECDH with an ephemeral secret and the card's public key.
pub fn p256_shared_secret(secret: EphemeralSecret, peer: &PublicKey) -> Zeroizing<[u8; 32]> {
    let shared = secret.diffie_hellman(peer);
    let raw = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw[..]);
    Zeroizing::new(out)
}

pub fn p256_public_from_sec1(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes)
        .map_err(|_| AuthError::Crypto("invalid P-256 public key".into()))
}

pub fn p256_public_to_sec1(public: &PublicKey) -> Vec<u8> {
    public.to_encoded_point(false).as_bytes().to_vec()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Reject an all-zero ECDH result. With a valid P-256 peer this should not
/// happen, but it is a cheap check against malformed card output.
pub fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_roundtrip_and_tamper() {
        let key = random_key();
        let nonce = random_nonce();
        let aad = b"FamiliarSmartcard/test";
        let plaintext = b"hello, vault";

        let (ciphertext, tag) = aes_gcm_encrypt(key.as_ref(), &nonce, plaintext, aad).unwrap();
        let decrypted = aes_gcm_decrypt(key.as_ref(), &nonce, &ciphertext, &tag, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);

        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        assert!(aes_gcm_decrypt(key.as_ref(), &nonce, &ciphertext, &bad_tag, aad).is_err());
    }

    #[test]
    fn hkdf_is_stable() {
        let a = hkdf_sha256(b"ikm", b"salt", b"info").unwrap();
        let b = hkdf_sha256(b"ikm", b"salt", b"info").unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn p256_ecdh_symmetry() {
        let (s1, p1) = p256_generate_ephemeral();
        let (s2, p2) = p256_generate_ephemeral();
        let a = p256_shared_secret(s1, &p2);
        let b = p256_shared_secret(s2, &p1);
        assert_eq!(a.as_ref(), b.as_ref());
    }
}
