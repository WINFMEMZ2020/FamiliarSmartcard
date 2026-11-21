//! Cryptographic primitives for the vault.
//!
//! - P-256 ECDH (ephemeral or static peer public key)
//! - HKDF-SHA256
//! - AES-256-GCM (detached tag)
//! - constant-time comparison
//! - zeroization helpers and unambiguous high-entropy recovery password generator

#![forbid(unsafe_code)]

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
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// 32-character unambiguous alphabet (excludes 0, O, 1, I, l).
/// Exactly 5 bits of entropy per character with zero modulo bias (`byte & 0x1F`).
const RECOVERY_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
pub const RECOVERY_GROUPS: usize = 9;
pub const RECOVERY_GROUP_LEN: usize = 4;
pub const RECOVERY_CONFIRM_CHARS: usize = 6;

/// Fill a fixed-size array from the OS CSPRNG.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(out.as_mut());
    out
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

/// Generate a 36-character grouped random password (`XXXX-XXXX-...`, 9 groups = 180 bits entropy).
pub fn generate_recovery_password() -> Zeroizing<String> {
    const RAW_CHARS: usize = RECOVERY_GROUPS * RECOVERY_GROUP_LEN;
    let mut raw_bytes = Zeroizing::new([0u8; RAW_CHARS]);
    OsRng.fill_bytes(raw_bytes.as_mut());

    let cap = RAW_CHARS + (RECOVERY_GROUPS - 1);
    let mut password = Zeroizing::new(String::with_capacity(cap));
    for (idx, &byte) in raw_bytes.iter().enumerate() {
        if idx > 0 && idx % RECOVERY_GROUP_LEN == 0 {
            password.push('-');
        }
        let ch = RECOVERY_ALPHABET[(byte & 0x1F) as usize] as char;
        password.push(ch);
    }
    password
}

/// Constant-time check that `typed_tail` matches the last `RECOVERY_CONFIRM_CHARS`
/// non-hyphen characters of `full_password` (case-insensitive ASCII).
pub fn verify_recovery_tail(full_password: &str, typed_tail: &str) -> bool {
    let mut expected = Zeroizing::new(Vec::with_capacity(36));
    for b in full_password.bytes() {
        if b != b'-' && !b.is_ascii_whitespace() {
            expected.push(b.to_ascii_uppercase());
        }
    }
    if expected.len() < RECOVERY_CONFIRM_CHARS {
        return false;
    }

    let mut actual = Zeroizing::new(Vec::with_capacity(16));
    for b in typed_tail.bytes() {
        if b != b'-' && !b.is_ascii_whitespace() {
            actual.push(b.to_ascii_uppercase());
        }
    }
    if actual.len() != RECOVERY_CONFIRM_CHARS {
        return false;
    }

    let tail_start = expected.len() - RECOVERY_CONFIRM_CHARS;
    constant_time_eq(&expected[tail_start..], actual.as_slice())
}

/// Generate an unbiased 8-digit random PIV PUK (`00000000`..`99999999`).
pub fn generate_random_puk() -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(8));
    let mut byte = Zeroizing::new([0u8; 1]);
    while out.len() < 8 {
        OsRng.fill_bytes(byte.as_mut());
        // Reject >= 250 so `byte % 10` has zero modulo bias across 0..=9.
        if byte[0] < 250 {
            out.push((b'0' + (byte[0] % 10)) as char);
        }
    }
    out
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
///
/// Uses a zeroizing working buffer so an error mid-operation never leaves an
/// unzeroized plaintext heap allocation behind.
pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AuthError::Crypto("invalid AES-256-GCM key length".into()))?;
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    let tag = cipher
        .encrypt_in_place_detached(&Nonce::from(*nonce), aad, buffer.as_mut())
        .map_err(|_| AuthError::Crypto("AES-256-GCM encryption failed".into()))?;
    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(&tag[..]);
    let ciphertext = buffer.as_slice().to_vec();
    Ok((ciphertext, tag_bytes))
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
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    if cipher
        .decrypt_in_place_detached(&Nonce::from(*nonce), aad, buffer.as_mut(), &Tag::from(*tag))
        .is_err()
    {
        buffer.zeroize();
        return Err(AuthError::Crypto(
            "AES-256-GCM authentication failed".into(),
        ));
    }
    Ok(buffer)
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
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw[..]);
    out
}

pub fn p256_public_from_sec1(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes)
        .map_err(|_| AuthError::Crypto("invalid P-256 public key".into()))
}

pub fn p256_public_to_sec1(public: &PublicKey) -> Vec<u8> {
    public.to_encoded_point(false).as_bytes().to_vec()
}

/// Ephemeral scalar blinding state for single-APDU anti-replay ECDH unwrap.
pub struct P256BlindState {
    scalar: Zeroizing<p256::NonZeroScalar>,
    card_pub_proj: p256::ProjectivePoint,
}

/// Blind `eph_pub_enroll_sec1` (`P_enroll`) with a fresh 256-bit random scalar `b`:
/// `B = P_enroll + b * G`.
///
/// Security properties:
/// - `B` is uniformly distributed over `P-256` on every login, preventing static
///   replay proxies AND hiding `P_enroll` from PC/SC / USB bus observers.
/// - Requires only **one** `GENERAL AUTHENTICATE` (`00 87`) APDU on `Slot 0x9D`,
///   guaranteeing **1 physical button press** even on hardware security keys whose
///   firmware requires a button press before every `00 87` command.
pub fn p256_blind_enrollment_point(
    eph_pub_enroll_sec1: &[u8],
    card_pub_sec1: &[u8],
) -> Result<(P256BlindState, Vec<u8>)> {
    let p_enroll = p256_public_from_sec1(eph_pub_enroll_sec1)?.to_projective();
    let card_pub_proj = p256_public_from_sec1(card_pub_sec1)?.to_projective();

    loop {
        let b = Zeroizing::new(p256::NonZeroScalar::random(&mut OsRng));
        let blinded_proj = p_enroll + (p256::ProjectivePoint::GENERATOR * **b);
        let blinded_aff = p256::AffinePoint::from(blinded_proj);
        if let Ok(blinded_pk) = PublicKey::from_affine(blinded_aff) {
            let sec1 = p256_public_to_sec1(&blinded_pk);
            return Ok((
                P256BlindState {
                    scalar: b,
                    card_pub_proj,
                },
                sec1,
            ));
        }
    }
}

/// Unblind the 32-byte X-coordinate `card_ecdh_x = x(d_C * B)` returned by the card
/// into the two candidate static shared-secret X-coordinates `x(±R - b * Q_card)`.
/// One candidate equals `x(d_C * P_enroll)` iff the card computed `d_C * B` live.
pub fn p256_unblind_ecdh_candidates(
    blind: P256BlindState,
    card_ecdh_x: &[u8],
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    if card_ecdh_x.len() != 32 || is_all_zero(card_ecdh_x) {
        return Err(AuthError::Crypto(
            "invalid ECDH shared secret from card".into(),
        ));
    }

    let mut compressed = Zeroizing::new([0u8; 33]);
    compressed[0] = 0x02;
    compressed[1..33].copy_from_slice(card_ecdh_x);

    let r_even = PublicKey::from_sec1_bytes(compressed.as_ref())
        .map_err(|_| AuthError::WrongCard)?
        .to_projective();
    let r_odd = -r_even;

    let offset = blind.card_pub_proj * **blind.scalar;
    let mut out = Vec::with_capacity(2);
    for cand_proj in [r_even - offset, r_odd - offset] {
        let cand_aff = p256::AffinePoint::from(cand_proj);
        if let Ok(cand_pk) = PublicKey::from_affine(cand_aff) {
            let mut raw_pt = Zeroizing::new(cand_pk.to_encoded_point(false).as_bytes().to_vec());
            if raw_pt.len() == 65 {
                let mut x_bytes = Zeroizing::new([0u8; 32]);
                x_bytes.copy_from_slice(&raw_pt[1..33]);
                if !is_all_zero(x_bytes.as_ref()) {
                    out.push(x_bytes);
                }
            }
            raw_pt.zeroize();
        }
    }

    if out.is_empty() {
        return Err(AuthError::WrongCard);
    }
    Ok(out)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Reject an all-zero ECDH result.
pub fn is_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
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

    #[test]
    fn p256_blinded_single_apdu_ecdh_recovers_exact_enrollment_secret_across_parities() {
        let card_sk = p256::SecretKey::random(&mut OsRng);
        let card_pk_sec1 = p256_public_to_sec1(&card_sk.public_key());

        let (eph_sec, eph_pub) = p256_generate_ephemeral();
        let eph_pub_sec1 = p256_public_to_sec1(&eph_pub);
        let expected_static = p256_shared_secret(eph_sec, &card_sk.public_key());

        // Run 32 independent blindings so both even and odd Y-coordinate parities of `d_C * B` are exercised!
        for _ in 0..32 {
            let (blind, blinded_pub_sec1) =
                p256_blind_enrollment_point(&eph_pub_sec1, &card_pk_sec1).unwrap();
            assert_ne!(blinded_pub_sec1, eph_pub_sec1);

            let blinded_pk = p256_public_from_sec1(&blinded_pub_sec1).unwrap();
            let card_raw =
                p256::ecdh::diffie_hellman(card_sk.to_nonzero_scalar(), blinded_pk.as_affine());
            let candidates =
                p256_unblind_ecdh_candidates(blind, card_raw.raw_secret_bytes()).unwrap();
            assert!(candidates
                .iter()
                .any(|c| constant_time_eq(c.as_ref(), expected_static.as_ref())));
        }
    }

    #[test]
    fn recovery_password_format_and_tail_verification() {
        let pw = generate_recovery_password();
        assert_eq!(pw.len(), 44);
        assert_eq!(pw.split('-').count(), 9);
        assert!(!pw.contains('0') && !pw.contains('O') && !pw.contains('1') && !pw.contains('I'));

        let clean: String = pw.chars().filter(|c| *c != '-').collect();
        let last6 = &clean[clean.len() - 6..];
        assert!(verify_recovery_tail(&pw, last6));
        assert!(verify_recovery_tail(&pw, &last6.to_ascii_lowercase()));
        assert!(!verify_recovery_tail(&pw, "22222"));
    }
}
