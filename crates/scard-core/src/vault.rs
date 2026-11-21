//! Versioned vault format.
//!
//! The vault contains only ciphertext and public metadata. It must never
//! contain `Eph_Priv_enroll`, the DEK, the KEK, or the Windows password.

#![forbid(unsafe_code)]

use crate::crypto::{aes_gcm_encrypt, random_nonce};
use crate::error::{AuthError, Result};
use zeroize::Zeroizing;

pub const VAULT_MAGIC: [u8; 4] = *b"FSC1";
pub const VAULT_VERSION: u8 = 1;
pub const APP_PIV: u8 = 1;
pub const ALG_P256: u8 = 1;
pub const PASSWORD_PADDED_LEN: usize = 256;
pub const PASSWORD_LAST_SET_TOLERANCE_SECS: u64 = 10;

const MAX_EPH_PUB: usize = 133;
const MAX_WRAPPED_DEK: usize = 128;
const MAX_CIPHERTEXT: usize = 512;
const MAX_TOTAL: usize = 4096;

#[derive(Debug, Clone)]
pub struct VaultBlob {
    pub version: u8,
    pub app: u8,
    pub slot: u8,
    pub alg: u8,
    pub card_pub_fingerprint: [u8; 32],
    pub eph_pub_enroll: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: [u8; 12],
    pub wrap_tag: [u8; 16],
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub password_last_set: u64,
    pub created_at: u64,
}

impl VaultBlob {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.version != VAULT_VERSION {
            return Err(AuthError::Vault(format!(
                "unsupported vault version {}",
                self.version
            )));
        }
        if self.eph_pub_enroll.len() > MAX_EPH_PUB
            || self.wrapped_dek.len() > MAX_WRAPPED_DEK
            || self.ciphertext.len() > MAX_CIPHERTEXT
        {
            return Err(AuthError::Vault("vault field too large".into()));
        }

        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&VAULT_MAGIC);
        out.push(self.version);
        out.push(self.app);
        out.push(self.slot);
        out.push(self.alg);
        out.extend_from_slice(&self.card_pub_fingerprint);
        push_bytes(&mut out, &self.eph_pub_enroll)?;
        push_bytes(&mut out, &self.wrapped_dek)?;
        out.extend_from_slice(&self.wrap_nonce);
        out.extend_from_slice(&self.wrap_tag);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        push_bytes(&mut out, &self.ciphertext)?;
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.password_last_set.to_le_bytes());
        out.extend_from_slice(&self.created_at.to_le_bytes());

        if out.len() > MAX_TOTAL {
            return Err(AuthError::Vault("encoded vault too large".into()));
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_TOTAL {
            return Err(AuthError::Vault("vault input too large".into()));
        }
        let mut reader = Reader::new(data);

        if reader.fixed::<4>()? != VAULT_MAGIC {
            return Err(AuthError::Vault("bad vault magic".into()));
        }
        let version = reader.u8()?;
        if version != VAULT_VERSION {
            return Err(AuthError::Vault(format!(
                "unsupported vault version {}",
                version
            )));
        }
        let app = reader.u8()?;
        let slot = reader.u8()?;
        let alg = reader.u8()?;
        if app != APP_PIV || alg != ALG_P256 {
            return Err(AuthError::Vault("unsupported app/algorithm".into()));
        }

        let card_pub_fingerprint = reader.fixed::<32>()?;
        let eph_pub_enroll = reader.blob(MAX_EPH_PUB)?;
        let wrapped_dek = reader.blob(MAX_WRAPPED_DEK)?;
        let wrap_nonce = reader.fixed::<12>()?;
        let wrap_tag = reader.fixed::<16>()?;
        let salt = reader.fixed::<32>()?;
        let nonce = reader.fixed::<12>()?;
        let ciphertext = reader.blob(MAX_CIPHERTEXT)?;
        let tag = reader.fixed::<16>()?;
        let password_last_set = reader.u64()?;
        let created_at = reader.u64()?;

        if reader.remaining() != 0 {
            return Err(AuthError::Vault("trailing bytes in vault".into()));
        }

        Ok(Self {
            version,
            app,
            slot,
            alg,
            card_pub_fingerprint,
            eph_pub_enroll,
            wrapped_dek,
            wrap_nonce,
            wrap_tag,
            salt,
            nonce,
            ciphertext,
            tag,
            password_last_set,
            created_at,
        })
    }

    /// Re-encrypt `password` under an already-verified `dek` and a new static
    /// `password_last_set` timestamp using a fresh random AES-GCM nonce.
    ///
    /// Used in Phase D of two-phase atomic password rotation after `NetUserSetInfo`
    /// updates the account password, avoiding a second smart-card touch/PIN cycle.
    pub fn reencrypt_password_with_dek(
        &self,
        dek: &[u8; 32],
        password: &str,
        sid: &str,
        username: &str,
        computer: &str,
        new_password_last_set: u64,
    ) -> Result<Self> {
        let padded = pad_password(password)?;
        let fresh_nonce = random_nonce();
        let aad = aad_password(&AadPasswordParams {
            version: self.version,
            app: self.app,
            slot: self.slot,
            alg: self.alg,
            fingerprint: &self.card_pub_fingerprint,
            sid,
            username,
            computer,
            password_last_set: new_password_last_set,
        });
        let (ciphertext, tag) = aes_gcm_encrypt(dek, &fresh_nonce, padded.as_ref(), &aad)?;
        let mut updated = self.clone();
        updated.nonce = fresh_nonce;
        updated.ciphertext = ciphertext;
        updated.tag = tag;
        updated.password_last_set = new_password_last_set;
        Ok(updated)
    }
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u16::try_from(value.len()).map_err(|_| AuthError::Vault("field too long".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8> {
        let value = *self
            .data
            .get(self.pos)
            .ok_or_else(|| AuthError::Vault("truncated vault".into()))?;
        self.pos += 1;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or_else(|| AuthError::Vault("vault offset overflow".into()))?;
        if end > self.data.len() {
            return Err(AuthError::Vault("truncated vault".into()));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.fixed::<2>()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.fixed::<8>()?))
    }

    fn blob(&mut self, max: usize) -> Result<Vec<u8>> {
        let len = self.u16()? as usize;
        if len > max {
            return Err(AuthError::Vault("vault field exceeds limit".into()));
        }
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| AuthError::Vault("vault offset overflow".into()))?;
        if end > self.data.len() {
            return Err(AuthError::Vault("truncated vault".into()));
        }
        let out = self.data[self.pos..end].to_vec();
        self.pos = end;
        Ok(out)
    }
}

fn push_lp(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&bytes[..len as usize]);
}

fn normalize_user(value: &str) -> String {
    value.to_lowercase()
}

fn normalize_computer(value: &str) -> String {
    value.to_uppercase()
}

pub struct AadPasswordParams<'a> {
    pub version: u8,
    pub app: u8,
    pub slot: u8,
    pub alg: u8,
    pub fingerprint: &'a [u8; 32],
    pub sid: &'a str,
    pub username: &'a str,
    pub computer: &'a str,
    pub password_last_set: u64,
}

/// AAD for the password ciphertext.
///
/// Variable-length fields use a u32 little-endian length prefix. The timestamp
/// is the static value stored in the vault; never a value recomputed during
/// login.
pub fn aad_password(params: &AadPasswordParams<'_>) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"FamiliarSmartcard/v2/aad-password\0");
    aad.extend_from_slice(&[params.version, params.app, params.slot, params.alg]);
    aad.extend_from_slice(params.fingerprint);
    push_lp(&mut aad, params.sid);
    push_lp(&mut aad, &normalize_user(params.username));
    push_lp(&mut aad, &normalize_computer(params.computer));
    aad.extend_from_slice(&params.password_last_set.to_le_bytes());
    aad
}

/// AAD for the wrapped DEK.
pub fn aad_wrap(
    version: u8,
    app: u8,
    slot: u8,
    alg: u8,
    fingerprint: &[u8; 32],
    sid: &str,
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"FamiliarSmartcard/v2/aad-wrap\0");
    aad.extend_from_slice(&[version, app, slot, alg]);
    aad.extend_from_slice(fingerprint);
    push_lp(&mut aad, sid);
    aad
}

/// Windows reports `usri1_password_age` as relative seconds; `now - age`
/// contains second-boundary jitter. Compare the derived timestamp with the
/// static enrollment value using a small tolerance.
pub fn password_last_set_matches(stored: u64, current: u64) -> bool {
    stored.abs_diff(current) <= PASSWORD_LAST_SET_TOLERANCE_SECS
}

/// Encode a UTF-16LE password with a 2-byte length prefix and zero padding.
/// All intermediate and returned buffers are wrapped in `Zeroizing`.
pub fn pad_password(password: &str) -> Result<Zeroizing<[u8; PASSWORD_PADDED_LEN]>> {
    let utf16: Zeroizing<Vec<u16>> = Zeroizing::new(password.encode_utf16().collect());
    if utf16.len() > 127 {
        return Err(AuthError::Vault("Windows password too long".into()));
    }
    let byte_len = utf16.len() * 2;
    let mut out = Zeroizing::new([0u8; PASSWORD_PADDED_LEN]);
    out[..2].copy_from_slice(&(byte_len as u16).to_le_bytes());
    for (i, unit) in utf16.iter().enumerate() {
        let offset = 2 + i * 2;
        out[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    Ok(out)
}

/// Decode the padded UTF-16LE password inside `Zeroizing` buffers.
pub fn unpad_password(padded: &[u8]) -> Result<Zeroizing<String>> {
    if padded.len() != PASSWORD_PADDED_LEN {
        return Err(AuthError::Vault("bad padded password length".into()));
    }
    let byte_len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    if byte_len > 254 || byte_len % 2 != 0 || 2 + byte_len > padded.len() {
        return Err(AuthError::Vault("bad password length prefix".into()));
    }
    let mut units: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(byte_len / 2));
    for i in 0..(byte_len / 2) {
        let offset = 2 + i * 2;
        units.push(u16::from_le_bytes([padded[offset], padded[offset + 1]]));
    }
    let decoded = String::from_utf16(&units)
        .map_err(|_| AuthError::Vault("invalid UTF-16 password".into()))?;
    Ok(Zeroizing::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultBlob {
        VaultBlob {
            version: VAULT_VERSION,
            app: APP_PIV,
            slot: 0x9D,
            alg: ALG_P256,
            card_pub_fingerprint: [0x11; 32],
            eph_pub_enroll: vec![0x04; 65],
            wrapped_dek: vec![0x22; 48],
            wrap_nonce: [0x33; 12],
            wrap_tag: [0x44; 16],
            salt: [0x55; 32],
            nonce: [0x66; 12],
            ciphertext: vec![0x77; PASSWORD_PADDED_LEN],
            tag: [0x88; 16],
            password_last_set: 123456,
            created_at: 654321,
        }
    }

    #[test]
    fn vault_roundtrip() {
        let vault = sample();
        let encoded = vault.encode().unwrap();
        let decoded = VaultBlob::decode(&encoded).unwrap();
        assert_eq!(decoded.slot, 0x9D);
        assert_eq!(decoded.eph_pub_enroll, vault.eph_pub_enroll);
        assert_eq!(decoded.password_last_set, vault.password_last_set);
    }

    #[test]
    fn vault_rejects_bad_magic() {
        let mut encoded = sample().encode().unwrap();
        encoded[0] = b'X';
        assert!(VaultBlob::decode(&encoded).is_err());
    }

    #[test]
    fn password_padding_roundtrip() {
        let padded = pad_password("pässwörd-123").unwrap();
        assert_eq!(
            unpad_password(&padded[..]).unwrap().as_str(),
            "pässwörd-123"
        );
    }

    #[test]
    fn password_rejects_odd_length() {
        let mut padded = [0u8; PASSWORD_PADDED_LEN];
        padded[0] = 3;
        assert!(unpad_password(&padded).is_err());
    }

    #[test]
    fn aad_has_no_variable_length_collision() {
        let fingerprint = [0x11; 32];
        let a = aad_password(&AadPasswordParams {
            version: VAULT_VERSION,
            app: APP_PIV,
            slot: 0x9D,
            alg: ALG_P256,
            fingerprint: &fingerprint,
            sid: "S-1-5-21-1",
            username: "alice",
            computer: "pc1",
            password_last_set: 123,
        });
        let b = aad_password(&AadPasswordParams {
            version: VAULT_VERSION,
            app: APP_PIV,
            slot: 0x9D,
            alg: ALG_P256,
            fingerprint: &fingerprint,
            sid: "S-1-5-21-1",
            username: "alic",
            computer: "epc1",
            password_last_set: 123,
        });
        assert_ne!(a, b);
    }

    #[test]
    fn password_last_set_tolerance() {
        assert!(password_last_set_matches(1000, 1010));
        assert!(password_last_set_matches(1000, 990));
        assert!(!password_last_set_matches(1000, 1011));
        assert!(!password_last_set_matches(1000, 989));
    }

    #[test]
    fn timestamp_is_part_of_aad() {
        let fingerprint = [0x11; 32];
        let a = aad_password(&AadPasswordParams {
            version: VAULT_VERSION,
            app: APP_PIV,
            slot: 0x9D,
            alg: ALG_P256,
            fingerprint: &fingerprint,
            sid: "S-1-5-21-1",
            username: "alice",
            computer: "pc1",
            password_last_set: 123,
        });
        let b = aad_password(&AadPasswordParams {
            version: VAULT_VERSION,
            app: APP_PIV,
            slot: 0x9D,
            alg: ALG_P256,
            fingerprint: &fingerprint,
            sid: "S-1-5-21-1",
            username: "alice",
            computer: "pc1",
            password_last_set: 124,
        });
        assert_ne!(a, b);
    }
}
