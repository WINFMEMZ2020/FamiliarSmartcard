//! Symmetric ECB block ciphers required for PIV Slot `0x9B` Management Key
//! challenge-response authentication (`NIST SP 800-73-4` Part 2 Appendix A.4.2):
//! - `0x03`: 3-Key Triple-DES (`3DES-EDE3`, 24-byte key, 8-byte block), including
//!   support for the degenerate PIV factory-default key (`K1 == K2 == K3 = 0102030405060708`).
//! - `0x08`: AES-128 (16-byte key, 16-byte block).
//! - `0x0A`: AES-192 (24-byte key, 16-byte block — default on newer PIV firmware).
//! - `0x0C`: AES-256 (32-byte key, 16-byte block).

#![forbid(unsafe_code)]

use crate::error::{AuthError, Result};
use crate::piv::{ALG_3DES, ALG_AES_128, ALG_AES_192, ALG_AES_256};
use aes::{Aes128, Aes192, Aes256};
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use zeroize::Zeroizing;

/// Return the cipher block size in bytes for a PIV `0x9B` management key algorithm.
pub fn mgmt_block_len(alg: u8) -> Result<usize> {
    match alg {
        ALG_3DES => Ok(8),
        ALG_AES_128 | ALG_AES_192 | ALG_AES_256 => Ok(16),
        _ => Err(AuthError::Unsupported(
            "unsupported PIV 0x9B management key algorithm",
        )),
    }
}

/// Return the expected key length in bytes for a PIV `0x9B` management key algorithm.
pub fn mgmt_key_len(alg: u8) -> Result<usize> {
    match alg {
        ALG_3DES => Ok(24),
        ALG_AES_128 => Ok(16),
        ALG_AES_192 => Ok(24),
        ALG_AES_256 => Ok(32),
        _ => Err(AuthError::Unsupported(
            "unsupported PIV 0x9B management key algorithm",
        )),
    }
}

/// Single-block ECB encryption for PIV `0x9B` management key authentication.
pub fn mgmt_ecb_encrypt(alg: u8, key: &[u8], block: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    match alg {
        ALG_3DES => {
            if key.len() != 24 || block.len() != 8 {
                return Err(AuthError::Crypto(
                    "3DES management key requires 24-byte key and 8-byte block".into(),
                ));
            }
            let mut k1 = Zeroizing::new([0u8; 8]);
            let mut k2 = Zeroizing::new([0u8; 8]);
            let mut k3 = Zeroizing::new([0u8; 8]);
            let mut b = Zeroizing::new([0u8; 8]);
            k1.copy_from_slice(&key[0..8]);
            k2.copy_from_slice(&key[8..16]);
            k3.copy_from_slice(&key[16..24]);
            b.copy_from_slice(block);

            let s1 = Zeroizing::new(des_crypt(&k1, &b, false));
            let s2 = Zeroizing::new(des_crypt(&k2, &s1, true));
            let s3 = Zeroizing::new(des_crypt(&k3, &s2, false));
            Ok(Zeroizing::new(s3.to_vec()))
        }
        ALG_AES_128 => {
            if key.len() != 16 || block.len() != 16 {
                return Err(AuthError::Crypto(
                    "AES-128 management key requires 16-byte key and 16-byte block".into(),
                ));
            }
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| AuthError::Crypto("invalid AES-128 key".into()))?;
            let mut buf = Zeroizing::new([0u8; 16]);
            buf.copy_from_slice(block);
            cipher.encrypt_block((&mut *buf).into());
            Ok(Zeroizing::new(buf.to_vec()))
        }
        ALG_AES_192 => {
            if key.len() != 24 || block.len() != 16 {
                return Err(AuthError::Crypto(
                    "AES-192 management key requires 24-byte key and 16-byte block".into(),
                ));
            }
            let cipher = Aes192::new_from_slice(key)
                .map_err(|_| AuthError::Crypto("invalid AES-192 key".into()))?;
            let mut buf = Zeroizing::new([0u8; 16]);
            buf.copy_from_slice(block);
            cipher.encrypt_block((&mut *buf).into());
            Ok(Zeroizing::new(buf.to_vec()))
        }
        ALG_AES_256 => {
            if key.len() != 32 || block.len() != 16 {
                return Err(AuthError::Crypto(
                    "AES-256 management key requires 32-byte key and 16-byte block".into(),
                ));
            }
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| AuthError::Crypto("invalid AES-256 key".into()))?;
            let mut buf = Zeroizing::new([0u8; 16]);
            buf.copy_from_slice(block);
            cipher.encrypt_block((&mut *buf).into());
            Ok(Zeroizing::new(buf.to_vec()))
        }
        _ => Err(AuthError::Unsupported(
            "unsupported PIV 0x9B management key algorithm",
        )),
    }
}

/// Single-block ECB decryption for PIV `0x9B` management key authentication.
pub fn mgmt_ecb_decrypt(alg: u8, key: &[u8], block: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    match alg {
        ALG_3DES => {
            if key.len() != 24 || block.len() != 8 {
                return Err(AuthError::Crypto(
                    "3DES management key requires 24-byte key and 8-byte block".into(),
                ));
            }
            let mut k1 = Zeroizing::new([0u8; 8]);
            let mut k2 = Zeroizing::new([0u8; 8]);
            let mut k3 = Zeroizing::new([0u8; 8]);
            let mut b = Zeroizing::new([0u8; 8]);
            k1.copy_from_slice(&key[0..8]);
            k2.copy_from_slice(&key[8..16]);
            k3.copy_from_slice(&key[16..24]);
            b.copy_from_slice(block);

            let s1 = Zeroizing::new(des_crypt(&k3, &b, true));
            let s2 = Zeroizing::new(des_crypt(&k2, &s1, false));
            let s3 = Zeroizing::new(des_crypt(&k1, &s2, true));
            Ok(Zeroizing::new(s3.to_vec()))
        }
        ALG_AES_128 => {
            if key.len() != 16 || block.len() != 16 {
                return Err(AuthError::Crypto(
                    "AES-128 management key requires 16-byte key and 16-byte block".into(),
                ));
            }
            let cipher = Aes128::new_from_slice(key)
                .map_err(|_| AuthError::Crypto("invalid AES-128 key".into()))?;
            let mut buf = Zeroizing::new([0u8; 16]);
            buf.copy_from_slice(block);
            cipher.decrypt_block((&mut *buf).into());
            Ok(Zeroizing::new(buf.to_vec()))
        }
        ALG_AES_192 => {
            if key.len() != 24 || block.len() != 16 {
                return Err(AuthError::Crypto(
                    "AES-192 management key requires 24-byte key and 16-byte block".into(),
                ));
            }
            let cipher = Aes192::new_from_slice(key)
                .map_err(|_| AuthError::Crypto("invalid AES-192 key".into()))?;
            let mut buf = Zeroizing::new([0u8; 16]);
            buf.copy_from_slice(block);
            cipher.decrypt_block((&mut *buf).into());
            Ok(Zeroizing::new(buf.to_vec()))
        }
        ALG_AES_256 => {
            if key.len() != 32 || block.len() != 16 {
                return Err(AuthError::Crypto(
                    "AES-256 management key requires 32-byte key and 16-byte block".into(),
                ));
            }
            let cipher = Aes256::new_from_slice(key)
                .map_err(|_| AuthError::Crypto("invalid AES-256 key".into()))?;
            let mut buf = Zeroizing::new([0u8; 16]);
            buf.copy_from_slice(block);
            cipher.decrypt_block((&mut *buf).into());
            Ok(Zeroizing::new(buf.to_vec()))
        }
        _ => Err(AuthError::Unsupported(
            "unsupported PIV 0x9B management key algorithm",
        )),
    }
}

// ---------------------------------------------------------------------------
// FIPS PUB 46-3 Single-Block DES (used solely as the 3-stage EDE3 primitive)
// ---------------------------------------------------------------------------

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const E_TABLE: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P_TABLE: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const SBOX: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

#[inline]
fn permute(input: u64, in_bits: u8, table: &[u8]) -> u64 {
    let mut out = 0u64;
    for &pos in table {
        out = (out << 1) | ((input >> (in_bits - pos)) & 1);
    }
    out
}

#[inline]
fn rotl28(val: u32, shift: u8) -> u32 {
    ((val << shift) | (val >> (28 - shift))) & 0x0FFF_FFFF
}

fn des_subkeys(key: &[u8; 8]) -> Zeroizing<[u64; 16]> {
    let raw = u64::from_be_bytes(*key);
    let pc1 = permute(raw, 64, &PC1);
    let mut c = ((pc1 >> 28) as u32) & 0x0FFF_FFFF;
    let mut d = (pc1 as u32) & 0x0FFF_FFFF;
    let mut subkeys = Zeroizing::new([0u64; 16]);
    for (round, &s) in SHIFTS.iter().enumerate() {
        c = rotl28(c, s);
        d = rotl28(d, s);
        let cd = ((c as u64) << 28) | (d as u64);
        subkeys[round] = permute(cd, 56, &PC2);
    }
    subkeys
}

fn feistel(r: u32, subkey: u64) -> u32 {
    let expanded = permute(r as u64, 32, &E_TABLE) ^ subkey;
    let mut s_out = 0u32;
    for (box_idx, sbox) in SBOX.iter().enumerate() {
        let six = ((expanded >> (42 - box_idx * 6)) & 0x3F) as usize;
        let row = ((six >> 4) & 0x02) | (six & 0x01);
        let col = (six >> 1) & 0x0F;
        s_out = (s_out << 4) | (sbox[row][col] as u32);
    }
    permute(s_out as u64, 32, &P_TABLE) as u32
}

fn des_crypt(key: &[u8; 8], block: &[u8; 8], decrypt: bool) -> [u8; 8] {
    let subkeys = des_subkeys(key);
    let ip = permute(u64::from_be_bytes(*block), 64, &IP);
    let mut left = (ip >> 32) as u32;
    let mut right = ip as u32;

    for i in 0..16 {
        let sk = if decrypt { subkeys[15 - i] } else { subkeys[i] };
        let next_left = right;
        let next_right = left ^ feistel(right, sk);
        left = next_left;
        right = next_right;
    }

    let preoutput = ((right as u64) << 32) | (left as u64);
    permute(preoutput, 64, &FP).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piv::DEFAULT_MGMT_KEY;

    #[test]
    fn des_and_3des_match_nist_sp800_67_and_default_piv_key() {
        // 1. Classic FIPS 46-3 single-DES test vector via degenerate EDE3 (K1 == K2 == K3)
        let mut k_single = [0u8; 24];
        let single_8 = hex::decode("0123456789ABCDEF").unwrap();
        k_single[0..8].copy_from_slice(&single_8);
        k_single[8..16].copy_from_slice(&single_8);
        k_single[16..24].copy_from_slice(&single_8);
        let plain = hex::decode("4E6F772069732074").unwrap();
        let enc = mgmt_ecb_encrypt(ALG_3DES, &k_single, &plain).unwrap();
        assert_eq!(&enc[..], &hex::decode("3FA40E8A984D4815").unwrap()[..]);
        let dec = mgmt_ecb_decrypt(ALG_3DES, &k_single, &enc).unwrap();
        assert_eq!(&dec[..], &plain[..]);

        // 2. NIST SP 800-67 Rev 2 TDEA 3-key test vector:
        // K1 = 0123456789ABCDEF, K2 = 23456789ABCDEF01, K3 = 456789ABCDEF0123
        // Plain = 5468652071756663 ("The qufc") -> Cipher = A826FD8CE53B855F
        let tdea_key = hex::decode("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123").unwrap();
        let tdea_plain = hex::decode("5468652071756663").unwrap();
        let tdea_enc = mgmt_ecb_encrypt(ALG_3DES, &tdea_key, &tdea_plain).unwrap();
        assert_eq!(&tdea_enc[..], &hex::decode("A826FD8CE53B855F").unwrap()[..]);
        let tdea_dec = mgmt_ecb_decrypt(ALG_3DES, &tdea_key, &tdea_enc).unwrap();
        assert_eq!(&tdea_dec[..], &tdea_plain[..]);

        // 3. Factory default PIV 0x9B key (0102030405060708 x 3)
        let challenge = [0xA5, 0x5A, 0x12, 0x34, 0x99, 0xFE, 0x00, 0x77];
        let def_enc = mgmt_ecb_encrypt(ALG_3DES, &DEFAULT_MGMT_KEY, &challenge).unwrap();
        assert_ne!(&def_enc[..], &challenge[..]);
        let def_dec = mgmt_ecb_decrypt(ALG_3DES, &DEFAULT_MGMT_KEY, &def_enc).unwrap();
        assert_eq!(&def_dec[..], &challenge[..]);
    }

    #[test]
    fn aes_128_192_256_match_nist_fips_197_vectors() {
        let plain = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();

        // FIPS 197 Appendix C.1 AES-128
        let k128 = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let c128 = mgmt_ecb_encrypt(ALG_AES_128, &k128, &plain).unwrap();
        assert_eq!(
            &c128[..],
            &hex::decode("69C4E0D86A7B0430D8CDB78070B4C55A").unwrap()[..]
        );
        assert_eq!(
            &mgmt_ecb_decrypt(ALG_AES_128, &k128, &c128).unwrap()[..],
            &plain[..]
        );

        // FIPS 197 Appendix C.2 AES-192
        let k192 = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
        let c192 = mgmt_ecb_encrypt(ALG_AES_192, &k192, &plain).unwrap();
        assert_eq!(
            &c192[..],
            &hex::decode("DDA97CA4864CDFE06EAF70A0EC0D7191").unwrap()[..]
        );
        assert_eq!(
            &mgmt_ecb_decrypt(ALG_AES_192, &k192, &c192).unwrap()[..],
            &plain[..]
        );

        // FIPS 197 Appendix C.3 AES-256
        let k256 = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let c256 = mgmt_ecb_encrypt(ALG_AES_256, &k256, &plain).unwrap();
        assert_eq!(
            &c256[..],
            &hex::decode("8EA2B7CA516745BFEAFC49904B496089").unwrap()[..]
        );
        assert_eq!(
            &mgmt_ecb_decrypt(ALG_AES_256, &k256, &c256).unwrap()[..],
            &plain[..]
        );
    }
}
