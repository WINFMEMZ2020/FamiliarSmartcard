//! PIV `0xF9` attestation certificate verification and public-key extraction.
//!
//! Uses Windows `Crypt32` (`CertCreateCertificateContext` and
//! `CryptVerifyCertificateSignatureEx`) so both P-256 and P-384 attestation CAs
//! (e.g. RS-Key self-signed P-384 `0xF9` CA or YubiKey intermediate CA) are
//! verified without pulling in unverified ASN.1 parsers.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::crypto::{constant_time_eq, sha256};
use crate::error::{AuthError, Result};
use core::ffi::c_void;
use windows::Win32::Security::Cryptography::{
    CertCreateCertificateContext, CertFreeCertificateContext, CryptVerifyCertificateSignatureEx,
    CERT_CONTEXT, CRYPT_VERIFY_CERT_FLAGS, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
    CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};

const MAX_CERT_DER_LEN: usize = 8192;

struct CertGuard(*const CERT_CONTEXT);

impl CertGuard {
    fn parse(der: &[u8], label: &str) -> Result<Self> {
        if der.is_empty() || der.len() > MAX_CERT_DER_LEN {
            return Err(AuthError::Attestation(format!(
                "{label} certificate length {} is invalid",
                der.len()
            )));
        }
        // SAFETY: `der` is non-empty and bounded within `u32::MAX`.
        let ptr =
            unsafe { CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der) };
        if ptr.is_null() {
            return Err(AuthError::Attestation(format!(
                "failed to parse {label} X.509 DER certificate"
            )));
        }
        Ok(Self(ptr))
    }

    fn public_key_bytes(&self) -> Result<Vec<u8>> {
        // SAFETY: `self.0` was created by `CertCreateCertificateContext` and is valid.
        unsafe {
            let info = (*self.0).pCertInfo;
            if info.is_null() {
                return Err(AuthError::Attestation(
                    "certificate has null CERT_INFO".into(),
                ));
            }
            let bit_blob = &(*info).SubjectPublicKeyInfo.PublicKey;
            if bit_blob.pbData.is_null() || bit_blob.cbData == 0 || bit_blob.cbData > 1024 {
                return Err(AuthError::Attestation(
                    "certificate SubjectPublicKeyInfo has invalid public key".into(),
                ));
            }
            if bit_blob.cUnusedBits != 0 {
                return Err(AuthError::Attestation(
                    "certificate public key BIT STRING has non-zero unused bits".into(),
                ));
            }
            Ok(std::slice::from_raw_parts(bit_blob.pbData, bit_blob.cbData as usize).to_vec())
        }
    }
}

impl Drop for CertGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is owned by this RAII guard and freed once.
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
            self.0 = std::ptr::null();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// SHA-256 fingerprint of the `0xF9` attestation CA public key bytes.
    pub f9_public_key_fingerprint: [u8; 32],
}

/// Extract raw public key bytes (e.g. 65-byte uncompressed P-256 SEC1 point)
/// from an X.509 DER certificate.
pub fn extract_cert_public_key_bytes(cert_der: &[u8]) -> Result<Vec<u8>> {
    let cert = CertGuard::parse(cert_der, "PIV slot")?;
    cert.public_key_bytes()
}

/// Cryptographically verify that `slot_cert_der` (`0x9D` attestation certificate)
/// was signed by `f9_cert_der` (`0xF9` attestation CA certificate) and certifies
/// the exact `expected_slot_pub_sec1` public key.
pub fn verify_slot_attestation(
    slot_cert_der: &[u8],
    f9_cert_der: &[u8],
    expected_slot_pub_sec1: &[u8],
) -> Result<VerifiedAttestation> {
    let slot_cert = CertGuard::parse(slot_cert_der, "slot 0x9D attestation")?;
    let f9_cert = CertGuard::parse(f9_cert_der, "slot 0xF9 attestation CA")?;

    // SAFETY: Both `slot_cert.0` and `f9_cert.0` are valid `CERT_CONTEXT` pointers.
    unsafe {
        CryptVerifyCertificateSignatureEx(
            None,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
            slot_cert.0 as *const c_void,
            CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
            Some(f9_cert.0 as *const c_void),
            CRYPT_VERIFY_CERT_FLAGS(0),
            None,
        )
    }
    .map_err(|error| {
        AuthError::Attestation(format!(
            "slot 0x9D attestation signature failed verification against 0xF9 CA: {}",
            error.message()
        ))
    })?;

    let attested_pub = slot_cert.public_key_bytes()?;
    if !constant_time_eq(&attested_pub, expected_slot_pub_sec1) {
        return Err(AuthError::Attestation(
            "attested 0x9D public key does not match the slot's active public key".into(),
        ));
    }

    let f9_pub = f9_cert.public_key_bytes()?;
    let f9_public_key_fingerprint = sha256(&f9_pub);

    Ok(VerifiedAttestation {
        f9_public_key_fingerprint,
    })
}
