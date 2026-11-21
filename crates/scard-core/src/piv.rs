//! PIV (NIST SP 800-73-4) APDU subset and PIV metadata/attestation extensions.
//!
//! All commands are synchronous and must be issued inside a PC/SC transaction.

#![forbid(unsafe_code)]

use crate::error::{AuthError, Result};
use crate::pcsc::ScardCard;
use zeroize::{Zeroize, Zeroizing};

/// Full PIV AID: A0 00 00 03 08 00 00 10 00 01 00.
pub const PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

pub const SLOT_KEY_MANAGEMENT: u8 = 0x9D;
pub const SLOT_PIV_AUTH: u8 = 0x9A;
pub const SLOT_DIGITAL_SIGNATURE: u8 = 0x9C;
pub const SLOT_CARD_AUTH: u8 = 0x9E;
pub const SLOT_ATTESTATION: u8 = 0xF9;
pub const KEY_REF_PIN: u8 = 0x80;
pub const KEY_REF_PUK: u8 = 0x81;

pub const ALG_ECC_P256: u8 = 0x11;
pub const ALG_ECC_P384: u8 = 0x14;

pub const PIN_POLICY_NEVER: u8 = 0x01;
pub const PIN_POLICY_ONCE: u8 = 0x02;
pub const PIN_POLICY_ALWAYS: u8 = 0x03;

pub const TOUCH_POLICY_NEVER: u8 = 0x01;
pub const TOUCH_POLICY_ALWAYS: u8 = 0x02;
pub const TOUCH_POLICY_CACHED: u8 = 0x03;

pub const ORIGIN_GENERATED: u8 = 0x01;
pub const ORIGIN_IMPORTED: u8 = 0x02;

pub const OID_CERT_PIV_AUTH: [u8; 3] = [0x5F, 0xC1, 0x05];
pub const OID_CERT_DIGITAL_SIGNATURE: [u8; 3] = [0x5F, 0xC1, 0x0A];
pub const OID_CERT_KEY_MANAGEMENT: [u8; 3] = [0x5F, 0xC1, 0x0B];
pub const OID_CERT_CARD_AUTH: [u8; 3] = [0x5F, 0xC1, 0x01];
/// PIV vendor extension data object holding the `0xF9` attestation certificate.
pub const OID_CERT_ATTESTATION: [u8; 3] = [0x5F, 0xFF, 0x01];

const MAX_CHAINING_ROUNDS: usize = 32;
const MAX_RESPONSE_ACCUMULATED: usize = 8192;

/// Abstraction over APDU transport to enable deterministic unit testing and
/// fault/replay injection without physical hardware.
pub trait ApduTransport {
    fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>>;
    fn mark_pin_attempted(&self) {}
}

/// SW1/SW2 plus response data. Automatically zeroized on drop so APDU payloads
/// (such as ECDH shared secrets) do not linger in process heap memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl Drop for ApduResponse {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl ApduResponse {
    pub fn is_success(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    pub fn status(&self) -> u16 {
        ((self.sw1 as u16) << 8) | self.sw2 as u16
    }
}

/// Result of SELECT PIV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectInfo {
    pub raw: Vec<u8>,
    pub card_name: Option<String>,
    pub algorithms: Vec<u8>,
}

/// PIV metadata returned by the `GET METADATA` extension (`00 F7`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotMetadata {
    pub raw: Vec<u8>,
}

/// Parsed security attributes from PIV slot metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotPolicy {
    pub algorithm: Option<u8>,
    pub pin_policy: Option<u8>,
    pub touch_policy: Option<u8>,
    pub origin: Option<u8>,
    pub public_key_sec1: Option<Vec<u8>>,
}

/// Read-only PIN (`0x80`) or PUK (`0x81`) status from `GET METADATA` (`00 F7`)
/// (with standard NIST SP 800-73-4 empty `VERIFY` fallback for PIN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinPukMetadata {
    pub is_default: Option<bool>,
    pub total_retries: Option<u8>,
    pub remaining_retries: Option<u8>,
}

impl SlotMetadata {
    pub fn parse_pin_puk(&self) -> PinPukMetadata {
        let is_default = find_tlv(&self.raw, 0x05).and_then(|v| v.first().map(|&b| b != 0));
        let (total_retries, remaining_retries) = match find_tlv(&self.raw, 0x06) {
            Some(v) if v.len() >= 2 => (Some(v[0]), Some(v[1])),
            Some(v) if v.len() == 1 => (None, Some(v[0])),
            _ => (None, None),
        };
        PinPukMetadata {
            is_default,
            total_retries,
            remaining_retries,
        }
    }
    pub fn parse(&self) -> SlotPolicy {
        let algorithm = find_tlv(&self.raw, 0x01).and_then(|v| v.first().copied());
        let policy = find_tlv(&self.raw, 0x02);
        let pin_policy = policy.and_then(|v| v.first().copied());
        let touch_policy = policy.and_then(|v| v.get(1).copied());
        let origin = find_tlv(&self.raw, 0x03).and_then(|v| v.first().copied());

        let mut public_key_sec1 = None;
        for wrapper in [0x04u32, 0x06u32] {
            if let Some(pk_obj) = find_tlv_recursive(&self.raw, wrapper, 0) {
                if let Some(point) = find_tlv_recursive(pk_obj, 0x86, 0) {
                    public_key_sec1 = Some(point.to_vec());
                    break;
                }
            }
        }

        SlotPolicy {
            algorithm,
            pin_policy,
            touch_policy,
            origin,
            public_key_sec1,
        }
    }
}

/// Enforce the project's mandatory security policy on PIV slot 0x9D:
/// ECC P-256 (`0x11`), PIN policy ALWAYS (`0x03`), and on-card generation (`0x01`).
pub fn validate_slot_9d_policy(policy: &SlotPolicy) -> Result<()> {
    match policy.algorithm {
        Some(ALG_ECC_P256) => {}
        Some(other) => {
            return Err(AuthError::CardPolicy(format!(
                "slot 0x9D uses algorithm 0x{other:02X}, expected ECC P-256 (0x11)"
            )));
        }
        None => {
            return Err(AuthError::CardPolicy(
                "slot 0x9D metadata is missing algorithm tag".into(),
            ));
        }
    }

    match policy.pin_policy {
        Some(PIN_POLICY_ALWAYS) => {}
        Some(PIN_POLICY_ONCE) => {
            return Err(AuthError::CardPolicy(
                "slot 0x9D has PIN policy ONCE; re-generate the key with PIN policy ALWAYS".into(),
            ));
        }
        Some(PIN_POLICY_NEVER) => {
            return Err(AuthError::CardPolicy(
                "slot 0x9D has PIN policy NEVER; re-generate the key with PIN policy ALWAYS".into(),
            ));
        }
        Some(other) => {
            return Err(AuthError::CardPolicy(format!(
                "slot 0x9D has unsupported PIN policy 0x{other:02X}; expected ALWAYS (0x03)"
            )));
        }
        None => {
            return Err(AuthError::CardPolicy(
                "slot 0x9D metadata is missing PIN policy tag".into(),
            ));
        }
    }

    match policy.origin {
        Some(ORIGIN_GENERATED) => {}
        Some(ORIGIN_IMPORTED) => {
            return Err(AuthError::CardPolicy(
                "slot 0x9D key was imported; generate the key on-card so no external copy exists"
                    .into(),
            ));
        }
        Some(other) => {
            return Err(AuthError::CardPolicy(format!(
                "slot 0x9D has unknown key origin 0x{other:02X}; expected on-card (0x01)"
            )));
        }
        None => {
            return Err(AuthError::CardPolicy(
                "slot 0x9D metadata is missing key origin tag".into(),
            ));
        }
    }

    Ok(())
}

/// A PIV session bound to an open card transport.
pub struct PivSession<'a, T: ApduTransport + ?Sized = ScardCard> {
    card: &'a T,
}

impl<'a, T: ApduTransport + ?Sized> PivSession<'a, T> {
    pub fn new(card: &'a T) -> Self {
        Self { card }
    }

    /// Transmit one APDU and transparently handle ISO 7816 `61xx` / `6Cxx`.
    pub fn transmit(&self, apdu: &[u8]) -> Result<ApduResponse> {
        let mut current = Zeroizing::new(apdu.to_vec());
        let mut data = Zeroizing::new(Vec::new());

        for _ in 0..MAX_CHAINING_ROUNDS {
            let raw = Zeroizing::new(self.card.transmit_apdu(&current)?);
            if raw.len() < 2 {
                return Err(AuthError::Internal(
                    "APDU response shorter than SW1SW2".into(),
                ));
            }
            let sw1 = raw[raw.len() - 2];
            let sw2 = raw[raw.len() - 1];
            let chunk = &raw[..raw.len() - 2];

            if data.len().saturating_add(chunk.len()) > MAX_RESPONSE_ACCUMULATED {
                return Err(AuthError::Internal(
                    "APDU response exceeds 8192-byte safety cap".into(),
                ));
            }

            if sw1 == 0x61 {
                data.extend_from_slice(chunk);
                *current = vec![0x00, 0xC0, 0x00, 0x00, sw2];
                continue;
            }
            if sw1 == 0x6C {
                if current.len() >= 5 {
                    current[4] = sw2;
                }
                continue;
            }

            data.extend_from_slice(chunk);
            let owned = std::mem::take(&mut *data);
            return Ok(ApduResponse {
                data: owned,
                sw1,
                sw2,
            });
        }

        Err(AuthError::Internal("too many APDU chaining rounds".into()))
    }

    /// SELECT the PIV application.
    pub fn select(&self) -> Result<SelectInfo> {
        let lc = u8::try_from(PIV_AID.len())
            .map_err(|_| AuthError::Internal("PIV AID too long".into()))?;
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, lc];
        apdu.extend_from_slice(&PIV_AID);
        let response = self.transmit(&apdu)?;
        if !response.is_success() {
            return Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            });
        }
        let select_data = response.data.clone();
        let card_name = find_tlv_recursive(&select_data, 0x50, 0)
            .and_then(|v| String::from_utf8(v.to_vec()).ok());
        let algorithms = find_tlv_recursive(&select_data, 0x80, 0)
            .map(|v| v.to_vec())
            .unwrap_or_default();

        Ok(SelectInfo {
            raw: select_data,
            card_name,
            algorithms,
        })
    }

    /// PIV GET DATA. Returns `None` when the object is absent (`6A82` / `6A88`).
    pub fn get_data(&self, tag: &[u8]) -> Result<Option<Vec<u8>>> {
        let tag_len = u8::try_from(tag.len())
            .map_err(|_| AuthError::Unsupported("PIV GET DATA tag too long"))?;
        let mut data_field = Vec::with_capacity(2 + tag.len());
        data_field.push(0x5C);
        data_field.push(tag_len);
        data_field.extend_from_slice(tag);

        let lc = u8::try_from(data_field.len())
            .map_err(|_| AuthError::Unsupported("PIV GET DATA payload too long"))?;
        let mut apdu = Vec::with_capacity(5 + data_field.len());
        apdu.extend_from_slice(&[0x00, 0xCB, 0x3F, 0xFF, lc]);
        apdu.extend_from_slice(&data_field);

        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(Some(response.data.clone())),
            (0x6A, 0x82) | (0x6A, 0x88) => Ok(None),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// PIV `GET METADATA` extension (`00 F7`).
    /// Returns `None` if the slot has no key or the card does not implement `00 F7`.
    pub fn get_metadata(&self, slot: u8) -> Result<Option<SlotMetadata>> {
        let apdu = [0x00, 0xF7, 0x00, slot, 0x00];
        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(Some(SlotMetadata {
                raw: response.data.clone(),
            })),
            (0x6A, 0x88) | (0x6A, 0x82) | (0x6D, 0x00) | (0x6A, 0x81) => Ok(None),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// PIV `ATTEST` extension (`00 F9 <slot> 00`).
    ///
    /// Note: unlike `GET METADATA` (`00 F7 00 <slot>` where `slot` is in `P2`),
    /// `ATTEST` places `slot` in `P1` and requires `P2 = 0x00` (passing `slot`
    /// in `P2` triggers ISO 7816 `SW=6A86` Incorrect P1/P2).
    /// Returns the raw DER X.509 attestation certificate for `slot`, or `None` if unsupported.
    pub fn attest_slot(&self, slot: u8) -> Result<Option<Vec<u8>>> {
        let apdu = [0x00, 0xF9, slot, 0x00, 0x00];
        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) if !response.data.is_empty() => {
                unwrap_piv_cert_bytes(response.data.clone())
            }
            (0x90, 0x00) | (0x6D, 0x00) | (0x6A, 0x81) | (0x6A, 0x82) | (0x6A, 0x88) => Ok(None),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// Read and unwrap a PIV X.509 DER certificate object (`53 { 70 <DER> [71 <certInfo>] }`).
    pub fn read_certificate_der(&self, object: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(wrapper) = self.get_data(object)? else {
            return Ok(None);
        };
        unwrap_piv_cert_bytes(wrapper)
    }

    /// Read the `0xF9` attestation intermediate/device CA certificate (`5F FF 01`).
    pub fn read_attestation_ca_cert(&self) -> Result<Option<Vec<u8>>> {
        self.read_certificate_der(&OID_CERT_ATTESTATION)
    }

    /// Read the EC public key (uncompressed 65-byte SEC1 point) for `slot`.
    ///
    /// Prefers `GET METADATA` (`00 F7`), then falls back to extracting the
    /// uncompressed P-256 point from the slot's standard PIV X.509 certificate.
    pub fn read_ec_public_key(&self, slot: u8) -> Result<Vec<u8>> {
        if let Some(metadata) = self.get_metadata(slot)? {
            let parsed = metadata.parse();
            if let Some(point) = parsed.public_key_sec1 {
                return Ok(point);
            }
        }

        let cert_oid = match slot {
            SLOT_PIV_AUTH => &OID_CERT_PIV_AUTH[..],
            SLOT_DIGITAL_SIGNATURE => &OID_CERT_DIGITAL_SIGNATURE[..],
            SLOT_KEY_MANAGEMENT => &OID_CERT_KEY_MANAGEMENT[..],
            SLOT_CARD_AUTH => &OID_CERT_CARD_AUTH[..],
            _ => return Err(AuthError::NoKey),
        };
        let cert_der = self
            .read_certificate_der(cert_oid)?
            .ok_or(AuthError::NoKey)?;
        crate::attestation::extract_cert_public_key_bytes(&cert_der)
    }

    /// Query read-only PIN (`0x80`) or PUK (`0x81`) retry/default metadata without
    /// consuming any retry attempt.
    pub fn get_pin_puk_metadata(&self, key_ref: u8) -> Result<Option<PinPukMetadata>> {
        if let Some(meta) = self.get_metadata(key_ref)? {
            let parsed = meta.parse_pin_puk();
            if parsed.remaining_retries.is_some() || parsed.is_default.is_some() {
                return Ok(Some(parsed));
            }
        }

        // Standard NIST SP 800-73-4 read-only status probe for PIV Application PIN (0x80):
        // VERIFY with absent command data never decrements the retry counter.
        if key_ref == KEY_REF_PIN {
            let resp = self.transmit(&[0x00, 0x20, 0x00, KEY_REF_PIN])?;
            let resp = if resp.sw1 == 0x67 && resp.sw2 == 0x00 {
                self.transmit(&[0x00, 0x20, 0x00, KEY_REF_PIN, 0x00])?
            } else {
                resp
            };
            match (resp.sw1, resp.sw2) {
                (0x63, sw2) if (sw2 & 0xF0) == 0xC0 => {
                    return Ok(Some(PinPukMetadata {
                        is_default: None,
                        total_retries: None,
                        remaining_retries: Some(sw2 & 0x0F),
                    }));
                }
                (0x69, 0x83) => {
                    return Ok(Some(PinPukMetadata {
                        is_default: None,
                        total_retries: None,
                        remaining_retries: Some(0),
                    }));
                }
                _ => {}
            }
        }

        Ok(None)
    }

    /// VERIFY the PIV PIN.
    ///
    /// PIV PINs are 6-8 ASCII digits and are padded to 8 bytes with 0xFF.
    pub fn verify_pin(&self, pin: &[u8]) -> Result<()> {
        let padded = pad_pin_bytes(pin)?;

        let mut apdu = Zeroizing::new(vec![0x00, 0x20, 0x00, 0x80, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
        apdu[5..13].copy_from_slice(&padded[..]);

        self.card.mark_pin_attempted();
        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(()),
            (0x63, 0xC0) | (0x69, 0x83) => Err(AuthError::PinBlocked),
            (0x63, sw2) if (sw2 & 0xF0) == 0xC0 => Err(AuthError::PinIncorrect(sw2 & 0x0F)),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// NIST SP 800-73-4 `RESET RETRY COUNTER` (`00 2C 00 80 10 <8B PUK> <8B New PIN>`).
    ///
    /// Unblocks a blocked PIV Application PIN using the 6-8 char PUK, sets `new_pin`,
    /// and restores the card's PIN retry counter to its maximum (3).
    /// Slot `0x9D` key material is untouched, so existing vaults remain valid.
    pub fn reset_pin_with_puk(&self, puk: &[u8], new_pin: &[u8]) -> Result<()> {
        let padded_puk = pad_puk_bytes(puk)?;
        let padded_pin = pad_pin_bytes(new_pin)?;

        let mut apdu = Zeroizing::new(vec![0u8; 21]);
        apdu[0..5].copy_from_slice(&[0x00, 0x2C, 0x00, KEY_REF_PIN, 0x10]);
        apdu[5..13].copy_from_slice(&padded_puk[..]);
        apdu[13..21].copy_from_slice(&padded_pin[..]);

        self.card.mark_pin_attempted();
        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(()),
            (0x63, 0xC0) | (0x69, 0x83) => Err(AuthError::PukBlocked),
            (0x63, sw2) if (sw2 & 0xF0) == 0xC0 => Err(AuthError::PukIncorrect(sw2 & 0x0F)),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// NIST SP 800-73-4 `CHANGE REFERENCE DATA` for PUK (`00 24 00 81 10 <8B Current PUK> <8B New PUK>`).
    pub fn change_puk(&self, current_puk: &[u8], new_puk: &[u8]) -> Result<()> {
        let padded_cur = pad_puk_bytes(current_puk)?;
        let padded_new = pad_puk_bytes(new_puk)?;

        let mut apdu = Zeroizing::new(vec![0u8; 21]);
        apdu[0..5].copy_from_slice(&[0x00, 0x24, 0x00, KEY_REF_PUK, 0x10]);
        apdu[5..13].copy_from_slice(&padded_cur[..]);
        apdu[13..21].copy_from_slice(&padded_new[..]);

        self.card.mark_pin_attempted();
        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(()),
            (0x63, 0xC0) | (0x69, 0x83) => Err(AuthError::PukBlocked),
            (0x63, sw2) if (sw2 & 0xF0) == 0xC0 => Err(AuthError::PukIncorrect(sw2 & 0x0F)),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// PIV GENERAL AUTHENTICATE with ECDH.
    ///
    /// Request:  7C { 82 00 85 <ephemeral public key> }
    /// Response: 7C { 82 <shared secret> }
    pub fn general_authenticate_ecdh(
        &self,
        slot: u8,
        algorithm: u8,
        ephemeral_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        if ephemeral_public_key.len() > 127 {
            return Err(AuthError::Unsupported("ephemeral public key too large"));
        }

        let empty_resp = tlv(0x82, &[])?;
        let exp_tag = tlv(0x85, ephemeral_public_key)?;
        let mut inner = Vec::with_capacity(empty_resp.len() + exp_tag.len());
        inner.extend_from_slice(&empty_resp);
        inner.extend_from_slice(&exp_tag);
        let outer = tlv(0x7C, &inner)?;

        let lc = u8::try_from(outer.len())
            .map_err(|_| AuthError::Unsupported("ECDH APDU payload exceeds short APDU limit"))?;
        let mut apdu = Vec::with_capacity(5 + outer.len());
        apdu.extend_from_slice(&[0x00, 0x87, algorithm, slot, lc]);
        apdu.extend_from_slice(&outer);

        let response = self.transmit(&apdu)?;
        if !response.is_success() {
            return Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            });
        }

        let outer = find_tlv(&response.data, 0x7C).ok_or_else(|| {
            AuthError::Internal("GENERAL AUTHENTICATE response missing 7C".into())
        })?;
        let secret = find_tlv(outer, 0x82).ok_or_else(|| {
            AuthError::Internal("GENERAL AUTHENTICATE response missing 82".into())
        })?;
        Ok(secret.to_vec())
    }
}

/// Validate and pad a 6-8 ASCII digit PIV PIN to 8 bytes with `0xFF`.
pub fn pad_pin_bytes(pin: &[u8]) -> Result<Zeroizing<[u8; 8]>> {
    if pin.len() < 6 || pin.len() > 8 || !pin.iter().all(|b| b.is_ascii_digit()) {
        return Err(AuthError::PinRequired);
    }
    let mut padded = Zeroizing::new([0xFFu8; 8]);
    padded[..pin.len()].copy_from_slice(pin);
    Ok(padded)
}

/// Validate and pad a 6-8 printable ASCII PIV PUK (`0x21..=0x7E`) to 8 bytes with `0xFF`.
pub fn pad_puk_bytes(puk: &[u8]) -> Result<Zeroizing<[u8; 8]>> {
    if puk.len() < 6 || puk.len() > 8 || !puk.iter().all(|&b| (0x21..=0x7E).contains(&b)) {
        return Err(AuthError::PukRequired);
    }
    let mut padded = Zeroizing::new([0xFFu8; 8]);
    padded[..puk.len()].copy_from_slice(puk);
    Ok(padded)
}

/// Unwrap either a raw X.509 DER SEQUENCE (`30 ...`) or a PIV `53 { 70 <DER> [71 <certInfo>] }` wrapper.
fn unwrap_piv_cert_bytes(wrapper: Vec<u8>) -> Result<Option<Vec<u8>>> {
    if wrapper.first() == Some(&0x30) {
        return Ok(Some(wrapper));
    }
    if let Some(outer_53) = find_tlv_recursive(&wrapper, 0x53, 0) {
        if let Some(cert_info) = find_tlv_recursive(outer_53, 0x71, 0) {
            if cert_info.first().copied().unwrap_or(0) != 0 {
                return Err(AuthError::Unsupported(
                    "compressed PIV certificate is not supported",
                ));
            }
        }
        if let Some(der) = find_tlv_recursive(outer_53, 0x70, 0) {
            return Ok(Some(der.to_vec()));
        }
    }
    if let Some(der) = find_tlv_recursive(&wrapper, 0x70, 0) {
        return Ok(Some(der.to_vec()));
    }
    Ok(None)
}

/// Encode a short-form TLV (values up to 255 bytes) without panicking.
pub(crate) fn tlv(tag: u8, value: &[u8]) -> Result<Vec<u8>> {
    if value.len() <= 127 {
        let mut out = Vec::with_capacity(2 + value.len());
        out.push(tag);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
        Ok(out)
    } else if value.len() <= 255 {
        let mut out = Vec::with_capacity(3 + value.len());
        out.push(tag);
        out.push(0x81);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
        Ok(out)
    } else {
        Err(AuthError::Unsupported("TLV value exceeds 255 bytes"))
    }
}

/// Find a single-byte tag in a flat TLV sequence.
pub(crate) fn find_tlv(data: &[u8], tag: u8) -> Option<&[u8]> {
    let mut pos = 0usize;
    while pos + 2 <= data.len() {
        let current_tag = data[pos];
        pos += 1;
        let (len, header_len) = parse_length(data, pos)?;
        pos = pos.checked_add(header_len)?;
        let end = pos.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        let value = &data[pos..end];
        if current_tag == tag {
            return Some(value);
        }
        pos = end;
    }
    None
}

/// Recursively find a tag, including two/three-byte BER tags and constructed wrappers.
pub(crate) fn find_tlv_recursive(data: &[u8], wanted: u32, depth: usize) -> Option<&[u8]> {
    if depth > 8 {
        return None;
    }

    let mut pos = 0usize;
    while pos < data.len() {
        let (tag, tag_len) = parse_tag(data, pos)?;
        pos = pos.checked_add(tag_len)?;
        let (len, header_len) = parse_length(data, pos)?;
        pos = pos.checked_add(header_len)?;
        let end = pos.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        let value = &data[pos..end];

        if tag == wanted {
            return Some(value);
        }

        if (tag & 0x20) != 0 || tag == 0x53 || tag == 0x7C || tag == 0x7F49 {
            if let Some(found) = find_tlv_recursive(value, wanted, depth + 1) {
                return Some(found);
            }
        }

        pos = end;
    }
    None
}

fn parse_tag(data: &[u8], pos: usize) -> Option<(u32, usize)> {
    let first = *data.get(pos)?;
    if (first & 0x1F) != 0x1F {
        return Some((first as u32, 1));
    }

    let mut tag = first as u32;
    let mut used = 1usize;
    loop {
        let byte = *data.get(pos.checked_add(used)?)?;
        tag = (tag << 8) | byte as u32;
        used += 1;
        if (byte & 0x80) == 0 {
            break;
        }
        if used > 3 {
            return None;
        }
    }
    Some((tag, used))
}

fn parse_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *data.get(pos)?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let count = (first & 0x7F) as usize;
    if count == 0 || count > 2 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..count {
        len = (len << 8) | *data.get(pos.checked_add(1 + i)?)? as usize;
    }
    Some((len, 1 + count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct MockTransport {
        responses: RefCell<VecDeque<Vec<u8>>>,
    }

    impl ApduTransport for MockTransport {
        fn transmit_apdu(&self, _apdu: &[u8]) -> Result<Vec<u8>> {
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| AuthError::Internal("mock out of responses".into()))
        }
    }

    #[test]
    fn pin_padding_is_ff() {
        let mut padded = [0xFFu8; 8];
        padded[..6].copy_from_slice(b"123456");
        assert_eq!(padded, [b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF]);
    }

    #[test]
    fn tlv_roundtrip_and_no_panic_on_large_input() {
        let encoded = tlv(0x85, &[0x04, 0xAA, 0xBB]).unwrap();
        assert_eq!(encoded, vec![0x85, 0x03, 0x04, 0xAA, 0xBB]);
        assert_eq!(find_tlv(&encoded, 0x85), Some(&[0x04, 0xAA, 0xBB][..]));
        assert!(tlv(0x85, &[0u8; 300]).is_err());
    }

    #[test]
    fn metadata_policy_validation_enforces_always_and_on_card() {
        let metadata = SlotMetadata {
            raw: hex::decode(
                "0101110202030103010104438641049b8dbc6dcb92018da4fd1a48668dcc12ce4af6a227469adb0ce702d17b16e9fd4224f0fe5a88570b8a92ecb201fdab60fc539aa977b767cc07903f07a4d63706",
            )
            .unwrap(),
        };
        let parsed = metadata.parse();
        assert_eq!(parsed.algorithm, Some(ALG_ECC_P256));
        assert_eq!(parsed.pin_policy, Some(PIN_POLICY_ALWAYS));
        assert_eq!(parsed.touch_policy, Some(TOUCH_POLICY_NEVER));
        assert_eq!(parsed.origin, Some(ORIGIN_GENERATED));
        assert!(validate_slot_9d_policy(&parsed).is_ok());

        // Reject PIN ONCE
        let mut once = parsed.clone();
        once.pin_policy = Some(PIN_POLICY_ONCE);
        assert!(validate_slot_9d_policy(&once).is_err());

        // Reject Imported key
        let mut imported = parsed;
        imported.origin = Some(ORIGIN_IMPORTED);
        assert!(validate_slot_9d_policy(&imported).is_err());
    }

    #[test]
    fn apdu_chaining_supports_more_than_8_rounds_for_certificates() {
        let mut chunks = VecDeque::new();
        for i in 0..12u8 {
            let mut resp = vec![i; 200];
            resp.extend_from_slice(&[0x61, 0xC8]);
            chunks.push_back(resp);
        }
        chunks.push_back(vec![0xFF, 0x90, 0x00]);
        let transport = MockTransport {
            responses: RefCell::new(chunks),
        };
        let session = PivSession::new(&transport);
        let resp = session.transmit(&[0x00, 0xCB, 0x3F, 0xFF, 0x00]).unwrap();
        assert!(resp.is_success());
        assert_eq!(resp.data.len(), 12 * 200 + 1);
    }

    #[test]
    fn ecdh_request_has_7c_82_00_85() {
        let eph = [0x04u8; 65];
        let inner = [tlv(0x82, &[]).unwrap(), tlv(0x85, &eph).unwrap()].concat();
        let outer = tlv(0x7C, &inner).unwrap();

        assert_eq!(outer[0], 0x7C);
        assert_eq!(outer[1], 0x45);
        assert_eq!(&outer[2..6], &[0x82, 0x00, 0x85, 0x41]);
        assert_eq!(outer.len(), 71);
    }

    struct RecordingTransport {
        sent: RefCell<Vec<Vec<u8>>>,
        responses: RefCell<VecDeque<Vec<u8>>>,
    }

    impl ApduTransport for RecordingTransport {
        fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>> {
            self.sent.borrow_mut().push(apdu.to_vec());
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| AuthError::Internal("mock out of responses".into()))
        }
    }

    #[test]
    fn reset_pin_with_puk_and_change_puk_format_and_status_codes() {
        let transport = RecordingTransport {
            sent: RefCell::new(Vec::new()),
            responses: RefCell::new(VecDeque::from(vec![
                vec![0x90, 0x00],
                vec![0x63, 0xC2],
                vec![0x63, 0xC0],
                vec![0x90, 0x00],
            ])),
        };
        let session = PivSession::new(&transport);

        // 1. Valid RESET RETRY COUNTER (8-byte default PUK + 6-digit new PIN padded with 0xFF)
        session.reset_pin_with_puk(b"12345678", b"654321").unwrap();
        assert_eq!(
            transport.sent.borrow()[0],
            vec![
                0x00, 0x2C, 0x00, 0x80, 0x10, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'6',
                b'5', b'4', b'3', b'2', b'1', 0xFF, 0xFF
            ]
        );

        // 2. Wrong PUK with 2 attempts remaining
        assert!(matches!(
            session.reset_pin_with_puk(b"00000000", b"654321"),
            Err(AuthError::PukIncorrect(2))
        ));

        // 3. 63 C0 (counter reached zero) maps directly to PukBlocked
        assert!(matches!(
            session.reset_pin_with_puk(b"00000000", b"654321"),
            Err(AuthError::PukBlocked)
        ));

        // 4. CHANGE REFERENCE DATA for PUK (00 24 00 81 10)
        session.change_puk(b"12345678", b"87654321").unwrap();
        assert_eq!(
            &transport.sent.borrow()[3][..5],
            &[0x00, 0x24, 0x00, 0x81, 0x10]
        );
    }

    #[test]
    fn pin_puk_metadata_parses_default_and_retries() {
        let meta = SlotMetadata {
            raw: vec![0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x01],
        };
        let parsed = meta.parse_pin_puk();
        assert_eq!(parsed.is_default, Some(true));
        assert_eq!(parsed.total_retries, Some(3));
        assert_eq!(parsed.remaining_retries, Some(1));
    }
}
