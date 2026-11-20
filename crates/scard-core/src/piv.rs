//! PIV (NIST SP 800-73-4) APDU subset used by FamiliarSmartcard.
//!
//! Only what the vault needs is implemented:
//! - SELECT PIV application;
//! - GET DATA (certificate / public-key template) and Yubico GET METADATA;
//! - VERIFY PIN (PIV PIN, 6-8 chars, padded to 8 bytes with 0xFF);
//! - GENERAL AUTHENTICATE for ECDH (tags 0x7C / 0x85 / 0x82).
//!
//! All commands are synchronous and must be issued inside a PC/SC transaction.

use crate::error::{AuthError, Result};
use crate::pcsc::ScardCard;

/// Full PIV AID: A0 00 00 03 08 00 00 10 00 01 00.
pub const PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// PIV Key Management slot.
pub const SLOT_KEY_MANAGEMENT: u8 = 0x9D;
/// PIV Authentication slot.
pub const SLOT_PIV_AUTH: u8 = 0x9A;
/// PIV Digital Signature slot.
pub const SLOT_DIGITAL_SIGNATURE: u8 = 0x9C;
/// PIV Card Authentication slot.
pub const SLOT_CARD_AUTH: u8 = 0x9E;

/// PIV algorithm id for ECC P-256.
pub const ALG_ECC_P256: u8 = 0x11;
/// PIV algorithm id for ECC P-384.
pub const ALG_ECC_P384: u8 = 0x14;

/// PIV certificate object ids.
pub const OID_CERT_PIV_AUTH: [u8; 3] = [0x5F, 0xC1, 0x05];
pub const OID_CERT_DIGITAL_SIGNATURE: [u8; 3] = [0x5F, 0xC1, 0x0A];
pub const OID_CERT_KEY_MANAGEMENT: [u8; 3] = [0x5F, 0xC1, 0x0B];
pub const OID_CERT_CARD_AUTH: [u8; 3] = [0x5F, 0xC1, 0x01];
/// PIV public-key template object.
pub const OID_PUBLIC_KEY: [u8; 2] = [0x7F, 0x49];

/// SW1/SW2 plus response data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
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

/// PIV metadata returned by the Yubico GET METADATA extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotMetadata {
    pub raw: Vec<u8>,
}

/// A PIV session bound to an open card handle.
pub struct PivSession<'a> {
    card: &'a ScardCard,
}

impl<'a> PivSession<'a> {
    pub fn new(card: &'a ScardCard) -> Self {
        Self { card }
    }

    /// Transmit one APDU and transparently handle ISO 7816 `61xx` / `6Cxx`.
    pub fn transmit(&self, apdu: &[u8]) -> Result<ApduResponse> {
        let mut current = apdu.to_vec();
        let mut data = Vec::new();

        for _ in 0..8 {
            let raw = self.card.transmit(&current)?;
            if raw.len() < 2 {
                return Err(AuthError::Internal(
                    "APDU response shorter than SW1SW2".into(),
                ));
            }
            let sw1 = raw[raw.len() - 2];
            let sw2 = raw[raw.len() - 1];
            let chunk = &raw[..raw.len() - 2];

            if sw1 == 0x61 {
                data.extend_from_slice(chunk);
                current = vec![0x00, 0xC0, 0x00, 0x00, sw2];
                continue;
            }
            if sw1 == 0x6C {
                if current.len() >= 5 {
                    current[4] = sw2;
                }
                continue;
            }

            data.extend_from_slice(chunk);
            return Ok(ApduResponse { data, sw1, sw2 });
        }

        Err(AuthError::Internal("too many APDU chaining rounds".into()))
    }

    /// SELECT the PIV application.
    pub fn select(&self) -> Result<SelectInfo> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, PIV_AID.len() as u8];
        apdu.extend_from_slice(&PIV_AID);
        let response = self.transmit(&apdu)?;
        if !response.is_success() {
            return Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            });
        }
        let card_name = find_tlv_recursive(&response.data, 0x50, 0)
            .and_then(|v| String::from_utf8(v.to_vec()).ok());
        let algorithms = find_tlv_recursive(&response.data, 0x80, 0)
            .map(|v| v.to_vec())
            .unwrap_or_default();

        Ok(SelectInfo {
            raw: response.data,
            card_name,
            algorithms,
        })
    }

    /// PIV GET DATA. Returns `None` for `6A82` (object not found).
    pub fn get_data(&self, tag: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut data_field = vec![0x5C, tag.len() as u8];
        data_field.extend_from_slice(tag);
        let mut apdu = vec![0x00, 0xCB, 0x3F, 0xFF, data_field.len() as u8];
        apdu.extend_from_slice(&data_field);

        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(Some(response.data)),
            (0x6A, 0x82) | (0x6A, 0x88) => Ok(None),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// Yubico GET METADATA. Returns `None` if the slot has no key (`6A88`).
    pub fn get_metadata(&self, slot: u8) -> Result<Option<SlotMetadata>> {
        let apdu = [0x00, 0xF7, 0x00, slot, 0x00];
        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(Some(SlotMetadata { raw: response.data })),
            (0x6A, 0x88) | (0x6A, 0x82) => Ok(None),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// Read the EC public key for a specific PIV slot.
    ///
    /// Prefers the Yubico GET METADATA public-key field (tag 0x06 -> 0x86),
    /// then falls back to the standard PIV public-key template (`7F49`).
    pub fn read_ec_public_key(&self, slot: u8) -> Result<Vec<u8>> {
        if let Some(metadata) = self.get_metadata(slot)? {
            // Yubico metadata uses 0x04 for the public-key object; some
            // implementations use 0x06. Accept both, then find the SEC1 point.
            for wrapper in [0x04u32, 0x06u32] {
                if let Some(public_key_object) = find_tlv_recursive(&metadata.raw, wrapper, 0) {
                    if let Some(point) = find_tlv_recursive(public_key_object, 0x86, 0) {
                        return Ok(point.to_vec());
                    }
                }
            }
        }

        let data = self.get_data(&OID_PUBLIC_KEY)?.ok_or(AuthError::NoKey)?;

        // Typical response shape: 53 { 7F49 { 86 <point> } }.
        find_tlv_recursive(&data, 0x86, 0)
            .map(|v| v.to_vec())
            .ok_or(AuthError::NoKey)
    }

    /// Read a PIV certificate object (e.g. `OID_CERT_KEY_MANAGEMENT`).
    pub fn read_certificate(&self, object: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_data(object)
    }

    /// VERIFY the PIV PIN.
    ///
    /// PIV PINs are 6-8 characters and are padded to 8 bytes with 0xFF.
    pub fn verify_pin(&self, pin: &[u8]) -> Result<()> {
        if pin.len() < 6 || pin.len() > 8 {
            return Err(AuthError::PinRequired);
        }
        let mut padded = [0xFFu8; 8];
        padded[..pin.len()].copy_from_slice(pin);

        let mut apdu = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu.extend_from_slice(&padded);
        let response = self.transmit(&apdu)?;
        match (response.sw1, response.sw2) {
            (0x90, 0x00) => Ok(()),
            (0x63, sw2) => Err(AuthError::PinIncorrect(sw2 & 0x0F)),
            (0x69, 0x83) => Err(AuthError::PinBlocked),
            _ => Err(AuthError::Apdu {
                sw1: response.sw1,
                sw2: response.sw2,
            }),
        }
    }

    /// PIV GENERAL AUTHENTICATE with ECDH.
    ///
    /// Request:  7C { 85 <ephemeral public key> }
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

        // PIV/Yubico ECDH requires an empty response tag (82 00) before the
        // exponentiation tag (85 41 <public key>). Omitting 82 00 makes the
        // request ambiguous and is rejected by standard cards.
        let inner = [tlv(0x82, &[]), tlv(0x85, ephemeral_public_key)].concat();
        let outer = tlv(0x7C, &inner);

        let mut apdu = vec![0x00, 0x87, algorithm, slot, outer.len() as u8];
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

/// Encode a short-form TLV. Values up to 255 bytes only.
pub(crate) fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() <= 255);
    let mut out = vec![tag, value.len() as u8];
    out.extend_from_slice(value);
    out
}

/// Find a single-byte tag in a flat TLV sequence.
pub(crate) fn find_tlv(data: &[u8], tag: u8) -> Option<&[u8]> {
    let mut pos = 0usize;
    while pos + 2 <= data.len() {
        let current_tag = data[pos];
        pos += 1;
        let (len, header_len) = parse_length(data, pos)?;
        pos += header_len;
        if pos + len > data.len() {
            return None;
        }
        let value = &data[pos..pos + len];
        if current_tag == tag {
            return Some(value);
        }
        pos += len;
    }
    None
}

/// Recursively find a tag, including two/three-byte BER tags and constructed
/// wrappers such as `53` and `7F49`. Depth-limited to avoid hostile input.
pub(crate) fn find_tlv_recursive(data: &[u8], wanted: u32, depth: usize) -> Option<&[u8]> {
    if depth > 8 {
        return None;
    }

    let mut pos = 0usize;
    while pos < data.len() {
        let (tag, tag_len) = parse_tag(data, pos)?;
        pos += tag_len;
        let (len, header_len) = parse_length(data, pos)?;
        pos += header_len;
        if pos + len > data.len() {
            return None;
        }
        let value = &data[pos..pos + len];

        if tag == wanted {
            return Some(value);
        }

        // Constructed tags and common PIV wrappers contain nested TLVs.
        if (tag & 0x20) != 0 || tag == 0x53 || tag == 0x7C || tag == 0x7F49 {
            if let Some(found) = find_tlv_recursive(value, wanted, depth + 1) {
                return Some(found);
            }
        }

        pos += len;
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
        let byte = *data.get(pos + used)?;
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
        len = (len << 8) | *data.get(pos + 1 + i)? as usize;
    }
    Some((len, 1 + count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_padding_is_ff() {
        let mut padded = [0xFFu8; 8];
        padded[..6].copy_from_slice(b"123456");
        assert_eq!(padded, [b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF]);
    }

    #[test]
    fn tlv_roundtrip() {
        let encoded = tlv(0x85, &[0x04, 0xAA, 0xBB]);
        assert_eq!(encoded, vec![0x85, 0x03, 0x04, 0xAA, 0xBB]);
        assert_eq!(find_tlv(&encoded, 0x85), Some(&[0x04, 0xAA, 0xBB][..]));
    }

    #[test]
    fn find_ec_point_inside_piv_wrapper() {
        // 53 { 7F49 { 86 41 <65 bytes> } }
        let point = [0x04u8; 65];
        let mut inner = vec![0x86, 0x41];
        inner.extend_from_slice(&point);
        let mut pk = vec![0x7F, 0x49, inner.len() as u8];
        pk.extend_from_slice(&inner);
        let mut outer = vec![0x53, pk.len() as u8];
        outer.extend_from_slice(&pk);

        let found = find_tlv_recursive(&outer, 0x86, 0).unwrap();
        assert_eq!(found, &point[..]);
    }

    #[test]
    fn metadata_public_key_uses_tag_04() {
        let metadata = hex::decode(
            "0101110202030103010104438641049b8dbc6dcb92018da4fd1a48668dcc12ce4af6a227469adb0ce702d17b16e9fd4224f0fe5a88570b8a92ecb201fdab60fc539aa977b767cc07903f07a4d63706",
        )
        .unwrap();
        let public_key_object = find_tlv_recursive(&metadata, 0x04, 0).unwrap();
        let point = find_tlv_recursive(public_key_object, 0x86, 0).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
    }

    #[test]
    fn ecdh_request_has_7c_82_00_85() {
        let eph = [0x04u8; 65];
        let mut inner = vec![0x82, 0x00, 0x85, eph.len() as u8];
        inner.extend_from_slice(&eph);
        let mut outer = vec![0x7C, inner.len() as u8];
        outer.extend_from_slice(&inner);

        // 7C 45 = 69-byte payload: 82 00 (2) + 85 41 <65> (67).
        assert_eq!(outer[0], 0x7C);
        assert_eq!(outer[1], 0x45);
        assert_eq!(&outer[2..6], &[0x82, 0x00, 0x85, 0x41]);
        assert_eq!(outer.len(), 71);
    }
}
