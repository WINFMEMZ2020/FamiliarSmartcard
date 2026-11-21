//! On-card PIV key provisioning (`0x9D` with user-chosen `Touch = ALWAYS` or `NEVER`,
//! optional `0x9E` `PIN=NEVER` hardware anti-phishing key, matching X.509 certificates,
//! and `0x9B` Management Key authentication / rotation).

#![forbid(unsafe_code)]

use crate::crypto::{p256_public_from_sec1, random_array, sha256};
use crate::error::{AuthError, Result};
use crate::pcsc::{ScardContext, SCARD_LEAVE_CARD, SCARD_RESET_CARD};
use crate::piv::{
    find_tlv, find_tlv_recursive, pad_pin_bytes, tlv_ber, validate_slot_9d_policy, ApduTransport,
    PivSession, ALG_3DES, ALG_AES_128, ALG_AES_192, ALG_AES_256, DEFAULT_MGMT_KEY,
    OID_CERT_CARD_AUTH, OID_CERT_KEY_MANAGEMENT, OID_PRINTED_INFO, PIN_POLICY_ALWAYS,
    PIN_POLICY_NEVER, SLOT_CARD_AUTH, SLOT_KEY_MANAGEMENT, TOUCH_POLICY_ALWAYS,
    TOUCH_POLICY_CACHED, TOUCH_POLICY_NEVER,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

pub struct CardProvisionOptions<'a> {
    pub reader: Option<&'a str>,
    /// Verified BEFORE modifying any card slot so a mistyped PIN never overwrites
    /// an existing `0x9D` key, and so Yubico PIN-protected `0x9B` keys (`5F C1 09`)
    /// can be read automatically when no hex Management Key is entered.
    pub pin: Option<&'a [u8]>,
    /// Either `TOUCH_POLICY_ALWAYS` (`0x02`) or `TOUCH_POLICY_NEVER` (`0x01`).
    pub touch_policy_9d: u8,
    /// When `true`, also generates an on-card ECC P-256 key in `Slot 0x9E`
    /// (`Card Authentication`, `PIN=NEVER`, `Touch=NEVER`) for pre-PIN anti-phishing.
    pub provision_9e: bool,
    /// Optional hex string (32, 48, or 64 hex chars) for the current `0x9B` Management Key.
    /// When `None` or empty, uses the PIV factory default `010203...08` (or a PIN-protected
    /// Management Key stored in `5F C1 09` if `pin` was supplied).
    pub current_mgmt_key_hex: Option<&'a str>,
    /// Optional hex string (32, 48, or 64 hex chars) to rotate `0x9B` Management Key
    /// after slot provisioning succeeds.
    pub new_mgmt_key_hex: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct CardProvisionResult {
    pub card_name: Option<String>,
    pub pub_9d_sec1: Vec<u8>,
    pub fingerprint_9d: [u8; 32],
    pub touch_policy_9d: u8,
    pub pub_9e_sec1: Option<Vec<u8>>,
    pub mgmt_alg_used: u8,
    pub mgmt_key_rotated: bool,
}

/// Parse a user-entered hex Management Key (ignoring spaces, hyphens, and colons)
/// into a `Zeroizing<Vec<u8>>` of length 16 (AES-128), 24 (3DES/AES-192), or 32 (AES-256).
pub fn parse_mgmt_key_hex(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut cleaned = Zeroizing::new(String::with_capacity(input.len()));
    for ch in input.chars() {
        if !ch.is_ascii_whitespace() && ch != '-' && ch != ':' {
            cleaned.push(ch);
        }
    }
    if !matches!(cleaned.len(), 32 | 48 | 64) {
        return Err(AuthError::CardPolicy(
            "PIV 0x9B Management Key must be 32, 48, or 64 hex characters (16, 24, or 32 bytes)"
                .into(),
        ));
    }
    let decoded = Zeroizing::new(hex::decode(cleaned.as_bytes()).map_err(|_| {
        AuthError::CardPolicy("PIV 0x9B Management Key contains non-hexadecimal characters".into())
    })?);
    Ok(decoded)
}

/// Check (read-only) whether the first connected PIV card already has a key in `Slot 0x9D`.
pub fn card_has_9d_key(reader: Option<&str>) -> bool {
    let Ok(context) = ScardContext::new() else {
        return false;
    };
    let readers = match reader {
        Some(r) => vec![r.to_string()],
        None => context.list_readers().unwrap_or_default(),
    };
    for reader_name in readers {
        let Ok(mut card) = context.connect(&reader_name) else {
            continue;
        };
        if card.begin_transaction().is_err() {
            continue;
        }
        let session = PivSession::new(&card);
        let has_9d = session.select().is_ok()
            && (session
                .get_metadata(SLOT_KEY_MANAGEMENT)
                .ok()
                .flatten()
                .is_some()
                || session.read_ec_public_key(SLOT_KEY_MANAGEMENT).is_ok());
        let _ = card.end_transaction(SCARD_LEAVE_CARD);
        let _ = card.disconnect(SCARD_LEAVE_CARD);
        if has_9d {
            return true;
        }
    }
    false
}

/// Provision `Slot 0x9D` (with `TOUCH_POLICY_CACHED`, `TOUCH_POLICY_ALWAYS`, or `TOUCH_POLICY_NEVER`),
/// optionally `Slot 0x9E` (`PIN=NEVER`, `Touch=NEVER`), write matching PIV X.509 certificates,
/// and optionally rotate `Slot 0x9B` Management Key on the connected PIV smart card.
pub fn provision_card(opts: &CardProvisionOptions<'_>) -> Result<CardProvisionResult> {
    if !matches!(
        opts.touch_policy_9d,
        TOUCH_POLICY_CACHED | TOUCH_POLICY_ALWAYS | TOUCH_POLICY_NEVER
    ) {
        return Err(AuthError::CardPolicy(
            "Slot 0x9D touch policy must be CACHED (0x03), ALWAYS (0x02), or NEVER (0x01)".into(),
        ));
    }
    if let Some(pin) = opts.pin {
        let _ = pad_pin_bytes(pin)?;
    }
    if let Some(cur_hex) = opts.current_mgmt_key_hex.filter(|s| !s.trim().is_empty()) {
        let _ = parse_mgmt_key_hex(cur_hex)?;
    }
    if let Some(new_hex) = opts.new_mgmt_key_hex.filter(|s| !s.trim().is_empty()) {
        let _ = parse_mgmt_key_hex(new_hex)?;
    }

    let context = ScardContext::new()?;
    let readers = match opts.reader {
        Some(r) => vec![r.to_string()],
        None => context.list_readers()?,
    };
    if readers.is_empty() {
        return Err(AuthError::NoReader);
    }

    let mut last_error = None;
    for reader_name in readers {
        let mut card = match context.connect(&reader_name) {
            Ok(c) => c,
            Err(e) => {
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = card.begin_transaction() {
            last_error = Some(e);
            continue;
        }

        let attempt = provision_card_with_transport(&card, opts);
        // Reset card after management/PIN session so authenticated state never lingers!
        let _ = card.end_transaction(SCARD_RESET_CARD);
        let _ = card.disconnect(SCARD_RESET_CARD);

        match attempt {
            Ok(res) => {
                let _ = crate::storage::clear_last_attempt_cooldown(&res.fingerprint_9d);
                return Ok(res);
            }
            // Terminal authentication / policy errors halt immediately without trying other readers.
            Err(e @ AuthError::PinIncorrect(_))
            | Err(e @ AuthError::PinBlocked)
            | Err(e @ AuthError::CardPolicy(_)) => return Err(e),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or(AuthError::NoCard))
}

/// Transport-generic provisioning workflow (deterministic unit-tested without PC/SC hardware).
pub fn provision_card_with_transport<T: ApduTransport>(
    transport: &T,
    opts: &CardProvisionOptions<'_>,
) -> Result<CardProvisionResult> {
    if !matches!(
        opts.touch_policy_9d,
        TOUCH_POLICY_CACHED | TOUCH_POLICY_ALWAYS | TOUCH_POLICY_NEVER
    ) {
        return Err(AuthError::CardPolicy(
            "Slot 0x9D touch policy must be CACHED (0x03), ALWAYS (0x02), or NEVER (0x01)".into(),
        ));
    }

    let custom_cur = match opts.current_mgmt_key_hex.filter(|s| !s.trim().is_empty()) {
        Some(hex_str) => Some(parse_mgmt_key_hex(hex_str)?),
        None => None,
    };
    let custom_new = match opts.new_mgmt_key_hex.filter(|s| !s.trim().is_empty()) {
        Some(hex_str) => Some(parse_mgmt_key_hex(hex_str)?),
        None => None,
    };

    let session = PivSession::new(transport);
    let selected = session.select()?;

    // SAFETY ORDER 1: Verify PIN FIRST (when provided) BEFORE authenticating 0x9B or
    // overwriting any slot! If the user mistyped their PIN, we abort cleanly with zero
    // changes to the card's existing keys, and verifying PIN also unlocks `5F C1 09`
    // for cards using a Yubico PIN-protected Management Key.
    let mut pin_verified = false;
    if let Some(pin) = opts.pin {
        session.verify_pin(pin)?;
        pin_verified = true;
    }

    // SAFETY ORDER 2: Resolve & authenticate PIV 0x9B Management Key.
    let mgmt_meta = session.get_mgmt_key_metadata()?;
    let mgmt_key_bytes: Zeroizing<Vec<u8>> = if let Some(explicit) = custom_cur {
        explicit
    } else if pin_verified && mgmt_meta.as_ref().and_then(|m| m.is_default) != Some(true) {
        match read_pin_protected_mgmt_key(&session) {
            Some(protected_key) => protected_key,
            None => Zeroizing::new(DEFAULT_MGMT_KEY.to_vec()),
        }
    } else {
        Zeroizing::new(DEFAULT_MGMT_KEY.to_vec())
    };

    let mgmt_alg_used = authenticate_mgmt_auto(&session, mgmt_meta.as_ref(), &mgmt_key_bytes)?;

    // Step 3: Generate on-card ECC P-256 key in Slot 0x9D (`PIN=ALWAYS`, user-chosen `Touch`).
    let pub_9d_sec1 =
        session.generate_p256_key(SLOT_KEY_MANAGEMENT, PIN_POLICY_ALWAYS, opts.touch_policy_9d)?;

    // Verify metadata immediately when the card supports `00 F7` so policy compliance is guaranteed.
    if let Some(meta_9d) = session.get_metadata(SLOT_KEY_MANAGEMENT)? {
        let parsed = meta_9d.parse();
        validate_slot_9d_policy(&parsed)?;
        if opts.touch_policy_9d != TOUCH_POLICY_NEVER
            && parsed.touch_policy != Some(opts.touch_policy_9d)
        {
            return Err(AuthError::CardPolicy(
                "card generated 0x9D key without enforcing the requested hardware Touch Policy"
                    .into(),
            ));
        }
    }

    // Write matching PIV X.509 certificate to `5F C1 0B` so no stale certificate remains
    // and standard PIV certificate readers see the newly generated `0x9D` public key.
    let cert_9d_der = build_slot_x509_cert_der(&pub_9d_sec1, "Familiar Smartcard PIV 9D")?;
    let cert_9d_obj = wrap_piv_cert_object(&cert_9d_der)?;
    session.put_data(&OID_CERT_KEY_MANAGEMENT, &cert_9d_obj)?;

    // Step 4: Optionally generate on-card ECC P-256 key in Slot 0x9E (`PIN=NEVER`, `Touch=NEVER`)
    // for pre-PIN hardware anti-phishing.
    let pub_9e_sec1 = if opts.provision_9e {
        let pk_9e =
            session.generate_p256_key(SLOT_CARD_AUTH, PIN_POLICY_NEVER, TOUCH_POLICY_NEVER)?;
        let cert_9e_der = build_slot_x509_cert_der(&pk_9e, "Familiar Smartcard PIV 9E")?;
        let cert_9e_obj = wrap_piv_cert_object(&cert_9e_der)?;
        session.put_data(&OID_CERT_CARD_AUTH, &cert_9e_obj)?;
        Some(pk_9e)
    } else {
        None
    };

    // Step 5: Optionally rotate Slot 0x9B Management Key AFTER slots are provisioned,
    // and immediately re-authenticate to confirm the new key took effect cleanly.
    let mut mgmt_key_rotated = false;
    if let Some(new_key) = custom_new {
        let target_alg = choose_new_mgmt_alg(mgmt_alg_used, new_key.len())?;
        session.set_management_key(target_alg, &new_key, false)?;
        session.authenticate_mgmt_key_with_alg(target_alg, &new_key)?;
        mgmt_key_rotated = true;
    }

    let fingerprint_9d = sha256(&pub_9d_sec1);
    Ok(CardProvisionResult {
        card_name: selected.card_name,
        pub_9d_sec1,
        fingerprint_9d,
        touch_policy_9d: opts.touch_policy_9d,
        pub_9e_sec1,
        mgmt_alg_used,
        mgmt_key_rotated,
    })
}

fn read_pin_protected_mgmt_key<T: ApduTransport>(
    session: &PivSession<'_, T>,
) -> Option<Zeroizing<Vec<u8>>> {
    let printed = Zeroizing::new(session.get_data(&OID_PRINTED_INFO).ok()??);
    let inner_88 = find_tlv_recursive(&printed, 0x88, 0)?;
    let key_bytes = find_tlv(inner_88, 0x89)?;
    if matches!(key_bytes.len(), 16 | 24 | 32) {
        Some(Zeroizing::new(key_bytes.to_vec()))
    } else {
        None
    }
}

fn authenticate_mgmt_auto<T: ApduTransport>(
    session: &PivSession<'_, T>,
    meta: Option<&crate::piv::MgmtKeyMetadata>,
    key: &[u8],
) -> Result<u8> {
    if let Some(alg) = meta.and_then(|m| m.algorithm) {
        let expected_len = crate::mgmt_cipher::mgmt_key_len(alg)?;
        if key.len() != expected_len {
            return Err(AuthError::CardPolicy(format!(
                "card 0x9B Management Key uses custom {expected_len}-byte cipher (alg 0x{alg:02X}); enter the matching {}-char hex Management Key",
                expected_len * 2
            )));
        }
        session.authenticate_mgmt_key_with_alg(alg, key)?;
        return Ok(alg);
    }

    // Metadata (`00 F7 00 9B`) unavailable: infer cipher from key length, trying 3DES then AES-192 for 24-byte keys.
    match key.len() {
        16 => {
            session.authenticate_mgmt_key_with_alg(ALG_AES_128, key)?;
            Ok(ALG_AES_128)
        }
        32 => {
            session.authenticate_mgmt_key_with_alg(ALG_AES_256, key)?;
            Ok(ALG_AES_256)
        }
        24 => match session.authenticate_mgmt_key_with_alg(ALG_3DES, key) {
            Ok(()) => Ok(ALG_3DES),
            Err(AuthError::Apdu { sw1: 0x6A, .. })
            | Err(AuthError::Apdu {
                sw1: 0x69,
                sw2: 0x84,
            }) => {
                session.authenticate_mgmt_key_with_alg(ALG_AES_192, key)?;
                Ok(ALG_AES_192)
            }
            Err(other) => Err(other),
        },
        _ => Err(AuthError::CardPolicy(
            "invalid 0x9B Management Key length".into(),
        )),
    }
}

fn choose_new_mgmt_alg(current_alg: u8, new_key_len: usize) -> Result<u8> {
    match new_key_len {
        16 => Ok(ALG_AES_128),
        32 => Ok(ALG_AES_256),
        24 => {
            if current_alg == ALG_AES_192 {
                Ok(ALG_AES_192)
            } else {
                Ok(ALG_3DES)
            }
        }
        _ => Err(AuthError::CardPolicy(
            "new 0x9B Management Key must be 16, 24, or 32 bytes".into(),
        )),
    }
}

fn wrap_piv_cert_object(cert_der: &[u8]) -> Result<Vec<u8>> {
    let t70 = tlv_ber(0x70, cert_der)?;
    let mut out = Vec::with_capacity(t70.len() + 5);
    out.extend_from_slice(&t70);
    out.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
    Ok(out)
}

/// Build a valid X.509v3 DER certificate carrying `pub_sec1` (65-byte uncompressed P-256 point)
/// signed with a one-time ephemeral P-256 provisioning key (requiring zero card touches/PIN).
pub fn build_slot_x509_cert_der(pub_sec1: &[u8], subject_cn: &str) -> Result<Vec<u8>> {
    let _ = p256_public_from_sec1(pub_sec1)?;
    if pub_sec1.len() != 65 {
        return Err(AuthError::Crypto(
            "expected 65-byte uncompressed SEC1 P-256 public key".into(),
        ));
    }

    let issuer_key = SigningKey::random(&mut OsRng);
    build_x509_cert_with_signer(
        &issuer_key,
        "Familiar Smartcard Provisioning",
        subject_cn,
        pub_sec1,
    )
}

fn build_x509_cert_with_signer(
    signer: &SigningKey,
    issuer_cn: &str,
    subject_cn: &str,
    subject_pub_sec1: &[u8],
) -> Result<Vec<u8>> {
    // ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
    const ALG_ECDSA_SHA256: [u8; 12] = [
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    ];
    // SubjectPublicKeyInfo prefix for uncompressed P-256 point (RFC 5480)
    const P256_SPKI_HEADER: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];

    let version_v3 = [0xA0, 0x03, 0x02, 0x01, 0x02];
    let mut serial_bytes = random_array::<16>();
    serial_bytes[0] = (serial_bytes[0] & 0x7F) | 0x01; // strictly positive non-minimal-leading-zero DER INTEGER
    let serial = tlv_ber(0x02, &serial_bytes)?;

    let issuer = encode_x509_cn_name(issuer_cn)?;
    let subject = encode_x509_cn_name(subject_cn)?;

    // Validity: GeneralizedTime 20250101000000Z .. 20991231235959Z
    let not_before = tlv_ber(0x18, b"20250101000000Z")?;
    let not_after = tlv_ber(0x18, b"20991231235959Z")?;
    let mut validity_inner = Vec::with_capacity(not_before.len() + not_after.len());
    validity_inner.extend_from_slice(&not_before);
    validity_inner.extend_from_slice(&not_after);
    let validity = tlv_ber(0x30, &validity_inner)?;

    let mut spki = Vec::with_capacity(P256_SPKI_HEADER.len() + subject_pub_sec1.len());
    spki.extend_from_slice(&P256_SPKI_HEADER);
    spki.extend_from_slice(subject_pub_sec1);

    let mut tbs_inner = Vec::with_capacity(256);
    tbs_inner.extend_from_slice(&version_v3);
    tbs_inner.extend_from_slice(&serial);
    tbs_inner.extend_from_slice(&ALG_ECDSA_SHA256);
    tbs_inner.extend_from_slice(&issuer);
    tbs_inner.extend_from_slice(&validity);
    tbs_inner.extend_from_slice(&subject);
    tbs_inner.extend_from_slice(&spki);
    let tbs_der = tlv_ber(0x30, &tbs_inner)?;

    let signature: Signature = signer.sign(&tbs_der);
    let sig_der = signature.to_der();
    let mut sig_bits = Vec::with_capacity(1 + sig_der.as_bytes().len());
    sig_bits.push(0x00);
    sig_bits.extend_from_slice(sig_der.as_bytes());
    let sig_bit_string = tlv_ber(0x03, &sig_bits)?;

    let mut cert_inner =
        Vec::with_capacity(tbs_der.len() + ALG_ECDSA_SHA256.len() + sig_bit_string.len());
    cert_inner.extend_from_slice(&tbs_der);
    cert_inner.extend_from_slice(&ALG_ECDSA_SHA256);
    cert_inner.extend_from_slice(&sig_bit_string);
    tlv_ber(0x30, &cert_inner)
}

fn encode_x509_cn_name(cn: &str) -> Result<Vec<u8>> {
    // OID 2.5.4.3 (commonName): 06 03 55 04 03
    let oid_cn = [0x06, 0x03, 0x55, 0x04, 0x03];
    let utf8_val = tlv_ber(0x0C, cn.as_bytes())?;
    let mut atv_inner = Vec::with_capacity(oid_cn.len() + utf8_val.len());
    atv_inner.extend_from_slice(&oid_cn);
    atv_inner.extend_from_slice(&utf8_val);
    let atv = tlv_ber(0x30, &atv_inner)?;
    let rdn = tlv_ber(0x31, &atv)?;
    tlv_ber(0x30, &rdn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{extract_cert_public_key_bytes, verify_slot_attestation};
    use crate::crypto::{p256_generate_ephemeral, p256_public_to_sec1};
    use crate::mgmt_cipher::{mgmt_block_len, mgmt_ecb_decrypt, mgmt_ecb_encrypt};
    use crate::piv::SLOT_CARD_MANAGEMENT;
    use std::cell::RefCell;

    #[test]
    fn generated_x509_der_parses_and_verifies_under_windows_crypt32() {
        let (_sec, slot_pub) = p256_generate_ephemeral();
        let slot_pub_sec1 = p256_public_to_sec1(&slot_pub);

        let ca_signer = SigningKey::random(&mut OsRng);
        let ca_pub_sec1 = ca_signer
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let ca_cert =
            build_x509_cert_with_signer(&ca_signer, "Test CA", "Test CA", &ca_pub_sec1).unwrap();
        let leaf_cert =
            build_x509_cert_with_signer(&ca_signer, "Test CA", "Slot 9D", &slot_pub_sec1).unwrap();

        let extracted = extract_cert_public_key_bytes(&leaf_cert).unwrap();
        assert_eq!(extracted, slot_pub_sec1);

        // Windows Crypt32 signature & SPKI verification passes 100%!
        let verified = verify_slot_attestation(&leaf_cert, &ca_cert, &slot_pub_sec1).unwrap();
        assert_eq!(verified.f9_public_key_fingerprint, sha256(&ca_pub_sec1));
    }

    struct SimulatedProvisionCard {
        pin: Vec<u8>,
        mgmt_alg: CellAlg,
        mgmt_key: RefCell<Vec<u8>>,
        supports_touch_always: bool,
        pending_witness: RefCell<Option<Vec<u8>>>,
        mgmt_authenticated: RefCell<bool>,
        generated_9d_touch: RefCell<Option<u8>>,
        generated_9e: RefCell<bool>,
        put_data_buf: RefCell<Vec<u8>>,
        certs_written: RefCell<Vec<[u8; 3]>>,
        pub_9d: Vec<u8>,
        pub_9e: Vec<u8>,
    }

    type CellAlg = std::cell::Cell<u8>;

    impl SimulatedProvisionCard {
        fn new(mgmt_alg: u8, mgmt_key: Vec<u8>, supports_touch_always: bool) -> Self {
            let (_s1, p1) = p256_generate_ephemeral();
            let (_s2, p2) = p256_generate_ephemeral();
            Self {
                pin: b"123456".to_vec(),
                mgmt_alg: std::cell::Cell::new(mgmt_alg),
                mgmt_key: RefCell::new(mgmt_key),
                supports_touch_always,
                pending_witness: RefCell::new(None),
                mgmt_authenticated: RefCell::new(false),
                generated_9d_touch: RefCell::new(None),
                generated_9e: RefCell::new(false),
                put_data_buf: RefCell::new(Vec::new()),
                certs_written: RefCell::new(Vec::new()),
                pub_9d: p256_public_to_sec1(&p1),
                pub_9e: p256_public_to_sec1(&p2),
            }
        }
    }

    impl ApduTransport for SimulatedProvisionCard {
        fn transmit_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>> {
            let cla = apdu[0];
            let ins = apdu[1];
            let p1 = apdu[2];
            let p2 = apdu[3];

            match (cla, ins, p1, p2) {
                // SELECT PIV
                (0x00, 0xA4, 0x04, 0x00) => Ok(vec![0x90, 0x00]),
                // VERIFY PIN
                (0x00, 0x20, 0x00, 0x80) => {
                    let expected = pad_pin_bytes(&self.pin)?;
                    if apdu[5..13] == expected[..] {
                        Ok(vec![0x90, 0x00])
                    } else {
                        Ok(vec![0x63, 0xC2])
                    }
                }
                // GET METADATA 0x9B or 0x9D
                (0x00, 0xF7, 0x00, SLOT_CARD_MANAGEMENT) => {
                    let is_def =
                        u8::from(self.mgmt_key.borrow().as_slice() == &DEFAULT_MGMT_KEY[..]);
                    Ok(vec![
                        0x01,
                        0x01,
                        self.mgmt_alg.get(),
                        0x05,
                        0x01,
                        is_def,
                        0x90,
                        0x00,
                    ])
                }
                (0x00, 0xF7, 0x00, SLOT_KEY_MANAGEMENT) => {
                    let Some(tp) = *self.generated_9d_touch.borrow() else {
                        return Ok(vec![0x6A, 0x88]);
                    };
                    let mut out = vec![
                        0x01, 0x01, 0x11, // ECC P-256
                        0x02, 0x02, 0x03, tp, // PIN=ALWAYS, Touch=tp
                        0x03, 0x01, 0x01, // On-card
                        0x04, 0x43, 0x86, 0x41,
                    ];
                    out.extend_from_slice(&self.pub_9d);
                    out.extend_from_slice(&[0x90, 0x00]);
                    Ok(out)
                }
                // GENERAL AUTHENTICATE 0x9B (Mutual Auth)
                (0x00, 0x87, alg, SLOT_CARD_MANAGEMENT) => {
                    if alg != self.mgmt_alg.get() {
                        return Ok(vec![0x6A, 0x80]);
                    }
                    let data = &apdu[5..];
                    if data == [0x7C, 0x02, 0x80, 0x00] {
                        let blen = mgmt_block_len(alg)?;
                        let witness = vec![0x42u8; blen];
                        let enc = mgmt_ecb_encrypt(alg, &self.mgmt_key.borrow(), &witness)?;
                        *self.pending_witness.borrow_mut() = Some(witness);
                        let t80 = crate::piv::tlv(0x80, &enc)?;
                        let mut out = crate::piv::tlv(0x7C, &t80)?;
                        out.extend_from_slice(&[0x90, 0x00]);
                        return Ok(out);
                    }
                    let outer = find_tlv(data, 0x7C).unwrap();
                    let dec_w = find_tlv(outer, 0x80).unwrap();
                    let host_c = find_tlv(outer, 0x81).unwrap();
                    let expected_w = self.pending_witness.borrow_mut().take().unwrap();
                    if dec_w != expected_w.as_slice() {
                        *self.mgmt_authenticated.borrow_mut() = false;
                        return Ok(vec![0x69, 0x82]);
                    }
                    *self.mgmt_authenticated.borrow_mut() = true;
                    let enc_c = mgmt_ecb_encrypt(alg, &self.mgmt_key.borrow(), host_c)?;
                    let t82 = crate::piv::tlv(0x82, &enc_c)?;
                    let mut out = crate::piv::tlv(0x7C, &t82)?;
                    out.extend_from_slice(&[0x90, 0x00]);
                    Ok(out)
                }
                // GENERATE ASYMMETRIC KEY PAIR
                (0x00, 0x47, 0x00, slot) => {
                    if !*self.mgmt_authenticated.borrow() {
                        return Ok(vec![0x69, 0x82]);
                    }
                    let ac = find_tlv(&apdu[5..], 0xAC).unwrap();
                    let tp = find_tlv(ac, 0xAB).unwrap()[0];
                    if tp != TOUCH_POLICY_NEVER && !self.supports_touch_always {
                        return Ok(vec![0x6A, 0x80]);
                    }
                    let pk = if slot == SLOT_KEY_MANAGEMENT {
                        *self.generated_9d_touch.borrow_mut() = Some(tp);
                        &self.pub_9d
                    } else {
                        *self.generated_9e.borrow_mut() = true;
                        &self.pub_9e
                    };
                    let mut out = vec![0x7F, 0x49, 0x43, 0x86, 0x41];
                    out.extend_from_slice(pk);
                    out.extend_from_slice(&[0x90, 0x00]);
                    Ok(out)
                }
                // PUT DATA (with CLA=0x10 command chaining)
                (0x10, 0xDB, 0x3F, 0xFF) => {
                    if !*self.mgmt_authenticated.borrow() {
                        return Ok(vec![0x69, 0x82]);
                    }
                    self.put_data_buf.borrow_mut().extend_from_slice(&apdu[5..]);
                    Ok(vec![0x90, 0x00])
                }
                (0x00, 0xDB, 0x3F, 0xFF) => {
                    if !*self.mgmt_authenticated.borrow() {
                        return Ok(vec![0x69, 0x82]);
                    }
                    let mut buf = self.put_data_buf.borrow_mut();
                    buf.extend_from_slice(&apdu[5..]);
                    let oid = find_tlv(&buf, 0x5C).unwrap();
                    let mut oid_arr = [0u8; 3];
                    oid_arr.copy_from_slice(oid);
                    // Verify wrapped certificate parses back cleanly!
                    let outer_53 = find_tlv_recursive(&buf, 0x53, 0).unwrap();
                    let cert_der = find_tlv_recursive(outer_53, 0x70, 0).unwrap();
                    let _ = extract_cert_public_key_bytes(cert_der).unwrap();
                    self.certs_written.borrow_mut().push(oid_arr);
                    buf.clear();
                    Ok(vec![0x90, 0x00])
                }
                // SET MANAGEMENT KEY (00 FF FF FF)
                (0x00, 0xFF, 0xFF, 0xFF) => {
                    if !*self.mgmt_authenticated.borrow() {
                        return Ok(vec![0x69, 0x82]);
                    }
                    let new_alg = apdu[5];
                    let len = apdu[7] as usize;
                    self.mgmt_alg.set(new_alg);
                    *self.mgmt_key.borrow_mut() = apdu[8..8 + len].to_vec();
                    let _ = mgmt_ecb_decrypt(
                        new_alg,
                        &self.mgmt_key.borrow(),
                        &vec![0u8; mgmt_block_len(new_alg)?],
                    )?;
                    Ok(vec![0x90, 0x00])
                }
                _ => Ok(vec![0x6D, 0x00]),
            }
        }
    }

    #[test]
    fn provision_supports_touch_always_and_never_9e_and_mgmt_rotation_safely() {
        // 1. Mistyped PIN aborts BEFORE overwriting 0x9D!
        let card = SimulatedProvisionCard::new(ALG_AES_192, DEFAULT_MGMT_KEY.to_vec(), true);
        let bad_pin = provision_card_with_transport(
            &card,
            &CardProvisionOptions {
                reader: None,
                pin: Some(b"999999"),
                touch_policy_9d: TOUCH_POLICY_ALWAYS,
                provision_9e: true,
                current_mgmt_key_hex: None,
                new_mgmt_key_hex: None,
            },
        )
        .unwrap_err();
        assert!(matches!(bad_pin, AuthError::PinIncorrect(2)));
        assert!(card.generated_9d_touch.borrow().is_none());

        // 2. Provision Touch = ALWAYS + 0x9E + rotate 0x9B to custom AES-256 key!
        let new_k256 = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF";
        let ok_always = provision_card_with_transport(
            &card,
            &CardProvisionOptions {
                reader: None,
                pin: Some(b"123456"),
                touch_policy_9d: TOUCH_POLICY_ALWAYS,
                provision_9e: true,
                current_mgmt_key_hex: None,
                new_mgmt_key_hex: Some(new_k256),
            },
        )
        .unwrap();
        assert_eq!(ok_always.touch_policy_9d, TOUCH_POLICY_ALWAYS);
        assert!(ok_always.pub_9e_sec1.is_some());
        assert!(ok_always.mgmt_key_rotated);
        assert_eq!(
            *card.certs_written.borrow(),
            vec![OID_CERT_KEY_MANAGEMENT, OID_CERT_CARD_AUTH]
        );

        // 3. Re-provision same card switching to Touch = NEVER using the newly rotated AES-256 0x9B key!
        let ok_never = provision_card_with_transport(
            &card,
            &CardProvisionOptions {
                reader: None,
                pin: Some(b"123456"),
                touch_policy_9d: TOUCH_POLICY_NEVER,
                provision_9e: false,
                current_mgmt_key_hex: Some(new_k256),
                new_mgmt_key_hex: None,
            },
        )
        .unwrap();
        assert_eq!(ok_never.touch_policy_9d, TOUCH_POLICY_NEVER);
        assert_eq!(ok_never.mgmt_alg_used, ALG_AES_256);

        // 3b. Re-provision same card switching to Touch = CACHED (single touch + immediate reset)!
        let ok_cached = provision_card_with_transport(
            &card,
            &CardProvisionOptions {
                reader: None,
                pin: Some(b"123456"),
                touch_policy_9d: TOUCH_POLICY_CACHED,
                provision_9e: true,
                current_mgmt_key_hex: Some(new_k256),
                new_mgmt_key_hex: None,
            },
        )
        .unwrap();
        assert_eq!(ok_cached.touch_policy_9d, TOUCH_POLICY_CACHED);

        // 4. Non-touch card strictly FAILS CLOSED when Touch = ALWAYS or CACHED is requested!
        let non_touch_card =
            SimulatedProvisionCard::new(ALG_3DES, DEFAULT_MGMT_KEY.to_vec(), false);
        let fail_closed = provision_card_with_transport(
            &non_touch_card,
            &CardProvisionOptions {
                reader: None,
                pin: Some(b"123456"),
                touch_policy_9d: TOUCH_POLICY_ALWAYS,
                provision_9e: true,
                current_mgmt_key_hex: None,
                new_mgmt_key_hex: None,
            },
        )
        .unwrap_err();
        assert!(matches!(fail_closed, AuthError::CardPolicy(_)));
    }
}
