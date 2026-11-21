//! Read-only card probing used by the enrollment GUI and diagnostics.

#![forbid(unsafe_code)]

use crate::attestation::verify_slot_attestation;
use crate::error::{AuthError, Result};
use crate::pcsc::{ScardContext, SCARD_LEAVE_CARD};
use crate::piv::{
    validate_slot_9d_policy, MgmtKeyMetadata, PinPukMetadata, PivSession, SlotPolicy, KEY_REF_PIN,
    KEY_REF_PUK, SLOT_CARD_AUTH, SLOT_DIGITAL_SIGNATURE, SLOT_KEY_MANAGEMENT, SLOT_PIV_AUTH,
};

#[derive(Debug, Clone)]
pub struct SlotProbe {
    pub slot: u8,
    pub has_key: bool,
    pub metadata_hex: String,
    pub policy: Option<SlotPolicy>,
    pub policy_valid_for_9d: bool,
    pub policy_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReaderProbe {
    pub reader: String,
    pub atr_hex: String,
    pub piv_selected: bool,
    pub card_name: Option<String>,
    pub algorithms: Vec<u8>,
    pub pin_metadata: Option<PinPukMetadata>,
    pub puk_metadata: Option<PinPukMetadata>,
    pub mgmt_metadata: Option<MgmtKeyMetadata>,
    pub slots: Vec<SlotProbe>,
    pub f9_fingerprint_hex: Option<String>,
    pub attestation_verified: bool,
    pub error: Option<String>,
}

/// Enumerate readers and, when a card is present, select PIV, inspect slot
/// policies, and verify `0x9D`/`0xF9` attestation if available.
///
/// Never writes to the card, never verifies a PIN, and leaves all cards in
/// `SCARD_LEAVE_CARD` state.
pub fn probe_readers() -> Result<Vec<ReaderProbe>> {
    let context = ScardContext::new()?;
    let readers = context.list_readers()?;
    let mut out = Vec::with_capacity(readers.len());

    for reader in readers {
        let mut info = ReaderProbe {
            reader: reader.clone(),
            atr_hex: String::new(),
            piv_selected: false,
            card_name: None,
            algorithms: Vec::new(),
            pin_metadata: None,
            puk_metadata: None,
            mgmt_metadata: None,
            slots: Vec::new(),
            f9_fingerprint_hex: None,
            attestation_verified: false,
            error: None,
        };

        match context.connect(&reader) {
            Ok(mut card) => {
                info.atr_hex = card.atr().map(hex::encode).unwrap_or_default();

                if let Err(error) = card.begin_transaction() {
                    info.error = Some(error.to_string());
                    out.push(info);
                    continue;
                }

                let session = PivSession::new(&card);
                match session.select() {
                    Ok(selected) => {
                        info.piv_selected = true;
                        info.card_name = selected.card_name;
                        info.algorithms = selected.algorithms;
                        info.pin_metadata =
                            session.get_pin_puk_metadata(KEY_REF_PIN).ok().flatten();
                        info.puk_metadata =
                            session.get_pin_puk_metadata(KEY_REF_PUK).ok().flatten();
                        info.mgmt_metadata = session.get_mgmt_key_metadata().ok().flatten();

                        let mut pub_9d: Option<Vec<u8>> = None;

                        for slot in [
                            SLOT_PIV_AUTH,
                            SLOT_DIGITAL_SIGNATURE,
                            SLOT_KEY_MANAGEMENT,
                            SLOT_CARD_AUTH,
                        ] {
                            match session.get_metadata(slot) {
                                Ok(Some(metadata)) => {
                                    let parsed = metadata.parse();
                                    let (valid_9d, policy_err) = if slot == SLOT_KEY_MANAGEMENT {
                                        if let Some(pk) = &parsed.public_key_sec1 {
                                            pub_9d = Some(pk.clone());
                                        }
                                        match validate_slot_9d_policy(&parsed) {
                                            Ok(()) => (true, None),
                                            Err(e) => (false, Some(e.to_string())),
                                        }
                                    } else {
                                        (false, None)
                                    };
                                    info.slots.push(SlotProbe {
                                        slot,
                                        has_key: true,
                                        metadata_hex: hex::encode(metadata.raw),
                                        policy: Some(parsed),
                                        policy_valid_for_9d: valid_9d,
                                        policy_error: policy_err,
                                    });
                                }
                                Ok(None) => {
                                    // Standard PIV fallback: check whether the slot holds a standard
                                    // PIV X.509 certificate even when vendor `00 F7` is unsupported.
                                    let std_pk =
                                        session.read_ec_public_key(slot).ok().filter(|pk| {
                                            crate::crypto::p256_public_from_sec1(pk).is_ok()
                                        });
                                    let valid_9d = slot == SLOT_KEY_MANAGEMENT && std_pk.is_some();
                                    if valid_9d {
                                        pub_9d = std_pk.clone();
                                    }
                                    info.slots.push(SlotProbe {
                                        slot,
                                        has_key: std_pk.is_some(),
                                        metadata_hex: String::new(),
                                        policy: None,
                                        policy_valid_for_9d: valid_9d,
                                        policy_error: None,
                                    });
                                }
                                Err(error) => {
                                    info.error = Some(error.to_string());
                                    break;
                                }
                            }
                        }

                        if let Some(pk_9d) = pub_9d {
                            if let (Ok(Some(slot_cert)), Ok(Some(f9_cert))) = (
                                session.attest_slot(SLOT_KEY_MANAGEMENT),
                                session.read_attestation_ca_cert(),
                            ) {
                                if let Ok(verified) =
                                    verify_slot_attestation(&slot_cert, &f9_cert, &pk_9d)
                                {
                                    info.attestation_verified = true;
                                    info.f9_fingerprint_hex =
                                        Some(hex::encode(verified.f9_public_key_fingerprint));
                                }
                            }
                        }
                    }
                    Err(error) => {
                        info.error = Some(error.to_string());
                    }
                }

                let _ = card.end_transaction(SCARD_LEAVE_CARD);
                let _ = card.disconnect(SCARD_LEAVE_CARD);
            }
            Err(AuthError::NoCard) | Err(AuthError::CardBusy) => {
                info.error = Some("no card present or card busy".into());
            }
            Err(error) => {
                info.error = Some(error.to_string());
            }
        }

        out.push(info);
    }

    Ok(out)
}

/// Lightweight read-only session check used before resolving `ExplicitUser` ("Other user")
/// usernames so unauthenticated callers without a smart card (or with a busy card)
/// receive the exact same reader/card error regardless of whether a typed username exists.
pub fn ensure_piv_card_present_in_session() -> Result<()> {
    let context = ScardContext::new()?;
    let readers = context.list_readers()?;
    if readers.is_empty() {
        return Err(AuthError::NoReader);
    }

    let mut last_error = None;
    for reader in readers {
        let mut card = match context.connect(&reader) {
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
        let ok = PivSession::new(&card).select().is_ok();
        let _ = card.end_transaction(SCARD_LEAVE_CARD);
        let _ = card.disconnect(SCARD_LEAVE_CARD);
        if ok {
            return Ok(());
        }
    }

    Err(last_error.unwrap_or(AuthError::NoCard))
}
