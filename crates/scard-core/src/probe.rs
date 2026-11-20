//! Read-only card probing used by the enrollment GUI and diagnostics.

use crate::error::{AuthError, Result};
use crate::pcsc::{ScardContext, SCARD_LEAVE_CARD};
use crate::piv::{
    PivSession, SLOT_CARD_AUTH, SLOT_DIGITAL_SIGNATURE, SLOT_KEY_MANAGEMENT, SLOT_PIV_AUTH,
};

#[derive(Debug, Clone)]
pub struct SlotProbe {
    pub slot: u8,
    pub has_key: bool,
    pub metadata_hex: String,
}

#[derive(Debug, Clone)]
pub struct ReaderProbe {
    pub reader: String,
    pub atr_hex: String,
    pub piv_selected: bool,
    pub card_name: Option<String>,
    pub algorithms: Vec<u8>,
    pub slots: Vec<SlotProbe>,
    pub error: Option<String>,
}

/// Enumerate readers and, when a card is present, select PIV and read metadata.
///
/// This function never writes to the card, never verifies a PIN, and never
/// changes key material.
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
            slots: Vec::new(),
            error: None,
        };

        match context.connect(&reader) {
            Ok(mut card) => {
                info.atr_hex = card.atr().map(|atr| hex::encode(atr)).unwrap_or_default();

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

                        for slot in [
                            SLOT_PIV_AUTH,
                            SLOT_DIGITAL_SIGNATURE,
                            SLOT_KEY_MANAGEMENT,
                            SLOT_CARD_AUTH,
                        ] {
                            match session.get_metadata(slot) {
                                Ok(Some(metadata)) => info.slots.push(SlotProbe {
                                    slot,
                                    has_key: true,
                                    metadata_hex: hex::encode(metadata.raw),
                                }),
                                Ok(None) => info.slots.push(SlotProbe {
                                    slot,
                                    has_key: false,
                                    metadata_hex: String::new(),
                                }),
                                Err(error) => {
                                    info.error = Some(error.to_string());
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        info.error = Some(error.to_string());
                    }
                }

                let _ = card.end_transaction(SCARD_LEAVE_CARD);
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
