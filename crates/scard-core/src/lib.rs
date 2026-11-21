//! FamiliarSmartcard core.
//!
//! Synchronous cryptographic, PIV APDU, vault, account, attestation, and IPC
//! primitives shared by `familiar-auth-helper`, `cred-provider`, and `enroll-gui`.

pub mod account;
pub mod attestation;
pub mod crypto;
pub mod dpapi;
pub mod enroll;
pub mod error;
pub mod ipc;
pub mod pcsc;
pub mod piv;
pub mod probe;
pub mod storage;
pub mod typestate;
pub mod vault;

pub use account::{current_user, UserInfo};
pub use enroll::{
    change_card_puk, enroll, enroll_with_options, query_card_pin_remaining,
    repin_connected_card_attestation, unblock_card_pin, AttestationPolicy, EnrollOptions,
    EnrollResult,
};
pub use error::{AuthError, Result};
pub use piv::PinPukMetadata;
pub use probe::{probe_readers, ReaderProbe, SlotProbe};
pub use typestate::{
    unlock, unlock_with_transport, AuthPipeline, CardConnected, CredentialDecrypted,
    FreshnessProven, KeyUnwrapped, PinVerified, PinVerifiedForUnwrap, VaultLoaded,
};
pub use vault::VaultBlob;
