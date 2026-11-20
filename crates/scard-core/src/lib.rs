//! FamiliarSmartcard core.
//!
//! The core is intentionally synchronous: one authentication attempt owns one
//! PC/SC context, one card handle, and one transaction. No background threads
//! are created here.

pub mod crypto;
pub mod dpapi;
pub mod enroll;
pub mod error;
pub mod pcsc;
pub mod piv;
pub mod probe;
pub mod storage;
pub mod typestate;
pub mod vault;

pub use enroll::{enroll, EnrollResult};
pub use error::{AuthError, Result};
pub use probe::{probe_readers, ReaderProbe, SlotProbe};
pub use typestate::{
    unlock, AuthPipeline, CardConnected, CredentialDecrypted, FreshnessProven, KeyUnwrapped,
    PinVerified, PinVerifiedForUnwrap, VaultLoaded,
};
pub use vault::VaultBlob;
