use thiserror::Error;

/// Errors returned by the FamiliarSmartcard core.
///
/// Security rule: every error path must be terminal for the current
/// authentication pipeline. The typestate layer consumes the current state and
/// never exposes a later state after an error.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("PC/SC error 0x{0:08X}")]
    Pcsc(i32),

    #[error("no smart card reader found")]
    NoReader,

    #[error("no smart card present")]
    NoCard,

    #[error("smart card is busy (another process holds it)")]
    CardBusy,

    #[error("smart card operation timed out or was cancelled")]
    Timeout,

    #[error("Windows password changed; re-enrollment is required")]
    PasswordChanged,

    #[error("the inserted card does not match the enrolled card")]
    WrongCard,

    #[error("PIV slot has no key; provision the card first")]
    NoKey,

    #[error("PIN is required")]
    PinRequired,

    #[error("PIN incorrect; remaining attempts: {0}")]
    PinIncorrect(u8),

    #[error("PIN is blocked; use the PUK or administration PIN to unblock")]
    PinBlocked,

    #[error("APDU failed with SW={sw1:02X}{sw2:02X}")]
    Apdu { sw1: u8, sw2: u8 },

    #[error("vault error: {0}")]
    Vault(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("DPAPI error: {0}")]
    Dpapi(String),

    #[error("registry error: 0x{0:08X}")]
    Registry(i32),

    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = core::result::Result<T, AuthError>;

impl From<windows::core::Error> for AuthError {
    fn from(value: windows::core::Error) -> Self {
        AuthError::Internal(value.message())
    }
}
