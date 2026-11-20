use windows::core::GUID;

/// Fixed CLSID for the FamiliarSmartcard Credential Provider.
/// Generate once and never change it; the registry uses this value.
pub const CLSID_FAMILIAR_SMARTCARD: GUID = GUID::from_u128(0x6E2B7F4A_9C1D_4E8B_9A7F_3D5C1E2B4A60);
