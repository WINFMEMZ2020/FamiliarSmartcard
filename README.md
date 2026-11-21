# FamiliarSmartcard

Windows local-account sign-in and workstation unlock via an RS-Key PIV `0x9D`
P-256 key and a hardened Credential Provider V2.

## Principles

See `PROJECT_PRINCIPLES.md`. All runtime, CLI, and UI messages are strictly English.

## Workspace Layout

- `crates/scard-core` — PC/SC, PIV APDU, `0x9D` policy & `0xF9` attestation verifier, vault format, DPAPI, SDDL ACLs, IPC framing, and Typestate pipeline.
- `crates/auth-helper` — `familiar-auth-helper.exe`: same-session isolated PC/SC unlock helper with hard timeout protection for `LogonUI.exe`.
- `crates/cred-provider` — `cred_provider.dll`: COM Credential Provider V2 supporting both bound user tiles and RDP "Other user" sign-in.
- `crates/enroll-gui` — `familiar-enroll.exe`: native Win32 two-phase setup, offline recovery-sheet verification, attestation pinning, and pure-Rust installer.

## Build & Test

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release --workspace
```

Release binaries in `target\release\`:

- `cred_provider.dll` (installed as `C:\Program Files\FamiliarSmartcard\familiar_cred_provider.dll`)
- `familiar-auth-helper.exe` (installed alongside the DLL)
- `familiar-enroll.exe`

## CLI Commands

```powershell
# Read-only probe: checks PIN/PUK retries, slot 0x9D policy (P-256, PIN ALWAYS, On-card) & 0xF9 attestation
.\familiar-enroll.exe --probe

# Stateless crypto self-test (no registry writes, no Windows password change)
.\familiar-enroll.exe --card-selftest <PIV-PIN>

# Unblock a locked PIV PIN (SW=6983) using the card PUK (factory default: 12345678) and reset retries to 3
.\familiar-enroll.exe --unblock-pin <PUK> <NEW-PIN>

# Change the card PUK (replace factory default 12345678 with your own 6-8 char PUK)
.\familiar-enroll.exe --change-puk <CURRENT-PUK> <NEW-PUK>

# Re-pin the connected card's 0xF9 attestation root in HKLM (Admin; run after `rsk otp burn` or card replacement)
.\familiar-enroll.exe --repin-attestation

# Clear the pinned 0xF9 attestation root from HKLM (Admin)
.\familiar-enroll.exe --clear-attestation
```

## Enrollment Workflows

Launch `familiar-enroll.exe` (requests UAC elevation automatically):

1. **`Set up & rotate password (Recommended)`**:
   - Validates the local Workgroup account, verifies `0x9D` (`ECCP256`, `PIN ALWAYS`, `On-card`) and `0xF9` attestation, generates a **36-character unambiguous random password** (`XXXX-XXXX-...`), and runs a real card unlock self-test **before** changing your Windows password.
   - Displays (and optionally prints via direct GDI) the offline recovery sheet and requires typing the last 6 characters to confirm.
   - Atomically rotates the local password (`UF_DONT_EXPIRE_PASSWD`), commits the verified `VaultBlob`, and installs/registers the Credential Provider and helper in `C:\Program Files\FamiliarSmartcard\`.
2. **`Re-bind current password (Dev / Rescue — Not Recommended for Production)`**:
   - Binds the existing Windows password without rotating it. **Not recommended** outside isolated test VMs or post-rescue re-binding because the native Windows password tile remains enabled; a human-chosen password can still be guessed (especially when RDP NLA is disabled).

## Security Notes

- Always configure a Windows Account Lockout Threshold (`net accounts /lockoutthreshold:5`).
- Never expose RDP TCP 3389 directly to the internet or untrusted LANs when NLA (`UserAuthentication=0`) is disabled; restrict port 3389 to VPN/WireGuard/IPsec interfaces.
- Before production use, change the default PIV PIN, PUK, and Management Key (never pass `--protect`), and complete RS-Key OTP burn + `lock-page58` + Secure Boot, then run `familiar-enroll.exe --repin-attestation` (or click `Re-pin card root`).
