# Familiar Smartcard

Windows local-account sign-in and workstation unlock via a standard PIV
(NIST SP 800-73-4) smart card or hardware security key (`0x9D` ECC P-256) and a
hardened Credential Provider V2.

## Principles

See `PROJECT_PRINCIPLES.md`. All runtime, CLI, and UI messages are strictly English.

## Workspace Layout

- `crates/scard-core` — PC/SC, PIV APDU (`VERIFY`, `RESET RETRY COUNTER`, `CHANGE REFERENCE DATA`, `GENERAL AUTHENTICATE` ECDH), `0x9D` policy & `0xF9` attestation verifier, vault format, DPAPI, SDDL ACLs, IPC framing, and Typestate pipeline.
- `crates/auth-helper` — `familiar-auth-helper.exe`: same-session isolated PC/SC unlock & PUK-unblock helper with hard timeout protection and 60s last-attempt safety cooldown.
- `crates/cred-provider` — `cred_provider.dll`: COM Credential Provider V2 supporting bound user tiles, RDP "Other user" sign-in, and in-place PUK unblock on the lock screen.
- `crates/enroll-gui` — `familiar-enroll.exe`: native Win32 two-phase setup, offline recovery-sheet verification, PIN unblock / PUK management, attestation pinning, and pure-Rust installer.

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
# Read-only probe: checks PIN/PUK retries, 0x9B mgmt key, slot 0x9D policy & 0xF9 attestation
.\familiar-enroll.exe --probe

# Provision on-card ECC P-256 0x9D key with custom Touch Policy (always or never) + 0x9E anti-phishing key
.\familiar-enroll.exe --provision-card always --pin <PIV-PIN>
.\familiar-enroll.exe --provision-card never  --pin <PIV-PIN>

# Stateless crypto self-test (no registry writes, no Windows password change)
.\familiar-enroll.exe --card-selftest <PIV-PIN>

# Unblock a locked PIV PIN (SW=6983) using the card PUK (PIV default: 12345678) and reset retries to 3
.\familiar-enroll.exe --unblock-pin <PUK> <NEW-PIN>

# Change the card PUK (replace default 12345678 with your own 6-8 char PUK)
.\familiar-enroll.exe --change-puk <CURRENT-PUK> <NEW-PUK>

# Re-pin the connected card's 0xF9 attestation root in HKLM (Admin; run after card replacement or reset)
.\familiar-enroll.exe --repin-attestation

# Clear the pinned 0xF9 attestation root from HKLM (Admin)
.\familiar-enroll.exe --clear-attestation
```

## Enrollment Workflows

Launch `familiar-enroll.exe` (requests UAC elevation automatically):

1. **`Set up & rotate password (Recommended)`**:
   - Optionally provisions a fresh on-card `0x9D` ECC P-256 key directly inside the workflow with your choice of **`Touch = ALWAYS`** (physical touch required) or **`Touch = NEVER`** (PIN only), optionally provisions **`Slot 0x9E` (`PIN=NEVER`)** for pre-PIN hardware anti-phishing, and supports custom or rotated `0x9B` Management Keys (no external `ykman` required).
   - Validates the local Workgroup account, verifies `0x9D` (`ECCP256`, `PIN ALWAYS`, `On-card` when metadata is exposed, or standard `5F C1 0B` X.509 certificate) and `0xF9` attestation if supported, generates a **36-character unambiguous random password** (`XXXX-XXXX-...`), and runs a real card unlock self-test **before** changing your Windows password.
   - Displays (and optionally prints via direct GDI) the offline recovery sheet and requires typing the last 6 characters to confirm.
   - Atomically rotates the local password (`UF_DONT_EXPIRE_PASSWD`), commits the verified `VaultBlob`, and installs/registers the Credential Provider and helper in `C:\Program Files\FamiliarSmartcard\`.
2. **`Re-bind current password (Advanced / Rescue — Not Recommended for Production)`**:
   - Binds the existing Windows password without rotating it. **Not recommended** outside post-rescue re-binding (when the account already uses a rotated recovery password) or isolated test environments because the native Windows password tile remains enabled; a human-chosen password can still be guessed (especially when RDP NLA is disabled).

## Security Notes

- **Sole-Administrator Lockout Safety**: When using **`Set up & rotate password (Recommended)`**, the 36-character random recovery password provides **180 bits of entropy** (immune to online guessing without needing a SAM account lockout threshold — avoiding a 5-try remote DoS lockout that would also block `STATUS_ACCOUNT_LOCKED_OUT` smart-card sign-ins on a sole-administrator machine). If you use `Re-bind` with a human password and manually enable `net accounts /lockoutthreshold:5`, always configure a short auto-unlock duration (never permanent lockout on a sole admin account).
- **Network Boundary for Non-NLA RDP**: Never expose RDP TCP 3389 directly to the internet or untrusted LANs when NLA (`UserAuthentication=0`) is disabled; restrict port 3389 to WireGuard / Tailscale / IPsec interfaces.
- **Card Hardening (`TOUCH_POLICY_ALWAYS` & Optional Slot `0x9E` Pre-PIN Guard)**:
  - Before production use, change the default PIV PIN (`123456`), PUK (`12345678`), and Management Key.
  - Provisioning slot `0x9D` with `TOUCH_POLICY_ALWAYS` prevents processes inside a remote RDP session from silently invoking your redirected smart card without physical finger touch.
  - Optionally provisioning an on-card `ECC P-256` (`PIN=NEVER`) key in PIV slot **`0x9E` (`Card Authentication`)** automatically activates **Pre-PIN Hardware Anti-Phishing** during enrollment, challenging `0x9E` dynamically *before* sending a single byte of your PIN or PUK.
