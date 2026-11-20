# FamiliarSmartcard

Windows local-account login/unlock via an RS-Key PIV 9D P-256 key and a
custom Credential Provider.

## Principles

See `PROJECT_PRINCIPLES.md`. All UI and runtime messages are English.

## Layout

- `crates/scard-core` — PC/SC, PIV APDU, vault format, DPAPI, Typestate.
- `crates/cred-provider` — Windows Credential Provider DLL.
- `crates/enroll-gui` — native Win32 probe/enrollment/self-test GUI.
- `ARCHITECTURE_AND_PLAN.md` — v2.1 design.
- `SECURITY_AUDIT.md`, `PLAN_V2_1_PATCH.md`, `PLAN_V2_1_REVIEW.md` — audits.

## Build

```powershell
cargo build --workspace
cargo test -p scard-core
```

Headless probe (useful over RDP or in the test VM):

```powershell
cargo run -p enroll-gui -- --probe
```

Card-only crypto self-test (no registry write, no Windows password change):

```powershell
cargo run -p enroll-gui -- --card-selftest <PIV-PIN>
```

Enrollment GUI (must be elevated so it can write HKLM):

```powershell
Start-Process .\target\debug\familiar-enroll.exe -Verb RunAs
```

Enter the PIV PIN and the current Windows password, click `Bind current account`,
then `Self-test`.

Release Credential Provider:

```powershell
cargo build --release -p cred-provider
```

The DLL is `target\release\cred_provider.dll`.

## Prerequisites

1. RS-Key PIV 9D must contain an on-card P-256 key with PIN policy `ALWAYS`.
2. `SCardSvr` must be running on the target machine.
3. The target account must be a local Workgroup account.
4. The GUI must be run elevated to write `HKLM`.

Provisioning is complete when `Slot 0x9D: key present` appears in the probe
output. The development card has a 9D P-256 key with PIN policy `ALWAYS` and
touch policy `NEVER`; it still uses the **default development PIN**. Change the
PIN/PUK/management key before any real use.

## Current limitations

- The GUI binds the **existing** Windows password; random-password rotation and
  the two-phase recovery-sheet flow are not wired yet.
- The development card uses the default PIN. Production provisioning must also
  rotate PIN/PUK/management key, remove `--protect`, and pin `f9` attestation.
- The Credential Provider currently uses the synchronous PC/SC path in
  `GetSerialization`; the isolated helper/timeout process is designed in the
  plan but not implemented yet.
- `f9` attestation verification is not implemented in the GUI yet.

## Register the Credential Provider

Run an elevated PowerShell:

```powershell
.\scripts\register_cp.ps1
```

Unregister/rescue:

```powershell
.\scripts\unregister_cp.ps1
# or import the rescue .reg file
```

Do not expose RDP port 3389 without VPN/firewall isolation when NLA is disabled.
