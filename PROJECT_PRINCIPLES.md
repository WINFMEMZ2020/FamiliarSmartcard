# FamiliarSmartcard Project Principles

1. **UI language is English only.**
   - All user-visible strings, labels, status text, error messages, logon UI text, and diagnostic output must be English.
   - No Chinese prompts may be added to the Credential Provider, enrollment GUI, CLI output, or runtime error paths.
   - Design documents may remain bilingual/Chinese; this rule applies to shipped UI and runtime messages.

2. **Fail closed.**
   - Any authentication, card, vault, or KERB error terminates the current attempt.
   - No automatic retry, no auto-logon, no default credential provider.

3. **No card, no password.**
   - The vault must never contain material that can recover the Windows password without the enrolled PIV smart card.
   - `Eph_Priv_enroll` is never persisted.

4. **Freshness before unwrap.**
   - A fresh ECDH challenge must succeed before the static `Eph_Pub_enroll` unwrap.

5. **Never lock the user out.**
   - Keep the native Windows password provider available.
   - Do not change the real account password before card self-test and recovery-sheet verification.

6. **Protect LogonUI.**
   - PC/SC work must not block the LogonUI STA indefinitely; use an isolated helper or a tested watchdog.

7. **No secrets in logs.**
   - Never log PINs, passwords, DEKs, KEKs, shared secrets, or decrypted credentials.
