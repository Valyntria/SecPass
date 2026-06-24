# SecPass hardening checks

I could not run `cargo check` in the sandbox because neither `cargo`, `rustc`, nor `rustfmt` is installed here. I performed static consistency checks instead.

Static checks performed:

- Rust source files have balanced raw brace counts.
- `EncryptedBlob` no longer exposes public `salt`, `nonce`, or `ciphertext` fields.
- Crypto blob parsing validates salt length, nonce length, ciphertext/tag length, and KDF parameters before decryption.
- New crypto blob format stores Argon2id parameters and versioning metadata.
- Legacy blob parser is retained for old prototype vaults.
- Derived key and plaintext JSON buffers are wrapped with `Zeroizing` where practical.
- Vault master password is stored as `SecretString`.
- `Entry` has custom redacted `Debug` instead of derived secret-leaking `Debug`.
- Vault writes use `tempfile::NamedTempFile::persist`, fsync, and Unix `0600` permissions where possible.
- Master password minimum raised to 14 characters.
- Password generator no longer uses modulo selection.
- TOTP supports normalized raw Base32 and basic `otpauth://` URI secret extraction.
- TOTP secrets are validated before saving.
- TOTP/password/username copy uses the timed clipboard clear helper.
- New-entry password-generator modal returns to the correct `"new"` edit state.
- Added missing `rfd`, `rand_chacha`, and `tempfile` dependencies; removed unused `clipboard` dependency.

Manual follow-up still recommended on your machine:

```bash
cargo fmt
cargo check
cargo test
cargo clippy -- -D warnings
```
