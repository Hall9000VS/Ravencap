# Changelog

## Unreleased

## 2.0.1 - 2026-05-03

- Rejected archive file entries as soon as their streamed size exceeds the manifest size, before writing the oversized chunk to unpack output.
- Required unpack output parent directories to exist before temporary extraction begins.
- Rejected source filesystem path components and TAR entry paths containing backslashes instead of silently converting them to forward slashes.
- Expanded Windows reserved-name rejection to include `COM0`, `LPT0`, `CONIN$`, and `CONOUT$`.
- Split macOS release artifacts into explicitly labeled x86_64 and arm64 builds.
- Documented unpack temporary plaintext limitations, stricter top-level symlink semantics, and metadata that Ravencap does not preserve.

## 2.0.0 - 2026-05-03

### Breaking

- Changed secret-bearing public API variants to store `SecretString`: `Recipient::Passphrase`, `Identity::Passphrase`, and `Identity::PrivateKey` no longer expose plain `String` values.
- Removed `Clone`, `PartialEq`, and `Eq` implementations from secret-bearing public option and identity types.
- Raised the declared Rust MSRV from 1.85 to 1.88.

### Security and Hardening

- Store core passphrases and private identity text in `SecretString` with redacted `Debug` output instead of plain public `String` fields.
- Reduced internal `SecretString` cloning by consuming owned recipient and identity values during age conversion.
- Removed `Debug` derivations from CLI argument structs that can contain `--insecure-passphrase-cli` values.
- Made `inspect` apply manifest policy validation before reporting manifest counts.
- Documented streaming decrypt plaintext emission before final EOF authentication and the requirement to pack quiescent input trees.
- Added CI coverage for the declared Rust 1.88 MSRV and set workflow permissions to read-only contents.

## 1.0.2 - 2026-05-03

- Restored the v1.0.0 and v1.0.1 changelog entries after a post-release documentation regression.
- Restored archive manifest, unpack, verify, NFC normalization, and symlink regression tests that were accidentally removed after v1.0.1.
- Converted the fuzz targets from stdin corpus replay binaries into cargo-fuzz/libFuzzer harnesses.
- Documented the Windows MSVC sanitizer runtime setup needed for local cargo-fuzz runs.
- Kept unpack temporary-directory cleanup active if the final output-directory rename fails after verification.
- Made RAVP prelude parsing reject unknown payload types, unknown compression codes, and unsupported payload/compression combinations directly.
- Aligned `PackOptions::default()` with the documented archive zstd default and removed misleading raw-stream compression, prompt, and lossy option-conversion APIs from the core API.
- Added README release, build, and security-status polish plus stronger cargo-deny source and duplicate-version policy.

## 1.0.1 - 2026-05-02

- Fixed archive manifest `path_encoding` to the v1 canonical `utf-8-nfc-forward-slash` value.
- Accepted standard age identity files with comment lines when deriving public keys or decrypting.
- Rejected `.` as a whole symlink target and added a regression test.
- Avoided creating a missing unpack parent directory before archive authentication and verification succeeds.
- Replaced inline `--passphrase` CLI usage with `--passphrase-file`, prompt mode, or explicit `--insecure-passphrase-cli` for controlled tests.

## 1.0.0 - 2026-05-02

- Initialized the Ravencap workspace, crate layout, docs skeleton, and CI scaffold.
- Added standard age X25519 key generation, public-key export, and public-key encrypt/decrypt flows.
- Added managed `-o` output through same-directory temporary files with `--overwrite` protection.
- Implemented the `info` command as a non-decrypting public age header check.
- Implemented `verify --quick` to authenticate the full outer age stream without manifest or checksum verification.
- Implemented `inspect` human and JSON output for the decrypted RAVP prelude and manifest prefix.
- Applied the archive-mode zstd default to packed TAR payload streams.
- Added full archive manifest entries for directories and regular files with sizes and SHA-256 hashes.
- Implemented safe archive unpack for regular files, directories, and safe relative symlinks.
- Added full archive verification for supported TAR archive payloads with manifest size and SHA-256 checks.
- Added `verify --json` for quick and full verification reports.
- Tightened archive path validation with UTF-8 NFC normalization, traversal rejection, Windows reserved-name rejection, and safe symlink target resolution.
- Stabilized the `ravencap-core` public API around top-level functions and option/report types.
- Added library integration tests, malicious input regression tests, standalone fuzz harnesses, seed corpora, and small v1 test vectors.
- Added optional age/rage interop smoke validation script for checked-in public-key vectors.
- Expanded release documentation for format semantics, trust-model commands, output safety, examples, threat model, and limitations.
