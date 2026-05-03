# Changelog

## Unreleased

- Restored the v1.0.0 and v1.0.1 changelog entries after a post-release documentation regression.
- Restored archive manifest, unpack, verify, NFC normalization, and symlink regression tests that were accidentally removed after v1.0.1.
- Converted the fuzz targets from stdin corpus replay binaries into cargo-fuzz/libFuzzer harnesses.
- Documented the Windows MSVC sanitizer runtime setup needed for local cargo-fuzz runs.
- Kept unpack temporary-directory cleanup active if the final output-directory rename fails after verification.
- Made RAVP prelude parsing reject unknown payload types and compression codes directly.
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
