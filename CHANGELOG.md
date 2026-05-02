# Changelog

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
