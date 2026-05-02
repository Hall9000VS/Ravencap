# Changelog

## Unreleased

- Initialized the Ravencap workspace, crate layout, docs skeleton, and CI scaffold.
- Added standard age X25519 key generation, public-key export, and public-key encrypt/decrypt flows.
- Added managed `-o` output through same-directory temporary files with `--overwrite` protection.
- Implemented the `info` command as a non-decrypting public age header check.
- Implemented `verify --quick` to authenticate the full outer age stream without manifest or checksum verification.
- Implemented `inspect` human and JSON output for the decrypted RAVP prelude and manifest prefix.
