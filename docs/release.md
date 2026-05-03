# Release Checklist

Ravencap releases should make the source revision, binaries, and verification material easy to audit before users trust the tool with private archives.

## Versioning

- Use `2.0.0` or another major version for public Rust API breaks, including secret-bearing type changes and removed trait implementations.
- Use a minor version for compatible CLI or library additions.
- Use a patch version for compatible fixes and documentation-only release corrections.
- Move changelog entries out of `Unreleased` before tagging.

## Pre-Release Validation

Run these checks from a clean working tree:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo +1.88.0 check --workspace --all-targets
cargo +1.88.0 test --workspace
cargo audit -q
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins
git diff --check
```

Wait for hosted CI to pass on Ubuntu, Windows, macOS, and the MSRV job before publishing a GitHub Release.

## Release Artifacts

For each GitHub Release, attach:

- source tag and release notes matching `CHANGELOG.md`
- Linux, macOS, and Windows CLI binaries built from the tagged commit
- SHA-256 checksums for every binary archive
- a signed checksum file using cosign, minisign, or another documented signing key
- optional SBOM or cargo-auditable metadata when the packaging pipeline supports it

## Manual Binary Build

Until an automated release workflow is added, build each platform binary on the matching runner or host:

```sh
cargo build --release --locked
```

Name artifacts with the version, target OS, target architecture, and archive format, for example `ravencap-v2.0.0-windows-x86_64.zip`.

Generate checksums from the final archives:

```sh
sha256sum ravencap-v2.0.0-*.tar.gz ravencap-v2.0.0-*.zip > SHA256SUMS
```

On Windows PowerShell:

```powershell
Get-FileHash .\ravencap-v2.0.0-*.zip -Algorithm SHA256
```

## Future Automation

The preferred next step is a tag-triggered GitHub Actions release workflow that builds platform binaries, generates checksums, signs them, uploads release assets, and records provenance from the exact tag commit.