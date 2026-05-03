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

## Automated Release

Pushing a signed or reviewed tag named `v*` runs the release workflow in `.github/workflows/release.yml`.

The workflow:

- builds release binaries with `cargo build --release --locked`
- packages Linux x86_64, macOS x86_64, macOS arm64, and Windows x86_64 archives
- generates a `SHA256SUMS` file for the archives
- signs `SHA256SUMS` with keyless cosign and uploads the signature plus bundle
- creates GitHub artifact attestations from the checksum file
- creates the GitHub Release from the tag and changelog section

The release workflow uses pinned GitHub Actions and requires `contents: write`, `id-token: write`, and `attestations: write` permissions.

## Release Artifacts

For each GitHub Release, attach:

- source tag and release notes matching `CHANGELOG.md`
- Linux, macOS, and Windows CLI binaries built from the tagged commit, with macOS x86_64 and macOS arm64 artifacts labeled separately
- SHA-256 checksums for every binary archive
- `SHA256SUMS.sig` and `SHA256SUMS.cosign.bundle` for keyless cosign verification
- GitHub artifact attestations for the checksummed release archives
- optional SBOM or cargo-auditable metadata when the packaging pipeline supports it

Verify checksums after downloading the release assets:

```sh
sha256sum -c SHA256SUMS
```

Verify the checksum signature with cosign keyless identity constraints:

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/Hall9000VS/Ravencap/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify GitHub artifact attestations:

```sh
gh attestation verify ravencap-v2.0.1-linux-x86_64.tar.gz --repo Hall9000VS/Ravencap
gh attestation verify ravencap-v2.0.1-macos-x86_64.tar.gz --repo Hall9000VS/Ravencap
gh attestation verify ravencap-v2.0.1-macos-arm64.tar.gz --repo Hall9000VS/Ravencap
gh attestation verify ravencap-v2.0.1-windows-x86_64.zip --repo Hall9000VS/Ravencap
```

## Manual Binary Build

If the automated workflow is unavailable, build each platform binary on the matching runner or host:

```sh
cargo build --release --locked
```

Name artifacts with the version, target OS, target architecture, and archive format, for example `ravencap-v2.0.1-windows-x86_64.zip`.

Generate checksums from the final archives:

```sh
sha256sum ravencap-v2.0.1-*.tar.gz ravencap-v2.0.1-*.zip > SHA256SUMS
```

On Windows PowerShell:

```powershell
Get-FileHash .\ravencap-v2.0.1-*.zip -Algorithm SHA256
```

## Future Automation

The next release hardening step is to add SBOM generation or cargo-auditable metadata to the published binary archives.
