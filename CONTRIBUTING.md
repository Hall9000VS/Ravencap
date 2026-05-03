# Contributing

## Workflow

1. Create a feature branch from `main`.
2. Keep the workspace building with `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace`.
3. Open a pull request with scope, risk, and validation notes.

## Current Focus

The repository is in v1.0 release-candidate hardening. Prefer small, isolated changes that keep the documented CLI, format, library API, and security boundaries aligned.

## Local Troubleshooting

- Run `cargo fmt --all --check` first when CI reports formatting drift.
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` before opening changes that touch Rust code.
- Run `cargo test --workspace` for the full local test suite.
- Run `cargo check --manifest-path fuzz/Cargo.toml --bins` when touching fuzz harnesses or parser/path validation code.
- When `cargo-fuzz` and the nightly sanitizer runtime are available, run the checked-in fuzz corpora with the commands in `fuzz/README.md`.
- CI installs `cargo-audit` and `cargo-deny`; local runs need those tools installed before `cargo audit` or `cargo deny check` will work.
- The optional `scripts/interop-age-rage.ps1` check skips missing `age` or `rage` binaries.
