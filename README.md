# Ravencap

[![CI](https://github.com/Hall9000VS/Ravencap/actions/workflows/ci.yml/badge.svg)](https://github.com/Hall9000VS/Ravencap/actions/workflows/ci.yml)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-93450a)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.2-informational)](CHANGELOG.md)

Streaming encrypted archive tool for files, folders, and Unix-style pipelines.

## Status

This repository contains Ravencap v1.0.2: age-compatible streaming encryption, archive pack/unpack, and trust-model commands for public info, manifest inspection, and quick/full verification.

Security status: Ravencap is an experimental personal project and has not been independently audited.

Copyright (c) 2026 VaV Labs.

A `.rav` file is a standard age-encrypted file. After age decryption, the plaintext begins with a Ravencap RAVP stream: a small prelude, a JSON manifest prefix, and the content stream.

Ravencap is focused on encrypted files, folders, and pipelines. It does not manage snapshots, retention, scheduling, deduplication, sync, cloud storage, or repositories.

## Quick Start

```sh
ravencap pack --passphrase-file passphrase.txt ./folder -o folder.rav
ravencap verify folder.rav --passphrase-file passphrase.txt
ravencap unpack folder.rav --passphrase-file passphrase.txt -o restored-folder
```

## Install / Build From Source

Install Rust 1.85 or newer from `https://rustup.rs/`, then build the CLI from this repository:

```sh
cargo build --release
```

The binary is written to `target/release/ravencap` on Unix-like systems and `target\release\ravencap.exe` on Windows. In PowerShell, run the local binary with an explicit current-directory prefix:

```powershell
.\target\release\ravencap.exe --help
```

## Usage

Password mode:

```sh
ravencap encrypt --passphrase-file passphrase.txt -i payload.ravp -o payload.rav
ravencap decrypt --passphrase-file passphrase.txt -i payload.rav -o payload.ravp
ravencap pack --passphrase-file passphrase.txt ./folder -o folder.rav
ravencap unpack folder.rav --passphrase-file passphrase.txt -o restored-folder
```

Public-key mode:

```sh
ravencap keygen -o alice.ravkey
ravencap pubkey alice.ravkey -o alice.ravpub
ravencap encrypt -r $(cat alice.ravpub) -i payload.ravp -o payload.rav
ravencap decrypt --identity alice.ravkey -i payload.rav -o payload.ravp
ravencap pack -r $(cat alice.ravpub) ./folder -o folder.rav
ravencap unpack folder.rav --identity alice.ravkey -o restored-folder
```

Use `--passphrase-file` for scripted local tests where prompting is not practical. Omit passphrase options to use the interactive prompt. Private-key identity files passed with `--identity` are read as age secret keys, including standard age identity files with comment lines.

Age/rage interop:

```sh
age -d -i alice.ravkey folder.rav > folder.ravp
rage -d -i alice.ravkey folder.rav > folder.ravp
ravencap decrypt --identity alice.ravkey -i folder.rav -o folder.ravp
```

These commands are equivalent at the encryption layer: they produce decrypted RAVP bytes. Standard age-compatible tools do not parse Ravencap manifests or unpack Ravencap archives. Use `ravencap inspect`, `ravencap verify`, or `ravencap unpack` for RAVP semantics.

Hardware-key and plugin note: `.rav` files use the age file format, so external age/rage tooling may be used for plugin-backed decryption to RAVP plaintext. The Ravencap CLI currently supports passphrases and age secret-key identity files directly; it does not invoke age plugins itself.

Public metadata check:

```sh
ravencap info payload.rav
ravencap inspect payload.rav --passphrase-file passphrase.txt
ravencap inspect payload.rav --passphrase-file passphrase.txt --json
ravencap verify --quick payload.rav --passphrase-file passphrase.txt
ravencap verify payload.rav --passphrase-file passphrase.txt
ravencap verify payload.rav --passphrase-file passphrase.txt --json
```

`info` only checks the public age header. `inspect` decrypts the RAVP prelude and manifest prefix, but does not verify the content stream. `verify --quick` authenticates the full outer age stream without archive semantics. Full `verify` authenticates the age stream, parses/decompresses the TAR payload, and validates manifest checksums.

Stdin/stdout raw stream usage:

```sh
ravencap encrypt --passphrase-file passphrase.txt < payload.ravp > payload.rav
ravencap decrypt --passphrase-file passphrase.txt < payload.rav > payload.ravp
```

Omit `-i` or `-o` on `encrypt`/`decrypt` to use stdin or stdout. Use `-` as the archive input path for commands such as `inspect`, `verify`, and `unpack` when reading from stdin. Omit passphrase options to be prompted. `--insecure-passphrase-cli` exists only for controlled tests and prints a warning because command-line secrets can appear in process listings and shell history.

## Output Safety

Managed `-o` writes are committed through a temporary file in the same directory. Existing output paths are preserved unless `--overwrite` is provided. This protects command-managed outputs from accidental replacement and avoids committing partial files when Ravencap returns an error.

Shell redirection is controlled by the shell, not Ravencap. Commands such as `ravencap decrypt ... > output` can leave partial files if interrupted or if the command fails after the shell creates the destination.

Archive unpack extracts to a temporary directory beside the requested output and renames it into place only after manifest and content verification succeeds. The requested output directory must not already exist.

## Security Notes And Limitations

- Ravencap relies on the age layer for encryption, recipient handling, and stream authentication.
- Losing a passphrase or private key means Ravencap cannot recover the plaintext.
- Compromised machines, malicious administrators, keyloggers, and unsafe shell history can expose secrets before Ravencap sees them.
- Archive paths are UTF-8, NFC-normalized, forward-slash relative paths. Absolute paths, traversal, Windows drive-like paths, reserved names, and unsafe symlink targets are rejected.
- Symlinks are restored only when the target stays inside the archive root and resolves to a file or directory entry in the manifest.
- Extraction should happen in a parent directory controlled by the caller. Ravencap does not fully defend against a concurrent local attacker modifying the extraction parent during the final rename.
- `inspect` is intentionally a partial read and must not be treated as content verification. Use full `verify` before trusting archive contents.

## Test Vectors And Examples

Small compatibility fixtures live in `tests/vectors` and are validated by `cargo test --workspace`. A simple non-technical user guide is in [docs/user-guide.md](docs/user-guide.md), more command examples are in [docs/examples.md](docs/examples.md), and the v1 format is described in [docs/file-format-v1.md](docs/file-format-v1.md).

## Workspace

- `crates/ravencap-cli`: CLI binary surface.
- `crates/ravencap-core`: high-level APIs for encrypt/decrypt/pack/unpack.
- `crates/ravencap-format`: RAVP payload constants, prelude, manifest, parser.
- `crates/ravencap-testkit`: shared fixtures and helpers.
- `tests/vectors`: small format-stable compatibility fixtures.

## Library API

`ravencap-core` exposes the v1 stable surface through top-level functions and option/report types: `encrypt_stream`, `decrypt_stream`, `pack_path`, `unpack_archive`, `read_public_info`, `inspect_manifest`, `verify_archive`, key helpers, and their associated options. Archive implementation modules are internal; manifest data types and path validators remain public for documented archive policy checks.

## Immediate Next Steps

The full v1.0 closure roadmap is tracked in [docs/v1-closure-plan.md](docs/v1-closure-plan.md).

1. Keep CI green on every push.
2. Run release-candidate checks from the closure plan.
3. Keep docs aligned with tested CLI behavior.
