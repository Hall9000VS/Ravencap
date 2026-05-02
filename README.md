# Ravencap

Streaming encrypted archive tool for files, folders, and Unix-style pipelines.

## Status

This repository contains the first working Ravencap implementation slice: a Phase 0.5 age streaming compatibility gate plus a real CLI for passphrase-based `pack`, `encrypt`, and `decrypt` flows.

## Usage

Password mode:

```sh
ravencap encrypt --passphrase "test" -i payload.ravp -o payload.rav
ravencap decrypt --passphrase "test" -i payload.rav -o payload.ravp
ravencap pack --passphrase "test" ./folder -o folder.rav
```

Public-key mode:

```sh
ravencap keygen -o alice.ravkey
ravencap pubkey alice.ravkey -o alice.ravpub
ravencap encrypt -r $(cat alice.ravpub) -i payload.ravp -o payload.rav
ravencap decrypt --identity alice.ravkey -i payload.rav -o payload.ravp
```

Omit `-i` or `-o` on `encrypt`/`decrypt` to use stdin or stdout. Omit `--passphrase` to be prompted, or use `--passphrase-file` for scripted local tests.

Managed `-o` writes are committed through a temporary file in the same directory. Existing output paths are preserved unless `--overwrite` is provided.

## Workspace

- `crates/ravencap-cli`: CLI binary surface.
- `crates/ravencap-core`: high-level APIs for encrypt/decrypt/pack/unpack.
- `crates/ravencap-format`: RAVP payload constants, prelude, manifest, parser.
- `crates/ravencap-testkit`: shared fixtures and helpers.

## Immediate Next Steps

The full v1.0 closure roadmap is tracked in [docs/v1-closure-plan.md](docs/v1-closure-plan.md).

1. Keep CI green on every push.
2. Implement archive pack/unpack with safe paths and zstd TAR payloads.
3. Complete `info`, `inspect`, and `verify` semantics.
