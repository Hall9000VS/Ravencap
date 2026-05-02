# Ravencap

Streaming encrypted archive tool for files, folders, and Unix-style pipelines.

## Status

This repository contains the first working Ravencap implementation slice: a Phase 0.5 age streaming compatibility gate plus a real CLI for passphrase-based `pack`, `encrypt`, and `decrypt` flows.

## Usage

```sh
ravencap encrypt --passphrase "test" -i payload.ravp -o payload.rav
ravencap decrypt --passphrase "test" -i payload.rav -o payload.ravp
ravencap pack --passphrase "test" ./folder -o folder.rav
```

Omit `-i` or `-o` on `encrypt`/`decrypt` to use stdin or stdout. Omit `--passphrase` to be prompted, or use `--passphrase-file` for scripted local tests.

## Workspace

- `crates/ravencap-cli`: CLI binary surface.
- `crates/ravencap-core`: high-level APIs for encrypt/decrypt/pack/unpack.
- `crates/ravencap-format`: RAVP payload constants, prelude, manifest, parser.
- `crates/ravencap-testkit`: shared fixtures and helpers.

## Immediate Next Steps

1. Add public-key recipient and identity support.
2. Implement extraction for RAVP tar payloads.
3. Turn the placeholder docs into full v1.0 product documentation.
