# ravencap-cli

Command-line interface for Ravencap encrypted archive workflows.

This package installs the `ravencap` binary. Ravencap is a streaming encrypted archive tool for files, folders, and Unix-style pipelines. It uses the standard age file format as the encrypted envelope and stores Ravencap's RAVP payload inside it.

## Install

```sh
cargo install ravencap-cli
```

Then run:

```sh
ravencap --help
```

## Quick Start

```sh
ravencap pack --passphrase-file passphrase.txt ./folder -o folder.rav
ravencap verify folder.rav --passphrase-file passphrase.txt
ravencap unpack folder.rav --passphrase-file passphrase.txt -o restored-folder
```

## Commands

- `pack`: encrypt a file or directory into a `.rav` archive.
- `unpack`: authenticate, verify, and extract a `.rav` archive.
- `encrypt`: encrypt a raw RAVP payload stream.
- `decrypt`: decrypt a `.rav` file to raw RAVP payload bytes.
- `info`: inspect public age envelope metadata.
- `inspect`: decrypt and print the Ravencap manifest.
- `verify`: run quick or full archive verification.
- `keygen`: create an age identity file.
- `pubkey`: derive an age public recipient from an identity file.

## Passphrases And Recipients

Use `--passphrase-file` for scripted local workflows where prompting is not practical. Omit passphrase options to use the interactive prompt. Public-key workflows use `--recipient` for encryption and `--identity` for decryption.

The explicit `--insecure-passphrase-cli` option exists for controlled tests only. Command-line arguments may be captured by shell history, process listings, or terminal logs.

## Security Note

Ravencap is designed around conservative archive extraction and verification behavior, but it has not undergone an independent third-party security audit. Review the repository `README.md`, `SECURITY.md`, and `THREAT_MODEL.md` before relying on it for sensitive workflows.

## License

MIT
