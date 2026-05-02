# Ravencap Test Vectors

These fixtures make Ravencap compatibility reproducible without relying on generated data during tests.

- `raw-none.ravp`: deterministic RAVP plaintext using payload type `raw`, compression `none`, an empty manifest, and a small payload.
- `archive-default.rav`: passphrase-encrypted archive generated from `source/project` with current Ravencap defaults. Passphrase: `ravencap-test-vector`.
- `archive-public-key.rav`: public-key encrypted archive generated from `source/project` with `identity/alice.ravpub`.
- `non-ravp-age.rav`: passphrase-encrypted age file whose decrypted plaintext is not an RAVP payload. Passphrase: `ravencap-test-vector`.
- `inspect/archive-default.json`: expected inspect JSON for `archive-default.rav`.

The checked-in encrypted `.rav` files are intentionally small. Age encryption is randomized, so refreshed `.rav` bytes are expected to differ even when the decrypted RAVP payload is format-compatible.

If files under `source/project` change, refresh `archive-default.rav`, `archive-public-key.rav`, and `inspect/archive-default.json` together.

## Refresh

From the repository root:

```powershell
cargo run -p ravencap-cli -- keygen -o tests/vectors/identity/alice.ravkey --overwrite
cargo run -p ravencap-cli -- pubkey tests/vectors/identity/alice.ravkey -o tests/vectors/identity/alice.ravpub --overwrite
cargo run -p ravencap-cli -- pack --passphrase-file tests/vectors/passphrase.txt tests/vectors/source/project -o tests/vectors/archive-default.rav --overwrite
cargo run -p ravencap-cli -- pack -r (Get-Content tests/vectors/identity/alice.ravpub -Raw).Trim() tests/vectors/source/project -o tests/vectors/archive-public-key.rav --overwrite
cargo run -p ravencap-cli -- encrypt --passphrase-file tests/vectors/passphrase.txt -i tests/vectors/source/non-ravp.txt -o tests/vectors/non-ravp-age.rav --overwrite
$inspect = cargo run -p ravencap-cli -- inspect tests/vectors/archive-default.rav --passphrase-file tests/vectors/passphrase.txt --json
Set-Content tests/vectors/inspect/archive-default.json ($inspect -join [Environment]::NewLine)
```

Then run `cargo test --workspace`.

## Interop

The optional `scripts/interop-age-rage.ps1` script decrypts `archive-public-key.rav` with installed `age` and/or `rage` binaries and checks that the decrypted plaintext starts with the RAVP magic. Missing binaries are skipped.
