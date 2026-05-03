# ravencap-format

Format types and parsers for Ravencap encrypted archive payloads.

This crate contains the stable RAVP format constants, manifest data structures, and prelude parsing helpers used by the Ravencap CLI and core library. It is intentionally small and does not perform encryption or filesystem extraction.

A `.rav` file is an age-encrypted file. After age decryption, the plaintext begins with a Ravencap payload stream:

1. 16-byte RAVP prelude
2. JSON manifest prefix
3. content stream

## Usage

```rust
use ravencap_format::{parse_prelude_prefix, RAVP_MAGIC, RAVP_VERSION};

let bytes = [
    b'R', b'A', b'V', b'P', 0,
    RAVP_VERSION,
    0, 0,
    0, 0, 0, 0, 0, 0, 0, 2,
];

let prelude = parse_prelude_prefix(&bytes)?;
assert_eq!(prelude.magic, *RAVP_MAGIC);
assert_eq!(prelude.manifest_len, 2);
# Ok::<(), ravencap_format::FormatError>(())
```

## Format Documentation

The file format is documented in the Ravencap repository:

- `FORMAT.md`
- `docs/file-format-v1.md`

## Security Note

This crate parses format metadata only. It does not authenticate encrypted data by itself; authentication is provided by the age envelope used by `ravencap-core` and the `ravencap` CLI.

## License

MIT
