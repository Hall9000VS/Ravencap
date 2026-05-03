# File Format v1

Ravencap v1 stores a Ravencap payload inside a standard age-compatible encrypted file. The outer `.rav` bytes are an age file. The plaintext produced by age decryption is an RAVP stream.

```text
.rav file
└── standard age file encryption format
    └── decrypted RAVP plaintext
        ├── prelude, 16 bytes
        ├── manifest JSON, manifest_length bytes
        └── content stream
```

The age layer provides encryption, recipient handling, passphrase handling, and stream authentication. Ravencap defines only the plaintext payload semantics after age decryption.

## Prelude

The RAVP prelude is 16 bytes:

| Field | Size | Value |
| --- | ---: | --- |
| magic | 5 bytes | `RAVP\0` |
| payload version | 1 byte | `1` |
| payload type | 1 byte | `1` raw stream, `2` TAR archive |
| compression | 1 byte | `0` none, `1` zstd |
| manifest length | 8 bytes | little-endian `u64`, maximum 8 MiB |

Parsers reject truncated preludes, invalid magic, unsupported versions, unknown payload types, unknown compression codes, and manifest lengths above the maximum.

## Manifest

The manifest is UTF-8 JSON immediately after the prelude. It has this top-level shape:

```json
{
  "version": 1,
  "path_encoding": "utf-8-nfc-forward-slash",
  "entries": []
}
```

Supported entry variants are:

```json
{ "type": "directory", "path": "project" }
{ "type": "file", "path": "project/README.md", "size": 25, "sha256": "...64 lowercase hex chars..." }
{ "type": "symlink", "path": "project/latest", "target": "README.md" }
```

Raw stream payloads use an empty manifest. TAR archive payloads include one entry per directory, regular file, and safe relative symlink. File hashes are SHA-256 of the uncompressed file bytes.

## Content Streams

- `payload_type = 1`: raw bytes with compression `none`. Ravencap does not interpret the content stream.
- `payload_type = 2`: TAR archive. `ravencap pack` uses zstd by default for archive payloads.

Full archive verification supports uncompressed and zstd-compressed TAR archive streams. It parses the TAR stream and checks that every entry matches the manifest type, size, and file digest expectations.

## Archive Path Policy

Archive paths are relative UTF-8 strings normalized to NFC with forward slashes. Validation rejects:

- empty paths or empty path components,
- absolute paths,
- `.` and `..` components,
- backslashes, colons, and NUL bytes,
- Windows drive-like syntax,
- reserved Windows component names such as `CON`, `PRN`, `AUX`, `NUL`, `COM1`, and `LPT1`,
- components ending in a space or dot,
- duplicate normalized paths.

Symlink targets are also UTF-8 NFC relative paths. A symlink target must stay inside the same top-level archive root component after resolving `.` and `..`, and it must resolve to a file or directory manifest entry. Multi-root archive symlink traversal across top-level components is intentionally unsupported in v1 format semantics.

Ravencap restores file contents, directories, and safe relative symlinks. It does not preserve ownership, group, mtime, permissions, setuid/setgid bits, ACLs, or extended attributes. Restored regular files are created according to the current platform defaults and process umask.

## Command Semantics

- `info` reads the public age header only. It does not decrypt and does not claim encrypted Ravencap metadata.
- `inspect` decrypts the prelude and manifest prefix. Human output includes the content-stream warning; JSON output sets `content_stream_verified` to `false`.
- `verify --quick` authenticates the full outer age stream but does not parse archive semantics.
- Full `verify` authenticates the age stream, parses the RAVP header and manifest, decompresses supported archive payloads, and validates manifest checksums.

## Test Vectors

Small fixtures live in `tests/vectors` and are validated by `crates/ravencap-core/tests/test_vectors.rs`. They cover deterministic RAVP plaintext, current-default passphrase and public-key archives, negative non-RAVP age plaintext, and expected inspect JSON. Refresh instructions are in `tests/vectors/README.md`.
