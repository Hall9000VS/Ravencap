# Ravencap Format Notes

Ravencap `.rav` files use a standard age-compatible outer file. The decrypted plaintext begins with an RAVP prelude followed by a manifest prefix and a content stream.

The age layer provides recipient handling, passphrase/public-key encryption, and stream authentication. Ravencap adds payload semantics after age decryption; it does not define a new outer encryption format.

## RAVP Layout

```text
.rav file
└── standard age file encryption format
    └── decrypted RAVP plaintext
        ├── prelude, 16 bytes
        ├── manifest JSON, manifest_length bytes
        └── content stream
```

## Prelude Fields

- magic: `RAVP\0`
- payload version: `1`
- payload type: `1` for raw stream, `2` for TAR archive
- compression: `0` for none, `1` for zstd
- manifest length: little-endian `u64`, capped at 8 MiB

Unknown versions, payload types, compression codes, truncated preludes, and oversized manifests are rejected.

## Manifest Format

The manifest is UTF-8 JSON with this top-level shape:

```json
{
  "version": 1,
  "path_encoding": "utf-8-nfc-forward-slash",
  "entries": []
}
```

Archive entries are tagged by `type`:

```json
{ "type": "directory", "path": "project" }
{ "type": "file", "path": "project/README.md", "size": 25, "sha256": "...64 lowercase hex chars..." }
{ "type": "symlink", "path": "project/latest", "target": "README.md" }
```

Raw stream payloads use an empty manifest. TAR archive payloads use directory, file, and symlink entries. File entries include the uncompressed size and SHA-256 digest of the file bytes.

## Payload Types And Compression

- Raw stream payloads (`payload_type = 1`) carry uninterpreted bytes and must use compression `none`.
- TAR archive payloads (`payload_type = 2`) carry a TAR stream and use zstd by default when produced by `ravencap pack`.
- Full archive verification currently supports uncompressed and zstd-compressed TAR archive payloads.

## Path Policy

Archive paths are normalized to UTF-8 NFC and forward slashes when packing. Validation rejects:

- empty paths or empty components,
- absolute paths,
- `.` and `..` components,
- backslashes, colons, and NUL bytes,
- Windows drive-like paths,
- Windows reserved component names such as `CON`, `NUL`, `COM1`, and `LPT1`,
- components ending in a space or dot,
- duplicate normalized archive paths.

Symlink targets must be relative, UTF-8 NFC, and must resolve inside the same archive root. A symlink target must resolve to a manifest file or directory entry, not another symlink.

The `ravencap-format` crate contains the public constants and parser types for this layer. `ravencap-core` applies archive semantic validation during packing, unpacking, and full verification.

## Trust-Model Commands

- `info` is non-decrypting. It may report whether the input starts with the public age v1 header, but it must not claim anything about encrypted Ravencap payload metadata.
- `inspect` decrypts only the RAVP prelude and manifest prefix. Its human output must warn that the content stream has not been fully verified, and JSON output reports `content_stream_verified: false`.
- `verify --quick` reads and authenticates the complete outer age stream. It does not parse the archive content stream and does not verify per-file manifest checksums.
- Full `verify` reads the complete stream, parses the RAVP prelude and manifest, decompresses supported TAR archive payloads, and validates manifest sizes and SHA-256 checksums. Human and JSON output report the same mode, success state, and notes.

## Test Vectors

Small compatibility fixtures live under `tests/vectors`. They include deterministic RAVP plaintext, passphrase and public-key `.rav` archives generated with current defaults, a negative non-RAVP age plaintext fixture, and expected inspect JSON. `crates/ravencap-core/tests/test_vectors.rs` validates these fixtures in CI.

Production-profile vectors, such as large archives or external age/rage matrix runs, should be documented and run as release validation rather than on every CI pass. Use `tests/vectors/README.md` to refresh the checked-in small vectors.
