# RustyArchive Format Notes

RustyArchive archives use a standard age-compatible outer file. The decrypted plaintext begins with an RAVP prelude followed by a manifest prefix and a content stream.

## Planned Payload Structure

- magic: `RAVP\0`
- payload version: `1`
- payload type: raw stream or tar archive
- compression: none or zstd
- manifest length: little-endian `u64`
- manifest bytes
- content stream bytes

The `rustyarchive-format` crate contains the initial constants and structs for this layer.
