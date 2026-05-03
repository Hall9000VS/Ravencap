# ravencap-core

Core library for Ravencap encrypted archive and stream workflows.

This crate provides the high-level Rust API behind the `ravencap` command-line tool. It handles age-compatible encryption and decryption, archive packing and unpacking, manifest inspection, verification, and conservative path validation.

## Capabilities

- Encrypt and decrypt raw streams with passphrases or age public keys.
- Pack files and directories into encrypted `.rav` archives.
- Unpack archives only after authentication and verification succeed.
- Inspect archive manifests without writing payload content.
- Run quick or full verification over encrypted archives.
- Reject unsafe archive paths, duplicate normalized paths, traversal, reserved names, and unsafe symlink targets.

## Usage

Encrypt a stream with a passphrase:

```rust
let plaintext = b"secret payload";
let mut encrypted = Vec::new();

ravencap_core::encrypt_stream(
    plaintext.as_slice(),
    &mut encrypted,
    ravencap_core::EncryptOptions::new()
        .recipient(ravencap_core::Recipient::passphrase("correct horse battery staple")),
)?;
# Ok::<(), ravencap_core::RavencapError>(())
```

Pack and unpack an archive:

```rust
let input_path = std::path::Path::new("folder");
let output_dir = std::path::Path::new("restored-folder");
let mut archive = Vec::new();

ravencap_core::pack_path(
    input_path,
    &mut archive,
    ravencap_core::PackOptions::new()
        .recipient(ravencap_core::Recipient::passphrase("correct horse battery staple")),
)?;

ravencap_core::unpack_archive(
    archive.as_slice(),
    output_dir,
    ravencap_core::UnpackOptions::new()
        .identity(ravencap_core::Identity::passphrase("correct horse battery staple")),
)?;
# Ok::<(), ravencap_core::RavencapError>(())
```

## Security Model

Ravencap uses the standard age file format for encryption, recipient handling, and stream authentication. The decrypted plaintext is a RAVP payload containing a manifest and content stream. Archive extraction is designed to avoid committing partial output before authentication, manifest checks, and content verification succeed.

Ravencap has not undergone an independent third-party security audit.

## Related Crates

- `ravencap-format`: RAVP constants, manifest types, and parser helpers.
- `ravencap-cli`: command-line interface.
- `ravencap-testkit`: shared test fixtures and helpers.

## License

MIT
