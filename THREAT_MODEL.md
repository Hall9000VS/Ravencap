# Threat Model

Ravencap is intended to provide a standard age-compatible encrypted envelope around a streaming Ravencap payload.

## Assets

- Plaintext file, folder, and pipeline contents.
- Passphrases and age secret-key identity files supplied to the CLI or library.
- Archive manifests and file metadata after decryption.
- Output paths written by managed `-o` commands and archive extraction.

## Attacker Model

Ravencap is designed for attackers who can read or modify stored `.rav` files, provide malformed encrypted inputs, or attempt archive path traversal during extraction. It also assumes normal local filesystem errors, interrupted commands, and accidental output-path reuse.

Ravencap does not assume it can protect secrets on a compromised live machine, against a malicious administrator, or against a local attacker who can concurrently modify the extraction parent directory.

## Protects Against

- unauthorized plaintext access without a valid recipient identity or password,
- encrypted stream tampering detected by the age layer,
- path traversal during archive extraction,
- accidental partial file replacement when using managed `-o` outputs.

## Protected Scenarios

- A `.rav` file copied through untrusted storage remains encrypted until decrypted with a valid passphrase or age identity.
- A modified age stream fails authentication before Ravencap accepts decrypted content.
- A Ravencap archive with traversal paths, absolute paths, duplicate manifest paths, invalid UTF-8 paths, or unsafe symlink targets is rejected before the final extraction output is committed.
- `inspect` can report manifest metadata without claiming that file content hashes were verified.
- Full `verify` authenticates the age stream and validates supported TAR archive payloads against the manifest.

## Non-Goals

- snapshot or retention management,
- cloud storage or sync,
- deduplication,
- concurrent attacker control of the extraction destination,
- arbitrary third-party plugin trust,
- recovery from lost passphrases or private keys,
- protection from shell history, process inspection, malware, keyloggers, or malicious administrators.

## Age And Plugin Assumptions

Ravencap relies on the age implementation for the outer file format, recipient handling, passphrase encryption, public-key encryption, and stream authentication. A standard age-compatible tool can decrypt a `.rav` file into RAVP plaintext, but it will not understand Ravencap archive semantics.

The Ravencap CLI directly supports passphrases and age secret-key identity files. Hardware-backed or plugin-backed age workflows should use age/rage tooling to decrypt to RAVP plaintext unless direct plugin support is added later. Trust in those plugins is outside Ravencap's current boundary.

## Path Traversal And Symlink Risks

Archive paths are required to be relative UTF-8 NFC forward-slash paths. Ravencap rejects absolute paths, traversal components, Windows drive-like syntax, reserved names, trailing dot/space components, NUL bytes, and duplicate normalized paths.

Symlink entries are accepted only when their target is relative, stays inside the same top-level archive root component after resolving `.` and `..`, and resolves to a file or directory manifest entry. Symlink-to-symlink targets are rejected. Multi-root archive symlink traversal across top-level components is intentionally unsupported in v1 format semantics.

## Archive Extraction Limitations

Ravencap validates archive paths, rejects traversal and unsafe symlink targets, extracts to a temporary output directory first, and commits the directory only after manifest and content verification succeeds.

This does not fully protect against a local attacker who can concurrently modify the parent output directory during extraction or final rename. Callers should extract into a directory they control and should not share the extraction parent with untrusted writers.

Managed `-o` file outputs are written through same-directory temporary files. Shell redirection is not managed by Ravencap and may leave partial files if the shell creates the destination before a failing command completes. Raw streaming decrypt can emit plaintext before the final age authentication check succeeds at EOF; callers that need all-or-nothing files should use managed `-o` output or verify first.

## Temporary Plaintext During Unpack

During archive unpack, Ravencap writes decrypted file bytes into a temporary directory before the per-file manifest SHA-256 check has completed. These bytes come from the authenticated age stream, but they have not yet been accepted as matching the Ravencap manifest.

If verification fails, Ravencap does not commit the temporary directory to the requested output path and relies on temporary-directory cleanup. Ravencap does not guarantee forensic erasure of temporary plaintext from journaling filesystems, snapshots, swap, crash recovery, or storage-level remnants.

## Pack Input Consistency

Archive packing reads file metadata and hashes for the manifest before writing the TAR payload. If the source tree changes while packing is in progress, the command can produce an archive whose manifest and payload disagree. Full `verify` and `unpack` detect that mismatch, but callers should pack quiescent input trees.
