# Threat Model Notes

This document expands the root `THREAT_MODEL.md` for v1 release review. It describes what Ravencap tries to protect, what it deliberately leaves outside scope, and which command guarantees are partial by design.

## Assets

- Plaintext bytes from files, folders, and stdin/stdout pipelines.
- Passphrases, passphrase files, and age secret-key identity files.
- Archive manifests, filenames, symlink targets, file sizes, and file digests after decryption.
- Managed output paths written with `-o` and archive extraction destinations.

## Attacker Capabilities

Ravencap considers inputs untrusted. An attacker may provide malformed `.rav` files, malformed RAVP plaintext after successful age authentication, malicious manifests, malicious TAR streams, traversal paths, duplicate paths, and unsafe symlink targets.

An attacker may also tamper with stored encrypted files. The age layer is expected to detect authenticated stream modification when the correct identity or passphrase is used.

Ravencap does not try to protect secrets already exposed on the local machine, secrets typed into unsafe terminals, shell history leaks, malicious administrators, compromised dependencies, or a parent extraction directory that an attacker can modify concurrently.

## Protected Scenarios

- Stored `.rav` files do not reveal plaintext without a valid passphrase or age identity.
- Tampered age streams fail authentication before Ravencap accepts decrypted content.
- Archive unpack rejects traversal paths, absolute paths, Windows drive-like paths, reserved names, duplicate paths, malformed manifests, checksum mismatches, and unsafe symlinks.
- Failed extraction does not commit the requested final output directory.
- Managed file outputs written with `-o` are protected from accidental overwrite unless `--overwrite` is supplied.

## Deliberate Non-Goals

Ravencap v1 does not provide snapshot management, retention policy, deduplication, scheduling, cloud storage, sync, repository management, or key recovery. It also does not directly invoke age plugins for hardware-backed identities.

## Age And Plugin Assumptions

The outer file format is standard age. Ravencap relies on age for encryption, recipient handling, passphrase handling, public-key handling, and authenticated stream decryption. A standard age-compatible tool can decrypt `.rav` into RAVP plaintext, but it will not inspect, verify, or unpack Ravencap archives.

Plugin-backed or hardware-backed workflows can use age/rage tooling to decrypt the outer layer to RAVP plaintext. Trust in those plugins and devices is outside Ravencap's current implementation boundary.

## Inspect And Verify Boundaries

`info` is non-decrypting and reports only public age-header compatibility. It does not identify encrypted Ravencap payload metadata.

`inspect` decrypts only enough RAVP plaintext to parse the prelude and manifest. It intentionally reports `content_stream_verified: false` because it does not read and hash file contents.

`verify --quick` authenticates the full outer age stream but does not validate archive entries or manifest checksums.

Full `verify` reads the full decrypted stream and validates supported TAR archive payloads against the manifest, including file sizes and SHA-256 hashes.

## Extraction Boundary

Ravencap extracts archive payloads into a temporary directory inside the existing parent directory of the requested output path, verifies the manifest and content stream, and then renames the temporary directory into place. The requested output directory must not already exist, and its parent directory must already exist.

This design avoids committing partial extraction output after a Ravencap error. It does not fully defend against a local attacker who can concurrently modify the parent directory during extraction or final rename. Callers should extract into a directory they control.

During archive unpack, Ravencap writes decrypted file bytes into the temporary directory before the per-file manifest SHA-256 check has completed. These bytes come from the authenticated age stream, but they have not yet been accepted as matching the Ravencap manifest. If verification fails, Ravencap does not commit the temporary directory to the requested output path and relies on temporary-directory cleanup. Ravencap does not guarantee forensic erasure of temporary plaintext from journaling filesystems, snapshots, swap, crash recovery, or storage-level remnants.

Ravencap restores file contents, directories, and safe relative symlinks. It does not preserve ownership, group, mtime, permissions, setuid/setgid bits, ACLs, or extended attributes. Restored regular files are created according to the current platform defaults and process umask.

## Shell Redirection Boundary

Managed `-o` file writes use same-directory temporary files and explicit overwrite checks. Shell redirection is outside Ravencap's control: a shell can create or truncate the destination before Ravencap starts, and interrupted redirected commands can leave partial output.
