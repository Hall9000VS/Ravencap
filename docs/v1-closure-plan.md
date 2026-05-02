# Ravencap v1.0 Closure Plan

This plan tracks the remaining work needed to close Ravencap v1.0 against the product scope through the final scope statement in section 22 of the specification.

## Current Baseline

Already in place:

- Cargo workspace and crate layout.
- Ravencap CLI binary and core library crates.
- Standard age passphrase encryption and decryption.
- Standard age X25519 key generation, public-key export, public-key encryption, and identity decryption.
- RAVP prelude constants, parser, and writer.
- Basic raw stream and pack encryption paths.
- Cross-platform CI scaffold with format, clippy, test, audit, and deny jobs.
- Initial README, format notes, threat model, security, changelog, and fuzz target placeholders.

Known incomplete areas:

- Full archive unpack is not implemented.
- Archive mode does not yet build a complete manifest for every entry.
- Archive mode does not yet apply zstd compression by default.
- Managed `-o` writes are not atomic yet.
- Inspect, verify, and info are still placeholder command surfaces.
- Safe path validation is still minimal.
- Fuzz targets and root integration tests are placeholders.
- v1.0 docs are not complete enough for release.

## Release Gates

Each gate must be green before moving to the next broad phase.

1. CI gate: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo audit`, and `cargo deny check` pass on Linux, Windows, and macOS.
2. Age compatibility gate: Ravencap-produced `.rav` files decrypt with standard age-compatible tooling to RAVP plaintext, and Ravencap decrypts from non-seekable stdin-style readers.
3. Safety gate: path traversal, unsafe symlinks, invalid manifests, malformed RAVP preludes, truncated streams, and tampered encrypted streams fail clearly.
4. Streaming gate: raw encryption, raw decryption, archive pack, archive unpack, inspect, and verify avoid buffering full content streams in memory.
5. Documentation gate: README, FORMAT, THREAT_MODEL, SECURITY, examples, and limitations accurately match implemented behavior.

## Milestone 0: CI And Repository Hygiene

Goal: make `main` boring and always green.

Deliverables:

- Confirm GitHub Actions uses current action versions.
- Confirm each crate has workspace package metadata, including license and repository.
- Fix `cargo deny check` allowlist and crate metadata issues.
- Decide whether `cargo audit` and `cargo deny` are required on every matrix OS or can run once on Ubuntu while build/test run everywhere.
- Add a short CI troubleshooting section to CONTRIBUTING.

Acceptance criteria:

- Latest `main` CI is green on all configured OSes.
- CI failure logs identify the failing step clearly.
- No warnings require immediate workflow migration.

## Milestone 1: Raw Stream Core Completion

Goal: finish v1.0 raw mode as a dependable age-compatible stream tool.

Deliverables:

- Keep passphrase and public-key raw encrypt/decrypt paths working through standard age APIs.
- Add explicit CLI options for compression mode, defaulting raw mode to none.
- Add non-RAVP plaintext rejection for commands that expect Ravencap payload semantics.
- Add wrong password, wrong key, truncated stream, and tampered stream tests.
- Add age/rage interoperability tests or an opt-in test script when external binaries are unavailable in CI.
- Add small format-stable RAVP plaintext test vectors.

Acceptance criteria:

- Large raw streams can be encrypted and decrypted without full buffering.
- Password and X25519 raw stream roundtrips are tested.
- Rust library raw APIs work independently of the CLI.
- Non-RAVP payloads fail clearly when parsed as Ravencap archives.

## Milestone 2: Managed Output And Atomic Writes

Goal: make `-o` safe and document stdout honestly.

Deliverables:

- Implement managed file output through same-directory temporary files.
- Add fsync best-effort behavior where supported.
- Add `--overwrite` semantics without truncating the existing final path before commit.
- Keep stdout as pure stream output and document that shell redirection is not atomic.
- Add atomic write failure tests using temporary directories.

Acceptance criteria:

- Failed writes leave no partial final file behind for managed `-o` paths.
- Existing output is preserved unless `--overwrite` succeeds.
- README and FORMAT describe `-o` vs shell redirection accurately.

## Milestone 3: Archive Pack

Goal: produce real Ravencap archive payloads for files and folders.

Deliverables:

- Walk input paths without buffering file contents.
- Normalize manifest paths to UTF-8 NFC forward-slash form.
- Reject non-UTF-8 paths, absolute paths, empty components, `.`, `..`, duplicate normalized paths, and Windows reserved names.
- Support regular files, directories, and safe relative symlinks.
- Build bounded manifest JSON before content stream.
- Enforce `MAX_MANIFEST_LENGTH`.
- Use zstd level 3 by default for archive mode.
- Keep raw mode default compression as none.

Acceptance criteria:

- Folder pack produces `[RAVP prelude][manifest JSON][zstd TAR stream]` inside a standard age file.
- Manifest contents match packed entries.
- Pack rejects unsafe paths and symlinks before writing a final archive.
- Large file contents are streamed, not buffered.

## Milestone 4: Safe Archive Unpack

Goal: restore folders safely from Ravencap archives.

Deliverables:

- Decrypt age stream.
- Parse RAVP prelude and manifest.
- Validate manifest version, encoding, paths, entry uniqueness, sizes, hashes, and symlinks.
- Decompress zstd archive streams.
- Read TAR entries with per-entry path validation.
- Extract to a temporary output directory first.
- Verify content against manifest before committing output.
- Restore safe symlinks late.
- Document the TOCTOU limitation.

Acceptance criteria:

- Archive roundtrip works for files, nested folders, empty directories, and safe symlinks.
- Path traversal and unsafe symlink test archives are rejected.
- Failed extraction does not leave a partially committed final output directory.

## Milestone 5: Info, Inspect, Verify

Goal: complete the trust-model UX.

Deliverables:

- Implement `info` without decryption and avoid claims about encrypted manifest contents.
- Implement `inspect` by decrypting only the RAVP prelude and manifest prefix.
- Always print the required inspect warning in human-readable mode.
- Add `inspect --json` with `content_stream_verified: false`.
- Implement `verify --quick` to authenticate the full age stream without semantic archive verification.
- Implement full `verify` to read the entire stream, parse/decompress TAR, and validate manifest checksums.
- Add JSON output where specified.

Acceptance criteria:

- `inspect` does not read full archive content.
- `verify --quick` and full `verify` have distinct, documented guarantees.
- Human output and JSON output match the spec.

## Milestone 6: Library API Stabilization

Goal: make `ravencap-core` usable by other Rust projects.

Deliverables:

- Review public types and function signatures.
- Keep parser internals private unless intentionally stable.
- Add crate-level docs and examples for raw encrypt, raw decrypt, pack, unpack, inspect, and verify.
- Add integration tests that use the library without the CLI.
- Decide what is v1.0 stable and what remains internal.

Acceptance criteria:

- Public API supports the documented use cases.
- docs.rs-style examples compile locally.
- CLI remains a thin wrapper over core APIs.

## Milestone 7: Fuzzing And Malicious Inputs

Goal: harden all untrusted input boundaries.

Deliverables:

- Convert placeholder fuzz targets into real targets for RAVP prelude parsing, manifest parsing, archive path parsing, and TAR entry path parsing.
- Add malformed corpora for invalid magic, unsupported version, oversized manifest length, truncated prefix, invalid JSON, duplicate paths, traversal paths, and unsafe symlinks.
- Add regression tests for every parser or path validation bug found.

Acceptance criteria:

- Fuzz targets build and run locally.
- Malicious input integration tests cover the known attack cases from the spec.

## Milestone 8: Test Vectors And Interop

Goal: make compatibility reproducible.

Deliverables:

- Add RAVP plaintext fixtures.
- Add `.rav` fixtures generated with current Ravencap defaults.
- Add negative fixtures for non-RAVP age plaintext.
- Add inspect manifest examples.
- Add an optional interop script for `age` and `rage` binaries.
- Document how to refresh vectors.

Acceptance criteria:

- Test vectors are small enough for the repository.
- CI validates format-stable vectors.
- Production-profile vectors are documented for release validation if too slow for every CI run.

## Milestone 9: Documentation Completion

Goal: make the release honest, usable, and security-conscious.

Deliverables:

- Expand README with positioning, non-goals, quick start, password mode, public-key mode, age/rage interop, hardware-key plugin note, stdin/stdout examples, pack/unpack examples, info/inspect/verify semantics, atomic write warning, security notes, and limitations.
- Expand FORMAT with age relationship, RAVP layout, prelude fields, manifest format, payload types, path policy, inspect semantics, verify semantics, and test vector references.
- Expand THREAT_MODEL with assets, attackers, protected scenarios, non-goals, age/plugin assumptions, path traversal risks, symlink risks, and known limitations.
- Keep SECURITY focused on supported versions and vulnerability reporting.
- Add examples in `docs/examples.md` that match tested commands.

Acceptance criteria:

- Docs do not claim unimplemented features.
- Docs avoid audit, military-grade, enterprise backup, or backup-system wording.
- Every documented command has either an integration test or an explicit limitation note.

## Milestone 10: Release Candidate

Goal: freeze scope and validate v1.0 end to end.

Deliverables:

- Run all CI jobs from a clean clone.
- Run large stream tests locally.
- Run archive roundtrip tests on Windows, macOS, and Linux.
- Run age/rage interop validation where binaries are available.
- Check `cargo tree`, `cargo audit`, and `cargo deny check`.
- Review all public errors for clear messages.
- Update CHANGELOG with v1.0 notes.
- Tag release only after a green release-candidate commit.

Acceptance criteria:

- Every v1.0 definition-of-done item is either complete or explicitly removed from scope before release.
- README and docs describe the final behavior exactly.
- `main` is green and releasable.

## Final Section 22 Closure Checklist

The project can be considered closed for the v1.0 scope when Ravencap is excellent at:

- age-compatible encryption workflows,
- streaming raw encryption,
- archive packing,
- archive extraction,
- safe path handling,
- manifest inspection,
- pipeline composability,
- library embedding.

The project must still not become:

- a backup repository,
- a snapshot manager,
- a deduplicating backup tool,
- a sync engine,
- a cloud backup client,
- an enterprise backup replacement,
- a custom age-like encryption format.

If a proposed task does not advance one of the allowed strengths above or protect one of the boundaries above, defer it until after v1.0.