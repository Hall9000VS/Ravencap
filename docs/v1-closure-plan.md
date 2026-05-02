# Ravencap v1.0 Closure Plan

This plan tracks the remaining work needed to close Ravencap v1.0 against the product scope through the final scope statement in section 22 of the specification.

## Current Baseline

Already in place:

- Cargo workspace and crate layout.
- Ravencap CLI binary and core library crates.
- Standard age passphrase encryption and decryption.
- Standard age X25519 key generation, public-key export, public-key encryption, and identity decryption.
- Non-decrypting `info` command for public age header detection.
- `inspect` human and JSON output for decrypted RAVP prelude and manifest prefix.
- `verify --quick` authentication of the full outer age stream.
- RAVP prelude constants, parser, and writer.
- Basic raw stream and pack encryption paths.
- Archive pack applies the zstd default to TAR payload streams.
- Archive manifests include directory, regular file, and safe relative symlink entries; files include sizes and SHA-256 hashes.
- Managed `-o` writes through same-directory temporary files with `--overwrite` protection.
- Cross-platform CI scaffold with format, clippy, test, audit, and deny jobs.
- Initial README, format notes, threat model, security, changelog, and fuzz target placeholders.

Known incomplete areas:

- Archive unpack is implemented for the current regular file, directory, and safe relative symlink subset, with safe temporary extraction and manifest/hash validation.
- Archive mode has current v1.0 path policy and malicious fixture coverage; additional corpus depth remains future hardening work.
- FORMAT and release docs describe managed output and shell redirection guarantees.
- Full verify authenticates the age stream and validates the current TAR manifest/checksum subset.
- The `ravencap-core` v1 public API is centered on top-level functions and option/report types, with implementation modules kept private.
- Small test vectors exist for deterministic RAVP plaintext, current-default encrypted archives, negative non-RAVP age plaintext, and inspect JSON.
- Fuzz targets and seed corpora exist as standalone Cargo harnesses.
- v1.0 docs are complete for the current release-candidate scope.

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

Status: CLI managed output is implemented for `pack`, `encrypt`, `decrypt`, `keygen`, and `pubkey`. Remaining work is documentation depth and any future command-specific output surfaces.

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

Status: Closed for the current v1.0 archive pack scope. Remaining archive hardening work moves to Milestone 4 and Milestone 7.

Deliverables:

- Walk input paths without buffering file contents. [done]
- Normalize manifest paths to UTF-8 NFC forward-slash form. [done]
- Reject non-UTF-8 paths, absolute paths, empty components, `.`, `..`, duplicate normalized paths, and Windows reserved names. [done]
- Support regular files, directories, and safe relative symlinks. [done]
- Build bounded manifest JSON before content stream. [done for directories, regular files, and safe relative symlinks]
- Enforce `MAX_MANIFEST_LENGTH`. [done]
- Use zstd level 3 by default for archive mode. [done for packed TAR payload streams]
- Keep raw mode default compression as none. [done]

Acceptance criteria:

- Folder pack produces `[RAVP prelude][manifest JSON][zstd TAR stream]` inside a standard age file. [done]
- Manifest contents match packed entries. [done]
- Pack rejects unsafe paths and unsafe symlinks before writing a final archive. [done]
- Large file contents are streamed, not buffered. [done]

## Milestone 4: Safe Archive Unpack

Goal: restore folders safely from Ravencap archives.

Status: Closed for the current v1.0 safe unpack scope. Additional malicious-input breadth moves to Milestone 7.

Deliverables:

- Decrypt age stream. [done]
- Parse RAVP prelude and manifest. [done]
- Validate manifest version, encoding, paths, entry uniqueness, sizes, hashes, and symlinks. [done]
- Decompress zstd archive streams. [done]
- Read TAR entries with per-entry path validation. [done]
- Extract to a temporary output directory first. [done]
- Verify content against manifest before committing output. [done]
- Restore safe symlinks late. [done]
- Document the TOCTOU limitation. [done]

Acceptance criteria:

- Archive roundtrip works for files, nested folders, empty directories, and safe symlinks. [done]
- Path traversal and unsafe symlink test archives are rejected. [done]
- Failed extraction does not leave a partially committed final output directory. [done]

## Milestone 5: Info, Inspect, Verify

Goal: complete the trust-model UX.

Status: Closed for the current v1.0 trust-model UX scope. Additional reporting polish can continue as post-closure refinement.

Deliverables:

- Implement `info` without decryption and avoid claims about encrypted manifest contents. [done]
- Implement `inspect` by decrypting only the RAVP prelude and manifest prefix. [done]
- Always print the required inspect warning in human-readable mode. [done]
- Add `inspect --json` with `content_stream_verified: false`. [done]
- Implement `verify --quick` to authenticate the full age stream without semantic archive verification. [done]
- Implement full `verify` to read the entire stream, parse/decompress TAR, and validate manifest checksums. [done]
- Add JSON output where specified. [done]

Acceptance criteria:

- `inspect` does not read full archive content. [done]
- `verify --quick` and full `verify` have distinct, documented guarantees. [done]
- Human output and JSON output match the spec. [done]

## Milestone 6: Library API Stabilization

Goal: make `ravencap-core` usable by other Rust projects.

Status: Closed for the current v1.0 library API scope. Future additions should be reviewed as intentional public API expansion.

Deliverables:

- Review public types and function signatures. [done]
- Keep parser internals private unless intentionally stable. [done]
- Add crate-level docs and examples for raw encrypt, raw decrypt, pack, unpack, inspect, and verify. [done]
- Add integration tests that use the library without the CLI. [done]
- Decide what is v1.0 stable and what remains internal. [done]

Acceptance criteria:

- Public API supports the documented use cases. [done]
- docs.rs-style examples compile locally. [done]
- CLI remains a thin wrapper over core APIs. [done]

## Milestone 7: Fuzzing And Malicious Inputs

Goal: harden all untrusted input boundaries.

Status: Closed for the current v1.0 fuzz harness and malicious regression scope. Future fuzzing can expand corpus depth and engine-specific automation.

Deliverables:

- Convert placeholder fuzz targets into real targets for RAVP prelude parsing, manifest parsing, archive path parsing, and TAR entry path parsing. [done]
- Add malformed corpora for invalid magic, unsupported version, oversized manifest length, truncated prefix, invalid JSON, duplicate paths, traversal paths, and unsafe symlinks. [done]
- Add regression tests for every parser or path validation bug found. [done]

Acceptance criteria:

- Fuzz targets build and run locally. [done]
- Malicious input integration tests cover the known attack cases from the spec. [done]

## Milestone 8: Test Vectors And Interop

Goal: make compatibility reproducible.

Status: Closed for the current v1.0 small-vector and optional interop scope. Larger production-profile vectors remain release-validation work rather than default CI fixtures.

Deliverables:

- Add RAVP plaintext fixtures. [done]
- Add `.rav` fixtures generated with current Ravencap defaults. [done]
- Add negative fixtures for non-RAVP age plaintext. [done]
- Add inspect manifest examples. [done]
- Add an optional interop script for `age` and `rage` binaries. [done]
- Document how to refresh vectors. [done]

Acceptance criteria:

- Test vectors are small enough for the repository. [done]
- CI validates format-stable vectors. [done]
- Production-profile vectors are documented for release validation if too slow for every CI run. [done]

## Milestone 9: Documentation Completion

Goal: make the release honest, usable, and security-conscious.

Status: Closed for the current v1.0 documentation scope. Release-candidate validation remains in Milestone 10.

Deliverables:

- Expand README with positioning, non-goals, quick start, password mode, public-key mode, age/rage interop, hardware-key plugin note, stdin/stdout examples, pack/unpack examples, info/inspect/verify semantics, atomic write warning, security notes, and limitations. [done]
- Expand FORMAT with age relationship, RAVP layout, prelude fields, manifest format, payload types, path policy, inspect semantics, verify semantics, and test vector references. [done]
- Expand THREAT_MODEL with assets, attackers, protected scenarios, non-goals, age/plugin assumptions, path traversal risks, symlink risks, and known limitations. [done]
- Keep SECURITY focused on supported versions and vulnerability reporting. [done]
- Add examples in `docs/examples.md` that match tested commands. [done]

Acceptance criteria:

- Docs do not claim unimplemented features. [done]
- Release-facing docs avoid unsupported security or product-positioning claims. [done]
- Every documented command has either an integration test or an explicit limitation note. [done]

## Milestone 10: Release Candidate

Goal: freeze scope and validate v1.0 end to end.

Status: Closed for the local v1.0 release-candidate validation scope. Final tag creation remains blocked until the changes are committed and the configured GitHub Actions matrix is green on `main`.

Deliverables:

- Run all CI jobs from a clean clone. [done locally for format, clippy, tests, fuzz build; final hosted matrix remains post-commit validation]
- Run large stream tests locally. [done]
- Run archive roundtrip tests on Windows, macOS, and Linux. [done locally on Windows; macOS/Linux covered by configured CI matrix after push]
- Run age/rage interop validation where binaries are available. [done as availability check; local binaries unavailable]
- Check `cargo tree`, `cargo audit`, and `cargo deny check`. [done for `cargo tree`; audit/deny require local tool install or CI]
- Review all public errors for clear messages. [done]
- Update CHANGELOG with v1.0 notes. [done]
- Tag release only after a green release-candidate commit. [deferred until after commit and hosted CI]

Acceptance criteria:

- Every v1.0 definition-of-done item is either complete or explicitly removed from scope before release. [done]
- README and docs describe the final behavior exactly. [done]
- `main` is green and releasable. [pending hosted CI confirmation after commit]

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

- a repository-management product,
- a snapshot manager,
- a deduplication service,
- a sync engine,
- a cloud storage client,
- a snapshot, retention, sync, or repository-management product,
- a custom age-like encryption format.

If a proposed task does not advance one of the allowed strengths above or protect one of the boundaries above, defer it until after v1.0.
