# Fuzzing

This directory contains small local fuzz harnesses for untrusted Ravencap input boundaries. They are intentionally buildable with plain Cargo so CI and contributors can catch harness drift without requiring a fuzzing engine.

Targets:

- `ravp_prelude_parser`: parses arbitrary bytes as an RAVP prelude prefix.
- `manifest_parser`: parses arbitrary bytes as both format-level and core archive manifests.
- `archive_path_validator`: validates archive paths and `link_path\0target` symlink target pairs.
- `tar_entry_path_validator`: parses arbitrary bytes as a TAR stream and validates discovered entry paths.

Build all harnesses:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Run a corpus file through a target:

```sh
cargo run --manifest-path fuzz/Cargo.toml --bin ravp_prelude_parser < fuzz/corpus/ravp_prelude_parser/invalid_magic.bin
```

Seed corpora live under `fuzz/corpus` and cover invalid magic, unsupported version, oversized manifest length, truncated prefix, invalid JSON, duplicate paths, traversal paths, unsafe symlinks, and non-TAR input.
