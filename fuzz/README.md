# Fuzzing

This directory contains cargo-fuzz/libFuzzer harnesses for untrusted Ravencap input boundaries.

Targets:

- `ravp_prelude_parser`: parses arbitrary bytes as an RAVP prelude prefix.
- `manifest_parser`: parses arbitrary bytes as both format-level and core archive manifests.
- `archive_path_validator`: validates archive paths and `link_path\0target` symlink target pairs.
- `tar_entry_path_validator`: parses arbitrary bytes as a TAR stream and validates discovered entry paths.

Build all harnesses without running fuzzing:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
```

Run a target with cargo-fuzz:

```sh
cargo +nightly fuzz run ravp_prelude_parser
```

Run only the checked-in corpus for a target:

```sh
cargo +nightly fuzz run ravp_prelude_parser fuzz/corpus/ravp_prelude_parser -- -runs=0
```

On Windows MSVC, full `cargo fuzz run` also requires the matching sanitizer runtime libraries. If those are unavailable, use `cargo check --manifest-path fuzz/Cargo.toml --bins` to catch harness drift and run fuzzing on a supported libFuzzer environment.

Seed corpora live under `fuzz/corpus` and cover invalid magic, unsupported version, oversized manifest length, truncated prefix, invalid JSON, duplicate paths, traversal paths, unsafe symlinks, and non-TAR input.
