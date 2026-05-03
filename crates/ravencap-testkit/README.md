# ravencap-testkit

Shared test fixtures and helpers for Ravencap crates.

This crate contains small utilities used by Ravencap's workspace tests. It is published so integration tests and downstream validation code can share stable fixture helpers without depending on private workspace paths.

## Usage

```rust
let magic = ravencap_testkit::sample_prelude_magic();
assert_eq!(magic, b"RAVP\0");
```

## Stability

`ravencap-testkit` is primarily intended for tests, examples, and validation tooling. Application code should normally depend on `ravencap-core` or `ravencap-format` instead.

## License

MIT
