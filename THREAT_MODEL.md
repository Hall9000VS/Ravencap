# Threat Model

RustyArchive is intended to provide a standard age-compatible encrypted envelope around a streaming RustyArchive payload.

## Protects Against

- unauthorized plaintext access without a valid recipient identity or password,
- encrypted stream tampering detected by the age layer,
- path traversal during archive extraction,
- accidental partial file replacement when using managed `-o` outputs.

## Non-Goals

- backup management,
- cloud sync,
- deduplication,
- concurrent attacker control of the extraction destination,
- arbitrary third-party plugin trust.
