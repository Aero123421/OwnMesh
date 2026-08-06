# ownmesh-protocol

Device protocol envelopes, version negotiation, and parser fuzz harness for OwnMesh.

## Features

- `Envelope` serialize/parse with structure + expiry validation
- `ProtocolVersion` negotiation (major-compatible, highest common minor)
- `fuzz_parse_envelope` panic-free entry (cargo-fuzz + stable test harness)

```bash
cargo test -p ownmesh-protocol
# optional:
# cargo install cargo-fuzz && cargo +nightly fuzz run parse_envelope
```

See `fuzz/README.md`.
