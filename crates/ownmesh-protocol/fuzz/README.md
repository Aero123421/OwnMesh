# ownmesh-protocol fuzz targets

Equivalent harnesses for the device protocol parser.

## cargo-fuzz (libFuzzer)

Requires a nightly toolchain with `cargo-fuzz` installed:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run parse_envelope
```

Target: `fuzz_targets/parse_envelope.rs` → `ownmesh_protocol::fuzz_parse_envelope`.

## Stable equivalent harness

Always available via the library test suite (no libFuzzer):

```bash
cargo test -p ownmesh-protocol fuzz_entry_does_not_panic -- --nocapture
cargo test -p ownmesh-protocol
```

The entry point `ownmesh_protocol::fuzz_parse_envelope` is panic-free on arbitrary bytes and is the shared body for both harnesses.
