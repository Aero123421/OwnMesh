#![no_main]

use libfuzzer_sys::fuzz_target;
use ownmesh_protocol::fuzz_parse_envelope;

fuzz_target!(|data: &[u8]| {
    fuzz_parse_envelope(data);
});
