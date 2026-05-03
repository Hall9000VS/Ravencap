#![no_main]

use libfuzzer_sys::fuzz_target;

fn fuzz_one(data: &[u8]) {
    let _ = ravencap_format::parse_prelude_prefix(data);
}

fuzz_target!(|data: &[u8]| fuzz_one(data));
