#![no_main]

use libfuzzer_sys::fuzz_target;

fn fuzz_one(data: &[u8]) {
    if let Ok(value) = std::str::from_utf8(data) {
        let value = value.trim_end_matches(['\r', '\n']);
        let _ = ravencap_core::paths::validate_relative_archive_path(value);

        let mut parts = value.splitn(2, '\0');
        if let (Some(link_path), Some(target)) = (parts.next(), parts.next()) {
            let _ = ravencap_core::paths::validate_relative_symlink_target(link_path, target);
        }
    }
}

fuzz_target!(|data: &[u8]| fuzz_one(data));
