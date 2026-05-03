#![no_main]

use libfuzzer_sys::fuzz_target;

fn fuzz_one(data: &[u8]) {
    let mut archive = tar::Archive::new(data);
    let Ok(entries) = archive.entries() else {
        return;
    };

    for entry in entries.take(64) {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(path) = entry.path() else {
            continue;
        };
        if let Some(path) = path.to_str() {
            let normalized = path.replace('\\', "/").trim_end_matches('/').to_string();
            let _ = ravencap_core::paths::validate_relative_archive_path(&normalized);

            if let Ok(Some(link_name)) = entry.link_name() {
                if let Some(link_name) = link_name.to_str() {
                    let link_name = link_name.replace('\\', "/");
                    let _ = ravencap_core::paths::validate_relative_symlink_target(
                        &normalized,
                        &link_name,
                    );
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| fuzz_one(data));
