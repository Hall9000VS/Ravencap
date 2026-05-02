use std::io::Read;

use ravencap_core::manifest::{ArchiveManifest, ManifestEntry};

fn fuzz_one(data: &[u8]) {
    let _ = serde_json::from_slice::<ravencap_format::Manifest>(data);
    if let Ok(manifest) = serde_json::from_slice::<ArchiveManifest>(data) {
        for entry in manifest.entries.iter().take(128) {
            match entry {
                ManifestEntry::Directory { path } | ManifestEntry::File { path, .. } => {
                    let _ = ravencap_core::paths::validate_relative_archive_path(path);
                }
                ManifestEntry::Symlink { path, target } => {
                    let _ = ravencap_core::paths::validate_relative_archive_path(path);
                    let _ = ravencap_core::paths::validate_relative_symlink_target(path, target);
                }
            }
        }
    }
}

fn main() {
    let mut data = Vec::new();
    std::io::stdin()
        .read_to_end(&mut data)
        .expect("read fuzz input");
    fuzz_one(&data);
}
