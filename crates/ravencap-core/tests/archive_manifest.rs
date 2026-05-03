use ravencap_core::manifest::{ArchiveManifest, ManifestEntry};

#[test]
fn tar_archive_manifest_records_directories_files_sizes_and_hashes() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("project");
    let nested = root.join("src");
    let readme = root.join("README.md");
    let source = nested.join("main.rs");

    std::fs::create_dir_all(&nested).expect("create nested dir");
    std::fs::write(&readme, b"hello\n").expect("write readme");
    std::fs::write(&source, b"fn main() {}\n").expect("write source");

    let manifest = ArchiveManifest::tar_archive(&root).expect("manifest");

    assert_eq!(manifest.version, 1);
    assert_eq!(manifest.path_encoding, "utf-8");
    assert!(manifest.entries.contains(&ManifestEntry::Directory {
        path: "project".to_string()
    }));
    assert!(manifest.entries.contains(&ManifestEntry::Directory {
        path: "project/src".to_string()
    }));
    assert!(manifest.entries.contains(&ManifestEntry::File {
        path: "project/README.md".to_string(),
        size: 6,
        sha256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".to_string(),
    }));
    assert!(manifest.entries.contains(&ManifestEntry::File {
        path: "project/src/main.rs".to_string(),
        size: 13,
        sha256: "536e506bb90914c243a12b397b9a998f85ae2cbd9ba02dfd03a9e155ca5ca0f4".to_string(),
    }));
}

#[test]
fn tar_archive_manifest_records_single_file() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let file = tempdir.path().join("payload.bin");

    std::fs::write(&file, b"payload").expect("write file");

    let manifest = ArchiveManifest::tar_archive(&file).expect("manifest");

    assert_eq!(
        manifest.entries,
        vec![ManifestEntry::File {
            path: "payload.bin".to_string(),
            size: 7,
            sha256: "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5".to_string(),
        }]
    );
}
