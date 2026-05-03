use ravencap_core::manifest::{ArchiveManifest, ManifestEntry};
use ravencap_core::{EncryptOptions, Identity, PackOptions, Recipient, UnpackOptions, VerifyMode};
use ravencap_format::{COMPRESSION_NONE, PAYLOAD_TAR_ARCHIVE, RAVP_VERSION, RavpPrelude};

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
    assert_eq!(manifest.path_encoding, "utf-8-nfc-forward-slash");
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

#[test]
fn tar_archive_manifest_normalizes_paths_to_nfc() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("project");
    let decomposed_name = "cafe\u{301}.txt";
    let normalized_name = "caf\u{e9}.txt";

    std::fs::create_dir(&root).expect("create root");
    std::fs::write(root.join(decomposed_name), b"hello").expect("write file");

    let manifest = ArchiveManifest::tar_archive(&root).expect("manifest");

    assert!(manifest.entries.contains(&ManifestEntry::File {
        path: format!("project/{normalized_name}"),
        size: 5,
        sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string(),
    }));
}

#[test]
fn packed_archive_unpacks_files_after_manifest_verification() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("project");
    let nested = root.join("src");
    let file = nested.join("main.rs");
    let archive = tempdir.path().join("project.rav");
    let output = tempdir.path().join("restored");

    std::fs::create_dir_all(&nested).expect("create nested dir");
    std::fs::write(&file, b"fn main() {}\n").expect("write source");

    let mut archive_bytes = Vec::new();
    ravencap_core::pack_path(
        &root,
        &mut archive_bytes,
        PackOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("pack archive");
    std::fs::write(&archive, archive_bytes).expect("write archive");

    ravencap_core::unpack_archive(
        std::fs::File::open(&archive).expect("open archive"),
        &output,
        UnpackOptions::new().identity(Identity::passphrase("correct")),
    )
    .expect("unpack archive");

    assert_eq!(
        std::fs::read(output.join("project/src/main.rs")).expect("read restored file"),
        b"fn main() {}\n"
    );
}

#[test]
fn packed_archive_unpacks_empty_directories() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("project");
    let empty = root.join("empty");
    let output = tempdir.path().join("restored");

    std::fs::create_dir_all(&empty).expect("create empty dir");

    let mut archive = Vec::new();
    ravencap_core::pack_path(
        &root,
        &mut archive,
        PackOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("pack archive");

    ravencap_core::unpack_archive(
        archive.as_slice(),
        &output,
        UnpackOptions::new().identity(Identity::passphrase("correct")),
    )
    .expect("unpack archive");

    assert!(output.join("project/empty").is_dir());
}

#[test]
fn full_verify_checks_manifest_and_tar_payload() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let file = tempdir.path().join("payload.txt");

    std::fs::write(&file, b"payload").expect("write file");

    let mut archive = Vec::new();
    ravencap_core::pack_path(
        &file,
        &mut archive,
        PackOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("pack archive");

    let report = ravencap_core::verify_archive(
        archive.as_slice(),
        vec![Identity::passphrase("correct")],
        VerifyMode::Full,
    )
    .expect("full verify");

    assert!(report.success);
    assert_eq!(report.mode, "full");
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("checksums verified"))
    );
}

#[test]
fn failed_unpack_does_not_commit_output_directory() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let file = tempdir.path().join("payload.txt");
    let output = tempdir.path().join("restored");

    std::fs::write(&file, b"payload").expect("write file");

    let mut archive = Vec::new();
    ravencap_core::pack_path(
        &file,
        &mut archive,
        PackOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("pack archive");

    let result = ravencap_core::unpack_archive(
        archive.as_slice(),
        &output,
        UnpackOptions::new().identity(Identity::passphrase("wrong")),
    );

    assert!(result.is_err());
    assert!(!output.exists());
}

#[test]
fn failed_unpack_does_not_create_missing_parent_directory() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let file = tempdir.path().join("payload.txt");
    let parent = tempdir.path().join("missing-parent");
    let output = parent.join("restored");

    std::fs::write(&file, b"payload").expect("write file");

    let mut archive = Vec::new();
    ravencap_core::pack_path(
        &file,
        &mut archive,
        PackOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("pack archive");

    let result = ravencap_core::unpack_archive(
        archive.as_slice(),
        &output,
        UnpackOptions::new().identity(Identity::passphrase("wrong")),
    );

    assert!(result.is_err());
    assert!(!parent.exists());
    assert!(!output.exists());
}

#[test]
fn malicious_archive_path_traversal_is_rejected() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output = tempdir.path().join("restored");
    let archive = encrypted_archive_from_manifest(ArchiveManifest {
        version: 1,
        path_encoding: "utf-8-nfc-forward-slash".to_string(),
        entries: vec![ManifestEntry::File {
            path: "project/../escape.txt".to_string(),
            size: 0,
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        }],
    });

    assert!(
        ravencap_core::verify_archive(
            archive.as_slice(),
            vec![Identity::passphrase("correct")],
            VerifyMode::Full,
        )
        .is_err()
    );
    assert!(
        ravencap_core::unpack_archive(
            archive.as_slice(),
            &output,
            UnpackOptions::new().identity(Identity::passphrase("correct")),
        )
        .is_err()
    );
    assert!(!output.exists());
}

#[test]
fn malicious_archive_unsafe_symlink_is_rejected() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output = tempdir.path().join("restored");
    let archive = encrypted_archive_from_manifest(ArchiveManifest {
        version: 1,
        path_encoding: "utf-8-nfc-forward-slash".to_string(),
        entries: vec![
            ManifestEntry::Directory {
                path: "project".to_string(),
            },
            ManifestEntry::Symlink {
                path: "project/link".to_string(),
                target: "../outside".to_string(),
            },
        ],
    });

    assert!(
        ravencap_core::verify_archive(
            archive.as_slice(),
            vec![Identity::passphrase("correct")],
            VerifyMode::Full,
        )
        .is_err()
    );
    assert!(
        ravencap_core::unpack_archive(
            archive.as_slice(),
            &output,
            UnpackOptions::new().identity(Identity::passphrase("correct")),
        )
        .is_err()
    );
    assert!(!output.exists());
}

#[test]
fn archive_path_validation_rejects_traversal_and_windows_drive_like_paths() {
    assert!(ravencap_core::paths::validate_relative_archive_path("folder/file.txt").is_ok());
    assert!(ravencap_core::paths::validate_relative_archive_path("folder/../file.txt").is_err());
    assert!(ravencap_core::paths::validate_relative_archive_path("C:/file.txt").is_err());
    assert!(ravencap_core::paths::validate_relative_archive_path("folder/CON.txt").is_err());
    assert!(
        ravencap_core::paths::validate_relative_archive_path("folder/cafe\u{301}.txt").is_err()
    );
}

#[test]
fn symlink_target_validation_allows_only_targets_inside_archive_root() {
    assert_eq!(
        ravencap_core::paths::validate_relative_symlink_target("project/link", "file.txt")
            .expect("safe target"),
        "project/file.txt"
    );
    assert_eq!(
        ravencap_core::paths::validate_relative_symlink_target("project/src/link", "../README.md")
            .expect("safe parent target"),
        "project/README.md"
    );
    assert!(
        ravencap_core::paths::validate_relative_symlink_target("project/link", "../outside")
            .is_err()
    );
    assert!(
        ravencap_core::paths::validate_relative_symlink_target("project/link", "/absolute")
            .is_err()
    );
    assert!(
        ravencap_core::paths::validate_relative_symlink_target("project/link", "cafe\u{301}.txt")
            .is_err()
    );
    assert!(ravencap_core::paths::validate_relative_symlink_target("project/link", ".").is_err());
}

#[cfg(unix)]
#[test]
fn packed_archive_preserves_safe_relative_symlink() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("project");
    let file = root.join("README.md");
    let link = root.join("README.link");
    let output = tempdir.path().join("restored");

    std::fs::create_dir(&root).expect("create root");
    std::fs::write(&file, b"hello\n").expect("write file");
    std::os::unix::fs::symlink("README.md", &link).expect("create symlink");

    let manifest = ArchiveManifest::tar_archive(&root).expect("manifest");
    assert!(manifest.entries.contains(&ManifestEntry::Symlink {
        path: "project/README.link".to_string(),
        target: "README.md".to_string(),
    }));

    let mut archive = Vec::new();
    ravencap_core::pack_path(
        &root,
        &mut archive,
        PackOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("pack archive");

    ravencap_core::unpack_archive(
        archive.as_slice(),
        &output,
        UnpackOptions::new().identity(Identity::passphrase("correct")),
    )
    .expect("unpack archive");

    let restored_link = output.join("project/README.link");
    assert_eq!(
        std::fs::read_link(restored_link).expect("read restored symlink"),
        std::path::PathBuf::from("README.md")
    );
}

fn encrypted_archive_from_manifest(manifest: ArchiveManifest) -> Vec<u8> {
    let manifest = serde_json::to_vec(&manifest).expect("serialize manifest");
    let prelude = RavpPrelude {
        payload_version: RAVP_VERSION,
        payload_type: PAYLOAD_TAR_ARCHIVE,
        compression: COMPRESSION_NONE,
        manifest_length: manifest.len() as u64,
    };
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&prelude.to_bytes());
    plaintext.extend_from_slice(&manifest);
    plaintext.extend_from_slice(&[0_u8; 1024]);

    let mut encrypted = Vec::new();
    ravencap_core::encrypt_stream(
        plaintext.as_slice(),
        &mut encrypted,
        EncryptOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("encrypt malicious fixture");
    encrypted
}
