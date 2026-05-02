use ravencap_core::manifest::{ArchiveManifest, ManifestEntry};
use ravencap_core::{EncryptOptions, Identity, Recipient, UnpackOptions, VerifyMode};
use ravencap_format::{COMPRESSION_NONE, PAYLOAD_TAR_ARCHIVE, RAVP_VERSION, RavpPrelude};

const PASSPHRASE: &str = "correct";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn malformed_ravp_preludes_are_rejected_after_age_authentication() {
    let cases = [
        encrypted_plaintext(b"not-ravp".to_vec()),
        encrypted_plaintext(manual_prelude(2, PAYLOAD_TAR_ARCHIVE, COMPRESSION_NONE, 0)),
        encrypted_plaintext(manual_prelude(
            1,
            PAYLOAD_TAR_ARCHIVE,
            COMPRESSION_NONE,
            8 * 1024 * 1024 + 1,
        )),
        encrypted_plaintext(b"RAVP".to_vec()),
    ];

    for archive in cases {
        assert!(
            ravencap_core::verify_archive(
                archive.as_slice(),
                vec![Identity::passphrase(PASSPHRASE)],
                VerifyMode::Full,
            )
            .is_err()
        );
    }
}

#[test]
fn invalid_manifest_json_is_rejected() {
    let archive = encrypted_ravp_plaintext(
        PAYLOAD_TAR_ARCHIVE,
        COMPRESSION_NONE,
        br#"{"version":1,"path_encoding":"utf-8-nfc-forward-slash","entries":["#.to_vec(),
        vec![0_u8; 1024],
    );

    assert!(
        ravencap_core::inspect_manifest(archive.as_slice(), vec![Identity::passphrase(PASSPHRASE)])
            .is_err()
    );
    assert!(
        ravencap_core::verify_archive(
            archive.as_slice(),
            vec![Identity::passphrase(PASSPHRASE)],
            VerifyMode::Full,
        )
        .is_err()
    );
}

#[test]
fn duplicate_manifest_paths_are_rejected() {
    let archive = encrypted_archive_from_manifest(ArchiveManifest {
        version: 1,
        path_encoding: "utf-8-nfc-forward-slash".to_string(),
        entries: vec![
            ManifestEntry::File {
                path: "project/a.txt".to_string(),
                size: 0,
                sha256: EMPTY_SHA256.to_string(),
            },
            ManifestEntry::File {
                path: "project/a.txt".to_string(),
                size: 0,
                sha256: EMPTY_SHA256.to_string(),
            },
        ],
    });

    assert_full_verify_and_unpack_reject(&archive);
}

#[test]
fn traversal_manifest_paths_are_rejected() {
    let archive = encrypted_archive_from_manifest(ArchiveManifest {
        version: 1,
        path_encoding: "utf-8-nfc-forward-slash".to_string(),
        entries: vec![ManifestEntry::File {
            path: "project/../escape.txt".to_string(),
            size: 0,
            sha256: EMPTY_SHA256.to_string(),
        }],
    });

    assert_full_verify_and_unpack_reject(&archive);
}

#[test]
fn unsafe_manifest_symlinks_are_rejected() {
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

    assert_full_verify_and_unpack_reject(&archive);
}

#[test]
fn traversal_tar_entry_paths_are_rejected() {
    let manifest = ArchiveManifest {
        version: 1,
        path_encoding: "utf-8-nfc-forward-slash".to_string(),
        entries: vec![ManifestEntry::File {
            path: "project/file.txt".to_string(),
            size: 0,
            sha256: EMPTY_SHA256.to_string(),
        }],
    };
    let manifest_bytes = serde_json::to_vec(&manifest).expect("serialize manifest");
    let tar_bytes = malicious_empty_tar_file("project/../escape.txt");

    let archive = encrypted_ravp_plaintext(
        PAYLOAD_TAR_ARCHIVE,
        COMPRESSION_NONE,
        manifest_bytes,
        tar_bytes,
    );
    assert_full_verify_and_unpack_reject(&archive);
}

fn assert_full_verify_and_unpack_reject(archive: &[u8]) {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output = tempdir.path().join("restored");

    let verify_result = ravencap_core::verify_archive(
        archive,
        vec![Identity::passphrase(PASSPHRASE)],
        VerifyMode::Full,
    );
    assert!(
        verify_result.is_err(),
        "full verify unexpectedly accepted malicious archive: {verify_result:?}"
    );

    let unpack_result = ravencap_core::unpack_archive(
        archive,
        &output,
        UnpackOptions::new().identity(Identity::passphrase(PASSPHRASE)),
    );
    assert!(
        unpack_result.is_err(),
        "unpack unexpectedly accepted malicious archive"
    );
    assert!(!output.exists());
}

fn encrypted_archive_from_manifest(manifest: ArchiveManifest) -> Vec<u8> {
    let manifest = serde_json::to_vec(&manifest).expect("serialize manifest");
    encrypted_ravp_plaintext(
        PAYLOAD_TAR_ARCHIVE,
        COMPRESSION_NONE,
        manifest,
        vec![0_u8; 1024],
    )
}

fn encrypted_ravp_plaintext(
    payload_type: u8,
    compression: u8,
    manifest: Vec<u8>,
    payload: Vec<u8>,
) -> Vec<u8> {
    let prelude = RavpPrelude {
        payload_version: RAVP_VERSION,
        payload_type,
        compression,
        manifest_length: manifest.len() as u64,
    };
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&prelude.to_bytes());
    plaintext.extend_from_slice(&manifest);
    plaintext.extend_from_slice(&payload);
    encrypted_plaintext(plaintext)
}

fn encrypted_plaintext(plaintext: Vec<u8>) -> Vec<u8> {
    let mut encrypted = Vec::new();
    ravencap_core::encrypt_stream(
        plaintext.as_slice(),
        &mut encrypted,
        EncryptOptions::new().recipient(Recipient::passphrase(PASSPHRASE)),
    )
    .expect("encrypt malicious fixture");
    encrypted
}

fn manual_prelude(version: u8, payload_type: u8, compression: u8, manifest_length: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RAVP\0");
    bytes.push(version);
    bytes.push(payload_type);
    bytes.push(compression);
    bytes.extend_from_slice(&manifest_length.to_le_bytes());
    bytes
}

fn malicious_empty_tar_file(path: &str) -> Vec<u8> {
    let mut header = [0_u8; 512];
    let path = path.as_bytes();
    header[..path.len()].copy_from_slice(path);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], 0);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
    let checksum = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum.as_bytes());

    let mut tar = Vec::new();
    tar.extend_from_slice(&header);
    tar.extend_from_slice(&[0_u8; 1024]);
    tar
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(0);
    let text = format!("{value:0width$o}", width = field.len() - 1);
    field[..text.len()].copy_from_slice(text.as_bytes());
}
