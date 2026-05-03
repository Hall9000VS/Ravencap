use ravencap_core::{
    Compression, EncryptOptions, Identity, PackOptions, Recipient, UnpackOptions, VerifyMode,
};

#[test]
fn pack_options_default_matches_new_archive_compression() {
    assert_eq!(PackOptions::default().compression, Compression::Zstd(3));
    assert_eq!(PackOptions::new().compression, Compression::Zstd(3));
}

#[test]
fn secret_bearing_api_debug_output_is_redacted() {
    let recipient = Recipient::passphrase("do-not-log");
    let identity = Identity::private_key("AGE-SECRET-KEY-1EXAMPLE");
    let options = EncryptOptions::new().recipient(Recipient::passphrase("also-secret"));

    let debug_output = format!("{recipient:?} {identity:?} {options:?}");

    assert!(debug_output.contains("<redacted>"));
    assert!(!debug_output.contains("do-not-log"));
    assert!(!debug_output.contains("AGE-SECRET-KEY-1EXAMPLE"));
    assert!(!debug_output.contains("also-secret"));
}

#[test]
fn public_raw_encrypt_decrypt_api_roundtrips() {
    let mut encrypted = Vec::new();
    ravencap_core::encrypt_stream(
        b"library payload".as_slice(),
        &mut encrypted,
        EncryptOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("encrypt stream");

    let public_info = ravencap_core::read_public_info(encrypted.as_slice()).expect("public info");
    assert!(public_info.age_compatible);

    let mut decrypted = Vec::new();
    ravencap_core::decrypt_stream(
        encrypted.as_slice(),
        &mut decrypted,
        vec![Identity::passphrase("correct")],
    )
    .expect("decrypt stream");

    assert_eq!(decrypted, b"library payload");
}

#[test]
fn public_archive_api_packs_inspects_verifies_and_unpacks() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let root = tempdir.path().join("project");
    let nested = root.join("src");
    let file = nested.join("main.rs");
    let output = tempdir.path().join("restored");

    std::fs::create_dir_all(&nested).expect("create nested dir");
    std::fs::write(&file, b"fn main() {}\n").expect("write source");

    let mut archive = Vec::new();
    ravencap_core::pack_path(
        &root,
        &mut archive,
        PackOptions::new().recipient(Recipient::passphrase("correct")),
    )
    .expect("pack path");

    let inspect =
        ravencap_core::inspect_manifest(archive.as_slice(), vec![Identity::passphrase("correct")])
            .expect("inspect archive");
    assert_eq!(inspect.payload_type, "tar_archive");
    assert_eq!(inspect.files, 1);
    assert!(!inspect.content_stream_verified);

    let quick_report = ravencap_core::verify_archive(
        archive.as_slice(),
        vec![Identity::passphrase("correct")],
        VerifyMode::Quick,
    )
    .expect("quick verify");
    assert_eq!(quick_report.mode, "quick");
    assert!(quick_report.success);

    let full_report = ravencap_core::verify_archive(
        archive.as_slice(),
        vec![Identity::passphrase("correct")],
        VerifyMode::Full,
    )
    .expect("full verify");
    assert_eq!(full_report.mode, "full");
    assert!(full_report.success);

    ravencap_core::unpack_archive(
        archive.as_slice(),
        &output,
        UnpackOptions::new().identity(Identity::passphrase("correct")),
    )
    .expect("unpack archive");

    assert_eq!(
        std::fs::read(output.join("project/src/main.rs")).expect("read restored source"),
        b"fn main() {}\n"
    );
}
