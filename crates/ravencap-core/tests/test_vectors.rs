use ravencap_core::{Identity, UnpackOptions, VerifyMode};
use ravencap_format::{
    COMPRESSION_NONE, COMPRESSION_ZSTD, PAYLOAD_RAW, PAYLOAD_TAR_ARCHIVE, RavpPrelude,
    parse_prelude_prefix,
};

const VECTOR_PASSPHRASE: &str = "ravencap-test-vector";
const RAW_NONE_RAVP: &[u8] = include_bytes!("../../../tests/vectors/raw-none.ravp");
const ARCHIVE_DEFAULT_RAV: &[u8] = include_bytes!("../../../tests/vectors/archive-default.rav");
const ARCHIVE_PUBLIC_KEY_RAV: &[u8] =
    include_bytes!("../../../tests/vectors/archive-public-key.rav");
const NON_RAVP_AGE_RAV: &[u8] = include_bytes!("../../../tests/vectors/non-ravp-age.rav");
const ALICE_RAVKEY: &str = include_str!("../../../tests/vectors/identity/alice.ravkey");
const ARCHIVE_DEFAULT_INSPECT_JSON: &str =
    include_str!("../../../tests/vectors/inspect/archive-default.json");

#[test]
fn raw_ravp_plaintext_vector_has_stable_prelude_manifest_and_payload() {
    let prelude = parse_prelude_prefix(&RAW_NONE_RAVP[..RavpPrelude::SERIALIZED_LEN])
        .expect("parse RAVP prelude");

    assert_eq!(prelude.payload_type, PAYLOAD_RAW);
    assert_eq!(prelude.compression, COMPRESSION_NONE);

    let manifest_start = RavpPrelude::SERIALIZED_LEN;
    let manifest_end = manifest_start + prelude.manifest_length as usize;
    let manifest: ravencap_core::manifest::ArchiveManifest =
        serde_json::from_slice(&RAW_NONE_RAVP[manifest_start..manifest_end])
            .expect("parse raw manifest");
    assert_eq!(manifest.version, 1);
    assert_eq!(manifest.path_encoding, "utf-8");
    assert!(manifest.entries.is_empty());
    assert_eq!(&RAW_NONE_RAVP[manifest_end..], b"raw vector payload\n");
}

#[test]
fn default_archive_vector_matches_inspect_json_and_full_verify() {
    let inspect = ravencap_core::inspect_manifest(
        ARCHIVE_DEFAULT_RAV,
        vec![Identity::passphrase(VECTOR_PASSPHRASE)],
    )
    .expect("inspect default archive vector");

    let expected: serde_json::Value =
        serde_json::from_str(ARCHIVE_DEFAULT_INSPECT_JSON).expect("parse expected inspect JSON");
    let actual = serde_json::to_value(&inspect).expect("serialize inspect info");
    assert_eq!(actual, expected);
    assert_eq!(inspect.payload_type, "tar_archive");
    assert_eq!(inspect.compression, "zstd");
    assert!(!inspect.content_stream_verified);

    let report = ravencap_core::verify_archive(
        ARCHIVE_DEFAULT_RAV,
        vec![Identity::passphrase(VECTOR_PASSPHRASE)],
        VerifyMode::Full,
    )
    .expect("full verify default archive vector");
    assert!(report.success);
    assert_eq!(report.mode, "full");
}

#[test]
fn public_key_archive_vector_decrypts_and_unpacks() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output = tempdir.path().join("restored");

    let report = ravencap_core::verify_archive(
        ARCHIVE_PUBLIC_KEY_RAV,
        vec![Identity::private_key(ALICE_RAVKEY)],
        VerifyMode::Full,
    )
    .expect("full verify public-key archive vector");
    assert!(report.success);

    ravencap_core::unpack_archive(
        ARCHIVE_PUBLIC_KEY_RAV,
        &output,
        UnpackOptions::new().identity(Identity::private_key(ALICE_RAVKEY)),
    )
    .expect("unpack public-key archive vector");

    assert_eq!(
        std::fs::read(output.join("project/README.md")).expect("read restored vector file"),
        b"# Ravencap vector fixture\r\n"
    );
}

#[test]
fn negative_non_ravp_age_vector_authenticates_but_fails_archive_semantics() {
    let quick_report = ravencap_core::verify_archive(
        NON_RAVP_AGE_RAV,
        vec![Identity::passphrase(VECTOR_PASSPHRASE)],
        VerifyMode::Quick,
    )
    .expect("quick verify non-RAVP age vector");
    assert!(quick_report.success);

    assert!(
        ravencap_core::inspect_manifest(
            NON_RAVP_AGE_RAV,
            vec![Identity::passphrase(VECTOR_PASSPHRASE)],
        )
        .is_err()
    );
    assert!(
        ravencap_core::verify_archive(
            NON_RAVP_AGE_RAV,
            vec![Identity::passphrase(VECTOR_PASSPHRASE)],
            VerifyMode::Full,
        )
        .is_err()
    );
}

#[test]
fn checked_in_vectors_stay_small() {
    assert!(ARCHIVE_DEFAULT_RAV.len() < 2 * 1024);
    assert!(ARCHIVE_PUBLIC_KEY_RAV.len() < 2 * 1024);
    assert!(NON_RAVP_AGE_RAV.len() < 2 * 1024);
    assert!(RAW_NONE_RAVP.len() < 512);
    assert_eq!(PAYLOAD_TAR_ARCHIVE, 2);
    assert_eq!(COMPRESSION_ZSTD, 1);
}
