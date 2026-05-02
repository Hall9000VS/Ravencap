use std::fs;
use std::process::Command;

fn ravencap() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ravencap"))
}

#[test]
fn output_path_refuses_to_clobber_without_overwrite() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let output = tempdir.path().join("identity.txt");
    fs::write(&output, "keep me").expect("seed output");

    let status = ravencap()
        .args(["keygen", "-o"])
        .arg(&output)
        .status()
        .expect("run keygen");

    assert!(!status.success());
    assert_eq!(fs::read_to_string(&output).expect("read output"), "keep me");
}

#[test]
fn failed_decrypt_preserves_existing_overwrite_target() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let plaintext = tempdir.path().join("plain.txt");
    let ciphertext = tempdir.path().join("cipher.rav");
    let output = tempdir.path().join("out.txt");

    fs::write(&plaintext, "secret payload").expect("seed plaintext");
    fs::write(&output, "existing output").expect("seed output");

    let encrypt_status = ravencap()
        .args(["encrypt", "--passphrase", "correct", "-i"])
        .arg(&plaintext)
        .args(["-o"])
        .arg(&ciphertext)
        .status()
        .expect("run encrypt");
    assert!(encrypt_status.success());

    let decrypt_status = ravencap()
        .args(["decrypt", "--passphrase", "wrong", "-i"])
        .arg(&ciphertext)
        .args(["-o"])
        .arg(&output)
        .arg("--overwrite")
        .status()
        .expect("run decrypt");

    assert!(!decrypt_status.success());
    assert_eq!(
        fs::read_to_string(&output).expect("read output"),
        "existing output"
    );
}

#[test]
fn info_reports_only_public_age_header() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let plaintext = tempdir.path().join("plain.txt");
    let ciphertext = tempdir.path().join("cipher.rav");

    fs::write(&plaintext, "secret payload").expect("seed plaintext");

    let encrypt_status = ravencap()
        .args(["encrypt", "--passphrase", "correct", "-i"])
        .arg(&plaintext)
        .args(["-o"])
        .arg(&ciphertext)
        .status()
        .expect("run encrypt");
    assert!(encrypt_status.success());

    let output = ravencap()
        .arg("info")
        .arg(&ciphertext)
        .output()
        .expect("run info");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("age_compatible: true"));
    assert!(stdout.contains("Ravencap payload details require decryption"));
    assert!(!stdout.contains("payload_type"));
    assert!(!stdout.contains("manifest"));
}

#[test]
fn quick_verify_authenticates_encrypted_stream() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let plaintext = tempdir.path().join("plain.txt");
    let ciphertext = tempdir.path().join("cipher.rav");

    fs::write(&plaintext, "secret payload").expect("seed plaintext");

    let encrypt_status = ravencap()
        .args(["encrypt", "--passphrase", "correct", "-i"])
        .arg(&plaintext)
        .args(["-o"])
        .arg(&ciphertext)
        .status()
        .expect("run encrypt");
    assert!(encrypt_status.success());

    let output = ravencap()
        .args(["verify", "--quick"])
        .arg(&ciphertext)
        .args(["--passphrase", "correct"])
        .output()
        .expect("run quick verify");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Quick verify completed: encrypted stream authenticated."));
    assert!(stdout.contains("Archive manifest and file checksums were NOT verified."));
}

#[test]
fn quick_verify_json_reports_unverified_manifest_and_checksums() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let plaintext = tempdir.path().join("plain.txt");
    let ciphertext = tempdir.path().join("cipher.rav");

    fs::write(&plaintext, "secret payload").expect("seed plaintext");

    let encrypt_status = ravencap()
        .args(["encrypt", "--passphrase", "correct", "-i"])
        .arg(&plaintext)
        .args(["-o"])
        .arg(&ciphertext)
        .status()
        .expect("run encrypt");
    assert!(encrypt_status.success());

    let output = ravencap()
        .args(["verify", "--quick", "--json"])
        .arg(&ciphertext)
        .args(["--passphrase", "correct"])
        .output()
        .expect("run quick verify json");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""mode": "quick""#));
    assert!(stdout.contains(r#""success": true"#));
    assert!(stdout.contains("archive manifest and file checksums were not verified"));
}

#[test]
fn quick_verify_fails_with_wrong_passphrase() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let plaintext = tempdir.path().join("plain.txt");
    let ciphertext = tempdir.path().join("cipher.rav");

    fs::write(&plaintext, "secret payload").expect("seed plaintext");

    let encrypt_status = ravencap()
        .args(["encrypt", "--passphrase", "correct", "-i"])
        .arg(&plaintext)
        .args(["-o"])
        .arg(&ciphertext)
        .status()
        .expect("run encrypt");
    assert!(encrypt_status.success());

    let output = ravencap()
        .args(["verify", "--quick"])
        .arg(&ciphertext)
        .args(["--passphrase", "wrong"])
        .output()
        .expect("run quick verify");

    assert!(!output.status.success());
}

#[test]
fn inspect_prints_warning_and_manifest_prefix_details() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let folder = tempdir.path().join("folder");
    let file = folder.join("note.txt");
    let archive = tempdir.path().join("folder.rav");

    fs::create_dir(&folder).expect("create folder");
    fs::write(&file, "archive payload").expect("seed file");

    let pack_status = ravencap()
        .args(["pack", "--passphrase", "correct"])
        .arg(&folder)
        .args(["-o"])
        .arg(&archive)
        .status()
        .expect("run pack");
    assert!(pack_status.success());

    let output = ravencap()
        .arg("inspect")
        .arg(&archive)
        .args(["--passphrase", "correct"])
        .output()
        .expect("run inspect");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        stdout.contains("Warning: this output is based on the encrypted manifest prefix only.")
    );
    assert!(stdout.contains("The archive content stream has NOT been fully verified."));
    assert!(stdout.contains("Payload type: tar_archive"));
    assert!(stdout.contains("Compression: zstd"));
    assert!(stdout.contains("Files: 1"));
    assert!(stdout.contains("Directories: 1"));
    assert!(stdout.contains("Content stream verified: false"));
}

#[test]
fn inspect_json_marks_content_stream_unverified() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let folder = tempdir.path().join("folder");
    let file = folder.join("note.txt");
    let archive = tempdir.path().join("folder.rav");

    fs::create_dir(&folder).expect("create folder");
    fs::write(&file, "raw payload").expect("seed file");

    let pack_status = ravencap()
        .args(["pack", "--passphrase", "correct"])
        .arg(&folder)
        .args(["-o"])
        .arg(&archive)
        .status()
        .expect("run pack");
    assert!(pack_status.success());

    let output = ravencap()
        .arg("inspect")
        .arg(&archive)
        .args(["--passphrase", "correct", "--json"])
        .output()
        .expect("run inspect json");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""payload_type": "tar_archive""#));
    assert!(stdout.contains(r#""content_stream_verified": false"#));
}

#[test]
fn unpack_restores_packed_folder() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let folder = tempdir.path().join("folder");
    let nested = folder.join("nested");
    let file = nested.join("note.txt");
    let archive = tempdir.path().join("folder.rav");
    let output = tempdir.path().join("restored");

    fs::create_dir_all(&nested).expect("create nested dir");
    fs::write(&file, "archive payload").expect("seed file");

    let pack_status = ravencap()
        .args(["pack", "--passphrase", "correct"])
        .arg(&folder)
        .args(["-o"])
        .arg(&archive)
        .status()
        .expect("run pack");
    assert!(pack_status.success());

    let unpack_status = ravencap()
        .arg("unpack")
        .arg(&archive)
        .args(["--passphrase", "correct", "-o"])
        .arg(&output)
        .status()
        .expect("run unpack");
    assert!(unpack_status.success());

    assert_eq!(
        fs::read_to_string(output.join("folder/nested/note.txt")).expect("read restored file"),
        "archive payload"
    );
}

#[test]
fn full_verify_reports_manifest_and_checksum_validation() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let folder = tempdir.path().join("folder");
    let file = folder.join("note.txt");
    let archive = tempdir.path().join("folder.rav");

    fs::create_dir(&folder).expect("create folder");
    fs::write(&file, "archive payload").expect("seed file");

    let pack_status = ravencap()
        .args(["pack", "--passphrase", "correct"])
        .arg(&folder)
        .args(["-o"])
        .arg(&archive)
        .status()
        .expect("run pack");
    assert!(pack_status.success());

    let output = ravencap()
        .arg("verify")
        .arg(&archive)
        .args(["--passphrase", "correct"])
        .output()
        .expect("run full verify");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Verify mode: full"));
    assert!(stdout.contains("archive manifest and file checksums verified"));
}

#[test]
fn full_verify_json_reports_manifest_and_checksum_validation() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let folder = tempdir.path().join("folder");
    let file = folder.join("note.txt");
    let archive = tempdir.path().join("folder.rav");

    fs::create_dir(&folder).expect("create folder");
    fs::write(&file, "archive payload").expect("seed file");

    let pack_status = ravencap()
        .args(["pack", "--passphrase", "correct"])
        .arg(&folder)
        .args(["-o"])
        .arg(&archive)
        .status()
        .expect("run pack");
    assert!(pack_status.success());

    let output = ravencap()
        .arg("verify")
        .arg(&archive)
        .args(["--passphrase", "correct", "--json"])
        .output()
        .expect("run full verify json");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""mode": "full""#));
    assert!(stdout.contains(r#""success": true"#));
    assert!(stdout.contains("archive manifest and file checksums verified"));
}
