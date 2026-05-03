use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::Decryptor;
use ravencap_format::{
    COMPRESSION_NONE, COMPRESSION_ZSTD, MAX_MANIFEST_LENGTH, PAYLOAD_RAW, PAYLOAD_TAR_ARCHIVE,
    RAVP_VERSION, RavpPrelude, parse_prelude_prefix,
};
use sha2::{Digest, Sha256};

use crate::manifest::{ArchiveManifest, ManifestEntry, PATH_ENCODING_UTF8_NFC_FORWARD_SLASH};
use crate::{
    Compression, Identity, PackOptions, RavencapError, Recipient, Result, UnpackOptions,
    VerifyReport,
};

pub fn pack_path(path: &Path, output: impl Write, options: PackOptions) -> Result<()> {
    let PackOptions {
        recipients,
        compression,
    } = options;
    let encryptor = crate::raw_stream::encryptor_from_recipients(recipients)?;
    let mut encrypted = encryptor
        .wrap_output(output)
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    if path == Path::new("-") {
        pack_raw(std::io::stdin().lock(), &mut encrypted)?;
    } else {
        pack_tar(path, &mut encrypted, &compression)?;
    }

    encrypted
        .finish()
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    Ok(())
}

pub fn unpack_archive(input: impl Read, output_dir: &Path, options: UnpackOptions) -> Result<()> {
    if output_dir.exists() {
        return Err(RavencapError::InvalidPath(format!(
            "output directory already exists: {}",
            output_dir.display()
        )));
    }

    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(RavencapError::InvalidPath(
            "output parent directory does not exist; create it first".to_string(),
        ));
    }

    let temp_dir = tempfile::Builder::new()
        .prefix(".ravencap-unpack-")
        .tempdir_in(parent)?;

    with_decrypted_archive(input, options.identities, |decrypted| {
        read_verified_tar_archive(decrypted, Some(temp_dir.path()))
    })?;

    commit_unpacked_temp_dir(temp_dir, output_dir)
}

fn commit_unpacked_temp_dir(temp_dir: tempfile::TempDir, output_dir: &Path) -> Result<()> {
    commit_unpacked_temp_dir_with(temp_dir, output_dir, |temp_path, output_dir| {
        Ok(std::fs::rename(temp_path, output_dir)?)
    })
}

fn commit_unpacked_temp_dir_with(
    temp_dir: tempfile::TempDir,
    output_dir: &Path,
    rename: impl FnOnce(&Path, &Path) -> Result<()>,
) -> Result<()> {
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    let temp_path = temp_dir.path().to_path_buf();

    if !parent.is_dir() {
        return Err(RavencapError::InvalidPath(
            "output parent directory does not exist; create it first".to_string(),
        ));
    }
    rename(&temp_path, output_dir)?;
    std::mem::forget(temp_dir);
    Ok(())
}

pub(crate) fn verify_archive_contents(
    input: impl Read,
    identities: Vec<Identity>,
) -> Result<VerifyReport> {
    with_decrypted_archive(input, identities, |decrypted| {
        read_verified_tar_archive(decrypted, None)
    })?;

    Ok(VerifyReport {
        mode: "full".to_string(),
        success: true,
        notes: vec![
            "encrypted stream authenticated to EOF".to_string(),
            "archive manifest and file checksums verified".to_string(),
        ],
    })
}

pub fn pack_raw(mut input: impl Read, mut output: impl Write) -> Result<()> {
    write_ravp_header(
        PAYLOAD_RAW,
        &ArchiveManifest::raw_stream(),
        COMPRESSION_NONE,
        &mut output,
    )?;
    std::io::copy(&mut input, &mut output)?;
    Ok(())
}

fn pack_tar(path: &Path, mut output: impl Write, compression: &Compression) -> Result<()> {
    write_ravp_header(
        PAYLOAD_TAR_ARCHIVE,
        &ArchiveManifest::tar_archive(path)?,
        compression_code(compression),
        &mut output,
    )?;

    match compression {
        Compression::None => {
            let mut builder = tar::Builder::new(output);
            append_path_to_tar(&mut builder, path)?;
            builder.finish()?;
        }
        Compression::Zstd(level) => {
            let encoder = zstd::stream::write::Encoder::new(output, i32::from(*level))?;
            let mut builder = tar::Builder::new(encoder);
            append_path_to_tar(&mut builder, path)?;
            let encoder = builder.into_inner()?;
            encoder.finish()?;
        }
    }

    Ok(())
}

fn append_path_to_tar(output: &mut tar::Builder<impl Write>, path: &Path) -> Result<()> {
    output.follow_symlinks(false);

    if path.is_dir() {
        let root_name = path.file_name().unwrap_or_default();
        output.append_dir_all(root_name, path)?;
    } else {
        let name = path
            .file_name()
            .ok_or_else(|| RavencapError::InvalidPath(path.display().to_string()))?;
        output.append_path_with_name(path, name)?;
    }

    Ok(())
}

fn with_decrypted_archive<T>(
    input: impl Read,
    identities: Vec<Identity>,
    operation: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<T> {
    crate::decrypt::validate_identities(&identities)?;

    let identities = crate::raw_stream::age_identities(identities)?;
    let decryptor = Decryptor::new(input).map_err(|error| RavencapError::Age(error.to_string()))?;
    let mut decrypted = decryptor
        .decrypt(identities.iter().map(|identity| identity.as_ref()))
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    operation(&mut decrypted)
}

fn read_verified_tar_archive(input: &mut dyn Read, output_dir: Option<&Path>) -> Result<()> {
    let (prelude, manifest) = read_archive_header(input)?;

    if prelude.payload_type != PAYLOAD_TAR_ARCHIVE {
        return Err(RavencapError::Format(
            "expected tar archive payload".to_string(),
        ));
    }

    let expected = validate_manifest(&manifest)?;

    match prelude.compression {
        COMPRESSION_NONE => {
            verify_tar_entries(input, &expected, output_dir)?;
            drain_to_eof(input)
        }
        COMPRESSION_ZSTD => {
            let mut decoder = zstd::stream::read::Decoder::new(input)?;
            verify_tar_entries(&mut decoder, &expected, output_dir)?;
            drain_to_eof(&mut decoder)
        }
        value => Err(RavencapError::Format(format!(
            "unsupported compression code: {value}"
        ))),
    }
}

fn read_archive_header(input: &mut dyn Read) -> Result<(RavpPrelude, ArchiveManifest)> {
    let mut prefix = [0_u8; RavpPrelude::SERIALIZED_LEN];
    input.read_exact(&mut prefix)?;
    let prelude =
        parse_prelude_prefix(&prefix).map_err(|error| RavencapError::Format(error.to_string()))?;

    let mut manifest = vec![0_u8; prelude.manifest_length as usize];
    input.read_exact(&mut manifest)?;
    let manifest = serde_json::from_slice(&manifest)?;

    Ok((prelude, manifest))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpectedEntry {
    Directory,
    File { size: u64, sha256: String },
    Symlink { target: String, resolved: String },
}

pub(crate) fn validate_manifest_policy(manifest: &ArchiveManifest) -> Result<()> {
    validate_manifest(manifest).map(|_| ())
}

fn validate_manifest(manifest: &ArchiveManifest) -> Result<HashMap<String, ExpectedEntry>> {
    if manifest.version != 1 {
        return Err(RavencapError::Format(format!(
            "unsupported manifest version: {}",
            manifest.version
        )));
    }

    if manifest.path_encoding != PATH_ENCODING_UTF8_NFC_FORWARD_SLASH {
        return Err(RavencapError::Format(format!(
            "unsupported path encoding: {}",
            manifest.path_encoding
        )));
    }

    let mut expected = HashMap::new();
    for entry in &manifest.entries {
        match entry {
            ManifestEntry::Directory { path } => {
                crate::paths::validate_relative_archive_path(path)?;
                if expected
                    .insert(path.clone(), ExpectedEntry::Directory)
                    .is_some()
                {
                    return Err(RavencapError::InvalidPath(format!(
                        "duplicate archive path: {path}"
                    )));
                }
            }
            ManifestEntry::File { path, size, sha256 } => {
                crate::paths::validate_relative_archive_path(path)?;
                validate_sha256(sha256)?;
                if expected
                    .insert(
                        path.clone(),
                        ExpectedEntry::File {
                            size: *size,
                            sha256: sha256.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(RavencapError::InvalidPath(format!(
                        "duplicate archive path: {path}"
                    )));
                }
            }
            ManifestEntry::Symlink { path, target } => {
                crate::paths::validate_relative_archive_path(path)?;
                let resolved = crate::paths::validate_relative_symlink_target(path, target)?;
                if expected
                    .insert(
                        path.clone(),
                        ExpectedEntry::Symlink {
                            target: target.clone(),
                            resolved,
                        },
                    )
                    .is_some()
                {
                    return Err(RavencapError::InvalidPath(format!(
                        "duplicate archive path: {path}"
                    )));
                }
            }
        }
    }

    for (path, entry) in &expected {
        if let ExpectedEntry::Symlink { resolved, .. } = entry {
            match expected.get(resolved) {
                Some(ExpectedEntry::File { .. } | ExpectedEntry::Directory) => {}
                Some(ExpectedEntry::Symlink { .. }) => {
                    return Err(RavencapError::InvalidPath(format!(
                        "symlink target must resolve to a file or directory manifest entry: {path}"
                    )));
                }
                None => {
                    return Err(RavencapError::InvalidPath(format!(
                        "symlink target is missing from manifest: {path}"
                    )));
                }
            }
        }
    }

    Ok(expected)
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }

    Err(RavencapError::Format(format!(
        "invalid sha256 digest: {value}"
    )))
}

fn verify_tar_entries(
    input: &mut dyn Read,
    expected: &HashMap<String, ExpectedEntry>,
    output_dir: Option<&Path>,
) -> Result<()> {
    let mut archive = tar::Archive::new(input);
    let mut seen = HashSet::new();
    let mut symlinks = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = tar_entry_path(&entry)?;
        crate::paths::validate_relative_archive_path(&path)?;

        if !seen.insert(path.clone()) {
            return Err(RavencapError::InvalidPath(format!(
                "duplicate tar entry: {path}"
            )));
        }

        let expected_entry = expected
            .get(&path)
            .ok_or_else(|| RavencapError::InvalidPath(format!("unexpected tar entry: {path}")))?;
        let entry_type = entry.header().entry_type();

        match expected_entry {
            ExpectedEntry::Directory => {
                if !entry_type.is_dir() {
                    return Err(RavencapError::Format(format!(
                        "manifest expected directory but tar entry differs: {path}"
                    )));
                }
                if let Some(output_dir) = output_dir {
                    std::fs::create_dir_all(output_dir.join(&path))?;
                }
            }
            ExpectedEntry::File { size, sha256 } => {
                if !entry_type.is_file() {
                    return Err(RavencapError::Format(format!(
                        "manifest expected file but tar entry differs: {path}"
                    )));
                }
                verify_file_entry(
                    &mut entry,
                    output_dir.map(|directory| directory.join(&path)),
                    *size,
                    sha256,
                )?;
            }
            ExpectedEntry::Symlink { target, resolved } => {
                if !entry_type.is_symlink() {
                    return Err(RavencapError::Format(format!(
                        "manifest expected symlink but tar entry differs: {path}"
                    )));
                }
                let actual_target = tar_entry_link_name(&entry)?.ok_or_else(|| {
                    RavencapError::InvalidPath(format!("symlink target is missing: {path}"))
                })?;
                if actual_target != *target {
                    return Err(RavencapError::InvalidPath(format!(
                        "symlink target mismatch for {path}"
                    )));
                }
                if let Some(output_dir) = output_dir {
                    symlinks.push((
                        path.clone(),
                        target.clone(),
                        resolved.clone(),
                        output_dir.to_path_buf(),
                    ));
                }
            }
        }
    }

    for path in expected.keys() {
        if !seen.contains(path) {
            return Err(RavencapError::Format(format!(
                "manifest entry missing from tar stream: {path}"
            )));
        }
    }

    for (path, target, resolved, output_dir) in symlinks {
        let target_entry = expected.get(&resolved).ok_or_else(|| {
            RavencapError::InvalidPath(format!("symlink target is missing from manifest: {path}"))
        })?;
        create_symlink_late(&output_dir, &path, &target, target_entry)?;
    }

    Ok(())
}

fn tar_entry_path(entry: &tar::Entry<'_, &mut dyn Read>) -> Result<String> {
    let path = entry.path()?;
    let path = path_to_forward_slash_string(path.as_ref())?;
    let path = path.trim_end_matches('/').to_string();
    if path.is_empty() {
        return Err(RavencapError::InvalidPath(
            "tar entry path must not be empty".to_string(),
        ));
    }
    Ok(path)
}

fn tar_entry_link_name(entry: &tar::Entry<'_, &mut dyn Read>) -> Result<Option<String>> {
    entry
        .link_name()?
        .map(|path| path_to_forward_slash_string(path.as_ref()))
        .transpose()
}

fn verify_file_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    output_path: Option<PathBuf>,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<()> {
    let mut output = match output_path {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            Some(File::create(path)?)
        }
        None => None,
    };
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let bytes_read = entry.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        size = size
            .checked_add(bytes_read as u64)
            .ok_or_else(|| RavencapError::Format("file size overflow".to_string()))?;
        if size > expected_size {
            return Err(RavencapError::Format(format!(
                "file size exceeds manifest size: expected {expected_size}, got more"
            )));
        }
        hasher.update(&buffer[..bytes_read]);
        if let Some(output) = output.as_mut() {
            output.write_all(&buffer[..bytes_read])?;
        }
    }

    if size != expected_size {
        return Err(RavencapError::Format(format!(
            "file size mismatch: expected {expected_size}, got {size}"
        )));
    }

    let actual_sha256 = hex_lower(&hasher.finalize());
    if actual_sha256 != expected_sha256 {
        return Err(RavencapError::Format(format!(
            "file checksum mismatch: expected {expected_sha256}, got {actual_sha256}"
        )));
    }

    Ok(())
}

fn drain_to_eof(input: &mut dyn Read) -> Result<()> {
    std::io::copy(input, &mut std::io::sink())?;
    Ok(())
}

fn create_symlink_late(
    output_dir: &Path,
    path: &str,
    target: &str,
    target_entry: &ExpectedEntry,
) -> Result<()> {
    let output_path = output_dir.join(path);
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        let _ = target_entry;
        std::os::unix::fs::symlink(target, output_path)?;
    }

    #[cfg(windows)]
    {
        match target_entry {
            ExpectedEntry::Directory => std::os::windows::fs::symlink_dir(target, output_path)?,
            ExpectedEntry::File { .. } => std::os::windows::fs::symlink_file(target, output_path)?,
            ExpectedEntry::Symlink { .. } => {
                return Err(RavencapError::InvalidPath(format!(
                    "symlink target must not be another symlink: {path}"
                )));
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (output_dir, path, target, target_entry);
        return Err(RavencapError::Unsupported(
            "symlink extraction is not supported on this platform",
        ));
    }

    Ok(())
}

fn path_to_forward_slash_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| RavencapError::InvalidPath("path is not valid UTF-8".to_string()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}

fn compression_code(compression: &Compression) -> u8 {
    match compression {
        Compression::None => COMPRESSION_NONE,
        Compression::Zstd(_) => COMPRESSION_ZSTD,
    }
}

fn write_ravp_header(
    payload_type: u8,
    manifest: &ArchiveManifest,
    compression: u8,
    mut output: impl Write,
) -> Result<()> {
    let manifest = serde_json::to_vec(manifest)?;
    if manifest.len() as u64 > MAX_MANIFEST_LENGTH {
        return Err(RavencapError::Format(format!(
            "manifest length exceeds limit: {}",
            manifest.len()
        )));
    }

    let prelude = RavpPrelude {
        payload_version: RAVP_VERSION,
        payload_type,
        compression,
        manifest_length: manifest.len() as u64,
    };

    output.write_all(&prelude.to_bytes())?;
    output.write_all(&manifest)?;
    Ok(())
}

impl PackOptions {
    pub fn passphrase(passphrase: impl Into<String>) -> Self {
        Self {
            recipients: vec![Recipient::passphrase(passphrase)],
            compression: Compression::Zstd(3),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_final_rename_cleans_unpacked_temp_dir() {
        let temp_parent = tempfile::tempdir().expect("temp parent");
        let temp_dir = tempfile::Builder::new()
            .prefix(".ravencap-unpack-")
            .tempdir_in(temp_parent.path())
            .expect("temp unpack dir");
        let temp_path = temp_dir.path().to_path_buf();
        let plaintext = temp_path.join("plaintext.txt");
        let output = temp_parent.path().join("restored");

        std::fs::write(&plaintext, b"secret").expect("write plaintext");

        let result = commit_unpacked_temp_dir_with(temp_dir, &output, |_temp_path, _output| {
            Err(RavencapError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced rename failure",
            )))
        });

        assert!(result.is_err());
        assert!(!temp_path.exists());
    }

    #[test]
    fn oversized_file_entry_is_rejected_before_writing_chunk() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let output = tempdir.path().join("oversized.bin");
        let tar_bytes = oversized_tar_file("project/oversized.bin", 1024 * 1024);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let mut entries = archive.entries().expect("tar entries");
        let mut entry = entries.next().expect("first entry").expect("tar entry");

        let result = verify_file_entry(
            &mut entry,
            Some(output.clone()),
            1,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );

        assert!(result.is_err());
        assert_eq!(std::fs::metadata(output).expect("output metadata").len(), 0);
    }

    fn oversized_tar_file(path: &str, size: usize) -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut output);
            let mut header = tar::Header::new_gnu();
            header.set_path(path).expect("set path");
            header.set_size(size as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append(&header, vec![0_u8; size].as_slice())
                .expect("append file");
            builder.finish().expect("finish tar");
        }
        output
    }
}
