use std::io::Read;

use age::Decryptor;
use ravencap_format::{
    COMPRESSION_NONE, COMPRESSION_ZSTD, PAYLOAD_RAW, PAYLOAD_TAR_ARCHIVE, RavpPrelude,
    parse_prelude_prefix,
};

use crate::manifest::{ArchiveManifest, ManifestEntry};
use crate::{Identity, InspectInfo, PublicInfo, RavencapError, Result, VerifyMode, VerifyReport};

pub const INSPECT_WARNING: &str = "Warning: this output is based on the encrypted manifest prefix only.\nThe archive content stream has NOT been fully verified.\nRun `Ravencap verify` to confirm the archive can be fully read.";
const AGE_V1_HEADER: &[u8] = b"age-encryption.org/v1\n";

pub fn read_public_info(mut input: impl Read) -> Result<PublicInfo> {
    let mut prefix = vec![0_u8; AGE_V1_HEADER.len()];
    let bytes_read = input.read(&mut prefix)?;
    let age_compatible = bytes_read == AGE_V1_HEADER.len() && prefix == AGE_V1_HEADER;

    let notes = if age_compatible {
        vec![
            "outer format appears to be age v1; Ravencap payload details require decryption"
                .to_string(),
        ]
    } else {
        vec!["input does not start with the age v1 header".to_string()]
    };

    Ok(PublicInfo {
        age_compatible,
        notes,
    })
}

pub fn inspect_manifest(input: impl Read, identities: Vec<Identity>) -> Result<InspectInfo> {
    let identities = crate::raw_stream::age_identities(identities)?;
    let decryptor = Decryptor::new(input).map_err(|error| RavencapError::Age(error.to_string()))?;
    let mut decrypted = decryptor
        .decrypt(identities.iter().map(|identity| identity.as_ref()))
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    let mut prefix = [0_u8; RavpPrelude::SERIALIZED_LEN];
    decrypted.read_exact(&mut prefix)?;
    let prelude =
        parse_prelude_prefix(&prefix).map_err(|error| RavencapError::Format(error.to_string()))?;

    let mut manifest = vec![0_u8; prelude.manifest_length as usize];
    decrypted.read_exact(&mut manifest)?;
    let manifest: ArchiveManifest = serde_json::from_slice(&manifest)?;
    crate::archive::validate_manifest_policy(&manifest)?;
    let counts = ManifestCounts::from_manifest(&manifest);

    Ok(InspectInfo {
        payload_type: payload_type_name(prelude.payload_type).to_string(),
        compression: compression_name(prelude.compression).to_string(),
        manifest_version: manifest.version,
        files: counts.files,
        directories: counts.directories,
        symlinks: counts.symlinks,
        uncompressed_size: counts.uncompressed_size,
        content_stream_verified: false,
    })
}

#[derive(Debug, Default)]
struct ManifestCounts {
    files: usize,
    directories: usize,
    symlinks: usize,
    uncompressed_size: u64,
}

impl ManifestCounts {
    fn from_manifest(manifest: &ArchiveManifest) -> Self {
        let mut counts = Self::default();

        for entry in &manifest.entries {
            match entry {
                ManifestEntry::File { size, .. } => {
                    counts.files += 1;
                    counts.uncompressed_size = counts.uncompressed_size.saturating_add(*size);
                }
                ManifestEntry::Directory { .. } => counts.directories += 1,
                ManifestEntry::Symlink { .. } => counts.symlinks += 1,
            }
        }

        counts
    }
}

fn payload_type_name(payload_type: u8) -> &'static str {
    match payload_type {
        PAYLOAD_RAW => "raw",
        PAYLOAD_TAR_ARCHIVE => "tar_archive",
        _ => "unknown",
    }
}

fn compression_name(compression: u8) -> &'static str {
    match compression {
        COMPRESSION_NONE => "none",
        COMPRESSION_ZSTD => "zstd",
        _ => "unknown",
    }
}

pub fn verify_archive(
    input: impl Read,
    identities: Vec<Identity>,
    mode: VerifyMode,
) -> Result<VerifyReport> {
    match mode {
        VerifyMode::Quick => {
            crate::decrypt_stream(input, std::io::sink(), identities)?;
            Ok(VerifyReport {
                mode: "quick".to_string(),
                success: true,
                notes: vec![
                    "encrypted stream authenticated to EOF".to_string(),
                    "archive manifest and file checksums were not verified".to_string(),
                ],
            })
        }
        VerifyMode::Full => crate::archive::verify_archive_contents(input, identities),
    }
}
