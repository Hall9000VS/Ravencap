use std::io::{Read, Write};
use std::path::Path;

use age::Encryptor;
use rustyarchive_format::{
    COMPRESSION_NONE, PAYLOAD_RAW, PAYLOAD_TAR_ARCHIVE, RAVP_VERSION, RavpPrelude,
    parse_prelude_prefix,
};

use crate::manifest::ArchiveManifest;
use crate::{
    Compression, EncryptOptions, PackOptions, Recipient, Result, RustyArchiveError, UnpackOptions,
};

pub fn pack_path(path: &Path, output: impl Write, options: PackOptions) -> Result<()> {
    let passphrase = crate::raw_stream::single_passphrase_recipient(&options.recipients)?;
    let encryptor = Encryptor::with_user_passphrase(crate::raw_stream::secret(passphrase));
    let mut encrypted = encryptor
        .wrap_output(output)
        .map_err(|error| RustyArchiveError::Age(error.to_string()))?;

    if path == Path::new("-") {
        pack_raw(std::io::stdin().lock(), &mut encrypted)?;
    } else {
        pack_tar(path, &mut encrypted)?;
    }

    encrypted
        .finish()
        .map_err(|error| RustyArchiveError::Age(error.to_string()))?;

    Ok(())
}

pub fn unpack_archive(input: impl Read, _output_dir: &Path, options: UnpackOptions) -> Result<()> {
    let mut decrypted = Vec::new();
    crate::decrypt_stream(input, &mut decrypted, options.identities)?;

    let mut cursor = std::io::Cursor::new(decrypted);
    let mut prefix = [0_u8; RavpPrelude::SERIALIZED_LEN];
    cursor.read_exact(&mut prefix)?;
    let _prelude = parse_prelude_prefix(&prefix)
        .map_err(|error| RustyArchiveError::Format(error.to_string()))?;

    Err(RustyArchiveError::NotImplemented(
        "archive extraction is planned after the Phase 0.5 pack/encrypt gate",
    ))
}

pub fn pack_raw(mut input: impl Read, mut output: impl Write) -> Result<()> {
    write_ravp_header(PAYLOAD_RAW, &ArchiveManifest::raw_stream(), &mut output)?;
    std::io::copy(&mut input, &mut output)?;
    Ok(())
}

fn pack_tar(path: &Path, mut output: impl Write) -> Result<()> {
    write_ravp_header(
        PAYLOAD_TAR_ARCHIVE,
        &ArchiveManifest::tar_archive(path),
        &mut output,
    )?;
    let mut builder = tar::Builder::new(output);

    if path.is_dir() {
        let root_name = path.file_name().unwrap_or_default();
        builder.append_dir_all(root_name, path)?;
    } else {
        let name = path
            .file_name()
            .ok_or_else(|| RustyArchiveError::InvalidPath(path.display().to_string()))?;
        builder.append_path_with_name(path, name)?;
    }

    builder.finish()?;
    Ok(())
}

fn write_ravp_header(
    payload_type: u8,
    manifest: &ArchiveManifest,
    mut output: impl Write,
) -> Result<()> {
    let manifest = serde_json::to_vec(manifest)?;
    let prelude = RavpPrelude {
        payload_version: RAVP_VERSION,
        payload_type,
        compression: COMPRESSION_NONE,
        manifest_length: manifest.len() as u64,
    };

    output.write_all(&prelude.to_bytes())?;
    output.write_all(&manifest)?;
    Ok(())
}

impl From<PackOptions> for EncryptOptions {
    fn from(options: PackOptions) -> Self {
        Self {
            recipients: options.recipients,
            compression: options.compression,
        }
    }
}

impl PackOptions {
    pub fn passphrase(passphrase: impl Into<String>) -> Self {
        Self {
            recipients: vec![Recipient::passphrase(passphrase)],
            compression: Compression::None,
        }
    }
}
