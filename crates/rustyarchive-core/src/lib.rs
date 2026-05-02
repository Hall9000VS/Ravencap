pub mod archive;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod inspect;
pub mod manifest;
pub mod paths;
pub mod raw_stream;

use std::io::{Read, Write};
use std::path::Path;

pub use error::{Result, RustyArchiveError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    PasswordPrompt,
    Passphrase(String),
    PublicKey(String),
}

impl Recipient {
    pub fn password_prompt() -> Self {
        Self::PasswordPrompt
    }

    pub fn passphrase(value: impl Into<String>) -> Self {
        Self::Passphrase(value.into())
    }

    pub fn public_key(value: impl Into<String>) -> Self {
        Self::PublicKey(value.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    Passphrase(String),
    PrivateKey(String),
}

impl Identity {
    pub fn passphrase(value: impl Into<String>) -> Self {
        Self::Passphrase(value.into())
    }

    pub fn private_key(value: impl Into<String>) -> Self {
        Self::PrivateKey(value.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncryptOptions {
    pub recipients: Vec<Recipient>,
    pub compression: Compression,
}

impl EncryptOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    pub fn compression_none(mut self) -> Self {
        self.compression = Compression::None;
        self
    }

    pub fn compression_zstd(mut self, level: u8) -> Self {
        self.compression = Compression::Zstd(level);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackOptions {
    pub recipients: Vec<Recipient>,
    pub compression: Compression,
}

impl PackOptions {
    pub fn new() -> Self {
        Self {
            recipients: Vec::new(),
            compression: Compression::Zstd(3),
        }
    }

    pub fn recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    pub fn compression_zstd(mut self, level: u8) -> Self {
        self.compression = Compression::Zstd(level);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnpackOptions {
    pub identities: Vec<Identity>,
}

impl UnpackOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn identity(mut self, identity: Identity) -> Self {
        self.identities.push(identity);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Compression {
    #[default]
    None,
    Zstd(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicInfo {
    pub age_compatible: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InspectInfo {
    pub payload_type: String,
    pub compression: String,
    pub content_stream_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyMode {
    Quick,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifyReport {
    pub mode: String,
    pub success: bool,
    pub notes: Vec<String>,
}

pub fn encrypt_stream<R: Read, W: Write>(
    input: R,
    output: W,
    options: EncryptOptions,
) -> Result<()> {
    raw_stream::encrypt_stream(input, output, options)
}

pub fn decrypt_stream<R: Read, W: Write>(
    input: R,
    output: W,
    identities: Vec<Identity>,
) -> Result<()> {
    raw_stream::decrypt_stream(input, output, identities)
}

pub fn pack_path(path: impl AsRef<Path>, output: impl Write, options: PackOptions) -> Result<()> {
    archive::pack_path(path.as_ref(), output, options)
}

pub fn unpack_archive(
    input: impl Read,
    output_dir: impl AsRef<Path>,
    options: UnpackOptions,
) -> Result<()> {
    archive::unpack_archive(input, output_dir.as_ref(), options)
}

pub fn read_public_info(input: impl Read) -> Result<PublicInfo> {
    inspect::read_public_info(input)
}

pub fn inspect_manifest(input: impl Read, identities: Vec<Identity>) -> Result<InspectInfo> {
    inspect::inspect_manifest(input, identities)
}

pub fn verify_archive(
    input: impl Read,
    identities: Vec<Identity>,
    mode: VerifyMode,
) -> Result<VerifyReport> {
    inspect::verify_archive(input, identities, mode)
}
