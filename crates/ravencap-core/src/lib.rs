//! High-level Ravencap APIs for age-compatible streaming encryption and archives.
//!
//! The v1 public surface is intentionally small: callers use the top-level
//! functions and option types in this crate, while archive parsing, encryption
//! plumbing, and extraction internals remain private implementation details.
//!
//! Raw stream encryption:
//!
//! ```no_run
//! # fn main() -> ravencap_core::Result<()> {
//! let plaintext = b"secret payload";
//! let mut encrypted = Vec::new();
//! ravencap_core::encrypt_stream(
//!     plaintext.as_slice(),
//!     &mut encrypted,
//!     ravencap_core::EncryptOptions::new()
//!         .recipient(ravencap_core::Recipient::passphrase("correct")),
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! Raw stream decryption:
//!
//! ```no_run
//! # fn main() -> ravencap_core::Result<()> {
//! # let encrypted: Vec<u8> = Vec::new();
//! let mut plaintext = Vec::new();
//! ravencap_core::decrypt_stream(
//!     encrypted.as_slice(),
//!     &mut plaintext,
//!     vec![ravencap_core::Identity::passphrase("correct")],
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! Pack and unpack archives:
//!
//! ```no_run
//! # fn main() -> ravencap_core::Result<()> {
//! let input_path = std::path::Path::new("folder");
//! let output_dir = std::path::Path::new("restored-folder");
//! let mut archive = Vec::new();
//!
//! ravencap_core::pack_path(
//!     input_path,
//!     &mut archive,
//!     ravencap_core::PackOptions::new()
//!         .recipient(ravencap_core::Recipient::passphrase("correct")),
//! )?;
//!
//! ravencap_core::unpack_archive(
//!     archive.as_slice(),
//!     output_dir,
//!     ravencap_core::UnpackOptions::new()
//!         .identity(ravencap_core::Identity::passphrase("correct")),
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! Inspect and verify archives:
//!
//! ```no_run
//! # fn main() -> ravencap_core::Result<()> {
//! # let archive: Vec<u8> = Vec::new();
//! let inspect = ravencap_core::inspect_manifest(
//!     archive.as_slice(),
//!     vec![ravencap_core::Identity::passphrase("correct")],
//! )?;
//! assert!(!inspect.content_stream_verified);
//!
//! let report = ravencap_core::verify_archive(
//!     archive.as_slice(),
//!     vec![ravencap_core::Identity::passphrase("correct")],
//!     ravencap_core::VerifyMode::Full,
//! )?;
//! assert!(report.success);
//! # Ok(())
//! # }
//! ```

mod archive;
mod decrypt;
mod encrypt;
pub mod error;
mod inspect;
pub mod manifest;
pub mod paths;
mod raw_stream;

use std::io::{Read, Write};
use std::path::Path;
use std::{fmt, fmt::Formatter};

use age::secrecy::{ExposeSecret, SecretString};
pub use error::{RavencapError, Result};
pub use inspect::INSPECT_WARNING;

pub enum Recipient {
    Passphrase(SecretString),
    PublicKey(String),
}

impl fmt::Debug for Recipient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passphrase(_) => formatter.write_str("Passphrase(<redacted>)"),
            Self::PublicKey(public_key) => formatter
                .debug_tuple("PublicKey")
                .field(public_key)
                .finish(),
        }
    }
}

impl Recipient {
    pub fn passphrase(value: impl Into<String>) -> Self {
        Self::Passphrase(SecretString::new(value.into().into()))
    }

    pub fn public_key(value: impl Into<String>) -> Self {
        Self::PublicKey(value.into())
    }
}

pub enum Identity {
    Passphrase(SecretString),
    PrivateKey(SecretString),
}

impl fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passphrase(_) => formatter.write_str("Passphrase(<redacted>)"),
            Self::PrivateKey(_) => formatter.write_str("PrivateKey(<redacted>)"),
        }
    }
}

impl Identity {
    pub fn passphrase(value: impl Into<String>) -> Self {
        Self::Passphrase(SecretString::new(value.into().into()))
    }

    pub fn private_key(value: impl Into<String>) -> Self {
        Self::PrivateKey(SecretString::new(value.into().into()))
    }
}

#[derive(Debug, Default)]
pub struct EncryptOptions {
    pub recipients: Vec<Recipient>,
}

impl EncryptOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recipient(mut self, recipient: Recipient) -> Self {
        self.recipients.push(recipient);
        self
    }
}

#[derive(Debug)]
pub struct PackOptions {
    pub recipients: Vec<Recipient>,
    pub compression: Compression,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            recipients: Vec::new(),
            compression: Compression::Zstd(3),
        }
    }
}

impl PackOptions {
    pub fn new() -> Self {
        Self::default()
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

#[derive(Debug, Default)]
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
    pub manifest_version: u8,
    pub files: usize,
    pub directories: usize,
    pub symlinks: usize,
    pub uncompressed_size: u64,
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

pub fn generate_private_key() -> String {
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_owned()
}

pub fn public_key_from_private_key(private_key: &str) -> Result<String> {
    let identity = raw_stream::first_private_key_from_text(private_key)?;
    Ok(identity.to_public().to_string())
}
