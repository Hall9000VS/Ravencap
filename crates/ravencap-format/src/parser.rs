use thiserror::Error;

use crate::constants::{MAX_MANIFEST_LENGTH, RAVP_MAGIC, RAVP_VERSION};
use crate::prelude::RavpPrelude;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("invalid RAVP magic")]
    InvalidMagic,

    #[error("unsupported RAVP version: {0}")]
    UnsupportedVersion(u8),

    #[error("manifest length exceeds limit: {0}")]
    ManifestTooLarge(u64),

    #[error("RAVP prefix is too short")]
    Truncated,
}

pub fn parse_prelude_prefix(bytes: &[u8]) -> Result<RavpPrelude, FormatError> {
    if bytes.len() < RavpPrelude::SERIALIZED_LEN {
        return Err(FormatError::Truncated);
    }

    if &bytes[..5] != RAVP_MAGIC {
        return Err(FormatError::InvalidMagic);
    }

    let payload_version = bytes[5];
    if payload_version != RAVP_VERSION {
        return Err(FormatError::UnsupportedVersion(payload_version));
    }

    let payload_type = bytes[6];
    let compression = bytes[7];
    let manifest_length =
        u64::from_le_bytes(bytes[8..16].try_into().expect("slice length checked"));

    if manifest_length > MAX_MANIFEST_LENGTH {
        return Err(FormatError::ManifestTooLarge(manifest_length));
    }

    Ok(RavpPrelude {
        payload_version,
        payload_type,
        compression,
        manifest_length,
    })
}
