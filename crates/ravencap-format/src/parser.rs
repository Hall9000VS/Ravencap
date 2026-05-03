use thiserror::Error;

use crate::constants::{
    COMPRESSION_NONE, COMPRESSION_ZSTD, MAX_MANIFEST_LENGTH, PAYLOAD_RAW, PAYLOAD_TAR_ARCHIVE,
    RAVP_MAGIC, RAVP_VERSION,
};
use crate::prelude::RavpPrelude;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("invalid RAVP magic")]
    InvalidMagic,

    #[error("unsupported RAVP version: {0}")]
    UnsupportedVersion(u8),

    #[error("unsupported payload type: {0}")]
    UnsupportedPayloadType(u8),

    #[error("unsupported compression code: {0}")]
    UnsupportedCompression(u8),

    #[error(
        "unsupported payload/compression combination: payload_type={payload_type}, compression={compression}"
    )]
    UnsupportedPayloadCompression { payload_type: u8, compression: u8 },

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

    if !matches!(payload_type, PAYLOAD_RAW | PAYLOAD_TAR_ARCHIVE) {
        return Err(FormatError::UnsupportedPayloadType(payload_type));
    }

    if !matches!(compression, COMPRESSION_NONE | COMPRESSION_ZSTD) {
        return Err(FormatError::UnsupportedCompression(compression));
    }

    match (payload_type, compression) {
        (PAYLOAD_RAW, COMPRESSION_NONE) => {}
        (PAYLOAD_TAR_ARCHIVE, COMPRESSION_NONE | COMPRESSION_ZSTD) => {}
        _ => {
            return Err(FormatError::UnsupportedPayloadCompression {
                payload_type,
                compression,
            });
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_prefix() -> [u8; RavpPrelude::SERIALIZED_LEN] {
        let mut prefix = [0_u8; RavpPrelude::SERIALIZED_LEN];
        prefix[..5].copy_from_slice(RAVP_MAGIC);
        prefix[5] = RAVP_VERSION;
        prefix[6] = PAYLOAD_RAW;
        prefix[7] = COMPRESSION_NONE;
        prefix
    }

    #[test]
    fn rejects_unknown_payload_type() {
        let mut prefix = valid_prefix();
        prefix[6] = 99;

        let error = parse_prelude_prefix(&prefix).expect_err("unknown payload type");

        assert!(matches!(error, FormatError::UnsupportedPayloadType(99)));
    }

    #[test]
    fn rejects_unknown_compression_code() {
        let mut prefix = valid_prefix();
        prefix[7] = 99;

        let error = parse_prelude_prefix(&prefix).expect_err("unknown compression code");

        assert!(matches!(error, FormatError::UnsupportedCompression(99)));
    }

    #[test]
    fn rejects_raw_payload_with_zstd_compression() {
        let mut prefix = valid_prefix();
        prefix[6] = PAYLOAD_RAW;
        prefix[7] = COMPRESSION_ZSTD;

        let error = parse_prelude_prefix(&prefix).expect_err("raw zstd combination");

        assert!(matches!(
            error,
            FormatError::UnsupportedPayloadCompression {
                payload_type: PAYLOAD_RAW,
                compression: COMPRESSION_ZSTD,
            }
        ));
    }

    #[test]
    fn accepts_tar_archive_with_zstd_compression() {
        let mut prefix = valid_prefix();
        prefix[6] = PAYLOAD_TAR_ARCHIVE;
        prefix[7] = COMPRESSION_ZSTD;

        let prelude = parse_prelude_prefix(&prefix).expect("tar zstd combination");

        assert_eq!(prelude.payload_type, PAYLOAD_TAR_ARCHIVE);
        assert_eq!(prelude.compression, COMPRESSION_ZSTD);
    }
}
