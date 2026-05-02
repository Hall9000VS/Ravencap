pub const RAVP_MAGIC: &[u8; 5] = b"RAVP\0";
pub const RAVP_VERSION: u8 = 1;

pub const PAYLOAD_RAW: u8 = 1;
pub const PAYLOAD_TAR_ARCHIVE: u8 = 2;

pub const COMPRESSION_NONE: u8 = 0;
pub const COMPRESSION_ZSTD: u8 = 1;

pub const MAX_MANIFEST_LENGTH: u64 = 8 * 1024 * 1024;
