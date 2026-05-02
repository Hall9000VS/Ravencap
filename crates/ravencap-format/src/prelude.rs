#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RavpPrelude {
    pub payload_version: u8,
    pub payload_type: u8,
    pub compression: u8,
    pub manifest_length: u64,
}

impl RavpPrelude {
    pub const SERIALIZED_LEN: usize = 16;

    pub fn to_bytes(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut bytes = [0_u8; Self::SERIALIZED_LEN];
        bytes[..5].copy_from_slice(crate::RAVP_MAGIC);
        bytes[5] = self.payload_version;
        bytes[6] = self.payload_type;
        bytes[7] = self.compression;
        bytes[8..16].copy_from_slice(&self.manifest_length.to_le_bytes());
        bytes
    }
}
