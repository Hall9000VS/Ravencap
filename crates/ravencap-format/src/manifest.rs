#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub path_encoding: String,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum ManifestEntry {
    #[serde(rename = "file")]
    File {
        path: String,
        size: u64,
        sha256: String,
    },
    #[serde(rename = "directory")]
    Directory { path: String },
    #[serde(rename = "symlink")]
    Symlink { path: String, target: String },
}
