#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArchiveManifest {
    pub version: u8,
    pub path_encoding: String,
    pub entries: Vec<ManifestEntry>,
}

impl ArchiveManifest {
    pub fn raw_stream() -> Self {
        Self {
            version: 1,
            path_encoding: "utf-8".to_string(),
            entries: Vec::new(),
        }
    }

    pub fn tar_archive(path: &std::path::Path) -> Self {
        let path = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());

        Self {
            version: 1,
            path_encoding: "utf-8".to_string(),
            entries: vec![ManifestEntry::Directory { path }],
        }
    }
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
