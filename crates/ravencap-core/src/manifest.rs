use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

use crate::paths::{validate_relative_archive_path, validate_relative_symlink_target};
use crate::{RavencapError, Result};

pub const PATH_ENCODING_UTF8_NFC_FORWARD_SLASH: &str = "utf-8-nfc-forward-slash";

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
            path_encoding: PATH_ENCODING_UTF8_NFC_FORWARD_SLASH.to_string(),
            entries: Vec::new(),
        }
    }

    pub fn tar_archive(path: &Path) -> Result<Self> {
        let entries = collect_manifest_entries(path)?;

        Ok(Self {
            version: 1,
            path_encoding: PATH_ENCODING_UTF8_NFC_FORWARD_SLASH.to_string(),
            entries,
        })
    }
}

fn collect_manifest_entries(path: &Path) -> Result<Vec<ManifestEntry>> {
    let root_name = archive_root_name(path)?;
    let mut entries = Vec::new();
    let mut seen = HashSet::new();

    if path.is_dir() {
        for entry in WalkDir::new(path).follow_links(false).sort_by_file_name() {
            let entry = entry.map_err(|error| RavencapError::InvalidPath(error.to_string()))?;
            let archive_path = archive_path_for_entry(path, &root_name, entry.path())?;
            push_manifest_entry(&mut entries, &mut seen, entry.path(), archive_path)?;
        }
    } else {
        push_manifest_entry(&mut entries, &mut seen, path, root_name)?;
    }

    Ok(entries)
}

fn push_manifest_entry(
    entries: &mut Vec<ManifestEntry>,
    seen: &mut HashSet<String>,
    filesystem_path: &Path,
    archive_path: String,
) -> Result<()> {
    validate_relative_archive_path(&archive_path)?;

    if !seen.insert(archive_path.clone()) {
        return Err(RavencapError::InvalidPath(format!(
            "duplicate archive path: {archive_path}"
        )));
    }

    let metadata = filesystem_path.symlink_metadata()?;
    let file_type = metadata.file_type();

    if file_type.is_dir() {
        entries.push(ManifestEntry::Directory { path: archive_path });
    } else if file_type.is_file() {
        entries.push(ManifestEntry::File {
            path: archive_path,
            size: metadata.len(),
            sha256: sha256_file(filesystem_path)?,
        });
    } else if file_type.is_symlink() {
        let target = symlink_target_to_string(&std::fs::read_link(filesystem_path)?)?;
        validate_relative_symlink_target(&archive_path, &target)?;
        entries.push(ManifestEntry::Symlink {
            path: archive_path,
            target,
        });
    } else {
        return Err(RavencapError::InvalidPath(format!(
            "unsupported filesystem entry: {}",
            filesystem_path.display()
        )));
    }

    Ok(())
}

fn archive_root_name(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .ok_or_else(|| RavencapError::InvalidPath(path.display().to_string()))?;
    archive_component_to_string(name)
}

fn archive_path_for_entry(root: &Path, root_name: &str, entry: &Path) -> Result<String> {
    let relative = entry
        .strip_prefix(root)
        .map_err(|error| RavencapError::InvalidPath(error.to_string()))?;

    if relative.as_os_str().is_empty() {
        return Ok(root_name.to_string());
    }

    let mut components = vec![root_name.to_string()];
    for component in relative.components() {
        match component {
            Component::Normal(component) => {
                components.push(archive_component_to_string(component)?)
            }
            _ => {
                return Err(RavencapError::InvalidPath(
                    "path contains unsupported components".to_string(),
                ));
            }
        }
    }

    Ok(components.join("/"))
}

fn archive_component_to_string(component: &std::ffi::OsStr) -> Result<String> {
    let component = component
        .to_str()
        .ok_or_else(|| RavencapError::InvalidPath("path is not valid UTF-8".to_string()))?;
    if component.contains('\\') {
        return Err(RavencapError::InvalidPath(
            "path component contains backslash, which is not representable in Ravencap archive paths"
                .to_string(),
        ));
    }
    Ok(normalize_archive_string(component))
}

fn symlink_target_to_string(path: &Path) -> Result<String> {
    let target = path.to_str().ok_or_else(|| {
        RavencapError::InvalidPath("symlink target is not valid UTF-8".to_string())
    })?;
    if target.contains('\\') {
        return Err(RavencapError::InvalidPath(
            "symlink target contains backslash, which is not representable in Ravencap archive paths"
                .to_string(),
        ));
    }
    Ok(normalize_archive_string(target))
}

fn normalize_archive_string(value: &str) -> String {
    value.nfc().collect()
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
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
