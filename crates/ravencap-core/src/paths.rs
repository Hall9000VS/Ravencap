use crate::{RavencapError, Result};

pub fn validate_relative_archive_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(RavencapError::InvalidPath(
            "path must not be empty".to_string(),
        ));
    }

    if path.starts_with('/') || path.contains("..") || path.contains('\\') {
        return Err(RavencapError::InvalidPath(path.to_string()));
    }

    Ok(())
}
