use crate::{RavencapError, Result};
use unicode_normalization::UnicodeNormalization;

pub fn validate_relative_archive_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(RavencapError::InvalidPath(
            "path must not be empty".to_string(),
        ));
    }

    if path.nfc().collect::<String>() != path {
        return Err(RavencapError::InvalidPath(path.to_string()));
    }

    if path.starts_with('/') || path.contains('\\') || path.contains(':') || path.contains('\0') {
        return Err(RavencapError::InvalidPath(path.to_string()));
    }

    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with([' ', '.'])
        {
            return Err(RavencapError::InvalidPath(path.to_string()));
        }

        let stem = component
            .split('.')
            .next()
            .unwrap_or(component)
            .to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err(RavencapError::InvalidPath(path.to_string()));
        }
    }

    Ok(())
}

pub fn validate_relative_symlink_target(link_path: &str, target: &str) -> Result<String> {
    validate_relative_archive_path(link_path)?;
    let root = link_path
        .split('/')
        .next()
        .ok_or_else(|| RavencapError::InvalidPath(link_path.to_string()))?;

    if target.is_empty()
        || target == "."
        || target.starts_with('/')
        || target.contains('\\')
        || target.contains(':')
        || target.contains('\0')
    {
        return Err(RavencapError::InvalidPath(target.to_string()));
    }

    if target.nfc().collect::<String>() != target {
        return Err(RavencapError::InvalidPath(target.to_string()));
    }

    let mut resolved = link_path
        .split('/')
        .take(link_path.split('/').count().saturating_sub(1))
        .map(str::to_string)
        .collect::<Vec<_>>();

    for component in target.split('/') {
        if component.is_empty() {
            return Err(RavencapError::InvalidPath(target.to_string()));
        }

        match component {
            "." => {}
            ".." => {
                if resolved.pop().is_none() {
                    return Err(RavencapError::InvalidPath(target.to_string()));
                }
            }
            component => {
                if component.ends_with([' ', '.']) {
                    return Err(RavencapError::InvalidPath(target.to_string()));
                }
                resolved.push(component.to_string());
            }
        }
    }

    if resolved.is_empty() {
        return Err(RavencapError::InvalidPath(target.to_string()));
    }

    let resolved = resolved.join("/");
    validate_relative_archive_path(&resolved)?;
    if resolved.split('/').next() != Some(root) {
        return Err(RavencapError::InvalidPath(target.to_string()));
    }

    Ok(resolved)
}
