use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ravencap_core::{Identity, Recipient};

pub(crate) fn resolve_recipients(
    insecure_passphrase_cli: Option<String>,
    passphrase_file: Option<PathBuf>,
    recipients: Vec<String>,
) -> Result<Vec<Recipient>> {
    let passphrase = resolve_optional_passphrase(insecure_passphrase_cli, passphrase_file)?;

    let mut resolved = Vec::new();
    if let Some(passphrase) = passphrase {
        resolved.push(Recipient::passphrase(passphrase));
    } else if recipients.is_empty() {
        resolved.push(Recipient::passphrase(
            rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?,
        ));
    }
    resolved.extend(recipients.into_iter().map(Recipient::public_key));
    Ok(resolved)
}

pub(crate) fn resolve_identities(
    insecure_passphrase_cli: Option<String>,
    passphrase_file: Option<PathBuf>,
    identities: Vec<PathBuf>,
) -> Result<Vec<Identity>> {
    let passphrase = resolve_optional_passphrase(insecure_passphrase_cli, passphrase_file)?;

    let mut resolved = Vec::new();
    if let Some(passphrase) = passphrase {
        resolved.push(Identity::passphrase(passphrase));
    } else if identities.is_empty() {
        resolved.push(Identity::passphrase(
            rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?,
        ));
    }

    for path in identities {
        let private_key = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read identity file {}", path.display()))?;
        resolved.push(Identity::private_key(private_key));
    }

    Ok(resolved)
}

fn resolve_optional_passphrase(
    insecure_passphrase_cli: Option<String>,
    passphrase_file: Option<PathBuf>,
) -> Result<Option<String>> {
    if insecure_passphrase_cli.is_some() && passphrase_file.is_some() {
        bail!("use only one of --insecure-passphrase-cli or --passphrase-file");
    }

    if let Some(passphrase) = insecure_passphrase_cli {
        eprintln!(
            "warning: --insecure-passphrase-cli exposes secrets through process listings and shell history; prefer --passphrase-file or the interactive prompt"
        );
        return Ok(Some(passphrase));
    }

    if let Some(path) = passphrase_file {
        let value = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read passphrase file {}", path.display()))?;
        return Ok(Some(value.trim_end_matches(['\r', '\n']).to_string()));
    }

    Ok(None)
}
