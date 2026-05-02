use crate::{Identity, Result, RustyArchiveError};

pub fn validate_identities(identities: &[Identity]) -> Result<()> {
    if identities.is_empty() {
        return Err(RustyArchiveError::NotImplemented(
            "at least one passphrase or identity is required",
        ));
    }

    Ok(())
}
