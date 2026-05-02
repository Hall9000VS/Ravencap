use crate::{Identity, RavencapError, Result};

pub fn validate_identities(identities: &[Identity]) -> Result<()> {
    if identities.is_empty() {
        return Err(RavencapError::InvalidOptions(
            "at least one passphrase or identity is required",
        ));
    }

    Ok(())
}
