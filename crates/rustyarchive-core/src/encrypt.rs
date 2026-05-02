use crate::{EncryptOptions, Result, RustyArchiveError};

pub fn validate_encrypt_options(options: &EncryptOptions) -> Result<()> {
    if options.recipients.is_empty() {
        return Err(RustyArchiveError::NotImplemented(
            "at least one passphrase or recipient is required",
        ));
    }

    Ok(())
}
