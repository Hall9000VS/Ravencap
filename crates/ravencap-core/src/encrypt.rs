use crate::{EncryptOptions, RavencapError, Result};

pub fn validate_encrypt_options(options: &EncryptOptions) -> Result<()> {
    if options.recipients.is_empty() {
        return Err(RavencapError::NotImplemented(
            "at least one passphrase or recipient is required",
        ));
    }

    Ok(())
}
