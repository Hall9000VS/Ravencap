use std::io::{Read, Write};

use age::secrecy::SecretString;
use age::{Decryptor, Encryptor};
use std::iter;

use crate::decrypt::validate_identities;
use crate::encrypt::validate_encrypt_options;
use crate::{EncryptOptions, Identity, RavencapError, Recipient, Result};

pub fn encrypt_stream(
    mut input: impl Read,
    output: impl Write,
    options: EncryptOptions,
) -> Result<()> {
    validate_encrypt_options(&options)?;

    let passphrase = single_passphrase_recipient(&options.recipients)?;
    let encryptor = Encryptor::with_user_passphrase(secret(passphrase));
    let mut encrypted = encryptor
        .wrap_output(output)
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    std::io::copy(&mut input, &mut encrypted)?;
    encrypted
        .finish()
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    Ok(())
}

pub fn decrypt_stream(
    input: impl Read,
    mut output: impl Write,
    identities: Vec<Identity>,
) -> Result<()> {
    validate_identities(&identities)?;

    let passphrase = single_passphrase_identity(&identities)?;
    let identity = age::scrypt::Identity::new(secret(passphrase));
    let decryptor = Decryptor::new(input).map_err(|error| RavencapError::Age(error.to_string()))?;
    let mut decrypted = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    std::io::copy(&mut decrypted, &mut output)?;

    Ok(())
}

pub(crate) fn single_passphrase_recipient(recipients: &[Recipient]) -> Result<&str> {
    match recipients {
        [Recipient::Passphrase(passphrase)] => Ok(passphrase),
        [Recipient::PasswordPrompt] => Err(RavencapError::NotImplemented(
            "CLI password prompting must resolve to a passphrase before calling core",
        )),
        [_] => Err(RavencapError::NotImplemented(
            "public-key recipients are not implemented in Phase 0.5",
        )),
        _ => Err(RavencapError::NotImplemented(
            "Phase 0.5 supports exactly one passphrase recipient",
        )),
    }
}

fn single_passphrase_identity(identities: &[Identity]) -> Result<&str> {
    match identities {
        [Identity::Passphrase(passphrase)] => Ok(passphrase),
        [Identity::PrivateKey(_)] => Err(RavencapError::NotImplemented(
            "public-key identities are not implemented in Phase 0.5",
        )),
        _ => Err(RavencapError::NotImplemented(
            "Phase 0.5 supports exactly one passphrase identity",
        )),
    }
}

pub(crate) fn secret(value: &str) -> SecretString {
    SecretString::new(value.to_owned().into())
}
