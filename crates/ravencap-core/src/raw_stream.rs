use std::io::{Read, Write};
use std::str::FromStr;

use age::secrecy::SecretString;
use age::{Decryptor, Encryptor};

use crate::decrypt::validate_identities;
use crate::encrypt::validate_encrypt_options;
use crate::{EncryptOptions, Identity, RavencapError, Recipient, Result};

pub fn encrypt_stream(
    mut input: impl Read,
    output: impl Write,
    options: EncryptOptions,
) -> Result<()> {
    validate_encrypt_options(&options)?;

    let encryptor = encryptor_from_recipients(&options.recipients)?;
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

    let identities = age_identities(&identities)?;
    let decryptor = Decryptor::new(input).map_err(|error| RavencapError::Age(error.to_string()))?;
    let mut decrypted = decryptor
        .decrypt(identities.iter().map(|identity| identity.as_ref()))
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    std::io::copy(&mut decrypted, &mut output)?;

    Ok(())
}

pub(crate) fn encryptor_from_recipients(recipients: &[Recipient]) -> Result<Encryptor> {
    let passphrases = recipients
        .iter()
        .filter_map(|recipient| match recipient {
            Recipient::Passphrase(passphrase) => Some(passphrase.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let public_keys = recipients
        .iter()
        .filter_map(|recipient| match recipient {
            Recipient::PublicKey(public_key) => Some(public_key.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();

    if !passphrases.is_empty() && !public_keys.is_empty() {
        return Err(RavencapError::NotImplemented(
            "age does not support mixing passphrase and public-key recipients in one file",
        ));
    }

    if passphrases.len() == 1 {
        return Ok(Encryptor::with_user_passphrase(secret(passphrases[0])));
    }

    if passphrases.len() > 1 {
        return Err(RavencapError::NotImplemented(
            "passphrase mode supports exactly one passphrase recipient",
        ));
    }

    let parsed = public_keys
        .iter()
        .map(|public_key| {
            age::x25519::Recipient::from_str(public_key.trim())
                .map_err(|error| RavencapError::Key(error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;

    Encryptor::with_recipients(
        parsed
            .iter()
            .map(|recipient| recipient as &dyn age::Recipient),
    )
    .map_err(|error| RavencapError::Age(error.to_string()))
}

pub(crate) fn age_identities(identities: &[Identity]) -> Result<Vec<Box<dyn age::Identity>>> {
    identities
        .iter()
        .map(|identity| match identity {
            Identity::Passphrase(passphrase) => {
                Ok(Box::new(age::scrypt::Identity::new(secret(passphrase)))
                    as Box<dyn age::Identity>)
            }
            Identity::PrivateKey(private_key) => Ok(Box::new(
                age::x25519::Identity::from_str(private_key.trim())
                    .map_err(|error| RavencapError::Key(error.to_string()))?,
            ) as Box<dyn age::Identity>),
        })
        .collect()
}

pub(crate) fn secret(value: &str) -> SecretString {
    SecretString::new(value.to_owned().into())
}
