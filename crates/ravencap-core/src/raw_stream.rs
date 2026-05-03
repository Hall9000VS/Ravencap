use std::io::{Read, Write};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
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

    let encryptor = encryptor_from_recipients(options.recipients)?;
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

    let identities = age_identities(identities)?;
    let decryptor = Decryptor::new(input).map_err(|error| RavencapError::Age(error.to_string()))?;
    let mut decrypted = decryptor
        .decrypt(identities.iter().map(|identity| identity.as_ref()))
        .map_err(|error| RavencapError::Age(error.to_string()))?;

    std::io::copy(&mut decrypted, &mut output)?;

    Ok(())
}

pub(crate) fn encryptor_from_recipients(recipients: Vec<Recipient>) -> Result<Encryptor> {
    let mut passphrases = Vec::new();
    let mut public_keys = Vec::new();

    for recipient in recipients {
        match recipient {
            Recipient::Passphrase(passphrase) => passphrases.push(passphrase),
            Recipient::PublicKey(public_key) => public_keys.push(public_key),
        }
    }

    if !passphrases.is_empty() && !public_keys.is_empty() {
        return Err(RavencapError::Unsupported(
            "age does not support mixing passphrase and public-key recipients in one file",
        ));
    }

    if passphrases.len() == 1 {
        return Ok(Encryptor::with_user_passphrase(
            passphrases.into_iter().next().expect("checked length"),
        ));
    }

    if passphrases.len() > 1 {
        return Err(RavencapError::InvalidOptions(
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

pub(crate) fn age_identities(identities: Vec<Identity>) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut parsed = Vec::new();

    for identity in identities {
        match identity {
            Identity::Passphrase(passphrase) => {
                parsed.push(
                    Box::new(age::scrypt::Identity::new(passphrase)) as Box<dyn age::Identity>
                );
            }
            Identity::PrivateKey(private_key) => {
                for private_key in private_key_lines(private_key.expose_secret())? {
                    parsed.push(Box::new(private_key) as Box<dyn age::Identity>);
                }
            }
        }
    }

    Ok(parsed)
}

pub(crate) fn first_private_key_from_text(value: &str) -> Result<age::x25519::Identity> {
    private_key_lines(value)?.into_iter().next().ok_or_else(|| {
        RavencapError::Key("identity file does not contain an age secret key".to_string())
    })
}

fn private_key_lines(value: &str) -> Result<Vec<age::x25519::Identity>> {
    let mut parsed = Vec::new();

    for line in value.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        parsed.push(
            age::x25519::Identity::from_str(line)
                .map_err(|error| RavencapError::Key(error.to_string()))?,
        );
    }

    if parsed.is_empty() {
        return Err(RavencapError::Key(
            "identity file does not contain an age secret key".to_string(),
        ));
    }

    Ok(parsed)
}
