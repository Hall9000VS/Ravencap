use std::io::{Cursor, Read};

use ravencap_core::{EncryptOptions, Identity, Recipient};

struct ReadOnlyStream(Cursor<Vec<u8>>);

impl Read for ReadOnlyStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

#[test]
fn phase_0_5_age_streaming_roundtrip_without_seek() {
    let plaintext = b"RAVP\0\x01\x01\0\0\0\0\0\0\0\0\0stream payload";
    let passphrase = "correct horse battery staple";
    let mut ciphertext = Vec::new();

    ravencap_core::encrypt_stream(
        plaintext.as_slice(),
        &mut ciphertext,
        EncryptOptions::new().recipient(Recipient::passphrase(passphrase)),
    )
    .expect("encrypt stream");

    assert!(ciphertext.starts_with(b"age-encryption.org/v1"));

    let mut decrypted = Vec::new();
    ravencap_core::decrypt_stream(
        ReadOnlyStream(Cursor::new(ciphertext)),
        &mut decrypted,
        vec![Identity::passphrase(passphrase)],
    )
    .expect("decrypt stream");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn public_key_streaming_roundtrip() {
    let private_key = ravencap_core::generate_private_key();
    let public_key = ravencap_core::public_key_from_private_key(&private_key).expect("public key");
    let plaintext = b"public-key stream payload";
    let mut ciphertext = Vec::new();

    ravencap_core::encrypt_stream(
        plaintext.as_slice(),
        &mut ciphertext,
        EncryptOptions::new().recipient(Recipient::public_key(public_key)),
    )
    .expect("encrypt to public key");

    let mut decrypted = Vec::new();
    ravencap_core::decrypt_stream(
        ReadOnlyStream(Cursor::new(ciphertext)),
        &mut decrypted,
        vec![Identity::private_key(private_key)],
    )
    .expect("decrypt with private key");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn large_raw_stream_roundtrips_without_seek() {
    let mut plaintext = Vec::with_capacity(8 * 1024 * 1024);
    for index in 0..plaintext.capacity() {
        plaintext.push((index % 251) as u8);
    }

    let passphrase = "large stream release candidate";
    let mut ciphertext = Vec::new();
    ravencap_core::encrypt_stream(
        plaintext.as_slice(),
        &mut ciphertext,
        EncryptOptions::new().recipient(Recipient::passphrase(passphrase)),
    )
    .expect("encrypt large stream");

    let mut decrypted = Vec::new();
    ravencap_core::decrypt_stream(
        ReadOnlyStream(Cursor::new(ciphertext)),
        &mut decrypted,
        vec![Identity::passphrase(passphrase)],
    )
    .expect("decrypt large stream");

    assert_eq!(decrypted, plaintext);
}
