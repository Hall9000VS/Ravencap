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
