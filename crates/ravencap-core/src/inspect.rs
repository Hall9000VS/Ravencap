use std::io::Read;

use crate::{Identity, InspectInfo, PublicInfo, RavencapError, Result, VerifyMode, VerifyReport};

pub const INSPECT_WARNING: &str = "Warning: this output is based on the encrypted manifest prefix only. The archive content stream has NOT been fully verified.";
const AGE_V1_HEADER: &[u8] = b"age-encryption.org/v1\n";

pub fn read_public_info(mut input: impl Read) -> Result<PublicInfo> {
    let mut prefix = vec![0_u8; AGE_V1_HEADER.len()];
    let bytes_read = input.read(&mut prefix)?;
    let age_compatible = bytes_read == AGE_V1_HEADER.len() && prefix == AGE_V1_HEADER;

    let notes = if age_compatible {
        vec![
            "outer format appears to be age v1; Ravencap payload details require decryption"
                .to_string(),
        ]
    } else {
        vec!["input does not start with the age v1 header".to_string()]
    };

    Ok(PublicInfo {
        age_compatible,
        notes,
    })
}

pub fn inspect_manifest(_input: impl Read, _identities: Vec<Identity>) -> Result<InspectInfo> {
    Err(RavencapError::NotImplemented(
        "manifest inspection is planned for Phase 3",
    ))
}

pub fn verify_archive(
    input: impl Read,
    identities: Vec<Identity>,
    mode: VerifyMode,
) -> Result<VerifyReport> {
    match mode {
        VerifyMode::Quick => {
            crate::decrypt_stream(input, std::io::sink(), identities)?;
            Ok(VerifyReport {
                mode: "quick".to_string(),
                success: true,
                notes: vec![
                    "encrypted stream authenticated to EOF".to_string(),
                    "archive manifest and file checksums were not verified".to_string(),
                ],
            })
        }
        VerifyMode::Full => Err(RavencapError::NotImplemented(
            "full archive verification is planned after manifest and unpack support",
        )),
    }
}
