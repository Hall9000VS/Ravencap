use std::io::Read;

use crate::{
    Identity, InspectInfo, PublicInfo, Result, RustyArchiveError, VerifyMode, VerifyReport,
};

pub const INSPECT_WARNING: &str = "Warning: this output is based on the encrypted manifest prefix only. The archive content stream has NOT been fully verified.";

pub fn read_public_info(_input: impl Read) -> Result<PublicInfo> {
    Ok(PublicInfo {
        age_compatible: true,
        notes: vec!["public age metadata reader not implemented yet".to_string()],
    })
}

pub fn inspect_manifest(_input: impl Read, _identities: Vec<Identity>) -> Result<InspectInfo> {
    Err(RustyArchiveError::NotImplemented(
        "manifest inspection is planned for Phase 3",
    ))
}

pub fn verify_archive(
    _input: impl Read,
    _identities: Vec<Identity>,
    mode: VerifyMode,
) -> Result<VerifyReport> {
    let mode = match mode {
        VerifyMode::Quick => "quick",
        VerifyMode::Full => "full",
    };

    Ok(VerifyReport {
        mode: mode.to_string(),
        success: false,
        notes: vec!["verification pipeline not implemented yet".to_string()],
    })
}
