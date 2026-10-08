use std::{fs, io, path::PathBuf};

use crate::forensic::audit::AuditLogger;
use crate::forensic::case::Case;
use crate::forensic::closure::CaseClosure;
use crate::forensic::signing::{IdentityOrigin, SigningIdentity};

#[derive(Debug, Clone)]
pub struct SealReport {
    pub closure_path: PathBuf,
    pub signature_path: PathBuf,
    pub identity_origin: IdentityOrigin,
    pub signing_directory: PathBuf,
}

pub fn seal_case(logger: &mut AuditLogger, case: &Case) -> io::Result<SealReport> {
    let identity = SigningIdentity::load_or_create()?;
    seal_case_with_identity(logger, case, &identity)
}

pub fn seal_case_with_identity(
    logger: &mut AuditLogger,
    case: &Case,
    identity: &SigningIdentity,
) -> io::Result<SealReport> {
    let case_metadata_sha256 = case.metadata_sha256()?;
    let closed_entry = logger.prepare_case_closed(case.id, Some(case_metadata_sha256.clone()))?;
    let signature = identity.sign_case(
        case.id,
        closed_entry.sequence,
        &closed_entry.entry_hash,
        &case_metadata_sha256,
    )?;

    let signature_path = match signature.save(&case.case_directory) {
        Ok(path) => path,
        Err(err) => return Err(err),
    };

    let closure = CaseClosure::new(
        case.id,
        closed_entry.sequence,
        closed_entry.entry_hash.clone(),
    );
    let closure_path = match closure.save(&case.case_directory) {
        Ok(path) => path,
        Err(err) => {
            let _ = fs::remove_file(&signature_path);
            return Err(err);
        }
    };

    if let Err(err) = logger.commit_prepared(&closed_entry) {
        let _ = fs::remove_file(&signature_path);
        let _ = fs::remove_file(&closure_path);
        return Err(err);
    }

    Ok(SealReport {
        closure_path,
        signature_path,
        identity_origin: identity.origin(),
        signing_directory: identity.directory().to_path_buf(),
    })
}
