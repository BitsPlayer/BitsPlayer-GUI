use std::{fs, io, path::PathBuf};

use crate::application::ports::{AuditLog, CaseStore, Signer};
use crate::application::report::{SealedReport, seal_case_report};
use crate::domain::case::Case;
use crate::domain::closure::CaseClosure;
use crate::domain::signing::IdentityOrigin;

#[derive(Debug, Clone)]
pub struct SealReport {
    pub closure_path: PathBuf,
    pub signature_path: PathBuf,
    pub identity_origin: IdentityOrigin,
    pub signing_directory: PathBuf,
}

pub fn seal_case_with_identity(
    logger: &mut impl AuditLog,
    case: &Case,
    identity: &impl Signer,
) -> io::Result<SealReport> {
    let case_metadata_sha256 = CaseStore::metadata_sha256(case)?;
    let report = seal_case_report(case)?;

    match seal_closure(logger, case, identity, &case_metadata_sha256, &report) {
        Ok(seal) => Ok(seal),
        Err(err) => {
            report.remove();
            Err(err)
        }
    }
}

fn seal_closure(
    logger: &mut impl AuditLog,
    case: &Case,
    identity: &impl Signer,
    case_metadata_sha256: &str,
    report: &SealedReport,
) -> io::Result<SealReport> {
    let closed_entry =
        logger.prepare_case_closed(case.id, Some(case_metadata_sha256.to_string()))?;
    let signature = identity.sign_case(
        case.id,
        closed_entry.sequence,
        &closed_entry.entry_hash,
        case_metadata_sha256,
        &report.manifest_sha256,
    )?;

    let signature_path = signature.save(&case.case_directory)?;

    let closure = CaseClosure::new(
        case.id,
        closed_entry.sequence,
        closed_entry.entry_hash.clone(),
        Some(report.manifest_sha256.clone()),
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
