use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::application::ports::{AuditLog, EvidenceCopier};
use crate::domain::audit::{AuditAction, CopyAttemptContext, EvidenceCopyContext};
use crate::domain::evidence::VerifiedCopy;

const EVIDENCE_DIRECTORY: &str = "evidence";

/// Copies evidence into `<case_directory>/evidence/working-<uuid>.<ext>` and audits the attempt.
/// Analysis and extraction must read the returned working copy, not the original source.
pub fn copy_evidence_for_analysis(
    logger: &mut impl AuditLog,
    copier: &impl EvidenceCopier,
    case_id: Uuid,
    case_directory: &Path,
    source: &Path,
) -> io::Result<VerifiedCopy> {
    let relative_destination =
        PathBuf::from(EVIDENCE_DIRECTORY).join(working_copy_file_name(source));
    let destination = case_directory.join(&relative_destination);
    let source_path = source.to_string_lossy().into_owned();
    let destination_path = relative_destination.to_string_lossy().into_owned();

    logger.log_copy_attempt(
        case_id,
        AuditAction::EvidenceCopyStarted,
        CopyAttemptContext {
            source_path: source_path.clone(),
            destination_path: destination_path.clone(),
            error: None,
        },
    )?;

    let copy = fs::create_dir_all(case_directory.join(EVIDENCE_DIRECTORY))
        .and_then(|()| copier.copy_verified(source, &destination));

    match copy {
        Ok(copy) => {
            logger.log_evidence_copy(
                case_id,
                EvidenceCopyContext {
                    original_path: source_path,
                    working_copy_path: destination_path,
                    original_sha256: copy.sha256.clone(),
                    working_copy_sha256: copy.sha256.clone(),
                    size_bytes: copy.size_bytes,
                },
            )?;
            Ok(copy)
        }
        Err(error) => {
            logger.log_copy_attempt(
                case_id,
                AuditAction::EvidenceCopyFailed,
                CopyAttemptContext {
                    source_path,
                    destination_path,
                    error: Some(error.to_string()),
                },
            )?;
            Err(error)
        }
    }
}

fn working_copy_file_name(source: &Path) -> String {
    match source.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => format!("working-{}.{extension}", Uuid::new_v4()),
        None => format!("working-{}", Uuid::new_v4()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::adapters::FsEvidenceCopier;
    use crate::infrastructure::audit::{AuditLogger, read_verified_audit};
    use crate::infrastructure::hashing::sha256_file;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bitsplayer_{name}_{}", Uuid::new_v4()))
    }

    #[test]
    fn successful_copy_is_audited_between_started_and_completed() {
        let case_dir = temp_dir("evidence_copy_ok");
        fs::create_dir_all(&case_dir).unwrap();
        let source = case_dir.join("input.mp4");
        fs::write(&source, b"evidence bytes").unwrap();
        let case_id = Uuid::new_v4();
        let audit_path = case_dir.join("logs").join("audit.jsonl");

        let mut logger = AuditLogger::new(&audit_path).unwrap();
        let copy =
            copy_evidence_for_analysis(&mut logger, &FsEvidenceCopier, case_id, &case_dir, &source)
                .unwrap();
        drop(logger);

        assert!(
            copy.copy_path
                .starts_with(case_dir.join(EVIDENCE_DIRECTORY))
        );
        assert_eq!(copy.sha256, sha256_file(&source).unwrap());

        let entries = read_verified_audit(&audit_path, case_id).unwrap();
        let actions: Vec<AuditAction> = entries.iter().map(|entry| entry.action).collect();
        assert_eq!(
            actions,
            vec![
                AuditAction::EvidenceCopyStarted,
                AuditAction::EvidenceCopyCompleted
            ]
        );
        let completed = entries[1].copy_context.as_ref().unwrap();
        assert_eq!(completed.original_sha256, copy.sha256);
        assert_eq!(completed.working_copy_sha256, copy.sha256);

        fs::remove_dir_all(case_dir).unwrap();
    }

    #[test]
    fn failed_copy_is_audited_and_not_reported_as_success() {
        let case_dir = temp_dir("evidence_copy_failed");
        fs::create_dir_all(&case_dir).unwrap();
        let source = case_dir.join("missing.mp4");
        let case_id = Uuid::new_v4();
        let audit_path = case_dir.join("logs").join("audit.jsonl");

        let mut logger = AuditLogger::new(&audit_path).unwrap();
        let result =
            copy_evidence_for_analysis(&mut logger, &FsEvidenceCopier, case_id, &case_dir, &source);
        drop(logger);

        assert!(result.is_err());
        let entries = read_verified_audit(&audit_path, case_id).unwrap();
        let actions: Vec<AuditAction> = entries.iter().map(|entry| entry.action).collect();
        assert_eq!(
            actions,
            vec![
                AuditAction::EvidenceCopyStarted,
                AuditAction::EvidenceCopyFailed
            ]
        );
        let failure = entries[1].copy_attempt_context.as_ref().unwrap();
        assert!(
            failure
                .error
                .as_deref()
                .is_some_and(|error| !error.is_empty())
        );

        fs::remove_dir_all(case_dir).unwrap();
    }
}
