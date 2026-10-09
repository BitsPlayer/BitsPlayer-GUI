use std::fs;

use uuid::Uuid;

use bitsplayer::application::evidence_copy::copy_evidence_for_analysis;
use bitsplayer::domain::audit::AuditAction;
use bitsplayer::infrastructure::adapters::FsEvidenceCopier;
use bitsplayer::infrastructure::audit::{AuditLogger, read_verified_audit, verify_audit_log};

#[test]
fn failed_copy_is_audited_and_blocks_analysis() {
    let case_directory =
        std::env::temp_dir().join(format!("bitsplayer_copy_failure_{}", Uuid::new_v4()));
    fs::create_dir_all(&case_directory).unwrap();
    let audit_path = case_directory.join("logs").join("audit.jsonl");
    let case_id = Uuid::new_v4();
    let missing_source = case_directory.join("missing-source.mp4");

    let mut logger = AuditLogger::new(&audit_path).unwrap();
    let result = copy_evidence_for_analysis(
        &mut logger,
        &FsEvidenceCopier,
        case_id,
        &case_directory,
        &missing_source,
    );
    drop(logger);

    assert!(result.is_err(), "copy of a missing source must fail");

    assert!(verify_audit_log(&audit_path).unwrap().valid);
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

    let evidence_files = fs::read_dir(case_directory.join("evidence"))
        .unwrap()
        .count();
    assert_eq!(evidence_files, 0, "no working copy may be left behind");

    let content = fs::read_to_string(&audit_path).unwrap();
    assert!(content.contains("EVIDENCE_COPY_FAILED"));
    assert!(
        !content.contains("ANALYSIS_STARTED"),
        "analysis must not start after a copy failure"
    );

    fs::remove_dir_all(case_directory).unwrap();
}
