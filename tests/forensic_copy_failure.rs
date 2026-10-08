use std::fs;

use uuid::Uuid;

use bitsplayer::forensic::audit::{
    verify_audit_log,
    AuditAction,
    AuditLogger,
    CopyAttemptContext,
    AuditResult,
};

fn temp_log(name: &str) -> std::path::PathBuf {
    let id = Uuid::new_v4();

    std::env::temp_dir()
        .join(format!(
            "bitsplayer_stage_d_{name}_{id}.jsonl"
        ))
}


#[test]
fn failed_copy_blocks_analysis_lifecycle() {

    let path = temp_log("copy_failure");

    let case_id = Uuid::new_v4();


    let mut logger =
        AuditLogger::new(&path)
            .expect("audit logger should initialize");


    logger
        .log(
            case_id,
            AuditAction::CaseCreated,
            None,
            None,
            Some("casehash".into()),
            AuditResult::Success,
        )
        .unwrap();


    logger
        .log_copy_attempt(
            case_id,
            AuditAction::EvidenceCopyStarted,
            CopyAttemptContext {
                source_path:
                    "/tmp/missing-source.mp4".into(),

                destination_path:
                    "evidence/working-test.mp4".into(),

                error:
                    None,
            },
        )
        .unwrap();



    logger
        .log_copy_attempt(
            case_id,
            AuditAction::EvidenceCopyFailed,
            CopyAttemptContext {
                source_path:
                    "/tmp/missing-source.mp4".into(),

                destination_path:
                    "evidence/working-test.mp4".into(),

                error:
                    Some(
                        "source file missing".into()
                    ),
            },
        )
        .unwrap();



    logger
        .close_case(
            case_id,
            Some("casehash".into()),
        )
        .unwrap();



    drop(logger);


    let verification =
        verify_audit_log(&path)
            .unwrap();


    assert!(
        verification.valid,
        "audit chain should remain valid"
    );


    let content =
        fs::read_to_string(&path)
            .unwrap();


    assert!(
        content.contains(
            "EVIDENCE_COPY_FAILED"
        )
    );


    assert!(
        !content.contains(
            "ANALYSIS_STARTED"
        ),
        "analysis must not start after copy failure"
    );


    fs::remove_file(path)
        .unwrap();
}
