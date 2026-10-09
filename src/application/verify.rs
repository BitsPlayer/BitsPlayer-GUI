use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::domain::audit::{AuditAction, AuditEntry, AuditResult, CopyAttemptContext};
use crate::domain::case::{CASE_SCHEMA_VERSION, Case};
use crate::domain::closure::{CLOSURE_SCHEMA_VERSION, CaseClosure};
use crate::domain::signing::{CaseSignature, SIGNATURE_SCHEMA_VERSION};
use crate::infrastructure::audit::read_verified_audit;
use crate::infrastructure::hashing::sha256_file;
use crate::infrastructure::report::load_manifest;
use crate::infrastructure::signing::load_verifying_key;

#[derive(Debug, Clone, Default)]
pub struct VerificationReport {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
}

impl VerificationReport {
    fn ok(&mut self, message: impl Into<String>) {
        self.checks.push(message.into());
    }

    fn warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }
}

pub fn verify_case(
    case_directory: &Path,
    artifact_directory: Option<&Path>,
    trusted_public_key: &Path,
) -> Result<VerificationReport, String> {
    let directories = artifact_directory
        .map(|directory| vec![directory.to_path_buf()])
        .unwrap_or_default();
    verify_case_directories(case_directory, &directories, trusted_public_key)
}

/// Verifies a sealed case. Artifact filenames are resolved across every
/// supplied directory and must match exactly one file.
pub fn verify_case_directories(
    case_directory: &Path,
    artifact_directories: &[PathBuf],
    trusted_public_key: &Path,
) -> Result<VerificationReport, String> {
    let mut summary = VerificationReport::default();

    if !case_directory.exists() {
        return Err(format!(
            "case directory does not exist: {}",
            case_directory.display()
        ));
    }
    if !case_directory.is_dir() {
        return Err(format!(
            "case path is not a directory: {}",
            case_directory.display()
        ));
    }
    summary.ok(format!(
        "case directory exists: {}",
        case_directory.display()
    ));

    let case_path = case_directory.join("case.json");
    let audit_path = case_directory.join("logs").join("audit.jsonl");
    let closure_path = case_directory.join("case_closure.json");
    let signature_path = case_directory.join("case_signature.json");

    let case = Case::load(&case_path).map_err(|error| format!("invalid case.json: {error}"))?;
    summary.ok("case.json parsed successfully");

    if case.schema_version != CASE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported case.json schema version: expected {}, found {}",
            CASE_SCHEMA_VERSION, case.schema_version
        ));
    }
    summary.ok(format!(
        "case.json schema version {} is supported",
        case.schema_version
    ));

    let actual_case_hash =
        sha256_file(&case_path).map_err(|error| format!("failed to hash case.json: {error}"))?;
    summary.ok(format!("case.json SHA-256 = {actual_case_hash}"));

    let entries = read_verified_audit(&audit_path, case.id)?;
    summary.ok(format!("audit chain valid: {} entries", entries.len()));

    let first_entry = entries
        .first()
        .ok_or_else(|| String::from("audit log contains no entries"))?;

    if first_entry.action != AuditAction::CaseCreated {
        return Err(format!(
            "first audit action must be CASE_CREATED, found {:?}",
            first_entry.action
        ));
    }
    summary.ok("first audit entry is CASE_CREATED");

    verify_operation_context(&case, &entries, &mut summary)?;
    verify_carve_ordering(&entries, &mut summary)?;
    verify_copy_lifecycle(&entries, &mut summary)?;
    verify_evidence_copies(&entries, case_directory, &mut summary)?;

    let created_case_hash = first_entry
        .case_metadata_sha256
        .as_deref()
        .ok_or_else(|| String::from("CASE_CREATED does not contain case_metadata_sha256"))?;

    let metadata_was_updated = entries
        .iter()
        .any(|entry| entry.action == AuditAction::CaseMetadataUpdated);

    if metadata_was_updated {
        summary
            .warning("case metadata update exists; CASE_CREATED hash represents original metadata");
    } else if created_case_hash != actual_case_hash {
        return Err(format!(
            "case.json hash mismatch: audit records {created_case_hash}, current file is {actual_case_hash}"
        ));
    } else {
        summary.ok("case.json matches CASE_CREATED metadata hash");
    }

    let last_entry = entries
        .last()
        .ok_or_else(|| String::from("audit log contains no final entry"))?;

    if let Some(abandoned) = entries
        .iter()
        .find(|entry| entry.action == AuditAction::CaseAbandoned)
    {
        return Err(format!(
            "case was abandoned without sealing at sequence {}",
            abandoned.sequence
        ));
    }

    if last_entry.action != AuditAction::CaseClosed {
        return Err(format!(
            "case is not sealed: final audit action is {:?}, expected CASE_CLOSED",
            last_entry.action
        ));
    }
    summary.ok("final audit entry is CASE_CLOSED");

    let final_case_hash = last_entry
        .case_metadata_sha256
        .as_deref()
        .ok_or_else(|| String::from("CASE_CLOSED does not contain case_metadata_sha256"))?;
    if final_case_hash != actual_case_hash {
        return Err(format!(
            "current case.json does not match CASE_CLOSED metadata hash: expected {final_case_hash}, found {actual_case_hash}"
        ));
    }
    summary.ok("current case.json matches CASE_CLOSED metadata hash");

    let closure = CaseClosure::load(&closure_path)
        .map_err(|error| format!("invalid case_closure.json: {error}"))?;
    summary.ok("case_closure.json parsed successfully");

    if closure.schema_version != CLOSURE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported case closure schema: expected {}, found {}",
            CLOSURE_SCHEMA_VERSION, closure.schema_version
        ));
    }
    summary.ok(format!(
        "case closure schema version {} is supported",
        closure.schema_version
    ));

    if closure.case_id != case.id {
        return Err(format!(
            "case_closure.json case ID {} does not match case.json ID {}",
            closure.case_id, case.id
        ));
    }
    summary.ok("case closure ID matches case.json");

    if closure.final_sequence != last_entry.sequence {
        return Err(format!(
            "closure final_sequence mismatch: closure={}, audit={}",
            closure.final_sequence, last_entry.sequence
        ));
    }
    summary.ok(format!(
        "closure final sequence matches audit ({})",
        closure.final_sequence
    ));

    if closure.total_entries != entries.len() as u64 {
        return Err(format!(
            "closure total_entries mismatch: closure={}, actual={}",
            closure.total_entries,
            entries.len()
        ));
    }
    summary.ok(format!(
        "closure entry count matches audit ({})",
        closure.total_entries
    ));

    if closure.final_head_hash != last_entry.entry_hash {
        return Err(format!(
            "closure final head hash mismatch: closure={}, audit={}",
            closure.final_head_hash, last_entry.entry_hash
        ));
    }
    summary.ok("closure final head hash matches final audit entry");

    let case_signature = CaseSignature::load(&signature_path)
        .map_err(|error| format!("invalid case_signature.json: {error}"))?;
    summary.ok("case_signature.json parsed successfully");
    verify_signature(
        &case_signature,
        &case,
        &closure,
        last_entry,
        &actual_case_hash,
        trusted_public_key,
        &mut summary,
    )?;
    verify_report_bindings(case_directory, &closure, &case_signature, &mut summary)?;

    verify_artifact_entries(&entries, artifact_directories, &mut summary)?;
    verify_provenance(&entries, &mut summary)?;
    Ok(summary)
}

fn verify_operation_context(
    case: &Case,
    entries: &[AuditEntry],
    summary: &mut VerificationReport,
) -> Result<(), String> {
    let first = entries
        .first()
        .ok_or_else(|| String::from("cannot verify context: empty audit log"))?;

    for entry in entries {
        if entry.host_context != first.host_context {
            return Err(format!(
                "host/examiner context changed inside audit at sequence {}",
                entry.sequence
            ));
        }
    }
    summary.ok("host/examiner context is consistent across all audit entries");

    if case.examiner != first.host_context.examiner {
        return Err(format!(
            "case examiner does not match audit host context: case={:?}, audit={:?}",
            case.examiner, first.host_context.examiner
        ));
    }
    summary.ok("case examiner matches audit examiner context");

    if first.host_context.operating_system.trim().is_empty() {
        return Err(String::from("audit operating_system is empty"));
    }
    if first.host_context.architecture.trim().is_empty() {
        return Err(String::from("audit architecture is empty"));
    }
    summary.ok(format!(
        "audit host context recorded: examiner={:?}, host={:?}, os={}, arch={}",
        first.host_context.examiner,
        first.host_context.host_name,
        first.host_context.operating_system,
        first.host_context.architecture
    ));

    for entry in entries {
        match entry.action {
            AuditAction::CarveAnalysisStarted | AuditAction::CarveAnalysisCompleted => {
                let context = entry.operation_context.as_ref().ok_or_else(|| {
                    format!(
                        "{:?} sequence {} is missing operation_context",
                        entry.action, entry.sequence
                    )
                })?;
                if context
                    .evidence_path
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(format!(
                        "{:?} sequence {} is missing evidence_path",
                        entry.action, entry.sequence
                    ));
                }
                if context.extraction_parameters.is_some() {
                    return Err(format!(
                        "{:?} sequence {} unexpectedly contains extraction parameters",
                        entry.action, entry.sequence
                    ));
                }
                let parameters = context.carve_parameters.as_ref().ok_or_else(|| {
                    format!(
                        "{:?} sequence {} is missing carve_parameters",
                        entry.action, entry.sequence
                    )
                })?;
                if parameters.width == 0 || parameters.height == 0 {
                    return Err(format!(
                        "{:?} sequence {} contains invalid carve dimensions {}x{}",
                        entry.action, entry.sequence, parameters.width, parameters.height
                    ));
                }
            }
            AuditAction::EvidenceRegistered
            | AuditAction::AnalysisStarted
            | AuditAction::AnalysisCompleted
            | AuditAction::IntegrityVerification => {
                let context = entry.operation_context.as_ref().ok_or_else(|| {
                    format!(
                        "{:?} sequence {} is missing operation_context",
                        entry.action, entry.sequence
                    )
                })?;
                if context
                    .evidence_path
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(format!(
                        "{:?} sequence {} is missing evidence_path",
                        entry.action, entry.sequence
                    ));
                }
                if context.extraction_parameters.is_some() {
                    return Err(format!(
                        "{:?} sequence {} unexpectedly contains extraction parameters",
                        entry.action, entry.sequence
                    ));
                }
                if context.carve_parameters.is_some() {
                    return Err(format!(
                        "{:?} sequence {} unexpectedly contains carve parameters",
                        entry.action, entry.sequence
                    ));
                }
            }
            AuditAction::ExtractStarted | AuditAction::ExtractCompleted => {
                let context = entry.operation_context.as_ref().ok_or_else(|| {
                    format!(
                        "{:?} sequence {} is missing operation_context",
                        entry.action, entry.sequence
                    )
                })?;
                if context
                    .evidence_path
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(format!(
                        "{:?} sequence {} is missing evidence_path",
                        entry.action, entry.sequence
                    ));
                }
                let parameters = context.extraction_parameters.as_ref().ok_or_else(|| {
                    format!(
                        "{:?} sequence {} is missing extraction_parameters",
                        entry.action, entry.sequence
                    )
                })?;
                if parameters.width == 0 || parameters.height == 0 {
                    return Err(format!(
                        "{:?} sequence {} contains invalid extraction dimensions {}x{}",
                        entry.action, entry.sequence, parameters.width, parameters.height
                    ));
                }
            }
            AuditAction::ArtifactCreated => {
                if let Some(context) = entry.operation_context.as_ref() {
                    if context
                        .evidence_path
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .is_empty()
                    {
                        return Err(format!(
                            "ARTIFACT_CREATED sequence {} contains an empty evidence_path",
                            entry.sequence
                        ));
                    }
                }
            }
            AuditAction::AnalysisFailed
            | AuditAction::CarveAnalysisFailed
            | AuditAction::ExtractFailed => {}
            AuditAction::CaseCreated
            | AuditAction::CaseMetadataUpdated
            | AuditAction::CaseClosed
            | AuditAction::CaseAbandoned
            | AuditAction::EvidenceCopyStarted
            | AuditAction::EvidenceCopyCompleted
            | AuditAction::EvidenceCopyFailed => {}
        }
    }

    summary.ok("operation context is structurally valid for analysis/extraction entries");
    Ok(())
}

fn verify_carve_ordering(
    entries: &[AuditEntry],
    summary: &mut VerificationReport,
) -> Result<(), String> {
    let has_carve = entries.iter().any(|entry| {
        matches!(
            entry.action,
            AuditAction::CarveAnalysisStarted
                | AuditAction::CarveAnalysisCompleted
                | AuditAction::CarveAnalysisFailed
        )
    });
    if !has_carve {
        summary.ok("no carve analysis rows; extraction ordering rules unchanged");
        return Ok(());
    }

    let mut verified_paths: Vec<&str> = Vec::new();
    let mut completed_carves: Vec<(&str, u32, u32)> = Vec::new();
    for entry in entries {
        let context = entry.operation_context.as_ref();
        let path = context
            .and_then(|context| context.evidence_path.as_deref())
            .unwrap_or("");
        match entry.action {
            AuditAction::IntegrityVerification if entry.result == AuditResult::Verified => {
                verified_paths.push(path);
            }
            AuditAction::CarveAnalysisStarted => {
                if !verified_paths.contains(&path) {
                    return Err(format!(
                        "CARVE_ANALYSIS_STARTED sequence {} is not preceded by a verified INTEGRITY_VERIFICATION for {path}",
                        entry.sequence
                    ));
                }
            }
            AuditAction::CarveAnalysisCompleted => {
                if let Some(parameters) = context.and_then(|c| c.carve_parameters.as_ref()) {
                    completed_carves.push((path, parameters.width, parameters.height));
                }
            }
            AuditAction::ExtractStarted => {
                let parameters = context
                    .and_then(|context| context.extraction_parameters.as_ref())
                    .ok_or_else(|| {
                        format!(
                            "EXTRACT_STARTED sequence {} is missing extraction_parameters",
                            entry.sequence
                        )
                    })?;
                let carve = completed_carves
                    .iter()
                    .rev()
                    .find(|(carve_path, _, _)| *carve_path == path)
                    .ok_or_else(|| {
                        format!(
                            "EXTRACT_STARTED sequence {} is not preceded by a CARVE_ANALYSIS_COMPLETED for {path}",
                            entry.sequence
                        )
                    })?;
                if carve.1 != parameters.width || carve.2 != parameters.height {
                    return Err(format!(
                        "EXTRACT_STARTED sequence {} uses {}x{} but the completed carve analysis used {}x{}",
                        entry.sequence, parameters.width, parameters.height, carve.1, carve.2
                    ));
                }
            }
            _ => {}
        }
    }

    summary.ok("carve analysis follows verified integrity and precedes every extraction");
    Ok(())
}

const EVIDENCE_DIRECTORY: &str = "evidence";

fn is_evidence_relative_path(path: &str) -> bool {
    match path.strip_prefix("evidence/") {
        Some(name) => artifact_file_path(Path::new(EVIDENCE_DIRECTORY), name).is_ok(),
        None => false,
    }
}

fn verify_copy_lifecycle(
    entries: &[AuditEntry],
    summary: &mut VerificationReport,
) -> Result<(), String> {
    let mut pending: Option<&CopyAttemptContext> = None;
    let mut copy_ready = false;

    for entry in entries {
        if entry.action != AuditAction::EvidenceCopyCompleted && entry.copy_context.is_some() {
            return Err(format!(
                "unexpected evidence copy context at sequence {}",
                entry.sequence
            ));
        }
        let is_copy_attempt = matches!(
            entry.action,
            AuditAction::EvidenceCopyStarted | AuditAction::EvidenceCopyFailed
        );
        if !is_copy_attempt && entry.copy_attempt_context.is_some() {
            return Err(format!(
                "unexpected copy attempt context at sequence {}",
                entry.sequence
            ));
        }

        match entry.action {
            AuditAction::EvidenceCopyStarted => {
                if pending.is_some() {
                    return Err(format!(
                        "overlapping evidence copy attempts at sequence {}",
                        entry.sequence
                    ));
                }
                let context = entry.copy_attempt_context.as_ref().ok_or_else(|| {
                    format!(
                        "EVIDENCE_COPY_STARTED sequence {} is missing copy attempt context",
                        entry.sequence
                    )
                })?;
                if entry.result != AuditResult::Started
                    || context.error.is_some()
                    || context.source_path.trim().is_empty()
                    || !is_evidence_relative_path(&context.destination_path)
                {
                    return Err(format!(
                        "invalid EVIDENCE_COPY_STARTED at sequence {}: destination must be evidence/<name>",
                        entry.sequence
                    ));
                }
                pending = Some(context);
                copy_ready = false;
            }
            AuditAction::EvidenceCopyCompleted => {
                let started = pending.take().ok_or_else(|| {
                    format!(
                        "EVIDENCE_COPY_COMPLETED without EVIDENCE_COPY_STARTED at sequence {}",
                        entry.sequence
                    )
                })?;
                let completed = entry.copy_context.as_ref().ok_or_else(|| {
                    format!(
                        "EVIDENCE_COPY_COMPLETED sequence {} is missing copy context",
                        entry.sequence
                    )
                })?;
                if entry.result != AuditResult::Success
                    || started.source_path != completed.original_path
                    || started.destination_path != completed.working_copy_path
                {
                    return Err(format!(
                        "EVIDENCE_COPY_COMPLETED at sequence {} does not match its started attempt",
                        entry.sequence
                    ));
                }
                copy_ready = true;
            }
            AuditAction::EvidenceCopyFailed => {
                let started = pending.take().ok_or_else(|| {
                    format!(
                        "EVIDENCE_COPY_FAILED without EVIDENCE_COPY_STARTED at sequence {}",
                        entry.sequence
                    )
                })?;
                let failed = entry.copy_attempt_context.as_ref().ok_or_else(|| {
                    format!(
                        "EVIDENCE_COPY_FAILED sequence {} is missing copy attempt context",
                        entry.sequence
                    )
                })?;
                if entry.result != AuditResult::Failed
                    || started.source_path != failed.source_path
                    || started.destination_path != failed.destination_path
                    || failed
                        .error
                        .as_deref()
                        .is_none_or(|error| error.trim().is_empty())
                {
                    return Err(format!(
                        "EVIDENCE_COPY_FAILED at sequence {} does not match its started attempt",
                        entry.sequence
                    ));
                }
                copy_ready = false;
            }
            AuditAction::AnalysisStarted | AuditAction::EvidenceRegistered => {
                if pending.is_some() || !copy_ready {
                    return Err(format!(
                        "{:?} at sequence {} requires a completed evidence copy",
                        entry.action, entry.sequence
                    ));
                }
            }
            AuditAction::CaseClosed if pending.is_some() => {
                return Err(format!(
                    "case closed while an evidence copy is pending at sequence {}",
                    entry.sequence
                ));
            }
            _ => {}
        }
    }

    if pending.is_some() {
        return Err(String::from("unterminated evidence copy attempt"));
    }
    summary.ok("evidence copy lifecycle is consistent");
    Ok(())
}

fn verify_evidence_copies(
    entries: &[AuditEntry],
    case_directory: &Path,
    summary: &mut VerificationReport,
) -> Result<(), String> {
    let completed: Vec<&AuditEntry> = entries
        .iter()
        .filter(|entry| entry.action == AuditAction::EvidenceCopyCompleted)
        .collect();
    if completed.is_empty() {
        summary.ok("no evidence working copies to verify");
        return Ok(());
    }

    let canonical_case = fs::canonicalize(case_directory)
        .map_err(|error| format!("cannot canonicalize case directory: {error}"))?;
    let evidence_directory = canonical_case.join(EVIDENCE_DIRECTORY);

    for entry in completed {
        let copy = entry.copy_context.as_ref().ok_or_else(|| {
            format!(
                "EVIDENCE_COPY_COMPLETED sequence {} is missing copy context",
                entry.sequence
            )
        })?;
        if copy.original_path.trim().is_empty() {
            return Err(format!(
                "EVIDENCE_COPY_COMPLETED sequence {} has an empty original path",
                entry.sequence
            ));
        }
        let hash_is_valid = copy.original_sha256.len() == 64
            && copy
                .original_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit());
        if !hash_is_valid || copy.original_sha256 != copy.working_copy_sha256 {
            return Err(format!(
                "invalid or mismatched source/working-copy SHA-256 at sequence {}",
                entry.sequence
            ));
        }
        if entry.evidence_sha256.as_deref() != Some(copy.original_sha256.as_str()) {
            return Err(format!(
                "EVIDENCE_COPY_COMPLETED sequence {} evidence hash does not match the source hash",
                entry.sequence
            ));
        }
        if !is_evidence_relative_path(&copy.working_copy_path) {
            return Err(format!(
                "working copy path must be evidence/<name>: {}",
                copy.working_copy_path
            ));
        }

        let path = case_directory.join(&copy.working_copy_path);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "working copy missing or unreadable {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file() {
            return Err(format!(
                "working copy must be a regular non-symlink file: {}",
                path.display()
            ));
        }
        let canonical_copy = fs::canonicalize(&path).map_err(|error| {
            format!(
                "working copy missing or unreadable {}: {error}",
                path.display()
            )
        })?;
        if canonical_copy.parent() != Some(evidence_directory.as_path()) {
            return Err(format!(
                "working copy is outside the case evidence directory: {}",
                path.display()
            ));
        }
        if metadata.len() != copy.size_bytes {
            return Err(format!(
                "working copy size mismatch for {}: audit={}, actual={}",
                copy.working_copy_path,
                copy.size_bytes,
                metadata.len()
            ));
        }

        let actual_hash = sha256_file(&path)
            .map_err(|error| format!("failed to hash working copy {}: {error}", path.display()))?;
        if actual_hash != copy.working_copy_sha256 {
            return Err(format!(
                "working copy SHA-256 mismatch for {}: audit={}, actual={actual_hash}",
                copy.working_copy_path, copy.working_copy_sha256
            ));
        }
        summary.ok(format!(
            "evidence working copy verified: {}",
            copy.working_copy_path
        ));
    }

    Ok(())
}

fn verify_signature(
    signature_file: &CaseSignature,
    case: &Case,
    closure: &CaseClosure,
    final_entry: &AuditEntry,
    actual_case_hash: &str,
    trusted_public_key_path: &Path,
    summary: &mut VerificationReport,
) -> Result<(), String> {
    if signature_file.schema_version != SIGNATURE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported case signature schema: expected {}, found {}",
            SIGNATURE_SCHEMA_VERSION, signature_file.schema_version
        ));
    }
    summary.ok(format!(
        "case signature schema version {} is supported",
        signature_file.schema_version
    ));

    if signature_file.case_id != case.id {
        return Err(format!(
            "signature case ID mismatch: signature={}, case={}",
            signature_file.case_id, case.id
        ));
    }
    summary.ok("signature case ID matches case.json");

    if signature_file.final_sequence != closure.final_sequence
        || signature_file.final_sequence != final_entry.sequence
    {
        return Err(String::from(
            "signature final_sequence does not match closure/audit",
        ));
    }
    summary.ok("signature final sequence matches closure and audit");

    if signature_file.final_head_hash != closure.final_head_hash
        || signature_file.final_head_hash != final_entry.entry_hash
    {
        return Err(String::from(
            "signature final_head_hash does not match closure/audit",
        ));
    }
    summary.ok("signature final head hash matches closure and audit");

    if signature_file.case_metadata_sha256 != actual_case_hash {
        return Err(format!(
            "signature case metadata hash mismatch: signature={}, actual={}",
            signature_file.case_metadata_sha256, actual_case_hash
        ));
    }
    summary.ok("signature case metadata hash matches case.json");

    let trusted_key = load_verifying_key(trusted_public_key_path).map_err(|error| {
        format!(
            "failed to read trusted public key {}: {error}",
            trusted_public_key_path.display()
        )
    })?;
    summary.ok(format!(
        "trusted public key loaded from {}",
        trusted_public_key_path.display()
    ));

    signature_file
        .verify(&trusted_key)
        .map_err(|error| format!("Ed25519 case signature verification failed: {error}"))?;
    summary.ok("embedded public key matches the trusted key");
    summary.ok("Ed25519 case signature is cryptographically valid");
    Ok(())
}

fn verify_report_bindings(
    case_directory: &Path,
    closure: &CaseClosure,
    signature_file: &CaseSignature,
    summary: &mut VerificationReport,
) -> Result<(), String> {
    let closure_manifest_sha256 = closure
        .report_manifest_sha256
        .as_deref()
        .ok_or_else(|| String::from("case_closure.json does not contain report_manifest_sha256"))?;
    let signature_manifest_sha256 = signature_file
        .report_manifest_sha256
        .as_deref()
        .ok_or_else(|| {
            String::from("case_signature.json does not contain report_manifest_sha256")
        })?;
    if closure_manifest_sha256 != signature_manifest_sha256 {
        return Err(format!(
            "report manifest hash mismatch: closure={closure_manifest_sha256}, signature={signature_manifest_sha256}"
        ));
    }
    summary.ok("closure and signature bind the same report manifest hash");

    let manifest_path = case_directory.join("report_manifest.json");
    let manifest_sha256 = sha256_file(&manifest_path)
        .map_err(|error| format!("failed to hash report_manifest.json: {error}"))?;
    if manifest_sha256 != closure_manifest_sha256 {
        return Err(format!(
            "report_manifest.json hash mismatch: expected {closure_manifest_sha256}, found {manifest_sha256}"
        ));
    }
    summary.ok("report_manifest.json matches closure and signature");

    let manifest = load_manifest(&manifest_path)
        .map_err(|error| format!("invalid report_manifest.json: {error}"))?;

    let report_files = [
        ("report.json", &manifest.report_json_sha256),
        ("report.html", &manifest.report_html_sha256),
    ];
    for (filename, expected) in report_files {
        let actual = sha256_file(&case_directory.join(filename))
            .map_err(|error| format!("failed to hash {filename}: {error}"))?;
        if &actual != expected {
            return Err(format!(
                "{filename} hash mismatch: manifest={expected}, actual={actual}"
            ));
        }
        summary.ok(format!("{filename} matches report_manifest.json"));
    }
    Ok(())
}

fn verify_provenance(
    entries: &[AuditEntry],
    summary: &mut VerificationReport,
) -> Result<(), String> {
    let first = entries
        .first()
        .ok_or_else(|| String::from("cannot verify provenance: empty audit log"))?;

    if first.git_commit.is_empty()
        || first.git_commit == "UNKNOWN"
        || first.cargo_lock_sha256 == "UNKNOWN"
        || first.cargo_lock_sha256.len() != 64
    {
        return Err(String::from(
            "audit build provenance is incomplete; refusing to accept the case",
        ));
    }

    for entry in entries {
        if entry.tool_version != first.tool_version {
            return Err(format!(
                "tool version changed inside audit at sequence {}",
                entry.sequence
            ));
        }
        if entry.git_commit != first.git_commit {
            return Err(format!(
                "Git commit changed inside audit at sequence {}",
                entry.sequence
            ));
        }
        if entry.cargo_lock_sha256 != first.cargo_lock_sha256 {
            return Err(format!(
                "Cargo.lock hash changed inside audit at sequence {}",
                entry.sequence
            ));
        }
        if entry.binary_sha256 != first.binary_sha256 {
            return Err(format!(
                "binary hash changed inside audit at sequence {}",
                entry.sequence
            ));
        }
    }

    summary.ok(format!(
        "build provenance is consistent across all entries (version {}, commit {})",
        first.tool_version, first.git_commit
    ));
    Ok(())
}

pub fn artifact_file_path(directory: &Path, filename: &str) -> Result<PathBuf, String> {
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains('\0')
        || filename == "."
        || filename == ".."
    {
        return Err(format!(
            "artifact filename is not a single path segment: {filename}"
        ));
    }

    let mut components = Path::new(filename).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) if name.to_str() == Some(filename) => {}
        _ => {
            return Err(format!(
                "artifact filename is not a single path segment: {filename}"
            ));
        }
    }

    Ok(directory.join(filename))
}

fn verify_artifact_entries(
    entries: &[AuditEntry],
    artifact_directories: &[PathBuf],
    summary: &mut VerificationReport,
) -> Result<(), String> {
    let artifact_entries: Vec<&AuditEntry> = entries
        .iter()
        .filter(|entry| entry.action == AuditAction::ArtifactCreated)
        .collect();

    if artifact_entries.is_empty() {
        summary.ok("no ARTIFACT_CREATED entries to verify");
        return Ok(());
    }

    summary.ok(format!(
        "{} artifact audit entr{} present",
        artifact_entries.len(),
        if artifact_entries.len() == 1 {
            "y"
        } else {
            "ies"
        }
    ));

    if artifact_directories.is_empty() {
        return Err(String::from(
            "artifact records exist, but --artifact-dir was not supplied; refusing to treat the case as verified",
        ));
    }

    for directory in artifact_directories {
        if !directory.is_dir() {
            return Err(format!(
                "artifact directory does not exist or is not a directory: {}",
                directory.display()
            ));
        }
    }

    for entry in artifact_entries {
        let filename = entry.artifact_filename.as_deref().ok_or_else(|| {
            format!(
                "ARTIFACT_CREATED sequence {} has no artifact_filename",
                entry.sequence
            )
        })?;
        let expected_hash = entry.artifact_sha256.as_deref().ok_or_else(|| {
            format!(
                "ARTIFACT_CREATED sequence {} has no artifact_sha256",
                entry.sequence
            )
        })?;
        let expected_size = entry.artifact_size_bytes.ok_or_else(|| {
            format!(
                "ARTIFACT_CREATED sequence {} has no artifact_size_bytes",
                entry.sequence
            )
        })?;
        if entry.source_evidence_sha256.is_none() {
            return Err(format!(
                "ARTIFACT_CREATED sequence {} is not linked to source evidence",
                entry.sequence
            ));
        }

        let path = locate_artifact(artifact_directories, filename)?;
        let metadata = std::fs::metadata(&path).map_err(|error| {
            format!("artifact missing or unreadable {}: {error}", path.display())
        })?;
        if !metadata.is_file() {
            return Err(format!(
                "artifact is not a regular file: {}",
                path.display()
            ));
        }
        if metadata.len() != expected_size {
            return Err(format!(
                "artifact size mismatch for {filename}: audit={expected_size}, actual={}",
                metadata.len()
            ));
        }

        let actual_hash = sha256_file(&path)
            .map_err(|error| format!("failed to hash artifact {}: {error}", path.display()))?;
        if actual_hash != expected_hash {
            return Err(format!(
                "artifact SHA-256 mismatch for {filename}: audit={expected_hash}, actual={actual_hash}"
            ));
        }
        summary.ok(format!("artifact verified: {filename}"));
    }

    Ok(())
}

fn locate_artifact(directories: &[PathBuf], filename: &str) -> Result<PathBuf, String> {
    let mut found = Vec::new();
    let mut seen_directories = Vec::new();

    for directory in directories {
        let key = std::fs::canonicalize(directory).unwrap_or_else(|_| directory.clone());
        if seen_directories.iter().any(|existing| existing == &key) {
            continue;
        }
        seen_directories.push(key);

        let path = artifact_file_path(directory, filename)?;
        if path.is_file() {
            found.push(path);
        }
    }

    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(format!(
            "artifact missing or unreadable: {filename} was not found in the supplied artifact directories"
        )),
        _ => Err(format!(
            "artifact filename {filename} matches more than one file across the supplied directories"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::seal::seal_case_with_identity;
    use crate::domain::artifact::ArtifactRecord;
    use crate::domain::audit::EvidenceCopyContext;
    use crate::domain::audit::{AuditAction, AuditResult};
    use crate::domain::context::{
        CarveParameters, ExtractionParameters, HostContext, OperationContext,
    };
    use crate::infrastructure::audit::AuditLogger;
    use crate::infrastructure::evidence_copy::create_verified_copy;
    use crate::infrastructure::signing::SigningIdentity;
    use chrono::Utc;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("bitsplayer_{name}_{unique}"))
    }

    fn seal_empty_case(key_dir: &Path) -> (Case, SigningIdentity) {
        let host = HostContext::collect();
        let case_dir = temp_dir("case");
        let case = Case::new("Session", host.examiner.clone(), case_dir);
        case.save().unwrap();
        let hash = case.metadata_sha256().unwrap();
        let mut logger =
            AuditLogger::new(case.case_directory.join("logs").join("audit.jsonl")).unwrap();
        logger
            .log(
                case.id,
                AuditAction::CaseCreated,
                None,
                None,
                Some(hash),
                AuditResult::Success,
            )
            .unwrap();
        let identity = SigningIdentity::load_or_create_in(key_dir).unwrap();
        seal_case_with_identity(&mut logger, &case, &identity).unwrap();
        drop(logger);
        (case, identity)
    }

    #[test]
    fn sealed_case_verifies_until_the_audit_or_key_is_changed() {
        let key_dir = temp_dir("keys");
        let (case, identity) = seal_empty_case(&key_dir);
        let public_key = identity.public_key_path();

        verify_case(&case.case_directory, None, &public_key).unwrap();

        let audit_path = case.case_directory.join("logs").join("audit.jsonl");
        let mut raw = fs::read(&audit_path).unwrap();
        let flip_at = raw.iter().position(|byte| *byte == b'a').unwrap();
        raw[flip_at] = b'b';
        fs::write(&audit_path, raw).unwrap();
        assert!(verify_case(&case.case_directory, None, &public_key).is_err());

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn swapped_public_key_fails_verification() {
        let key_dir = temp_dir("keys_swap");
        let other_dir = temp_dir("keys_other");
        let (case, identity) = seal_empty_case(&key_dir);
        let other = SigningIdentity::load_or_create_in(&other_dir).unwrap();

        let signature_path = case.case_directory.join("case_signature.json");
        let mut signature = CaseSignature::load(&signature_path).unwrap();
        signature.public_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            other.verifying_key().to_bytes(),
        );
        fs::remove_file(&signature_path).unwrap();
        signature.save(&case.case_directory).unwrap();

        assert!(verify_case(&case.case_directory, None, &identity.public_key_path()).is_err());
        assert!(verify_case(&case.case_directory, None, &other.public_key_path()).is_err());

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
        let _ = fs::remove_dir_all(other_dir);
    }

    #[test]
    fn sealed_report_files_are_bound_to_the_seal() {
        let key_dir = temp_dir("keys_report");
        let (case, identity) = seal_empty_case(&key_dir);
        let public_key = identity.public_key_path();

        let report = verify_case(&case.case_directory, None, &public_key).unwrap();
        assert!(
            report
                .checks
                .iter()
                .any(|check| check == "report.html matches report_manifest.json")
        );
        assert!(case.case_directory.join("report.json").is_file());
        assert!(case.case_directory.join("report.html").is_file());
        assert!(case.case_directory.join("report_manifest.json").is_file());

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn tampered_report_files_fail_verification() {
        let key_dir = temp_dir("keys_report_tamper");
        let (case, identity) = seal_empty_case(&key_dir);
        let public_key = identity.public_key_path();

        let html_path = case.case_directory.join("report.html");
        let original_html = fs::read(&html_path).unwrap();
        fs::write(&html_path, b"<html>edited</html>").unwrap();
        assert!(verify_case(&case.case_directory, None, &public_key).is_err());
        fs::write(&html_path, original_html).unwrap();
        verify_case(&case.case_directory, None, &public_key).unwrap();

        let json_path = case.case_directory.join("report.json");
        let original_json = fs::read(&json_path).unwrap();
        fs::write(&json_path, b"{}").unwrap();
        assert!(verify_case(&case.case_directory, None, &public_key).is_err());
        fs::write(&json_path, original_json).unwrap();

        let manifest_path = case.case_directory.join("report_manifest.json");
        let original_manifest = fs::read(&manifest_path).unwrap();
        fs::write(&manifest_path, b"{}").unwrap();
        assert!(verify_case(&case.case_directory, None, &public_key).is_err());
        fs::write(&manifest_path, original_manifest).unwrap();
        verify_case(&case.case_directory, None, &public_key).unwrap();

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn closure_and_signature_must_bind_the_same_report_manifest() {
        let key_dir = temp_dir("keys_report_binding");
        let (case, identity) = seal_empty_case(&key_dir);
        let public_key = identity.public_key_path();

        let closure_path = case.case_directory.join("case_closure.json");
        let mut closure = CaseClosure::load(&closure_path).unwrap();
        closure.report_manifest_sha256 = None;
        fs::remove_file(&closure_path).unwrap();
        closure.save(&case.case_directory).unwrap();
        assert!(verify_case(&case.case_directory, None, &public_key).is_err());

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn second_seal_does_not_remove_existing_report_files() {
        let key_dir = temp_dir("keys_reseal");
        let (case, identity) = seal_empty_case(&key_dir);
        let public_key = identity.public_key_path();

        let mut logger =
            AuditLogger::new(case.case_directory.join("logs").join("audit.jsonl")).unwrap();
        assert!(seal_case_with_identity(&mut logger, &case, &identity).is_err());
        drop(logger);

        assert!(case.case_directory.join("report.json").is_file());
        assert!(case.case_directory.join("report_manifest.json").is_file());
        verify_case(&case.case_directory, None, &public_key).unwrap();

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
    }

    #[test]
    fn artifact_names_cannot_escape_the_artifact_directory() {
        let key_dir = temp_dir("keys_artifact");
        let host = HostContext::collect();
        let case = Case::new("Session", host.examiner.clone(), temp_dir("case_artifact"));
        case.save().unwrap();
        let hash = case.metadata_sha256().unwrap();
        let mut logger =
            AuditLogger::new(case.case_directory.join("logs").join("audit.jsonl")).unwrap();
        logger
            .log(
                case.id,
                AuditAction::CaseCreated,
                None,
                None,
                Some(hash),
                AuditResult::Success,
            )
            .unwrap();

        let artifact = ArtifactRecord {
            path: PathBuf::from("../outside.png"),
            filename: String::from("../outside.png"),
            artifact_type: String::from("RECOVERED_FRAME_PNG"),
            size_bytes: 3,
            sha256: String::from("abc"),
            source_evidence_sha256: String::from("def"),
            created_at: Utc::now(),
        };
        logger.log_artifact(case.id, None, None, &artifact).unwrap();

        let identity = SigningIdentity::load_or_create_in(&key_dir).unwrap();
        seal_case_with_identity(&mut logger, &case, &identity).unwrap();
        drop(logger);

        let artifact_dir = temp_dir("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        let error = verify_case(
            &case.case_directory,
            Some(&artifact_dir),
            &identity.public_key_path(),
        )
        .unwrap_err();
        assert!(
            error.contains("single path segment"),
            "unexpected error: {error}"
        );
        assert!(artifact_file_path(&artifact_dir, "../outside.png").is_err());
        assert!(artifact_file_path(&artifact_dir, "frame.png").is_ok());

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn artifact_entries_require_an_artifact_directory() {
        let key_dir = temp_dir("keys_require_dir");
        let host = HostContext::collect();
        let case = Case::new("Session", host.examiner.clone(), temp_dir("case_require"));
        case.save().unwrap();
        let metadata_hash = case.metadata_sha256().unwrap();
        let mut logger =
            AuditLogger::new(case.case_directory.join("logs").join("audit.jsonl")).unwrap();
        logger
            .log(
                case.id,
                AuditAction::CaseCreated,
                None,
                None,
                Some(metadata_hash),
                AuditResult::Success,
            )
            .unwrap();

        let artifact_dir = temp_dir("real_artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        let artifact_path = artifact_dir.join("frame.png");
        fs::write(&artifact_path, b"png").unwrap();
        let artifact =
            ArtifactRecord::from_existing_file(&artifact_path, "RECOVERED_FRAME_PNG", "evidence")
                .unwrap();
        logger
            .log_artifact(
                case.id,
                Some(String::from("clip.mp4")),
                Some(String::from("evidence")),
                &artifact,
            )
            .unwrap();

        let identity = SigningIdentity::load_or_create_in(&key_dir).unwrap();
        seal_case_with_identity(&mut logger, &case, &identity).unwrap();
        drop(logger);

        let missing = verify_case(&case.case_directory, None, &identity.public_key_path());
        assert!(missing.is_err());
        verify_case(
            &case.case_directory,
            Some(&artifact_dir),
            &identity.public_key_path(),
        )
        .unwrap();

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
        let _ = fs::remove_dir_all(artifact_dir);
    }

    #[test]
    fn artifact_lookup_searches_every_supplied_directory() {
        let key_dir = temp_dir("keys_multi_dir");
        let host = HostContext::collect();
        let case = Case::new("Session", host.examiner.clone(), temp_dir("case_multi"));
        case.save().unwrap();
        let metadata_hash = case.metadata_sha256().unwrap();
        let mut logger =
            AuditLogger::new(case.case_directory.join("logs").join("audit.jsonl")).unwrap();
        logger
            .log(
                case.id,
                AuditAction::CaseCreated,
                None,
                None,
                Some(metadata_hash),
                AuditResult::Success,
            )
            .unwrap();

        let first_dir = temp_dir("artifacts_a");
        let second_dir = temp_dir("artifacts_b");
        fs::create_dir_all(&first_dir).unwrap();
        fs::create_dir_all(&second_dir).unwrap();
        let first_path = first_dir.join("frame_a.png");
        let second_path = second_dir.join("frame_b.png");
        fs::write(&first_path, b"one").unwrap();
        fs::write(&second_path, b"two").unwrap();
        let first =
            ArtifactRecord::from_existing_file(&first_path, "RECOVERED_FRAME_PNG", "evidence")
                .unwrap();
        let second =
            ArtifactRecord::from_existing_file(&second_path, "RECOVERED_FRAME_PNG", "evidence")
                .unwrap();
        logger.log_artifact(case.id, None, None, &first).unwrap();
        logger.log_artifact(case.id, None, None, &second).unwrap();

        let identity = SigningIdentity::load_or_create_in(&key_dir).unwrap();
        seal_case_with_identity(&mut logger, &case, &identity).unwrap();
        drop(logger);

        let public_key = identity.public_key_path();
        verify_case_directories(
            &case.case_directory,
            &[first_dir.clone(), second_dir.clone()],
            &public_key,
        )
        .unwrap();

        let missing =
            verify_case_directories(&case.case_directory, &[first_dir.clone()], &public_key);
        assert!(
            missing.is_err(),
            "a single directory cannot cover both artifacts"
        );

        let duplicate_dir = temp_dir("artifacts_dup");
        fs::create_dir_all(&duplicate_dir).unwrap();
        fs::write(duplicate_dir.join("frame_b.png"), b"other").unwrap();
        let ambiguous = verify_case_directories(
            &case.case_directory,
            &[first_dir.clone(), second_dir.clone(), duplicate_dir.clone()],
            &public_key,
        )
        .unwrap_err();
        assert!(
            ambiguous.contains("more than one file"),
            "unexpected error: {ambiguous}"
        );

        let _ = fs::remove_dir_all(&case.case_directory);
        let _ = fs::remove_dir_all(key_dir);
        let _ = fs::remove_dir_all(first_dir);
        let _ = fs::remove_dir_all(second_dir);
        let _ = fs::remove_dir_all(duplicate_dir);
    }

    fn copy_attempt(destination: &str, error: Option<&str>) -> CopyAttemptContext {
        CopyAttemptContext {
            source_path: String::from("/evidence/source.mp4"),
            destination_path: destination.to_string(),
            error: error.map(str::to_string),
        }
    }

    fn audit_entries(
        name: &str,
        steps: impl FnOnce(&mut AuditLogger, uuid::Uuid),
    ) -> Vec<AuditEntry> {
        let dir = temp_dir(name);
        fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.jsonl");
        let case_id = uuid::Uuid::new_v4();
        let mut logger = AuditLogger::new(&audit_path).unwrap();
        steps(&mut logger, case_id);
        drop(logger);
        let entries = read_verified_audit(&audit_path, case_id).unwrap();
        let _ = fs::remove_dir_all(dir);
        entries
    }

    #[test]
    fn copy_lifecycle_allows_registration_only_after_a_completed_copy() {
        let entries = audit_entries("copy_lifecycle_ok", |logger, case_id| {
            logger
                .log_copy_attempt(
                    case_id,
                    AuditAction::EvidenceCopyStarted,
                    copy_attempt("evidence/working-1.mp4", None),
                )
                .unwrap();
            logger
                .log_evidence_copy(
                    case_id,
                    EvidenceCopyContext {
                        original_path: String::from("/evidence/source.mp4"),
                        working_copy_path: String::from("evidence/working-1.mp4"),
                        original_sha256: "a".repeat(64),
                        working_copy_sha256: "a".repeat(64),
                        size_bytes: 3,
                    },
                )
                .unwrap();
            logger
                .log(
                    case_id,
                    AuditAction::EvidenceRegistered,
                    None,
                    None,
                    None,
                    AuditResult::Success,
                )
                .unwrap();
        });
        let mut summary = VerificationReport::default();
        verify_copy_lifecycle(&entries, &mut summary).unwrap();
    }

    #[test]
    fn copy_lifecycle_rejects_registration_without_a_copy() {
        let entries = audit_entries("copy_lifecycle_none", |logger, case_id| {
            logger
                .log(
                    case_id,
                    AuditAction::EvidenceRegistered,
                    None,
                    None,
                    None,
                    AuditResult::Success,
                )
                .unwrap();
        });
        let mut summary = VerificationReport::default();
        let error = verify_copy_lifecycle(&entries, &mut summary).unwrap_err();
        assert!(
            error.contains("requires a completed evidence copy"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn copy_lifecycle_rejects_analysis_after_a_failed_copy() {
        let entries = audit_entries("copy_lifecycle_failed", |logger, case_id| {
            logger
                .log_copy_attempt(
                    case_id,
                    AuditAction::EvidenceCopyStarted,
                    copy_attempt("evidence/working-1.mp4", None),
                )
                .unwrap();
            logger
                .log_copy_attempt(
                    case_id,
                    AuditAction::EvidenceCopyFailed,
                    copy_attempt("evidence/working-1.mp4", Some("disk full")),
                )
                .unwrap();
            logger
                .log(
                    case_id,
                    AuditAction::AnalysisStarted,
                    None,
                    None,
                    None,
                    AuditResult::Started,
                )
                .unwrap();
        });
        let mut summary = VerificationReport::default();
        let error = verify_copy_lifecycle(&entries, &mut summary).unwrap_err();
        assert!(
            error.contains("requires a completed evidence copy"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn copy_lifecycle_rejects_overlapping_and_unterminated_attempts() {
        let overlapping = audit_entries("copy_lifecycle_overlap", |logger, case_id| {
            for _ in 0..2 {
                logger
                    .log_copy_attempt(
                        case_id,
                        AuditAction::EvidenceCopyStarted,
                        copy_attempt("evidence/working-1.mp4", None),
                    )
                    .unwrap();
            }
        });
        let mut summary = VerificationReport::default();
        let error = verify_copy_lifecycle(&overlapping, &mut summary).unwrap_err();
        assert!(error.contains("overlapping"), "unexpected error: {error}");

        let unterminated = audit_entries("copy_lifecycle_unterminated", |logger, case_id| {
            logger
                .log_copy_attempt(
                    case_id,
                    AuditAction::EvidenceCopyStarted,
                    copy_attempt("evidence/working-1.mp4", None),
                )
                .unwrap();
        });
        let error = verify_copy_lifecycle(&unterminated, &mut summary).unwrap_err();
        assert!(error.contains("unterminated"), "unexpected error: {error}");
    }

    #[test]
    fn copy_destination_must_be_a_single_name_inside_evidence() {
        let entries = audit_entries("copy_lifecycle_escape", |logger, case_id| {
            logger
                .log_copy_attempt(
                    case_id,
                    AuditAction::EvidenceCopyStarted,
                    copy_attempt("../escape.mp4", None),
                )
                .unwrap();
        });
        let mut summary = VerificationReport::default();
        let error = verify_copy_lifecycle(&entries, &mut summary).unwrap_err();
        assert!(
            error.contains("destination must be evidence/<name>"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn evidence_working_copy_must_match_the_audit() {
        let case_dir = temp_dir("evidence_copy_verify");
        let evidence_dir = case_dir.join("evidence");
        fs::create_dir_all(&evidence_dir).unwrap();
        let source = case_dir.join("input.mp4");
        fs::write(&source, b"evidence bytes").unwrap();
        let working = evidence_dir.join("working-1.mp4");
        let copy = create_verified_copy(&source, &working).unwrap();

        let entries = audit_entries("evidence_copy_audit", |logger, case_id| {
            logger
                .log_evidence_copy(
                    case_id,
                    EvidenceCopyContext {
                        original_path: source.to_string_lossy().into_owned(),
                        working_copy_path: String::from("evidence/working-1.mp4"),
                        original_sha256: copy.sha256.clone(),
                        working_copy_sha256: copy.sha256.clone(),
                        size_bytes: copy.size_bytes,
                    },
                )
                .unwrap();
        });

        let mut summary = VerificationReport::default();
        verify_evidence_copies(&entries, &case_dir, &mut summary).unwrap();

        let mut permissions = fs::metadata(&working).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o600);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        fs::set_permissions(&working, permissions).unwrap();
        fs::write(&working, b"evidence BYTES").unwrap();
        let error = verify_evidence_copies(&entries, &case_dir, &mut summary).unwrap_err();
        assert!(
            error.contains("SHA-256 mismatch"),
            "unexpected error: {error}"
        );

        let _ = fs::remove_dir_all(case_dir);
    }

    fn carve_context(path: &str, width: u32, height: u32) -> OperationContext {
        let mut context = OperationContext::evidence(Path::new(path));
        context.carve_parameters = Some(CarveParameters {
            width,
            height,
            with_audio: false,
        });
        context
    }

    fn extract_context(path: &str, width: u32, height: u32) -> OperationContext {
        OperationContext::extraction(
            Path::new(path),
            ExtractionParameters {
                width,
                height,
                matrix: String::from("BT.709"),
                include_non_idr: false,
                include_partial: false,
                with_audio: false,
                all_frames: false,
                frame_offset: None,
            },
        )
    }

    fn log_step(
        logger: &mut AuditLogger,
        case_id: uuid::Uuid,
        action: AuditAction,
        result: AuditResult,
        context: OperationContext,
    ) {
        logger
            .log_with_context(case_id, action, None, None, None, result, context)
            .unwrap();
    }

    fn check_context_and_carve(entries: &[AuditEntry]) -> Result<(), String> {
        let case = Case::new(
            "t",
            entries[0].host_context.examiner.clone(),
            PathBuf::from("/tmp/unused"),
        );
        let mut summary = VerificationReport::default();
        verify_operation_context(&case, entries, &mut summary)?;
        verify_carve_ordering(entries, &mut summary)
    }

    const EV: &str = "evidence/working-1.mp4";

    fn integrity(logger: &mut AuditLogger, case_id: uuid::Uuid) {
        log_step(
            logger,
            case_id,
            AuditAction::IntegrityVerification,
            AuditResult::Verified,
            OperationContext::evidence(Path::new(EV)),
        );
    }

    fn carve_pair(logger: &mut AuditLogger, case_id: uuid::Uuid, width: u32, height: u32) {
        log_step(
            logger,
            case_id,
            AuditAction::CarveAnalysisStarted,
            AuditResult::Started,
            carve_context(EV, width, height),
        );
        log_step(
            logger,
            case_id,
            AuditAction::CarveAnalysisCompleted,
            AuditResult::Success,
            carve_context(EV, width, height),
        );
    }

    fn extract_started(logger: &mut AuditLogger, case_id: uuid::Uuid, width: u32, height: u32) {
        log_step(
            logger,
            case_id,
            AuditAction::ExtractStarted,
            AuditResult::Started,
            extract_context(EV, width, height),
        );
    }

    #[test]
    fn carve_then_matching_extract_is_accepted() {
        let entries = audit_entries("carve_ok", |logger, case_id| {
            integrity(logger, case_id);
            carve_pair(logger, case_id, 64, 48);
            extract_started(logger, case_id, 64, 48);
        });
        check_context_and_carve(&entries).unwrap();
    }

    #[test]
    fn extract_dimensions_must_match_the_completed_carve() {
        let entries = audit_entries("carve_mismatch", |logger, case_id| {
            integrity(logger, case_id);
            carve_pair(logger, case_id, 64, 48);
            extract_started(logger, case_id, 64, 32);
        });
        let error = check_context_and_carve(&entries).unwrap_err();
        assert!(error.contains("64x32"), "unexpected error: {error}");
    }

    #[test]
    fn extract_without_a_completed_carve_is_rejected_once_carving_is_used() {
        let entries = audit_entries("carve_missing_before_extract", |logger, case_id| {
            integrity(logger, case_id);
            extract_started(logger, case_id, 64, 48);
            carve_pair(logger, case_id, 64, 48);
        });
        assert!(check_context_and_carve(&entries).is_err());
    }

    #[test]
    fn carve_before_verified_integrity_is_rejected() {
        let entries = audit_entries("carve_before_integrity", |logger, case_id| {
            carve_pair(logger, case_id, 64, 48);
            integrity(logger, case_id);
        });
        let error = check_context_and_carve(&entries).unwrap_err();
        assert!(
            error.contains("INTEGRITY_VERIFICATION"),
            "unexpected error: {error}"
        );

        let entries = audit_entries("carve_unverified_integrity", |logger, case_id| {
            log_step(
                logger,
                case_id,
                AuditAction::IntegrityVerification,
                AuditResult::Unverified,
                OperationContext::evidence(Path::new(EV)),
            );
            carve_pair(logger, case_id, 64, 48);
        });
        assert!(check_context_and_carve(&entries).is_err());
    }

    #[test]
    fn carve_rows_require_parameters() {
        let entries = audit_entries("carve_no_params", |logger, case_id| {
            integrity(logger, case_id);
            log_step(
                logger,
                case_id,
                AuditAction::CarveAnalysisStarted,
                AuditResult::Started,
                OperationContext::evidence(Path::new(EV)),
            );
        });
        let error = check_context_and_carve(&entries).unwrap_err();
        assert!(
            error.contains("carve_parameters"),
            "unexpected error: {error}"
        );

        let entries = audit_entries("carve_zero_dims", |logger, case_id| {
            integrity(logger, case_id);
            carve_pair(logger, case_id, 0, 48);
        });
        assert!(check_context_and_carve(&entries).is_err());
    }

    #[test]
    fn analysis_rows_must_not_carry_carve_parameters() {
        let entries = audit_entries("analysis_with_carve", |logger, case_id| {
            log_step(
                logger,
                case_id,
                AuditAction::AnalysisStarted,
                AuditResult::Started,
                carve_context(EV, 64, 48),
            );
        });
        assert!(check_context_and_carve(&entries).is_err());
    }

    #[test]
    fn legacy_case_without_carve_rows_still_passes() {
        let entries = audit_entries("carve_legacy", |logger, case_id| {
            integrity(logger, case_id);
            extract_started(logger, case_id, 64, 48);
        });
        check_context_and_carve(&entries).unwrap();
    }
}
