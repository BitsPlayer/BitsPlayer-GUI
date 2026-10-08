use std::path::{Component, Path, PathBuf};

use crate::forensic::audit::{read_verified_audit, AuditAction, AuditEntry};
use crate::forensic::case::{Case, CASE_SCHEMA_VERSION};
use crate::forensic::closure::{CaseClosure, CLOSURE_SCHEMA_VERSION};
use crate::forensic::hashing::sha256_file;
use crate::forensic::signing::{load_verifying_key, CaseSignature, SIGNATURE_SCHEMA_VERSION};

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

    let actual_case_hash = sha256_file(&case_path)
        .map_err(|error| format!("failed to hash case.json: {error}"))?;
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

    let created_case_hash = first_entry
        .case_metadata_sha256
        .as_deref()
        .ok_or_else(|| String::from("CASE_CREATED does not contain case_metadata_sha256"))?;

    let metadata_was_updated = entries
        .iter()
        .any(|entry| entry.action == AuditAction::CaseMetadataUpdated);

    if metadata_was_updated {
        summary.warning(
            "case metadata update exists; CASE_CREATED hash represents original metadata",
        );
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

    verify_artifact_entries(&entries, artifact_directory, &mut summary)?;
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
                if context.evidence_path.as_deref().unwrap_or("").trim().is_empty() {
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
            }
            AuditAction::ExtractStarted | AuditAction::ExtractCompleted => {
                let context = entry.operation_context.as_ref().ok_or_else(|| {
                    format!(
                        "{:?} sequence {} is missing operation_context",
                        entry.action, entry.sequence
                    )
                })?;
                if context.evidence_path.as_deref().unwrap_or("").trim().is_empty() {
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
                    if context.evidence_path.as_deref().unwrap_or("").trim().is_empty() {
                        return Err(format!(
                            "ARTIFACT_CREATED sequence {} contains an empty evidence_path",
                            entry.sequence
                        ));
                    }
                }
            }
            AuditAction::AnalysisFailed | AuditAction::ExtractFailed => {}
            AuditAction::CaseCreated
            | AuditAction::CaseMetadataUpdated
            | AuditAction::CaseClosed => {}
        }
    }

    summary.ok("operation context is structurally valid for analysis/extraction entries");
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
    artifact_directory: Option<&Path>,
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

    let Some(directory) = artifact_directory else {
        return Err(String::from(
            "artifact records exist, but --artifact-dir was not supplied; refusing to treat the case as verified",
        ));
    };

    if !directory.is_dir() {
        return Err(format!(
            "artifact directory does not exist or is not a directory: {}",
            directory.display()
        ));
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

        let path = artifact_file_path(directory, filename)?;
        let metadata = std::fs::metadata(&path).map_err(|error| {
            format!("artifact missing or unreadable {}: {error}", path.display())
        })?;
        if !metadata.is_file() {
            return Err(format!("artifact is not a regular file: {}", path.display()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forensic::artifact::ArtifactRecord;
    use crate::forensic::audit::{AuditAction, AuditLogger, AuditResult};
    use crate::forensic::context::HostContext;
    use crate::forensic::seal::seal_case_with_identity;
    use crate::forensic::signing::SigningIdentity;
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
        let mut logger = AuditLogger::new(case.case_directory.join("logs").join("audit.jsonl")).unwrap();
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
        logger
            .log_artifact(case.id, None, None, &artifact)
            .unwrap();

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
        let artifact = ArtifactRecord::from_existing_file(&artifact_path, "RECOVERED_FRAME_PNG", "evidence")
            .unwrap();
        logger
            .log_artifact(case.id, Some(String::from("clip.mp4")), Some(String::from("evidence")), &artifact)
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
}
