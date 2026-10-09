use chrono::Utc;
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

use crate::domain::artifact::ArtifactRecord;
pub use crate::domain::audit::{
    AUDIT_SCHEMA_VERSION, AuditAction, AuditEntry, AuditResult, AuditVerification,
    CopyAttemptContext, EvidenceCopyContext,
};
use crate::domain::audit::{AuditFields, calculate_entry_hash, hash_of_entry};
use crate::domain::context::{HostContext, OperationContext};
use crate::domain::provenance::BuildProvenance;

#[derive(Default)]
struct CopyContexts {
    copy: Option<EvidenceCopyContext>,
    attempt: Option<CopyAttemptContext>,
}

#[derive(Debug)]
pub struct AuditLogger {
    path: PathBuf,
    file: File,
    provenance: BuildProvenance,
    host_context: HostContext,
    last_hash: Option<String>,
    next_sequence: u64,
}

impl AuditLogger {
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .append(true)
            .open(&path)?;

        file.try_lock_exclusive().map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "audit log is already locked by another process: {}: {err}",
                    path.display()
                ),
            )
        })?;

        let verification = match verify_audit_log(&path) {
            Ok(result) => result,
            Err(err) => {
                let _ = FileExt::unlock(&file);
                return Err(err);
            }
        };

        if !verification.valid {
            let message = verification
                .error
                .unwrap_or_else(|| String::from("existing audit log failed verification"));
            let _ = FileExt::unlock(&file);
            return Err(io::Error::new(io::ErrorKind::InvalidData, message));
        }

        let provenance = match BuildProvenance::collect() {
            Ok(value) => value,
            Err(err) => {
                let _ = FileExt::unlock(&file);
                return Err(io::Error::new(
                    err.kind(),
                    format!("failed to collect build provenance: {err}"),
                ));
            }
        };

        let host_context = HostContext::collect();

        Ok(Self {
            path,
            file,
            provenance,
            host_context,
            last_hash: verification.last_hash,
            next_sequence: verification.last_sequence.saturating_add(1),
        })
    }

    pub fn log(
        &mut self,
        case_id: Uuid,
        action: AuditAction,
        evidence_filename: Option<String>,
        evidence_sha256: Option<String>,
        case_metadata_sha256: Option<String>,
        result: AuditResult,
    ) -> io::Result<AuditEntry> {
        self.log_internal(
            case_id,
            action,
            result,
            evidence_filename,
            evidence_sha256,
            case_metadata_sha256,
            None,
            None,
            None,
            None,
            None,
            None,
            CopyContexts::default(),
        )
    }

    pub fn log_with_context(
        &mut self,
        case_id: Uuid,
        action: AuditAction,
        evidence_filename: Option<String>,
        evidence_sha256: Option<String>,
        case_metadata_sha256: Option<String>,
        result: AuditResult,
        operation_context: OperationContext,
    ) -> io::Result<AuditEntry> {
        self.log_internal(
            case_id,
            action,
            result,
            evidence_filename,
            evidence_sha256,
            case_metadata_sha256,
            None,
            None,
            None,
            None,
            None,
            Some(operation_context),
            CopyContexts::default(),
        )
    }

    pub fn log_artifact(
        &mut self,
        case_id: Uuid,
        evidence_filename: Option<String>,
        evidence_sha256: Option<String>,
        artifact: &ArtifactRecord,
    ) -> io::Result<AuditEntry> {
        self.log_artifact_with_context(case_id, evidence_filename, evidence_sha256, artifact, None)
    }

    pub fn log_artifact_with_context(
        &mut self,
        case_id: Uuid,
        evidence_filename: Option<String>,
        evidence_sha256: Option<String>,
        artifact: &ArtifactRecord,
        operation_context: Option<OperationContext>,
    ) -> io::Result<AuditEntry> {
        self.log_internal(
            case_id,
            AuditAction::ArtifactCreated,
            AuditResult::Success,
            evidence_filename,
            evidence_sha256,
            None,
            Some(artifact.filename.clone()),
            Some(artifact.sha256.clone()),
            Some(artifact.artifact_type.clone()),
            Some(artifact.size_bytes),
            Some(artifact.source_evidence_sha256.clone()),
            operation_context,
            CopyContexts::default(),
        )
    }

    pub fn log_evidence_copy(
        &mut self,
        case_id: Uuid,
        context: EvidenceCopyContext,
    ) -> io::Result<AuditEntry> {
        let evidence_filename = Path::new(&context.original_path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        let evidence_sha256 = Some(context.original_sha256.clone());
        self.log_internal(
            case_id,
            AuditAction::EvidenceCopyCompleted,
            AuditResult::Success,
            evidence_filename,
            evidence_sha256,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            CopyContexts {
                copy: Some(context),
                attempt: None,
            },
        )
    }

    pub fn log_copy_attempt(
        &mut self,
        case_id: Uuid,
        action: AuditAction,
        context: CopyAttemptContext,
    ) -> io::Result<AuditEntry> {
        let result = match (action, context.error.as_deref()) {
            (AuditAction::EvidenceCopyStarted, None) => AuditResult::Started,
            (AuditAction::EvidenceCopyFailed, Some(error)) if !error.trim().is_empty() => {
                AuditResult::Failed
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid copy attempt action or error",
                ));
            }
        };
        self.log_internal(
            case_id,
            action,
            result,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            CopyContexts {
                copy: None,
                attempt: Some(context),
            },
        )
    }

    fn log_internal(
        &mut self,
        case_id: Uuid,
        action: AuditAction,
        result: AuditResult,
        evidence_filename: Option<String>,
        evidence_sha256: Option<String>,
        case_metadata_sha256: Option<String>,
        artifact_filename: Option<String>,
        artifact_sha256: Option<String>,
        artifact_type: Option<String>,
        artifact_size_bytes: Option<u64>,
        source_evidence_sha256: Option<String>,
        operation_context: Option<OperationContext>,
        copy_contexts: CopyContexts,
    ) -> io::Result<AuditEntry> {
        let entry = self.build_entry(
            case_id,
            action,
            result,
            evidence_filename,
            evidence_sha256,
            case_metadata_sha256,
            artifact_filename,
            artifact_sha256,
            artifact_type,
            artifact_size_bytes,
            source_evidence_sha256,
            operation_context,
            copy_contexts,
        )?;
        self.commit_entry(&entry)?;
        Ok(entry)
    }

    fn build_entry(
        &self,
        case_id: Uuid,
        action: AuditAction,
        result: AuditResult,
        evidence_filename: Option<String>,
        evidence_sha256: Option<String>,
        case_metadata_sha256: Option<String>,
        artifact_filename: Option<String>,
        artifact_sha256: Option<String>,
        artifact_type: Option<String>,
        artifact_size_bytes: Option<u64>,
        source_evidence_sha256: Option<String>,
        operation_context: Option<OperationContext>,
        copy_contexts: CopyContexts,
    ) -> io::Result<AuditEntry> {
        let timestamp = Utc::now();
        let sequence = self.next_sequence;
        let previous_entry_hash = self.last_hash.clone();

        let fields = AuditFields {
            evidence_filename: evidence_filename.as_deref(),
            evidence_sha256: evidence_sha256.as_deref(),
            case_metadata_sha256: case_metadata_sha256.as_deref(),
            artifact_filename: artifact_filename.as_deref(),
            artifact_sha256: artifact_sha256.as_deref(),
            artifact_type: artifact_type.as_deref(),
            artifact_size_bytes,
            source_evidence_sha256: source_evidence_sha256.as_deref(),
            copy_context: copy_contexts.copy.as_ref(),
            copy_attempt_context: copy_contexts.attempt.as_ref(),
        };

        let entry_hash = calculate_entry_hash(
            AUDIT_SCHEMA_VERSION,
            sequence,
            &timestamp,
            case_id,
            &action,
            &result,
            &self.provenance,
            &fields,
            &self.host_context,
            operation_context.as_ref(),
            previous_entry_hash.as_deref(),
        )?;

        Ok(AuditEntry {
            schema_version: AUDIT_SCHEMA_VERSION,
            sequence,
            timestamp,
            case_id,
            action,
            result,
            tool_version: self.provenance.tool_version.clone(),
            git_commit: self.provenance.git_commit.clone(),
            cargo_lock_sha256: self.provenance.cargo_lock_sha256.clone(),
            binary_sha256: self.provenance.binary_sha256.clone(),
            evidence_filename,
            evidence_sha256,
            case_metadata_sha256,
            artifact_filename,
            artifact_sha256,
            artifact_type,
            artifact_size_bytes,
            source_evidence_sha256,
            host_context: self.host_context.clone(),
            operation_context,
            copy_context: copy_contexts.copy,
            copy_attempt_context: copy_contexts.attempt,
            previous_entry_hash,
            entry_hash,
        })
    }

    fn commit_entry(&mut self, entry: &AuditEntry) -> io::Result<()> {
        if entry.sequence != self.next_sequence || entry.previous_entry_hash != self.last_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "prepared audit entry does not match the current log head",
            ));
        }

        let serialized = serde_json::to_string(entry).map_err(io::Error::other)?;
        writeln!(self.file, "{serialized}")?;
        self.file.flush()?;
        self.file.sync_all()?;

        self.last_hash = Some(entry.entry_hash.clone());
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(())
    }

    pub fn prepare_case_closed(
        &self,
        case_id: Uuid,
        case_metadata_sha256: Option<String>,
    ) -> io::Result<AuditEntry> {
        self.build_entry(
            case_id,
            AuditAction::CaseClosed,
            AuditResult::Success,
            None,
            None,
            case_metadata_sha256,
            None,
            None,
            None,
            None,
            None,
            None,
            CopyContexts::default(),
        )
    }

    pub fn commit_prepared(&mut self, entry: &AuditEntry) -> io::Result<()> {
        self.commit_entry(entry)
    }

    pub fn close_case(
        &mut self,
        case_id: Uuid,
        case_metadata_sha256: Option<String>,
    ) -> io::Result<AuditEntry> {
        self.log(
            case_id,
            AuditAction::CaseClosed,
            None,
            None,
            case_metadata_sha256,
            AuditResult::Success,
        )
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_hash(&self) -> Option<&str> {
        self.last_hash.as_deref()
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn provenance(&self) -> &BuildProvenance {
        &self.provenance
    }
}

impl Drop for AuditLogger {
    fn drop(&mut self) {
        if let Err(err) = FileExt::unlock(&self.file) {
            eprintln!(
                "Failed to release audit log lock for {}: {err}",
                self.path.display()
            );
        }
    }
}

pub fn verify_audit_log(path: impl AsRef<Path>) -> io::Result<AuditVerification> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(AuditVerification {
            valid: true,
            entries_checked: 0,
            last_hash: None,
            last_sequence: 0,
            error: None,
        });
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut expected_previous_hash: Option<String> = None;
    let mut expected_case_id: Option<Uuid> = None;
    let mut expected_sequence = 1u64;
    let mut entries_checked = 0usize;
    let mut last_sequence = 0u64;

    for (index, line) in reader.lines().enumerate() {
        let line = line?;

        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry = match serde_json::from_str(&line) {
            Ok(entry) => entry,
            Err(err) => {
                return Ok(AuditVerification {
                    valid: false,
                    entries_checked,
                    last_hash: expected_previous_hash,
                    last_sequence,
                    error: Some(format!("invalid audit JSON at line {}: {}", index + 1, err)),
                });
            }
        };

        if entry.schema_version != AUDIT_SCHEMA_VERSION {
            return Ok(AuditVerification {
                valid: false,
                entries_checked,
                last_hash: expected_previous_hash,
                last_sequence,
                error: Some(format!(
                    "unsupported audit schema version {} at line {}",
                    entry.schema_version,
                    index + 1
                )),
            });
        }

        if let Some(expected) = expected_case_id {
            if entry.case_id != expected {
                return Ok(AuditVerification {
                    valid: false,
                    entries_checked,
                    last_hash: expected_previous_hash,
                    last_sequence,
                    error: Some(format!(
                        "case ID mismatch at audit line {}: expected {}, found {}",
                        index + 1,
                        expected,
                        entry.case_id
                    )),
                });
            }
        }

        if entry.sequence != expected_sequence {
            return Ok(AuditVerification {
                valid: false,
                entries_checked,
                last_hash: expected_previous_hash,
                last_sequence,
                error: Some(format!(
                    "audit sequence mismatch at line {}: expected {}, found {}",
                    index + 1,
                    expected_sequence,
                    entry.sequence
                )),
            });
        }

        if entry.previous_entry_hash != expected_previous_hash {
            return Ok(AuditVerification {
                valid: false,
                entries_checked,
                last_hash: expected_previous_hash,
                last_sequence,
                error: Some(format!("audit chain broken at line {}", index + 1)),
            });
        }

        let recalculated_hash = hash_of_entry(&entry)?;

        if recalculated_hash != entry.entry_hash {
            return Ok(AuditVerification {
                valid: false,
                entries_checked,
                last_hash: expected_previous_hash,
                last_sequence,
                error: Some(format!("audit entry hash mismatch at line {}", index + 1)),
            });
        }

        expected_previous_hash = Some(entry.entry_hash.clone());
        expected_case_id = Some(entry.case_id);
        last_sequence = entry.sequence;
        expected_sequence = expected_sequence.saturating_add(1);
        entries_checked += 1;
    }

    Ok(AuditVerification {
        valid: true,
        entries_checked,
        last_hash: expected_previous_hash,
        last_sequence,
        error: None,
    })
}

pub fn read_verified_audit(
    path: impl AsRef<Path>,
    expected_case_id: Uuid,
) -> Result<Vec<AuditEntry>, String> {
    let path = path.as_ref();
    let file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();
    let mut expected_previous_hash: Option<String> = None;
    let mut expected_sequence = 1u64;

    for (index, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|error| format!("failed reading audit line {}: {error}", index + 1))?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry = serde_json::from_str(&line)
            .map_err(|error| format!("invalid audit JSON at line {}: {error}", index + 1))?;

        if entry.schema_version != AUDIT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported audit schema at line {}: expected {}, found {}",
                index + 1,
                AUDIT_SCHEMA_VERSION,
                entry.schema_version
            ));
        }

        if entry.case_id != expected_case_id {
            return Err(format!(
                "case ID mismatch at audit line {}: expected {}, found {}",
                index + 1,
                expected_case_id,
                entry.case_id
            ));
        }

        if entry.sequence != expected_sequence {
            return Err(format!(
                "audit sequence mismatch at line {}: expected {}, found {}",
                index + 1,
                expected_sequence,
                entry.sequence
            ));
        }

        if entry.previous_entry_hash != expected_previous_hash {
            return Err(format!(
                "audit previous-entry hash mismatch at line {}",
                index + 1
            ));
        }

        let calculated_hash = hash_of_entry(&entry).map_err(|error| {
            format!("failed to hash audit entry at line {}: {error}", index + 1)
        })?;
        if calculated_hash != entry.entry_hash {
            return Err(format!(
                "audit entry hash mismatch at line {}: stored={}, calculated={}",
                index + 1,
                entry.entry_hash,
                calculated_hash
            ));
        }

        expected_previous_hash = Some(entry.entry_hash.clone());
        expected_sequence = expected_sequence.saturating_add(1);
        entries.push(entry);
    }

    if entries.is_empty() {
        return Err(String::from("audit log contains no entries"));
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_log(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("bitsplayer_{name}_{unique}.jsonl"))
    }

    #[test]
    fn creates_hash_chained_entries() {
        let path = temporary_log("audit");
        let case_id = Uuid::new_v4();
        let mut logger = AuditLogger::new(&path).unwrap();

        let first = logger
            .log(
                case_id,
                AuditAction::CaseCreated,
                None,
                None,
                Some(String::from("casehash")),
                AuditResult::Success,
            )
            .unwrap();

        let second = logger
            .log(
                case_id,
                AuditAction::EvidenceRegistered,
                Some(String::from("test.mp4")),
                Some(String::from("abc123")),
                None,
                AuditResult::Success,
            )
            .unwrap();

        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        assert_eq!(
            second.previous_entry_hash.as_deref(),
            Some(first.entry_hash.as_str())
        );

        drop(logger);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn verifies_valid_audit_chain() {
        let path = temporary_log("verify");
        let case_id = Uuid::new_v4();

        {
            let mut logger = AuditLogger::new(&path).unwrap();
            logger
                .log(
                    case_id,
                    AuditAction::CaseCreated,
                    None,
                    None,
                    Some(String::from("casehash")),
                    AuditResult::Success,
                )
                .unwrap();
            logger
                .log(
                    case_id,
                    AuditAction::AnalysisCompleted,
                    Some(String::from("test.mp4")),
                    Some(String::from("abc123")),
                    None,
                    AuditResult::Success,
                )
                .unwrap();
        }

        let result = verify_audit_log(&path).unwrap();
        assert!(result.valid);
        assert_eq!(result.entries_checked, 2);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn resumes_existing_audit_chain() {
        let path = temporary_log("resume");
        let case_id = Uuid::new_v4();

        let first_hash = {
            let mut logger = AuditLogger::new(&path).unwrap();
            logger
                .log(
                    case_id,
                    AuditAction::CaseCreated,
                    None,
                    None,
                    Some(String::from("casehash")),
                    AuditResult::Success,
                )
                .unwrap()
                .entry_hash
        };

        let mut reopened = AuditLogger::new(&path).unwrap();
        let second = reopened
            .log(
                case_id,
                AuditAction::EvidenceRegistered,
                Some(String::from("test.mp4")),
                Some(String::from("abc123")),
                None,
                AuditResult::Success,
            )
            .unwrap();

        assert_eq!(
            second.previous_entry_hash.as_deref(),
            Some(first_hash.as_str())
        );

        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn detects_tampered_audit_log() {
        let path = temporary_log("tampered");
        let case_id = Uuid::new_v4();

        {
            let mut logger = AuditLogger::new(&path).unwrap();
            logger
                .log(
                    case_id,
                    AuditAction::CaseCreated,
                    None,
                    None,
                    Some(String::from("casehash")),
                    AuditResult::Success,
                )
                .unwrap();
        }

        let original = fs::read_to_string(&path).unwrap();
        let tampered = original.replace("\"result\":\"SUCCESS\"", "\"result\":\"FAILED\"");
        fs::write(&path, tampered).unwrap();

        assert!(!verify_audit_log(&path).unwrap().valid);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_unknown_json_fields() {
        let path = temporary_log("unknown");
        let case_id = Uuid::new_v4();

        {
            let mut logger = AuditLogger::new(&path).unwrap();
            logger
                .log(
                    case_id,
                    AuditAction::CaseCreated,
                    None,
                    None,
                    Some(String::from("casehash")),
                    AuditResult::Success,
                )
                .unwrap();
        }

        let original = fs::read_to_string(&path).unwrap();
        let schema = format!("\"schema_version\":{AUDIT_SCHEMA_VERSION}");
        let tampered = original.replace(&schema, &format!("{schema},\"injected\":\"value\""));
        fs::write(&path, tampered).unwrap();

        assert!(!verify_audit_log(&path).unwrap().valid);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn detects_sequence_tampering() {
        let path = temporary_log("sequence");
        let case_id = Uuid::new_v4();

        {
            let mut logger = AuditLogger::new(&path).unwrap();
            logger
                .log(
                    case_id,
                    AuditAction::CaseCreated,
                    None,
                    None,
                    Some(String::from("casehash")),
                    AuditResult::Success,
                )
                .unwrap();
        }

        let original = fs::read_to_string(&path).unwrap();
        let tampered = original.replace("\"sequence\":1", "\"sequence\":99");
        fs::write(&path, tampered).unwrap();

        assert!(!verify_audit_log(&path).unwrap().valid);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn prevents_two_loggers_from_writing_same_audit() {
        let path = temporary_log("lock");
        let first = AuditLogger::new(&path).unwrap();
        assert!(AuditLogger::new(&path).is_err());
        drop(first);
        let reopened = AuditLogger::new(&path);
        assert!(reopened.is_ok());
        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn close_case_writes_final_audit_entry() {
        let path = temporary_log("close");
        let case_id = Uuid::new_v4();
        let mut logger = AuditLogger::new(&path).unwrap();

        logger
            .log(
                case_id,
                AuditAction::CaseCreated,
                None,
                None,
                Some(String::from("casehash")),
                AuditResult::Success,
            )
            .unwrap();

        let closed = logger
            .close_case(case_id, Some(String::from("casehash")))
            .unwrap();
        assert_eq!(closed.action, AuditAction::CaseClosed);
        assert_eq!(closed.sequence, 2);
        drop(logger);
        assert!(verify_audit_log(&path).unwrap().valid);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn artifact_fields_are_hash_chained() {
        let path = temporary_log("artifact");
        let case_id = Uuid::new_v4();
        let artifact_path = std::env::temp_dir().join("bitsplayer_fake_frame.png");

        let artifact = ArtifactRecord {
            path: artifact_path,
            filename: String::from("frame_00001.png"),
            artifact_type: String::from("RECOVERED_FRAME_PNG"),
            size_bytes: 123,
            sha256: String::from("artifacthash"),
            source_evidence_sha256: String::from("sourcehash"),
            created_at: Utc::now(),
        };

        let mut logger = AuditLogger::new(&path).unwrap();
        let entry = logger
            .log_artifact(
                case_id,
                Some(String::from("source.mp4")),
                Some(String::from("sourcehash")),
                &artifact,
            )
            .unwrap();

        assert_eq!(entry.action, AuditAction::ArtifactCreated);
        assert_eq!(entry.artifact_filename.as_deref(), Some("frame_00001.png"));
        assert_eq!(entry.artifact_sha256.as_deref(), Some("artifacthash"));
        assert_eq!(entry.source_evidence_sha256.as_deref(), Some("sourcehash"));

        drop(logger);
        assert!(verify_audit_log(&path).unwrap().valid);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn operation_context_is_hash_chained() {
        let path = temporary_log("context");
        let case_id = Uuid::new_v4();
        let mut logger = AuditLogger::new(&path).unwrap();

        let entry = logger
            .log_with_context(
                case_id,
                AuditAction::AnalysisStarted,
                Some(String::from("evidence.mp4")),
                Some(String::from("abc123")),
                None,
                AuditResult::Started,
                OperationContext::evidence(Path::new("/tmp/evidence.mp4")),
            )
            .unwrap();

        assert_eq!(
            entry
                .operation_context
                .as_ref()
                .and_then(|context| context.evidence_path.as_deref()),
            Some("/tmp/evidence.mp4")
        );

        drop(logger);
        assert!(verify_audit_log(&path).unwrap().valid);
        fs::remove_file(path).unwrap();
    }
}
