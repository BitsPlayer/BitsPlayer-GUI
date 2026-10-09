use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use uuid::Uuid;

use crate::domain::context::{HostContext, OperationContext};
use crate::domain::provenance::BuildProvenance;

pub const AUDIT_SCHEMA_VERSION: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditAction {
    CaseCreated,
    CaseMetadataUpdated,
    EvidenceCopyStarted,
    EvidenceCopyCompleted,
    EvidenceCopyFailed,
    EvidenceRegistered,
    AnalysisStarted,
    AnalysisCompleted,
    AnalysisFailed,
    IntegrityVerification,
    ExtractStarted,
    ExtractCompleted,
    ExtractFailed,
    ArtifactCreated,
    CaseClosed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCopyContext {
    pub original_path: String,
    pub working_copy_path: String,
    pub original_sha256: String,
    pub working_copy_sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyAttemptContext {
    pub source_path: String,
    pub destination_path: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditResult {
    Started,
    Success,
    Failed,
    Verified,
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub schema_version: u32,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub case_id: Uuid,
    pub action: AuditAction,
    pub result: AuditResult,

    pub tool_version: String,
    pub git_commit: String,
    pub cargo_lock_sha256: String,
    pub binary_sha256: String,

    pub evidence_filename: Option<String>,
    pub evidence_sha256: Option<String>,
    pub case_metadata_sha256: Option<String>,

    pub artifact_filename: Option<String>,
    pub artifact_sha256: Option<String>,
    pub artifact_type: Option<String>,
    pub artifact_size_bytes: Option<u64>,
    pub source_evidence_sha256: Option<String>,

    pub host_context: HostContext,
    pub operation_context: Option<OperationContext>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_context: Option<EvidenceCopyContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_attempt_context: Option<CopyAttemptContext>,

    pub previous_entry_hash: Option<String>,
    pub entry_hash: String,
}

#[derive(Debug)]
pub struct AuditVerification {
    pub valid: bool,
    pub entries_checked: usize,
    pub last_hash: Option<String>,
    pub last_sequence: u64,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct AuditHashPayload<'a> {
    schema_version: u32,
    sequence: u64,
    timestamp: &'a DateTime<Utc>,
    case_id: Uuid,
    action: &'a AuditAction,
    result: &'a AuditResult,

    tool_version: &'a str,
    git_commit: &'a str,
    cargo_lock_sha256: &'a str,
    binary_sha256: &'a str,

    evidence_filename: Option<&'a str>,
    evidence_sha256: Option<&'a str>,
    case_metadata_sha256: Option<&'a str>,

    artifact_filename: Option<&'a str>,
    artifact_sha256: Option<&'a str>,
    artifact_type: Option<&'a str>,
    artifact_size_bytes: Option<u64>,
    source_evidence_sha256: Option<&'a str>,

    host_context: &'a HostContext,
    operation_context: Option<&'a OperationContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    copy_context: Option<&'a EvidenceCopyContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    copy_attempt_context: Option<&'a CopyAttemptContext>,

    previous_entry_hash: Option<&'a str>,
}

pub(crate) struct AuditFields<'a> {
    pub(crate) evidence_filename: Option<&'a str>,
    pub(crate) evidence_sha256: Option<&'a str>,
    pub(crate) case_metadata_sha256: Option<&'a str>,
    pub(crate) artifact_filename: Option<&'a str>,
    pub(crate) artifact_sha256: Option<&'a str>,
    pub(crate) artifact_type: Option<&'a str>,
    pub(crate) artifact_size_bytes: Option<u64>,
    pub(crate) source_evidence_sha256: Option<&'a str>,
    pub(crate) copy_context: Option<&'a EvidenceCopyContext>,
    pub(crate) copy_attempt_context: Option<&'a CopyAttemptContext>,
}

pub(crate) fn hash_of_entry(entry: &AuditEntry) -> io::Result<String> {
    let provenance = BuildProvenance {
        tool_version: entry.tool_version.clone(),
        git_commit: entry.git_commit.clone(),
        cargo_lock_sha256: entry.cargo_lock_sha256.clone(),
        binary_sha256: entry.binary_sha256.clone(),
    };
    let fields = AuditFields {
        evidence_filename: entry.evidence_filename.as_deref(),
        evidence_sha256: entry.evidence_sha256.as_deref(),
        case_metadata_sha256: entry.case_metadata_sha256.as_deref(),
        artifact_filename: entry.artifact_filename.as_deref(),
        artifact_sha256: entry.artifact_sha256.as_deref(),
        artifact_type: entry.artifact_type.as_deref(),
        artifact_size_bytes: entry.artifact_size_bytes,
        source_evidence_sha256: entry.source_evidence_sha256.as_deref(),
        copy_context: entry.copy_context.as_ref(),
        copy_attempt_context: entry.copy_attempt_context.as_ref(),
    };
    calculate_entry_hash(
        entry.schema_version,
        entry.sequence,
        &entry.timestamp,
        entry.case_id,
        &entry.action,
        &entry.result,
        &provenance,
        &fields,
        &entry.host_context,
        entry.operation_context.as_ref(),
        entry.previous_entry_hash.as_deref(),
    )
}

pub(crate) fn calculate_entry_hash(
    schema_version: u32,
    sequence: u64,
    timestamp: &DateTime<Utc>,
    case_id: Uuid,
    action: &AuditAction,
    result: &AuditResult,
    provenance: &BuildProvenance,
    fields: &AuditFields<'_>,
    host_context: &HostContext,
    operation_context: Option<&OperationContext>,
    previous_entry_hash: Option<&str>,
) -> io::Result<String> {
    let payload = AuditHashPayload {
        schema_version,
        sequence,
        timestamp,
        case_id,
        action,
        result,
        tool_version: &provenance.tool_version,
        git_commit: &provenance.git_commit,
        cargo_lock_sha256: &provenance.cargo_lock_sha256,
        binary_sha256: &provenance.binary_sha256,
        evidence_filename: fields.evidence_filename,
        evidence_sha256: fields.evidence_sha256,
        case_metadata_sha256: fields.case_metadata_sha256,
        artifact_filename: fields.artifact_filename,
        artifact_sha256: fields.artifact_sha256,
        artifact_type: fields.artifact_type,
        artifact_size_bytes: fields.artifact_size_bytes,
        source_evidence_sha256: fields.source_evidence_sha256,
        host_context,
        operation_context,
        copy_context: fields.copy_context,
        copy_attempt_context: fields.copy_attempt_context,
        previous_entry_hash,
    };

    let bytes = serde_json::to_vec(&payload).map_err(io::Error::other)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}
