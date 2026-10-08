use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    pub path: PathBuf,
    pub filename: String,

    pub artifact_type: String,

    pub size_bytes: u64,
    pub sha256: String,

    pub source_evidence_sha256: String,

    pub created_at: DateTime<Utc>,
}

