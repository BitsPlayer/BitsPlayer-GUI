use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CLOSURE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseClosure {
    pub schema_version: u32,
    pub case_id: Uuid,
    pub closed_at: DateTime<Utc>,
    pub final_sequence: u64,
    pub total_entries: u64,
    pub final_head_hash: String,
    pub report_manifest_sha256: Option<String>,
}

impl CaseClosure {
    pub fn new(
        case_id: Uuid,
        final_sequence: u64,
        final_head_hash: String,
        report_manifest_sha256: Option<String>,
    ) -> Self {
        Self {
            schema_version: CLOSURE_SCHEMA_VERSION,
            case_id,
            closed_at: Utc::now(),
            final_sequence,
            total_entries: final_sequence,
            final_head_hash,
            report_manifest_sha256,
        }
    }
}
