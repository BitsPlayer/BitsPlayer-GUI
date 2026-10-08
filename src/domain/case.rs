use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const CASE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub schema_version: u32,
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub examiner: Option<String>,
    pub case_directory: PathBuf,
}

impl Case {
    pub fn new(
        name: impl Into<String>,
        examiner: Option<String>,
        case_directory: PathBuf,
    ) -> Self {
        Self {
            schema_version: CASE_SCHEMA_VERSION,
            id: Uuid::new_v4(),
            name: name.into(),
            created_at: Utc::now(),
            examiner,
            case_directory,
        }
    }

    pub fn new_in_base(
        name: impl Into<String>,
        examiner: Option<String>,
        base_directory: impl AsRef<Path>,
    ) -> Self {
        let id = Uuid::new_v4();
        let case_directory = base_directory.as_ref().join(format!("CASE-{id}"));
        Self {
            schema_version: CASE_SCHEMA_VERSION,
            id,
            name: name.into(),
            created_at: Utc::now(),
            examiner,
            case_directory,
        }
    }

    pub fn case_file_path(&self) -> PathBuf {
        self.case_directory.join("case.json")
    }
}
