use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
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
}

impl CaseClosure {
    pub fn new(
        case_id: Uuid,
        final_sequence: u64,
        final_head_hash: String,
    ) -> Self {
        Self {
            schema_version: CLOSURE_SCHEMA_VERSION,
            case_id,
            closed_at: Utc::now(),
            final_sequence,
            total_entries: final_sequence,
            final_head_hash,
        }
    }

    pub fn save(
        &self,
        case_directory: impl AsRef<Path>,
    ) -> io::Result<PathBuf> {
        let path = case_directory
            .as_ref()
            .join("case_closure.json");

        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;

        Ok(path)
    }

    pub fn load(
        path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let data = fs::read_to_string(path)?;

        let closure: Self =
            serde_json::from_str(&data)
                .map_err(io::Error::other)?;

        if closure.schema_version
            != CLOSURE_SCHEMA_VERSION
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported closure schema version {}",
                    closure.schema_version
                ),
            ));
        }

        Ok(closure)
    }
}