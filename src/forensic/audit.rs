use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub case_id: Uuid,
    pub action: String,
    pub tool_version: String,
    pub evidence_filename: Option<String>,
    pub evidence_sha256: Option<String>,
    pub result: String,
    pub previous_entry_hash: Option<String>,
    pub entry_hash: String,
}

#[derive(Debug)]
pub struct AuditLogger {
    path: PathBuf,
    last_hash: Option<String>,
}

#[derive(Debug)]
pub struct AuditVerification {
    pub valid: bool,
    pub entries_checked: usize,
    pub last_hash: Option<String>,
    pub error: Option<String>,
}

impl AuditLogger {
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let last_hash = if path.exists() {
            let verification = verify_audit_log(&path)?;

            if !verification.valid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    verification
                        .error
                        .unwrap_or_else(|| {
                            String::from(
                                "existing audit log failed verification",
                            )
                        }),
                ));
            }

            verification.last_hash
        } else {
            None
        };

        Ok(Self {
            path,
            last_hash,
        })
    }

    pub fn log(
        &mut self,
        case_id: Uuid,
        action: impl Into<String>,
        evidence_filename: Option<String>,
        evidence_sha256: Option<String>,
        result: impl Into<String>,
    ) -> io::Result<AuditEntry> {
        let timestamp = Utc::now();
        let action = action.into();
        let result = result.into();

        let previous_entry_hash = self.last_hash.clone();

        let entry_hash = calculate_entry_hash(
            timestamp,
            case_id,
            &action,
            env!("CARGO_PKG_VERSION"),
            evidence_filename.as_deref(),
            evidence_sha256.as_deref(),
            &result,
            previous_entry_hash.as_deref(),
        );

        let entry = AuditEntry {
            timestamp,
            case_id,
            action,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            evidence_filename,
            evidence_sha256,
            result,
            previous_entry_hash,
            entry_hash: entry_hash.clone(),
        };

        let serialized =
            serde_json::to_string(&entry)
                .map_err(io::Error::other)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        writeln!(file, "{serialized}")?;

        file.flush()?;

        self.last_hash = Some(entry_hash);

        Ok(entry)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn verify_audit_log(
    path: impl AsRef<Path>,
) -> io::Result<AuditVerification> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(AuditVerification {
            valid: true,
            entries_checked: 0,
            last_hash: None,
            error: None,
        });
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut expected_previous_hash: Option<String> = None;
    let mut entries_checked = 0usize;

    for (index, line) in reader.lines().enumerate() {
        let line = line?;

        if line.trim().is_empty() {
            continue;
        }

        let entry: AuditEntry =
            match serde_json::from_str(&line) {
                Ok(entry) => entry,

                Err(err) => {
                    return Ok(AuditVerification {
                        valid: false,
                        entries_checked,
                        last_hash: expected_previous_hash,
                        error: Some(format!(
                            "invalid JSON at audit line {}: {}",
                            index + 1,
                            err
                        )),
                    });
                }
            };

        if entry.previous_entry_hash
            != expected_previous_hash
        {
            return Ok(AuditVerification {
                valid: false,
                entries_checked,
                last_hash: expected_previous_hash,
                error: Some(format!(
                    "audit chain broken at line {}",
                    index + 1
                )),
            });
        }

        let recalculated_hash =
            calculate_entry_hash(
                entry.timestamp,
                entry.case_id,
                &entry.action,
                &entry.tool_version,
                entry.evidence_filename.as_deref(),
                entry.evidence_sha256.as_deref(),
                &entry.result,
                entry.previous_entry_hash.as_deref(),
            );

        if recalculated_hash
            != entry.entry_hash
        {
            return Ok(AuditVerification {
                valid: false,
                entries_checked,
                last_hash: expected_previous_hash,
                error: Some(format!(
                    "audit entry hash mismatch at line {}",
                    index + 1
                )),
            });
        }

        expected_previous_hash =
            Some(entry.entry_hash);

        entries_checked += 1;
    }

    Ok(AuditVerification {
        valid: true,
        entries_checked,
        last_hash: expected_previous_hash,
        error: None,
    })
}

fn calculate_entry_hash(
    timestamp: DateTime<Utc>,
    case_id: Uuid,
    action: &str,
    tool_version: &str,
    evidence_filename: Option<&str>,
    evidence_sha256: Option<&str>,
    result: &str,
    previous_entry_hash: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();

    hasher.update(timestamp.to_rfc3339());
    hasher.update(case_id.as_bytes());
    hasher.update(action.as_bytes());
    hasher.update(tool_version.as_bytes());

    hasher.update(
        evidence_filename
            .unwrap_or("")
            .as_bytes(),
    );

    hasher.update(
        evidence_sha256
            .unwrap_or("")
            .as_bytes(),
    );

    hasher.update(result.as_bytes());

    hasher.update(
        previous_entry_hash
            .unwrap_or("")
            .as_bytes(),
    );

    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{
        SystemTime,
        UNIX_EPOCH,
    };

    fn temporary_log(
        name: &str,
    ) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(
            format!(
                "bitsplayer_{name}_{unique}.jsonl"
            )
        )
    }

    #[test]
    fn creates_hash_chained_entries() {
        let path =
            temporary_log("audit");

        let case_id =
            Uuid::new_v4();

        let mut logger =
            AuditLogger::new(&path)
                .unwrap();

        let first = logger
            .log(
                case_id,
                "CASE_CREATED",
                None,
                None,
                "success",
            )
            .unwrap();

        let second = logger
            .log(
                case_id,
                "EVIDENCE_OPENED",
                Some(
                    String::from(
                        "test.mp4"
                    )
                ),
                Some(
                    String::from(
                        "abc123"
                    )
                ),
                "success",
            )
            .unwrap();

        assert!(
            first
                .previous_entry_hash
                .is_none()
        );

        assert_eq!(
            second
                .previous_entry_hash
                .as_deref(),
            Some(
                first
                    .entry_hash
                    .as_str()
            )
        );

        fs::remove_file(path)
            .unwrap();
    }

    #[test]
    fn verifies_valid_audit_chain() {
        let path =
            temporary_log(
                "verify"
            );

        let case_id =
            Uuid::new_v4();

        let mut logger =
            AuditLogger::new(&path)
                .unwrap();

        logger
            .log(
                case_id,
                "CASE_CREATED",
                None,
                None,
                "success",
            )
            .unwrap();

        logger
            .log(
                case_id,
                "ANALYSIS_COMPLETED",
                Some(
                    String::from(
                        "test.mp4"
                    )
                ),
                Some(
                    String::from(
                        "abc123"
                    )
                ),
                "success",
            )
            .unwrap();

        let result =
            verify_audit_log(&path)
                .unwrap();

        assert!(result.valid);
        assert_eq!(
            result.entries_checked,
            2
        );

        fs::remove_file(path)
            .unwrap();
    }

    #[test]
    fn resumes_existing_audit_chain() {
        let path =
            temporary_log(
                "resume"
            );

        let case_id =
            Uuid::new_v4();

        let first_hash = {
            let mut logger =
                AuditLogger::new(&path)
                    .unwrap();

            logger
                .log(
                    case_id,
                    "CASE_CREATED",
                    None,
                    None,
                    "success",
                )
                .unwrap()
                .entry_hash
        };

        let mut reopened =
            AuditLogger::new(&path)
                .unwrap();

        let second =
            reopened
                .log(
                    case_id,
                    "EVIDENCE_REGISTERED",
                    Some(
                        String::from(
                            "test.mp4"
                        )
                    ),
                    Some(
                        String::from(
                            "abc123"
                        )
                    ),
                    "success",
                )
                .unwrap();

        assert_eq!(
            second
                .previous_entry_hash
                .as_deref(),
            Some(
                first_hash.as_str()
            )
        );

        fs::remove_file(path)
            .unwrap();
    }

    #[test]
    fn detects_tampered_audit_log() {
        let path =
            temporary_log(
                "tampered"
            );

        let case_id =
            Uuid::new_v4();

        let mut logger =
            AuditLogger::new(&path)
                .unwrap();

        logger
            .log(
                case_id,
                "CASE_CREATED",
                None,
                None,
                "success",
            )
            .unwrap();

        let original =
            fs::read_to_string(
                &path
            )
            .unwrap();

        let tampered =
            original.replace(
                "\"result\":\"success\"",
                "\"result\":\"tampered\"",
            );

        fs::write(
            &path,
            tampered,
        )
        .unwrap();

        let result =
            verify_audit_log(&path)
                .unwrap();

        assert!(!result.valid);

        fs::remove_file(path)
            .unwrap();
    }
}