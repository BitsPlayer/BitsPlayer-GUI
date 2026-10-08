use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    Unverified,
    Verified,
    Failed,
}

#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub path: PathBuf,
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub registered_at: SystemTime,
    pub integrity_status: IntegrityStatus,

    pub modified_at: Option<SystemTime>,

    #[cfg(unix)]
    pub device_id: u64,

    #[cfg(unix)]
    pub inode: u64,
}

