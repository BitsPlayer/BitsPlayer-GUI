use crate::forensic::hashing::sha256_file;
use std::{
    fs,
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub path: PathBuf,
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub registered_at: SystemTime,
    pub integrity_verified: bool,
}

impl EvidenceRecord {
    pub fn from_path(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;

        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "evidence path is not a regular file",
            ));
        }

        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();

        let sha256 = sha256_file(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            filename,
            size_bytes: metadata.len(),
            sha256,
            registered_at: SystemTime::now(),
            integrity_verified: false,
        })
    }

    pub fn verify_integrity(&mut self) -> io::Result<bool> {
        let current_hash = sha256_file(&self.path)?;

        self.integrity_verified = current_hash == self.sha256;

        Ok(self.integrity_verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn creates_evidence_record_from_file() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir()
            .join(format!("bitsplayer_evidence_test_{unique}.bin"));

        fs::write(&path, b"abc").unwrap();

        let record = EvidenceRecord::from_path(&path).unwrap();

        assert_eq!(record.size_bytes, 3);
        assert_eq!(
            record.sha256,
            "ba7816bf8f01cfea414140de5dae2223\
b00361a396177a9cb410ff61f20015ad"
        );
        assert!(!record.integrity_verified);

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn verifies_unchanged_evidence() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir()
            .join(format!("bitsplayer_integrity_test_{unique}.bin"));

        fs::write(&path, b"abc").unwrap();

        let mut record = EvidenceRecord::from_path(&path).unwrap();

        let verified = record.verify_integrity().unwrap();

        assert!(verified);
        assert!(record.integrity_verified);

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn detects_changed_evidence() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir()
            .join(format!("bitsplayer_changed_test_{unique}.bin"));

        fs::write(&path, b"abc").unwrap();

        let mut record = EvidenceRecord::from_path(&path).unwrap();

        fs::write(&path, b"changed").unwrap();

        let verified = record.verify_integrity().unwrap();

        assert!(!verified);
        assert!(!record.integrity_verified);

        fs::remove_file(&path).unwrap();
    }
}