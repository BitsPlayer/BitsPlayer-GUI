use std::{
    fs,
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::forensic::hashing::sha256_file;

pub use crate::domain::evidence::{EvidenceRecord, IntegrityStatus};

impl EvidenceRecord {
    pub fn from_path(
        path: &Path,
    ) -> io::Result<Self> {
        let metadata =
            fs::metadata(path)?;

        if !metadata.is_file() {
            return Err(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "evidence path is not a regular file",
                ),
            );
        }

        let filename =
            path.file_name()
                .and_then(
                    |name| name.to_str(),
                )
                .unwrap_or("unknown")
                .to_string();

        let sha256 =
            sha256_file(path)?;

        let modified_at =
            metadata.modified().ok();

        #[cfg(unix)]
        let (
            device_id,
            inode,
        ) = {
            use std::os::unix::fs::MetadataExt;

            (
                metadata.dev(),
                metadata.ino(),
            )
        };

        Ok(Self {
            path:
                path.to_path_buf(),

            filename,

            size_bytes:
                metadata.len(),

            sha256,

            registered_at:
                SystemTime::now(),

            integrity_status:
                IntegrityStatus::Unverified,

            modified_at,

            #[cfg(unix)]
            device_id,

            #[cfg(unix)]
            inode,
        })
    }

    pub fn verify_integrity(
        &mut self,
    ) -> io::Result<IntegrityStatus> {
        let metadata =
            fs::metadata(
                &self.path,
            )?;

        if !metadata.is_file() {
            self.integrity_status =
                IntegrityStatus::Failed;

            return Ok(
                self.integrity_status,
            );
        }

        if metadata.len()
            != self.size_bytes
        {
            self.integrity_status =
                IntegrityStatus::Failed;

            return Ok(
                self.integrity_status,
            );
        }

        if metadata.modified().ok()
            != self.modified_at
        {
            self.integrity_status =
                IntegrityStatus::Failed;

            return Ok(
                self.integrity_status,
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if metadata.dev()
                != self.device_id
                || metadata.ino()
                    != self.inode
            {
                self.integrity_status =
                    IntegrityStatus::Failed;

                return Ok(
                    self.integrity_status,
                );
            }
        }

        let current_sha256 =
            sha256_file(
                &self.path,
            )?;

        self.integrity_status =
            if current_sha256
                == self.sha256
            {
                IntegrityStatus::Verified
            } else {
                IntegrityStatus::Failed
            };

        Ok(
            self.integrity_status,
        )
    }

    pub fn verify_unchanged_since(
        &self,
        before_sha256: &str,
    ) -> io::Result<bool> {
        let metadata =
            fs::metadata(
                &self.path,
            )?;

        if !metadata.is_file() {
            return Ok(false);
        }

        if metadata.len()
            != self.size_bytes
        {
            return Ok(false);
        }

        if metadata.modified().ok()
            != self.modified_at
        {
            return Ok(false);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if metadata.dev()
                != self.device_id
                || metadata.ino()
                    != self.inode
            {
                return Ok(false);
            }
        }

        let after_sha256 =
            sha256_file(
                &self.path,
            )?;

        Ok(
            after_sha256
                == before_sha256
                && after_sha256
                    == self.sha256
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        fs,
        time::{
            SystemTime,
            UNIX_EPOCH,
        },
    };

    fn temp_path(
        name: &str,
    ) -> PathBuf {
        let unique =
            SystemTime::now()
                .duration_since(
                    UNIX_EPOCH,
                )
                .unwrap()
                .as_nanos();

        std::env::temp_dir()
            .join(
                format!(
                    "bitsplayer_evidence_{name}_{unique}.bin"
                ),
            )
    }

    #[test]
    fn creates_evidence_record_from_file() {
        let path =
            temp_path(
                "create",
            );

        fs::write(
            &path,
            b"hello evidence",
        )
        .unwrap();

        let record =
            EvidenceRecord::from_path(
                &path,
            )
            .unwrap();

        assert_eq!(
            record.size_bytes,
            14
        );

        assert_eq!(
            record.sha256.len(),
            64
        );

        assert_eq!(
            record.integrity_status,
            IntegrityStatus::Unverified
        );

        fs::remove_file(
            path,
        )
        .unwrap();
    }

    #[test]
    fn verifies_unchanged_evidence() {
        let path =
            temp_path(
                "verify",
            );

        fs::write(
            &path,
            b"unchanged",
        )
        .unwrap();

        let mut record =
            EvidenceRecord::from_path(
                &path,
            )
            .unwrap();

        let status =
            record
                .verify_integrity()
                .unwrap();

        assert_eq!(
            status,
            IntegrityStatus::Verified
        );

        fs::remove_file(
            path,
        )
        .unwrap();
    }

    #[test]
    fn detects_changed_evidence() {
        let path =
            temp_path(
                "changed",
            );

        fs::write(
            &path,
            b"original",
        )
        .unwrap();

        let mut record =
            EvidenceRecord::from_path(
                &path,
            )
            .unwrap();

        fs::write(
            &path,
            b"changed!",
        )
        .unwrap();

        let status =
            record
                .verify_integrity()
                .unwrap();

        assert_eq!(
            status,
            IntegrityStatus::Failed
        );

        fs::remove_file(
            path,
        )
        .unwrap();
    }

    #[test]
    fn detects_post_analysis_change() {
        let path =
            temp_path(
                "post_analysis",
            );

        fs::write(
            &path,
            b"before analysis",
        )
        .unwrap();

        let record =
            EvidenceRecord::from_path(
                &path,
            )
            .unwrap();

        let before_hash =
            record.sha256.clone();

        assert!(
            record
                .verify_unchanged_since(
                    &before_hash,
                )
                .unwrap()
        );

        fs::write(
            &path,
            b"after analysis",
        )
        .unwrap();

        assert!(
            !record
                .verify_unchanged_since(
                    &before_hash,
                )
                .unwrap()
        );

        fs::remove_file(
            path,
        )
        .unwrap();
    }
}