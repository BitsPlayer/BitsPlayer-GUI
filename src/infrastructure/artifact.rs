use chrono::Utc;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::infrastructure::hashing::sha256_file;

pub use crate::domain::artifact::ArtifactRecord;

impl ArtifactRecord {
    pub fn from_existing_file(
        path: &Path,
        artifact_type: impl Into<String>,
        source_evidence_sha256: impl Into<String>,
    ) -> io::Result<Self> {
        let metadata =
            fs::metadata(path)?;

        if !metadata.is_file() {
            return Err(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "artifact path is not a regular file",
                ),
            );
        }

        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();

        let sha256 =
            sha256_file(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            filename,

            artifact_type:
                artifact_type.into(),

            size_bytes:
                metadata.len(),

            sha256,

            source_evidence_sha256:
                source_evidence_sha256.into(),

            created_at:
                Utc::now(),
        })
    }
}

pub fn write_artifact_new(
    path: &Path,
    bytes: &[u8],
    artifact_type: impl Into<String>,
    source_evidence_sha256: impl Into<String>,
) -> io::Result<ArtifactRecord> {
    /*
     * create_new(true) is important.
     *
     * It refuses to overwrite an existing forensic
     * artifact.
     */
    let mut file =
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;

    file.write_all(bytes)?;

    file.flush()?;

    /*
     * Ask the OS to push the newly written artifact
     * to storage before we hash/register it.
     */
    file.sync_all()?;

    drop(file);

    ArtifactRecord::from_existing_file(
        path,
        artifact_type,
        source_evidence_sha256,
    )
}

pub fn verify_artifact(
    artifact: &ArtifactRecord,
) -> io::Result<bool> {
    let current_hash =
        sha256_file(
            &artifact.path,
        )?;

    Ok(
        current_hash
            == artifact.sha256
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{
        SystemTime,
        UNIX_EPOCH,
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
                    "bitsplayer_artifact_{name}_{unique}.bin"
                ),
            )
    }

    #[test]
    fn creates_and_hashes_artifact() {
        let path =
            temp_path(
                "create",
            );

        let artifact =
            write_artifact_new(
                &path,
                b"artifact data",
                "TEST",
                "source123",
            )
            .unwrap();

        assert_eq!(
            artifact
                .source_evidence_sha256,
            "source123"
        );

        assert_eq!(
            artifact.size_bytes,
            13
        );

        assert_eq!(
            artifact.sha256.len(),
            64
        );

        assert!(
            verify_artifact(
                &artifact
            )
            .unwrap()
        );

        fs::remove_file(
            path,
        )
        .unwrap();
    }

    #[test]
    fn refuses_to_overwrite_existing_artifact() {
        let path =
            temp_path(
                "overwrite",
            );

        write_artifact_new(
            &path,
            b"first",
            "TEST",
            "source123",
        )
        .unwrap();

        let second =
            write_artifact_new(
                &path,
                b"second",
                "TEST",
                "source123",
            );

        assert!(
            second.is_err()
        );

        let contents =
            fs::read(
                &path,
            )
            .unwrap();

        assert_eq!(
            contents,
            b"first"
        );

        fs::remove_file(
            path,
        )
        .unwrap();
    }

    #[test]
    fn detects_modified_artifact() {
        let path =
            temp_path(
                "modified",
            );

        let artifact =
            write_artifact_new(
                &path,
                b"original",
                "TEST",
                "source123",
            )
            .unwrap();

        fs::write(
            &path,
            b"tampered",
        )
        .unwrap();

        assert!(
            !verify_artifact(
                &artifact
            )
            .unwrap()
        );

        fs::remove_file(
            path,
        )
        .unwrap();
    }
}