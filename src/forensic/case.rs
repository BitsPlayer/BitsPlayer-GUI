use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::forensic::hashing::sha256_file;

pub use crate::domain::case::{Case, CASE_SCHEMA_VERSION};

impl Case {
    pub fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.case_directory.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::create_dir(&self.case_directory).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "forensic case directory already exists: {}",
                        self.case_directory.display()
                    ),
                )
            } else {
                err
            }
        })?;

        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.case_file_path())?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    pub fn load(
        path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let data =
            fs::read_to_string(path)?;

        let case: Self =
            serde_json::from_str(&data)
                .map_err(io::Error::other)?;

        if case.schema_version
            != CASE_SCHEMA_VERSION
        {
            return Err(
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unsupported case schema version {}",
                        case.schema_version
                    ),
                ),
            );
        }

        Ok(case)
    }

    pub fn metadata_sha256(
        &self,
    ) -> io::Result<String> {
        sha256_file(
            &self.case_file_path(),
        )
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{
        SystemTime,
        UNIX_EPOCH,
    };

    fn temp_case_dir(
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
                    "bitsplayer_{name}_{unique}"
                ),
            )
    }

    #[test]
    fn creates_case_with_unique_id() {
        let case = Case::new(
            "Test Case",
            Some(
                String::from(
                    "Examiner",
                ),
            ),
            PathBuf::from(
                "/tmp/test-case",
            ),
        );

        assert_eq!(
            case.schema_version,
            CASE_SCHEMA_VERSION
        );

        assert_eq!(
            case.name,
            "Test Case"
        );

        assert_eq!(
            case.examiner.as_deref(),
            Some("Examiner")
        );

        assert!(!case.id.is_nil());
    }

    #[test]
    fn creates_case_inside_base_directory() {
        let base =
            temp_case_dir(
                "base",
            );

        let case =
            Case::new_in_base(
                "Test Case",
                None,
                &base,
            );

        assert!(
            case.case_directory
                .starts_with(
                    &base,
                )
        );

        let folder_name =
            case
                .case_directory
                .file_name()
                .unwrap()
                .to_string_lossy();

        assert_eq!(
            folder_name,
            format!("CASE-{}", case.id)
        );
    }

    #[test]
    fn saves_and_loads_case() {
        let dir =
            temp_case_dir(
                "case_save",
            );

        let case =
            Case::new(
                "Saved Case",
                Some(
                    String::from(
                        "Test Examiner",
                    ),
                ),
                dir.clone(),
            );

        case.save().unwrap();

        let loaded =
            Case::load(
                case.case_file_path(),
            )
            .unwrap();

        assert_eq!(
            loaded.id,
            case.id
        );

        assert_eq!(
            loaded.name,
            case.name
        );

        assert_eq!(
            loaded.examiner,
            case.examiner
        );

        assert_eq!(
            loaded.case_directory,
            case.case_directory
        );

        fs::remove_dir_all(
            dir,
        )
        .unwrap();
    }

    #[test]
    fn hashes_saved_case_metadata() {
        let dir =
            temp_case_dir(
                "case_hash",
            );

        let case =
            Case::new(
                "Hash Test Case",
                None,
                dir.clone(),
            );

        case.save().unwrap();

        let hash =
            case.metadata_sha256()
                .unwrap();

        assert_eq!(
            hash.len(),
            64
        );

        fs::remove_dir_all(
            dir,
        )
        .unwrap();
    }
}