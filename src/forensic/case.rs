use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
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

        let short_id = id
            .to_string()
            .chars()
            .take(8)
            .collect::<String>();

        let case_directory = base_directory
            .as_ref()
            .join(format!("CASE-{short_id}"));

        Self {
            id,
            name: name.into(),
            created_at: Utc::now(),
            examiner,
            case_directory,
        }
    }

    pub fn save(&self) -> io::Result<()> {
        fs::create_dir_all(&self.case_directory)?;

        let path = self.case_file_path();

        let json = serde_json::to_string_pretty(self)
            .map_err(io::Error::other)?;

        fs::write(path, json)
    }

    pub fn load(
        path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let data = fs::read_to_string(path)?;

        serde_json::from_str(&data)
            .map_err(io::Error::other)
    }

    pub fn case_file_path(&self) -> PathBuf {
        self.case_directory.join("case.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_case_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir()
            .join(format!("bitsplayer_{name}_{unique}"))
    }

    #[test]
    fn creates_case_with_unique_id() {
        let case = Case::new(
            "Test Case",
            Some(String::from("Examiner")),
            PathBuf::from("/tmp/test-case"),
        );

        assert_eq!(case.name, "Test Case");

        assert_eq!(
            case.examiner.as_deref(),
            Some("Examiner")
        );

        assert!(!case.id.is_nil());
    }

    #[test]
    fn creates_case_inside_base_directory() {
        let base = temp_case_dir("base");

        let case = Case::new_in_base(
            "Test Case",
            None,
            &base,
        );

        assert!(
            case.case_directory
                .starts_with(&base)
        );

        let folder_name = case
            .case_directory
            .file_name()
            .unwrap()
            .to_string_lossy();

        assert!(
            folder_name.starts_with("CASE-")
        );
    }

    #[test]
    fn saves_and_loads_case() {
        let dir = temp_case_dir("case_save");

        let case = Case::new(
            "Saved Case",
            Some(String::from("Test Examiner")),
            dir.clone(),
        );

        case.save().unwrap();

        let loaded = Case::load(
            case.case_file_path()
        )
        .unwrap();

        assert_eq!(loaded.id, case.id);
        assert_eq!(loaded.name, case.name);
        assert_eq!(
            loaded.examiner,
            case.examiner
        );

        assert_eq!(
            loaded.case_directory,
            case.case_directory
        );

        fs::remove_dir_all(dir)
            .unwrap();
    }
}