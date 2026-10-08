use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub use crate::domain::closure::{CaseClosure, CLOSURE_SCHEMA_VERSION};

impl CaseClosure {
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