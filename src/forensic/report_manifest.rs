use serde::{Deserialize, Serialize};

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use crate::forensic::hashing::sha256_file;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportManifest {

    pub report_json_sha256: String,

    pub report_html_sha256: String,
}



impl ReportManifest {

    pub fn create(
        case_directory: &Path,
    ) -> io::Result<Self> {

        let json_path =
            case_directory.join("report.json");

        let html_path =
            case_directory.join("report.html");


        Ok(Self {

            report_json_sha256:
                sha256_file(&json_path)?,


            report_html_sha256:
                sha256_file(&html_path)?,

        })
    }



    pub fn save(
        &self,
        case_directory: &Path,
    ) -> io::Result<PathBuf> {

        let path =
            case_directory.join(
                "report_manifest.json"
            );


        let data =
            serde_json::to_string_pretty(self)
                .map_err(io::Error::other)?;


        fs::write(
            &path,
            data,
        )?;


        Ok(path)
    }
}
