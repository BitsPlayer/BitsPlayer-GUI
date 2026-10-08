use serde::Serialize;
use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use crate::forensic::hashing::sha256_file;


#[derive(Debug, Serialize)]
pub struct ForensicReport {

    pub case_directory: String,

    pub case_json_sha256: Option<String>,

    pub audit_entries: usize,

    pub audit_actions: Vec<String>,

    pub evidence_files: Vec<EvidenceSummary>,
}



#[derive(Debug, Serialize)]
pub struct EvidenceSummary {

    pub filename: String,

    pub path: String,

    pub sha256: String,

    pub size_bytes: u64,
}



impl ForensicReport {

    pub fn generate(
        case_directory: &Path,
    ) -> io::Result<Self> {


        let case_json =
            case_directory.join("case.json");


        let case_json_sha256 =
            if case_json.exists() {

                Some(
                    sha256_file(&case_json)?
                )

            } else {

                None
            };



        let audit_path =
            case_directory
                .join("logs")
                .join("audit.jsonl");



        let audit_content =
            fs::read_to_string(&audit_path)?;



        let mut audit_actions =
            Vec::new();



        for line in audit_content.lines() {

            let value: serde_json::Value =
                serde_json::from_str(line)
                    .map_err(io::Error::other)?;


            if let Some(action) =
                value.get("action")
                    .and_then(|v| v.as_str())
            {
                audit_actions
                    .push(action.to_string());
            }
        }



        let evidence_directory =
            case_directory.join("evidence");


        let mut evidence_files =
            Vec::new();



        if evidence_directory.exists() {

            for entry in fs::read_dir(
                evidence_directory
            )? {

                let entry = entry?;

                let path =
                    entry.path();


                if path.is_file() {

                    let metadata =
                        fs::metadata(&path)?;


                    evidence_files.push(
                        EvidenceSummary {

                            filename:
                                path.file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .into_owned(),

                            path:
                                path.to_string_lossy()
                                    .into_owned(),

                            sha256:
                                sha256_file(&path)?,

                            size_bytes:
                                metadata.len(),
                        }
                    );
                }
            }
        }



        Ok(Self {

            case_directory:
                case_directory
                    .to_string_lossy()
                    .into_owned(),

            case_json_sha256,

            audit_entries:
                audit_actions.len(),

            audit_actions,

            evidence_files,
        })
    }

    pub fn save_json(

        &self,

        case_directory: &Path,

    ) -> io::Result<PathBuf> {

        let path =

            case_directory.join("report.json");


        let json =

            serde_json::to_string_pretty(self)

                .map_err(io::Error::other)?;


        fs::write(

            &path,

            json,

        )?;


        Ok(path)

    }

    pub fn save_html(

        &self,

        case_directory: &Path,

    ) -> io::Result<PathBuf> {

        let path =

            case_directory.join("report.html");


        let mut html = String::new();


        html.push_str(

            "<html><head><title>BitsPlayer Forensic Report</title></head><body>"

        );


        html.push_str(

            "<h1>BitsPlayer Forensic Report</h1>"

        );


        html.push_str(

            &format!(

                "<h2>Case Directory</h2><p>{}</p>",

                self.case_directory

            )

        );


        html.push_str(

            "<h2>Timeline</h2><ul>"

        );


        for action in &self.audit_actions {

            html.push_str(

                &format!(

                    "<li>{}</li>",

                    action

                )

            );
        }


        html.push_str(

            "</ul><h2>Evidence</h2>"

        );


        for evidence in &self.evidence_files {

            html.push_str(

                &format!(

                    "<p><b>{}</b><br>\
                     SHA-256: {}<br>\
                     Size: {} bytes</p>",

                    evidence.filename,

                    evidence.sha256,

                    evidence.size_bytes

                )

            );
        }


        html.push_str(

            "</body></html>"

        );


        fs::write(

            &path,

            html,

        )?;


        Ok(path)

    }
}
