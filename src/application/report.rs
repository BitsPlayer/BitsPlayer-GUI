use std::{
    fs,
    io::{self},
    path::{Path, PathBuf},
};

use crate::domain::audit::AuditAction;
use crate::domain::case::Case;
use crate::domain::report::{ForensicReport, ReportManifest};
use crate::infrastructure::audit::read_verified_audit;
use crate::infrastructure::hashing::sha256_file;
use crate::infrastructure::report::{collect_evidence_files, write_manifest, write_report_files};

#[derive(Debug, Clone)]
pub struct SealedReport {
    pub json_path: PathBuf,
    pub html_path: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_sha256: String,
}

impl SealedReport {
    pub fn remove(&self) {
        let _ = fs::remove_file(&self.json_path);
        let _ = fs::remove_file(&self.html_path);
        let _ = fs::remove_file(&self.manifest_path);
    }
}

pub fn build_case_report(case: &Case) -> io::Result<ForensicReport> {
    let audit_path = case.case_directory.join("logs").join("audit.jsonl");
    let entries = read_verified_audit(&audit_path, case.id).map_err(io::Error::other)?;

    let audit_actions = entries
        .iter()
        .map(|entry| action_name(entry.action))
        .collect::<io::Result<Vec<_>>>()?;

    let case_json = case.case_directory.join("case.json");
    let case_json_sha256 = if case_json.is_file() {
        Some(sha256_file(&case_json)?)
    } else {
        None
    };

    Ok(ForensicReport {
        case_json_sha256,
        audit_entries: entries.len(),
        audit_actions,
        evidence_files: collect_evidence_files(&case.case_directory)?,
    })
}

/// Writes `report.json` and `report.html` for a case directory, without a manifest.
pub fn write_case_report(case_directory: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let case = Case::load(case_directory.join("case.json"))?;
    let report = build_case_report(&case)?;
    write_report_files(case_directory, &report)
}

/// Writes the report files and `report_manifest.json` for sealing. On failure,
/// every file this call created is removed.
pub fn seal_case_report(case: &Case) -> io::Result<SealedReport> {
    let report = build_case_report(case)?;
    let (json_path, html_path) = write_report_files(&case.case_directory, &report)?;

    match write_sealed_manifest(&case.case_directory, &json_path, &html_path) {
        Ok((manifest_path, manifest_sha256)) => Ok(SealedReport {
            json_path,
            html_path,
            manifest_path,
            manifest_sha256,
        }),
        Err(err) => {
            let _ = fs::remove_file(&json_path);
            let _ = fs::remove_file(&html_path);
            Err(err)
        }
    }
}

fn write_sealed_manifest(
    case_directory: &Path,
    json_path: &Path,
    html_path: &Path,
) -> io::Result<(PathBuf, String)> {
    let manifest = ReportManifest {
        report_json_sha256: sha256_file(json_path)?,
        report_html_sha256: sha256_file(html_path)?,
    };
    write_manifest(case_directory, &manifest)
}

fn action_name(action: AuditAction) -> io::Result<String> {
    match serde_json::to_value(action).map_err(io::Error::other)? {
        serde_json::Value::String(name) => Ok(name),
        other => Err(io::Error::other(format!(
            "audit action serialized as {other}"
        ))),
    }
}
