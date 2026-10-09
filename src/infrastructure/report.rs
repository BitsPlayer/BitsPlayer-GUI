use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub use crate::domain::report::{ForensicReport, ReportEvidence, ReportManifest};

pub fn collect_evidence_files(case_directory: &Path) -> io::Result<Vec<ReportEvidence>> {
    let evidence_directory = case_directory.join("evidence");
    if !evidence_directory.is_dir() {
        return Ok(Vec::new());
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(&evidence_directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            paths.push(entry.path());
        }
    }
    paths.sort();

    paths
        .iter()
        .map(|path| {
            let filename = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(ReportEvidence {
                path: format!("evidence/{filename}"),
                filename,
                sha256: crate::infrastructure::hashing::sha256_file(path)?,
                size_bytes: fs::metadata(path)?.len(),
            })
        })
        .collect()
}

/// Writes `report.json` and `report.html`, both created new. If the HTML
/// write fails, the JSON written here is removed again.
pub fn write_report_files(
    case_directory: &Path,
    report: &ForensicReport,
) -> io::Result<(PathBuf, PathBuf)> {
    let json = serde_json::to_string_pretty(report).map_err(io::Error::other)?;
    let json_path = write_new(case_directory.join("report.json"), json.as_bytes())?;

    match write_new(
        case_directory.join("report.html"),
        report.to_html().as_bytes(),
    ) {
        Ok(html_path) => Ok((json_path, html_path)),
        Err(err) => {
            let _ = fs::remove_file(&json_path);
            Err(err)
        }
    }
}

/// Writes `report_manifest.json` and returns its path with the SHA-256 of the
/// exact bytes written.
pub fn write_manifest(
    case_directory: &Path,
    manifest: &ReportManifest,
) -> io::Result<(PathBuf, String)> {
    let json = serde_json::to_string_pretty(manifest).map_err(io::Error::other)?;
    let path = write_new(case_directory.join("report_manifest.json"), json.as_bytes())?;
    let sha256 = hex::encode(Sha256::digest(json.as_bytes()));
    Ok((path, sha256))
}

pub fn load_manifest(path: impl AsRef<Path>) -> io::Result<ReportManifest> {
    let data = fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(io::Error::other)
}

pub fn write_new(path: PathBuf, bytes: &[u8]) -> io::Result<PathBuf> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&path);
        return Err(err);
    }
    Ok(path)
}
