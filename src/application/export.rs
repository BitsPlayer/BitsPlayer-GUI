use std::{
    fs,
    io::{self},
    path::{Path, PathBuf},
};

use crate::domain::report::ReportManifest;
use crate::infrastructure::export::{
    read_zip_member, sha256_path, write_export_zip, zip_member_names, zip_member_sha256,
};
use crate::infrastructure::hashing::sha256_file;

const CASE_FILES: [&str; 7] = [
    "case.json",
    "case_closure.json",
    "case_signature.json",
    "report.json",
    "report.html",
    "report_manifest.json",
    "logs/audit.jsonl",
];

const VERIFICATION_RESULT: &str = "verification_result.txt";

const VERIFICATION_RESULT_TEXT: &str = "BitsPlayer Forensic Export Package\n\
\n\
To verify this package:\n\
1. Extract the zip into a directory.\n\
2. Run: bitsplayer-verify <EXTRACTED_CASE_DIRECTORY>\n\
\n\
A valid package reports VALID FORENSIC CASE.\n";

#[derive(Debug, Clone)]
pub struct ExportVerification {
    pub checks: Vec<String>,
}

pub fn create_export_package(case_directory: &Path) -> io::Result<PathBuf> {
    let case_directory = fs::canonicalize(case_directory)?;
    let case_name = case_directory
        .file_name()
        .ok_or_else(|| invalid_input("case directory has no name"))?
        .to_string_lossy()
        .into_owned();
    let parent = case_directory
        .parent()
        .ok_or_else(|| invalid_input("case directory has no parent"))?;
    let output = parent.join(format!("{case_name}-export.zip"));

    let mut files = Vec::new();
    for name in CASE_FILES {
        let path = case_directory.join(name);
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing case file: {name}"),
            ));
        }
        files.push((name.to_string(), path));
    }

    let evidence_directory = case_directory.join("evidence");
    if evidence_directory.is_dir() {
        let mut evidence = Vec::new();
        for entry in fs::read_dir(&evidence_directory)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                evidence.push(entry.path());
            }
        }
        evidence.sort();
        for path in evidence {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            files.push((format!("evidence/{name}"), path));
        }
    }

    write_export_zip(
        &output,
        &files,
        &[(VERIFICATION_RESULT, VERIFICATION_RESULT_TEXT)],
    )?;
    Ok(output)
}

pub fn verify_export_package(zip_path: &Path) -> Result<ExportVerification, String> {
    let mut checks = Vec::new();

    let expected = read_expected_zip_sha256(zip_path)?;
    let actual = sha256_file(zip_path).map_err(|error| format!("cannot read ZIP: {error}"))?;
    if expected != actual {
        return Err(String::from("ZIP SHA256 mismatch"));
    }
    checks.push(String::from("ZIP SHA256 verified"));

    let names = zip_member_names(zip_path).map_err(|error| format!("invalid ZIP: {error}"))?;
    for required in CASE_FILES.iter().copied().chain([VERIFICATION_RESULT]) {
        if !names.iter().any(|name| name == required) {
            return Err(format!("Missing file: {required}"));
        }
    }
    checks.push(String::from("Required files present"));

    let manifest_bytes = read_zip_member(zip_path, "report_manifest.json")
        .map_err(|error| format!("cannot read report_manifest.json: {error}"))?;
    let manifest: ReportManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid report_manifest.json: {error}"))?;
    for (member, expected_sha256) in [
        ("report.json", &manifest.report_json_sha256),
        ("report.html", &manifest.report_html_sha256),
    ] {
        let actual_sha256 = zip_member_sha256(zip_path, member)
            .map_err(|error| format!("cannot read {member}: {error}"))?;
        if &actual_sha256 != expected_sha256 {
            return Err(format!(
                "{member} SHA256 does not match report_manifest.json"
            ));
        }
    }
    checks.push(String::from(
        "report.json and report.html match report_manifest.json",
    ));
    checks.push(String::from("Export package structure valid"));

    Ok(ExportVerification { checks })
}

fn read_expected_zip_sha256(zip_path: &Path) -> Result<String, String> {
    let contents = fs::read_to_string(sha256_path(zip_path))
        .map_err(|_| String::from("Missing ZIP SHA256 file"))?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("SHA256: "))
        .map(String::from)
        .ok_or_else(|| String::from("ZIP SHA256 file has no SHA256 line"))
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use uuid::Uuid;

    use super::*;

    fn write_case(case_directory: &Path) {
        fs::create_dir_all(case_directory.join("logs")).unwrap();
        fs::create_dir_all(case_directory.join("evidence")).unwrap();
        fs::write(case_directory.join("case.json"), b"{\"case\":1}").unwrap();
        fs::write(case_directory.join("case_closure.json"), b"{\"closure\":1}").unwrap();
        fs::write(case_directory.join("case_signature.json"), b"{\"sig\":1}").unwrap();
        fs::write(case_directory.join("report.json"), b"{\"report\":1}").unwrap();
        fs::write(case_directory.join("report.html"), b"<html></html>").unwrap();
        fs::write(case_directory.join("logs").join("audit.jsonl"), b"{}\n").unwrap();
        fs::write(case_directory.join("evidence").join("input.mp4"), b"video").unwrap();

        let manifest = ReportManifest {
            report_json_sha256: sha256_file(&case_directory.join("report.json")).unwrap(),
            report_html_sha256: sha256_file(&case_directory.join("report.html")).unwrap(),
        };
        fs::write(
            case_directory.join("report_manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn temp_base(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bitsplayer_export_{name}_{}", Uuid::new_v4()))
    }

    #[test]
    fn export_then_verify_succeeds() {
        let base = temp_base("ok");
        let case_directory = base.join("case_ok");
        write_case(&case_directory);

        let zip_path = create_export_package(&case_directory).unwrap();
        let verification = verify_export_package(&zip_path).unwrap();

        assert_eq!(verification.checks.len(), 4);
        assert_eq!(
            zip_member_names(&zip_path).unwrap().len(),
            CASE_FILES.len() + 2
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn tampered_zip_fails_sha_check() {
        let base = temp_base("tampered");
        let case_directory = base.join("case_tampered");
        write_case(&case_directory);

        let zip_path = create_export_package(&case_directory).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&zip_path)
            .unwrap()
            .write_all(b"tamper")
            .unwrap();

        let error = verify_export_package(&zip_path).unwrap_err();
        assert_eq!(error, "ZIP SHA256 mismatch");

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn missing_member_fails_verification() {
        let base = temp_base("missing");
        let case_directory = base.join("case_missing");
        write_case(&case_directory);

        let files: Vec<(String, PathBuf)> = CASE_FILES
            .iter()
            .filter(|name| **name != "logs/audit.jsonl")
            .map(|name| (name.to_string(), case_directory.join(name)))
            .collect();
        let zip_path = base.join("case_missing-export.zip");
        write_export_zip(
            &zip_path,
            &files,
            &[(VERIFICATION_RESULT, VERIFICATION_RESULT_TEXT)],
        )
        .unwrap();

        let error = verify_export_package(&zip_path).unwrap_err();
        assert_eq!(error, "Missing file: logs/audit.jsonl");

        fs::remove_dir_all(base).unwrap();
    }
}
