use chrono::Utc;
use serde::Serialize;
use std::{
    fs,
    io::{self},
    path::{Path, PathBuf},
};

use crate::application::seal::SealReport;
use crate::domain::audit::AuditEntry;
use crate::domain::case::Case;
use crate::domain::report::{ForensicReport, ReportManifest};
use crate::infrastructure::audit::read_verified_audit;
use crate::infrastructure::hashing::sha256_file;
use crate::infrastructure::pdf_report::{
    ArtifactRow, PdfReportContent, SealSummary, TimelineRow, render, sign_pdf,
};
use crate::infrastructure::pdf_signing::{PdfSigningIdentity, SignerDetails};
use crate::infrastructure::report::{
    collect_evidence_files, write_manifest, write_report_files,
};
use crate::infrastructure::signing::CaseSignature;

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
        .map(|entry| enum_name(entry.action))
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

fn enum_name(value: impl Serialize) -> io::Result<String> {
    match serde_json::to_value(value).map_err(io::Error::other)? {
        serde_json::Value::String(name) => Ok(name),
        other => Err(io::Error::other(format!(
            "audit enum serialized as {other}"
        ))),
    }
}

pub fn build_pdf_report(
    case: &Case,
    seal: &SealReport,
    signer: SignerDetails,
) -> io::Result<PdfReportContent> {
    let audit_path = case.case_directory.join("logs").join("audit.jsonl");
    let entries = read_verified_audit(&audit_path, case.id).map_err(io::Error::other)?;
    let signature = CaseSignature::load(&seal.signature_path)?;

    let mut artifacts = Vec::new();
    let mut timeline = Vec::with_capacity(entries.len());
    for entry in &entries {
        if let Some(filename) = &entry.artifact_filename {
            artifacts.push(ArtifactRow {
                filename: filename.clone(),
                artifact_type: entry
                    .artifact_type
                    .clone()
                    .unwrap_or_else(|| String::from("unknown")),
                size_bytes: entry.artifact_size_bytes,
                created_at: entry.timestamp,
            });
        }
        timeline.push(TimelineRow {
            sequence: entry.sequence,
            timestamp: entry.timestamp,
            action: enum_name(entry.action)?,
            result: enum_name(entry.result)?,
            detail: entry_detail(entry),
        });
    }

    let case_json = case.case_directory.join("case.json");
    let case_json_sha256 = if case_json.is_file() {
        Some(sha256_file(&case_json)?)
    } else {
        None
    };

    Ok(PdfReportContent {
        case_name: case.name.clone(),
        case_id: case.id,
        examiner: case.examiner.clone(),
        case_created_at: case.created_at,
        case_directory: case.case_directory.display().to_string(),
        case_json_sha256,
        evidence: collect_evidence_files(&case.case_directory)?,
        artifacts,
        timeline,
        seal: SealSummary {
            final_sequence: signature.final_sequence,
            final_head_hash: signature.final_head_hash,
            report_manifest_sha256: signature.report_manifest_sha256,
            public_key: signature.public_key,
            signature: signature.signature,
            closure_path: seal.closure_path.display().to_string(),
        },
        signer,
        generated_at: Utc::now(),
        tool_version: String::from(env!("CARGO_PKG_VERSION")),
    })
}

pub fn export_signed_pdf(case: &Case, seal: &SealReport, out_path: &Path) -> io::Result<()> {
    let identity = PdfSigningIdentity::load_or_create(case.examiner.as_deref())?;
    let content = build_pdf_report(case, seal, identity.signer_details()?)?;
    let pdf = sign_pdf(render(&content), &identity)?;
    // The save dialog has already confirmed any overwrite.
    fs::write(out_path, &pdf)
}

fn entry_detail(entry: &AuditEntry) -> String {
    let mut parts = Vec::new();
    if let Some(filename) = &entry.artifact_filename {
        let kind = entry.artifact_type.as_deref().unwrap_or("artifact");
        parts.push(format!("{kind} {filename}"));
    } else if let Some(filename) = &entry.evidence_filename {
        parts.push(filename.clone());
    }

    if let Some(context) = &entry.operation_context {
        if let Some(parameters) = &context.extraction_parameters {
            parts.push(format!(
                "extract {}x{} {} non-IDR {} partial {} audio {} all frames {}",
                parameters.width,
                parameters.height,
                parameters.matrix,
                on_off(parameters.include_non_idr),
                on_off(parameters.include_partial),
                on_off(parameters.with_audio),
                on_off(parameters.all_frames),
            ));
        }
        if let Some(parameters) = &context.carve_parameters {
            let mut carve = format!(
                "carve {}x{} audio {}",
                parameters.width,
                parameters.height,
                on_off(parameters.with_audio)
            );
            if let Some(codec) = &parameters.codec {
                carve.push_str(&format!(" codec {codec}"));
            }
            parts.push(carve);
        }
    }

    if parts.is_empty() {
        String::from("-")
    } else {
        parts.join("; ")
    }
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}
