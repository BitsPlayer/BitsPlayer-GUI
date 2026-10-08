//! Ports implemented by infrastructure. Use cases depend on these traits.

use std::io;
use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use crate::domain::artifact::ArtifactRecord;
use crate::domain::audit::AuditEntry;
use crate::domain::signing::{CaseSignature, IdentityOrigin};

pub trait AuditLog {
    fn prepare_case_closed(
        &self,
        case_id: Uuid,
        case_metadata_sha256: Option<String>,
    ) -> io::Result<AuditEntry>;

    fn commit_prepared(&mut self, entry: &AuditEntry) -> io::Result<()>;
}

pub trait Signer {
    fn origin(&self) -> IdentityOrigin;
    fn directory(&self) -> &Path;
    fn sign_case(
        &self,
        case_id: Uuid,
        final_sequence: u64,
        final_head_hash: &str,
        case_metadata_sha256: &str,
    ) -> io::Result<CaseSignature>;
}

pub trait CaseStore {
    fn metadata_sha256(&self) -> io::Result<String>;
}

pub trait Hasher {
    fn sha256_file(&self, path: &Path) -> io::Result<String>;
}

pub trait ArtifactWriter {
    fn write_new(
        &self,
        path: &Path,
        bytes: &[u8],
        artifact_type: &str,
        source_evidence_sha256: &str,
    ) -> io::Result<ArtifactRecord>;
}

pub trait LayoutAnalyzer {
    fn analyze(&self, path: &Path) -> Result<bitplay::Analysis>;
}

pub trait FrameExtractor {
    fn extract(
        &self,
        data: &[u8],
        input_name: &str,
        options: &iframe_extract::extract::Options,
        reporter: &mut dyn iframe_extract::report::Reporter,
    ) -> Result<iframe_extract::extract::Extraction>;
}

pub fn analyze_layout(path: &Path, analyzer: &impl LayoutAnalyzer) -> Result<bitplay::Analysis> {
    analyzer.analyze(path)
}

pub fn extract_frames(
    data: &[u8],
    input_name: &str,
    options: &iframe_extract::extract::Options,
    extractor: &impl FrameExtractor,
    reporter: &mut dyn iframe_extract::report::Reporter,
) -> Result<iframe_extract::extract::Extraction> {
    extractor.extract(data, input_name, options, reporter)
}

pub fn hash_file(path: &Path, hasher: &impl Hasher) -> io::Result<String> {
    hasher.sha256_file(path)
}

pub fn write_artifact(
    path: &Path,
    bytes: &[u8],
    artifact_type: &str,
    source_evidence_sha256: &str,
    writer: &impl ArtifactWriter,
) -> io::Result<ArtifactRecord> {
    writer.write_new(path, bytes, artifact_type, source_evidence_sha256)
}
