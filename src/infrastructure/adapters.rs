//! Concrete adapters for the application ports.

use std::io;
use std::path::Path;

use anyhow::Result;
use uuid::Uuid;

use crate::application::ports::{
    ArtifactWriter, AuditLog, CaseStore, FrameExtractor, Hasher, LayoutAnalyzer, Signer,
};
use crate::domain::artifact::ArtifactRecord;
use crate::domain::audit::AuditEntry;
use crate::domain::case::Case;
use crate::domain::signing::{CaseSignature, IdentityOrigin};
use crate::infrastructure::audit::AuditLogger;
use crate::infrastructure::signing::SigningIdentity;

impl AuditLog for AuditLogger {
    fn prepare_case_closed(
        &self,
        case_id: Uuid,
        case_metadata_sha256: Option<String>,
    ) -> io::Result<AuditEntry> {
        AuditLogger::prepare_case_closed(self, case_id, case_metadata_sha256)
    }

    fn commit_prepared(&mut self, entry: &AuditEntry) -> io::Result<()> {
        AuditLogger::commit_prepared(self, entry)
    }
}

impl Signer for SigningIdentity {
    fn origin(&self) -> IdentityOrigin {
        SigningIdentity::origin(self)
    }

    fn directory(&self) -> &Path {
        SigningIdentity::directory(self)
    }

    fn sign_case(
        &self,
        case_id: Uuid,
        final_sequence: u64,
        final_head_hash: &str,
        case_metadata_sha256: &str,
    ) -> io::Result<CaseSignature> {
        SigningIdentity::sign_case(
            self,
            case_id,
            final_sequence,
            final_head_hash,
            case_metadata_sha256,
        )
    }
}

impl CaseStore for Case {
    fn metadata_sha256(&self) -> io::Result<String> {
        Case::metadata_sha256(self)
    }
}

pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn sha256_file(&self, path: &Path) -> io::Result<String> {
        crate::infrastructure::hashing::sha256_file(path)
    }
}

pub struct FsArtifactWriter;

impl ArtifactWriter for FsArtifactWriter {
    fn write_new(
        &self,
        path: &Path,
        bytes: &[u8],
        artifact_type: &str,
        source_evidence_sha256: &str,
    ) -> io::Result<ArtifactRecord> {
        crate::infrastructure::artifact::write_artifact_new(
            path,
            bytes,
            artifact_type,
            source_evidence_sha256,
        )
    }
}

pub struct BitplayAnalyzer;

impl LayoutAnalyzer for BitplayAnalyzer {
    fn analyze(&self, path: &Path) -> Result<bitplay::Analysis> {
        bitplay::analyze(path)
    }
}

pub struct IframeExtractor;

impl FrameExtractor for IframeExtractor {
    fn extract(
        &self,
        data: &[u8],
        input_name: &str,
        options: &iframe_extract::extract::Options,
        reporter: &mut dyn iframe_extract::report::Reporter,
    ) -> Result<iframe_extract::extract::Extraction> {
        iframe_extract::extract::extract_with(data, input_name, options, reporter)
            .map_err(|err| anyhow::anyhow!(err))
    }
}
