use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io;
use uuid::Uuid;

pub const SIGNATURE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOrigin {
    Loaded,
    Created,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSignature {
    pub schema_version: u32,
    pub algorithm: String,
    pub case_id: Uuid,
    pub final_sequence: u64,
    pub final_head_hash: String,
    pub case_metadata_sha256: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Serialize)]
pub(crate) struct SignaturePayload<'a> {
    pub(crate) schema_version: u32,
    pub(crate) case_id: Uuid,
    pub(crate) final_sequence: u64,
    pub(crate) final_head_hash: &'a str,
    pub(crate) case_metadata_sha256: &'a str,
}


impl CaseSignature {
    /// Verifies the signature against `trusted`. The public key stored in the
    /// signature file is not a trust anchor; it must match `trusted`.
    pub fn verify(&self, trusted: &VerifyingKey) -> io::Result<()> {
        if self.schema_version != SIGNATURE_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported signature schema version {}",
                    self.schema_version
                ),
            ));
        }

        if self.algorithm != "Ed25519" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported signature algorithm",
            ));
        }

        let embedded = decode_verifying_key(&self.public_key)?;
        if embedded.as_bytes() != trusted.as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signature public key does not match the trusted key",
            ));
        }

        let signature = decode_signature(&self.signature)?;
        let payload = SignaturePayload {
            schema_version: self.schema_version,
            case_id: self.case_id,
            final_sequence: self.final_sequence,
            final_head_hash: &self.final_head_hash,
            case_metadata_sha256: &self.case_metadata_sha256,
        };
        let bytes = serde_json::to_vec(&payload).map_err(io::Error::other)?;

        trusted
            .verify(&bytes, &signature)
            .map_err(io::Error::other)
    }
}


pub fn decode_verifying_key(encoded: &str) -> io::Result<VerifyingKey> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(io::Error::other)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Ed25519 public key length",
        )
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(io::Error::other)
}

fn decode_signature(encoded: &str) -> io::Result<Signature> {
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(io::Error::other)?;
    let bytes: [u8; 64] = bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Ed25519 signature length",
        )
    })?;
    Ok(Signature::from_bytes(&bytes))
}

