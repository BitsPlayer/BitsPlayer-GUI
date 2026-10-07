use base64::{
    Engine as _,
    engine::general_purpose::STANDARD,
};

use chrono::{
    DateTime,
    Utc,
};

use ed25519_dalek::{
    Signature,
    Verifier,
    VerifyingKey,
};

use serde::{
    Deserialize,
    Serialize,
};

use sha2::{
    Digest,
    Sha256,
};

use std::{
    env,
    fs::{
        self,
        File,
    },
    io::{
        self,
        BufRead,
        BufReader,
        Read,
    },
    path::{
        Path,
        PathBuf,
    },
    process,
};

use uuid::Uuid;

const AUDIT_SCHEMA_VERSION: u32 = 3;
const CASE_SCHEMA_VERSION: u32 = 1;
const CLOSURE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_SCHEMA_VERSION: u32 = 1;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AuditAction {
    CaseCreated,
    CaseMetadataUpdated,

    EvidenceRegistered,

    AnalysisStarted,
    AnalysisCompleted,
    AnalysisFailed,

    IntegrityVerification,

    ExtractStarted,
    ExtractCompleted,
    ExtractFailed,

    ArtifactCreated,

    CaseClosed,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AuditResult {
    Started,
    Success,
    Failed,
    Verified,
    Unverified,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
#[serde(deny_unknown_fields)]
struct AuditEntry {
    schema_version: u32,
    sequence: u64,

    timestamp: DateTime<Utc>,
    case_id: Uuid,

    action: AuditAction,
    result: AuditResult,

    tool_version: String,
    git_commit: String,
    cargo_lock_sha256: String,
    binary_sha256: String,

    evidence_filename: Option<String>,
    evidence_sha256: Option<String>,

    case_metadata_sha256: Option<String>,

    artifact_filename: Option<String>,
    artifact_sha256: Option<String>,
    artifact_type: Option<String>,
    artifact_size_bytes: Option<u64>,
    source_evidence_sha256: Option<String>,

    previous_entry_hash: Option<String>,
    entry_hash: String,
}

#[derive(Serialize)]
struct AuditHashPayload<'a> {
    schema_version: u32,
    sequence: u64,

    timestamp: &'a DateTime<Utc>,
    case_id: Uuid,

    action: &'a AuditAction,
    result: &'a AuditResult,

    tool_version: &'a str,
    git_commit: &'a str,
    cargo_lock_sha256: &'a str,
    binary_sha256: &'a str,

    evidence_filename: Option<&'a str>,
    evidence_sha256: Option<&'a str>,

    case_metadata_sha256: Option<&'a str>,

    artifact_filename: Option<&'a str>,
    artifact_sha256: Option<&'a str>,
    artifact_type: Option<&'a str>,
    artifact_size_bytes: Option<u64>,
    source_evidence_sha256: Option<&'a str>,

    previous_entry_hash: Option<&'a str>,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
#[serde(deny_unknown_fields)]
struct CaseFile {
    schema_version: u32,

    id: Uuid,

    name: String,

    created_at: DateTime<Utc>,

    examiner: Option<String>,

    case_directory: PathBuf,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
#[serde(deny_unknown_fields)]
struct CaseClosure {
    schema_version: u32,

    case_id: Uuid,

    closed_at: DateTime<Utc>,

    final_sequence: u64,

    total_entries: u64,

    final_head_hash: String,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
#[serde(deny_unknown_fields)]
struct CaseSignature {
    schema_version: u32,

    algorithm: String,

    case_id: Uuid,

    final_sequence: u64,

    final_head_hash: String,

    case_metadata_sha256: String,

    public_key: String,

    signature: String,
}

/*
 * IMPORTANT:
 *
 * This payload must remain exactly compatible with
 * src/forensic/signing.rs.
 */
#[derive(Serialize)]
struct SignaturePayload<'a> {
    schema_version: u32,

    case_id: Uuid,

    final_sequence: u64,

    final_head_hash: &'a str,

    case_metadata_sha256: &'a str,
}

struct Arguments {
    case_directory: PathBuf,

    artifact_directory:
        Option<PathBuf>,

    trusted_public_key:
        PathBuf,
}

#[derive(Default)]
struct VerificationSummary {
    checks: usize,
    warnings: usize,
}

impl VerificationSummary {
    fn ok(
        &mut self,
        message: impl AsRef<str>,
    ) {
        self.checks += 1;

        println!(
            "[OK] {}",
            message.as_ref()
        );
    }

    fn warning(
        &mut self,
        message: impl AsRef<str>,
    ) {
        self.warnings += 1;

        println!(
            "[WARNING] {}",
            message.as_ref()
        );
    }
}

fn main() {
    let args =
        match parse_arguments() {
            Ok(args) => args,

            Err(message) => {
                eprintln!(
                    "ERROR: {message}"
                );

                print_usage();

                process::exit(2);
            }
        };

    match verify_case(
        &args,
    ) {
        Ok(summary) => {
            println!();

            println!(
                "VALID FORENSIC CASE"
            );

            println!(
                "{} checks passed, {} warning(s)",
                summary.checks,
                summary.warnings
            );

            process::exit(0);
        }

        Err(error) => {
            println!();

            eprintln!(
                "INVALID FORENSIC CASE"
            );

            eprintln!(
                "{error}"
            );

            process::exit(1);
        }
    }
}

fn parse_arguments(
) -> Result<Arguments, String> {
    let mut args =
        env::args()
            .skip(1);

    let Some(first) =
        args.next()
    else {
        return Err(
            String::from(
                "case directory is required",
            ),
        );
    };

    if first == "--help"
        || first == "-h"
    {
        print_usage();

        process::exit(0);
    }

    let case_directory =
        PathBuf::from(
            first,
        );

    let mut artifact_directory =
        None;

    let mut trusted_public_key:
        Option<PathBuf> =
        None;

    while let Some(arg) =
        args.next()
    {
        match arg.as_str() {
            "--artifact-dir" => {
                let Some(path) =
                    args.next()
                else {
                    return Err(
                        String::from(
                            "--artifact-dir requires a directory",
                        ),
                    );
                };

                artifact_directory =
                    Some(
                        PathBuf::from(
                            path,
                        ),
                    );
            }

            "--public-key" => {
                let Some(path) =
                    args.next()
                else {
                    return Err(
                        String::from(
                            "--public-key requires a file path",
                        ),
                    );
                };

                trusted_public_key =
                    Some(
                        PathBuf::from(
                            path,
                        ),
                    );
            }

            unknown => {
                return Err(
                    format!(
                        "unknown argument: {unknown}"
                    ),
                );
            }
        }
    }

    let trusted_public_key =
        match trusted_public_key {
            Some(path) => path,

            None => {
                default_public_key_path()?
            }
        };

    Ok(
        Arguments {
            case_directory,
            artifact_directory,
            trusted_public_key,
        },
    )
}

fn print_usage() {
    eprintln!(
        "BitsPlayer standalone forensic verifier"
    );

    eprintln!();

    eprintln!(
        "Usage:"
    );

    eprintln!(
        "  bitsplayer-verify <CASE_DIRECTORY>"
    );

    eprintln!(
        "  bitsplayer-verify <CASE_DIRECTORY> --public-key <PUBLIC_KEY_FILE>"
    );

    eprintln!(
        "  bitsplayer-verify <CASE_DIRECTORY> --artifact-dir <DIRECTORY> --public-key <PUBLIC_KEY_FILE>"
    );

    eprintln!();

    eprintln!(
        "Default trusted public key:"
    );

    eprintln!(
        "  ~/.config/bitsplayer/signing/public.key"
    );

    eprintln!();

    eprintln!(
        "Example:"
    );

    eprintln!(
        "  cargo run --bin bitsplayer-verify -- cases/CASE-12345678"
    );

    eprintln!();

    eprintln!(
        "Independent verification using a separately supplied trusted public key:"
    );

    eprintln!(
        "  cargo run --bin bitsplayer-verify -- cases/CASE-12345678 --public-key /path/to/public.key"
    );
}

fn default_public_key_path(
) -> Result<PathBuf, String> {
    let home =
        env::var_os(
            "HOME",
        )
        .ok_or_else(
            || {
                String::from(
                    "HOME environment variable is not available; use --public-key",
                )
            },
        )?;

    Ok(
        PathBuf::from(
            home,
        )
        .join(".config")
        .join("bitsplayer")
        .join("signing")
        .join("public.key"),
    )
}

fn verify_case(
    args: &Arguments,
) -> Result<VerificationSummary, String> {
    let mut summary =
        VerificationSummary::default();

    let case_directory =
        &args.case_directory;

    if !case_directory.exists() {
        return Err(
            format!(
                "case directory does not exist: {}",
                case_directory.display()
            ),
        );
    }

    if !case_directory.is_dir() {
        return Err(
            format!(
                "case path is not a directory: {}",
                case_directory.display()
            ),
        );
    }

    summary.ok(
        format!(
            "case directory exists: {}",
            case_directory.display()
        ),
    );

    let case_path =
        case_directory
            .join(
                "case.json",
            );

    let audit_path =
        case_directory
            .join("logs")
            .join(
                "audit.jsonl",
            );

    let closure_path =
        case_directory
            .join(
                "case_closure.json",
            );

    let signature_path =
        case_directory
            .join(
                "case_signature.json",
            );

    /*
     * ------------------------------------------------
     * CASE.JSON
     * ------------------------------------------------
     */

    let case =
        read_case_file(
            &case_path,
        )?;

    summary.ok(
        "case.json parsed successfully",
    );

    if case.schema_version
        != CASE_SCHEMA_VERSION
    {
        return Err(
            format!(
                "unsupported case.json schema version: expected {}, found {}",
                CASE_SCHEMA_VERSION,
                case.schema_version
            ),
        );
    }

    summary.ok(
        format!(
            "case.json schema version {} is supported",
            case.schema_version
        ),
    );

    let actual_case_hash =
        sha256_file(
            &case_path,
        )
        .map_err(
            |error| {
                format!(
                    "failed to hash case.json: {error}"
                )
            },
        )?;

    summary.ok(
        format!(
            "case.json SHA-256 = {actual_case_hash}"
        ),
    );

    /*
     * ------------------------------------------------
     * AUDIT LOG
     * ------------------------------------------------
     */

    let entries =
        read_and_verify_audit(
            &audit_path,
            case.id,
        )?;

    summary.ok(
        format!(
            "audit chain valid: {} entries",
            entries.len()
        ),
    );

    let Some(first_entry) =
        entries.first()
    else {
        return Err(
            String::from(
                "audit log contains no entries",
            ),
        );
    };

    if first_entry.action
        != AuditAction::CaseCreated
    {
        return Err(
            format!(
                "first audit action must be CASE_CREATED, found {:?}",
                first_entry.action
            ),
        );
    }

    summary.ok(
        "first audit entry is CASE_CREATED",
    );

    let created_case_hash =
        first_entry
            .case_metadata_sha256
            .as_deref()
            .ok_or_else(
                || {
                    String::from(
                        "CASE_CREATED does not contain case_metadata_sha256",
                    )
                },
            )?;

    let metadata_was_updated =
        entries
            .iter()
            .any(
                |entry| {
                    entry.action
                        == AuditAction::CaseMetadataUpdated
                },
            );

    if !metadata_was_updated {
        if created_case_hash
            != actual_case_hash
        {
            return Err(
                format!(
                    "case.json hash mismatch: audit records {}, current file is {}",
                    created_case_hash,
                    actual_case_hash
                ),
            );
        }

        summary.ok(
            "case.json matches CASE_CREATED metadata hash",
        );
    } else {
        summary.warning(
            "case metadata update exists; CASE_CREATED hash represents original metadata",
        );
    }

    let Some(last_entry) =
        entries.last()
    else {
        return Err(
            String::from(
                "audit log contains no final entry",
            ),
        );
    };

    if last_entry.action
        != AuditAction::CaseClosed
    {
        return Err(
            format!(
                "case is not sealed: final audit action is {:?}, expected CASE_CLOSED",
                last_entry.action
            ),
        );
    }

    summary.ok(
        "final audit entry is CASE_CLOSED",
    );

    let final_case_hash =
        last_entry
            .case_metadata_sha256
            .as_deref()
            .ok_or_else(
                || {
                    String::from(
                        "CASE_CLOSED does not contain case_metadata_sha256",
                    )
                },
            )?;

    if final_case_hash
        != actual_case_hash
    {
        return Err(
            format!(
                "current case.json does not match CASE_CLOSED metadata hash: expected {}, found {}",
                final_case_hash,
                actual_case_hash
            ),
        );
    }

    summary.ok(
        "current case.json matches CASE_CLOSED metadata hash",
    );

    /*
     * ------------------------------------------------
     * CLOSURE
     * ------------------------------------------------
     */

    let closure =
        read_closure(
            &closure_path,
        )?;

    summary.ok(
        "case_closure.json parsed successfully",
    );

    if closure.schema_version
        != CLOSURE_SCHEMA_VERSION
    {
        return Err(
            format!(
                "unsupported case closure schema: expected {}, found {}",
                CLOSURE_SCHEMA_VERSION,
                closure.schema_version
            ),
        );
    }

    summary.ok(
        format!(
            "case closure schema version {} is supported",
            closure.schema_version
        ),
    );

    if closure.case_id
        != case.id
    {
        return Err(
            format!(
                "case_closure.json case ID {} does not match case.json ID {}",
                closure.case_id,
                case.id
            ),
        );
    }

    summary.ok(
        "case closure ID matches case.json",
    );

    if closure.final_sequence
        != last_entry.sequence
    {
        return Err(
            format!(
                "closure final_sequence mismatch: closure={}, audit={}",
                closure.final_sequence,
                last_entry.sequence
            ),
        );
    }

    summary.ok(
        format!(
            "closure final sequence matches audit ({})",
            closure.final_sequence
        ),
    );

    if closure.total_entries
        != entries.len() as u64
    {
        return Err(
            format!(
                "closure total_entries mismatch: closure={}, actual={}",
                closure.total_entries,
                entries.len()
            ),
        );
    }

    summary.ok(
        format!(
            "closure entry count matches audit ({})",
            closure.total_entries
        ),
    );

    if closure.final_head_hash
        != last_entry.entry_hash
    {
        return Err(
            format!(
                "closure final head hash mismatch: closure={}, audit={}",
                closure.final_head_hash,
                last_entry.entry_hash
            ),
        );
    }

    summary.ok(
        "closure final head hash matches final audit entry",
    );

    /*
     * ------------------------------------------------
     * ED25519 SIGNATURE
     * ------------------------------------------------
     */

    let case_signature =
        read_case_signature(
            &signature_path,
        )?;

    summary.ok(
        "case_signature.json parsed successfully",
    );

    verify_case_signature(
        &case_signature,
        &case,
        &closure,
        last_entry,
        &actual_case_hash,
        &args.trusted_public_key,
        &mut summary,
    )?;

    /*
     * ------------------------------------------------
     * ARTIFACTS
     * ------------------------------------------------
     */

    verify_artifact_entries(
        &entries,
        args
            .artifact_directory
            .as_deref(),
        &mut summary,
    )?;

    /*
     * ------------------------------------------------
     * BUILD PROVENANCE
     * ------------------------------------------------
     */

    verify_provenance_consistency(
        &entries,
        &mut summary,
    )?;

    Ok(summary)
}

fn verify_case_signature(
    signature_file: &CaseSignature,

    case: &CaseFile,

    closure: &CaseClosure,

    final_entry: &AuditEntry,

    actual_case_hash: &str,

    trusted_public_key_path: &Path,

    summary: &mut VerificationSummary,
) -> Result<(), String> {
    if signature_file.schema_version
        != SIGNATURE_SCHEMA_VERSION
    {
        return Err(
            format!(
                "unsupported case signature schema: expected {}, found {}",
                SIGNATURE_SCHEMA_VERSION,
                signature_file.schema_version
            ),
        );
    }

    summary.ok(
        format!(
            "case signature schema version {} is supported",
            signature_file.schema_version
        ),
    );

    if signature_file.algorithm
        != "Ed25519"
    {
        return Err(
            format!(
                "unsupported case signature algorithm: {}",
                signature_file.algorithm
            ),
        );
    }

    summary.ok(
        "case signature algorithm is Ed25519",
    );

    if signature_file.case_id
        != case.id
    {
        return Err(
            format!(
                "signature case ID mismatch: signature={}, case={}",
                signature_file.case_id,
                case.id
            ),
        );
    }

    summary.ok(
        "signature case ID matches case.json",
    );

    if signature_file.final_sequence
        != closure.final_sequence
    {
        return Err(
            format!(
                "signature final_sequence mismatch: signature={}, closure={}",
                signature_file.final_sequence,
                closure.final_sequence
            ),
        );
    }

    if signature_file.final_sequence
        != final_entry.sequence
    {
        return Err(
            format!(
                "signature final_sequence mismatch with audit: signature={}, audit={}",
                signature_file.final_sequence,
                final_entry.sequence
            ),
        );
    }

    summary.ok(
        "signature final sequence matches closure and audit",
    );

    if signature_file.final_head_hash
        != closure.final_head_hash
    {
        return Err(
            String::from(
                "signature final_head_hash does not match case_closure.json",
            ),
        );
    }

    if signature_file.final_head_hash
        != final_entry.entry_hash
    {
        return Err(
            String::from(
                "signature final_head_hash does not match final audit entry",
            ),
        );
    }

    summary.ok(
        "signature final head hash matches closure and audit",
    );

    if signature_file.case_metadata_sha256
        != actual_case_hash
    {
        return Err(
            format!(
                "signature case metadata hash mismatch: signature={}, actual={}",
                signature_file.case_metadata_sha256,
                actual_case_hash
            ),
        );
    }

    summary.ok(
        "signature case metadata hash matches case.json",
    );

    /*
     * Load the trusted key OUTSIDE the case.
     *
     * We intentionally do not trust the public key
     * embedded in case_signature.json by itself.
     */
    let trusted_key =
        load_trusted_public_key(
            trusted_public_key_path,
        )?;

    summary.ok(
        format!(
            "trusted public key loaded from {}",
            trusted_public_key_path.display()
        ),
    );

    let embedded_key =
        decode_public_key(
            &signature_file.public_key,
        )?;

    /*
     * The public key claimed by the case must match
     * the externally trusted public key.
     */
    if embedded_key.to_bytes()
        != trusted_key.to_bytes()
    {
        return Err(
            String::from(
                "case signature public key does not match the externally trusted public key",
            ),
        );
    }

    summary.ok(
        "case embedded public key matches trusted external public key",
    );

    let signature =
        decode_signature(
            &signature_file.signature,
        )?;

    let payload =
        SignaturePayload {
            schema_version:
                signature_file.schema_version,

            case_id:
                signature_file.case_id,

            final_sequence:
                signature_file.final_sequence,

            final_head_hash:
                &signature_file.final_head_hash,

            case_metadata_sha256:
                &signature_file.case_metadata_sha256,
        };

    let payload_bytes =
        serde_json::to_vec(
            &payload,
        )
        .map_err(
            |error| {
                format!(
                    "failed to serialize signature payload: {error}"
                )
            },
        )?;

    trusted_key
        .verify(
            &payload_bytes,
            &signature,
        )
        .map_err(
            |error| {
                format!(
                    "Ed25519 case signature verification failed: {error}"
                )
            },
        )?;

    summary.ok(
        "Ed25519 case signature is cryptographically valid",
    );

    Ok(())
}

fn load_trusted_public_key(
    path: &Path,
) -> Result<VerifyingKey, String> {
    let encoded =
        fs::read_to_string(
            path,
        )
        .map_err(
            |error| {
                format!(
                    "failed to read trusted public key {}: {error}",
                    path.display()
                )
            },
        )?;

    decode_public_key(
        encoded.trim(),
    )
}

fn decode_public_key(
    encoded: &str,
) -> Result<VerifyingKey, String> {
    let bytes =
        STANDARD
            .decode(
                encoded.trim(),
            )
            .map_err(
                |error| {
                    format!(
                        "invalid Base64 Ed25519 public key: {error}"
                    )
                },
            )?;

    let bytes:
        [u8; 32] =
        bytes
            .try_into()
            .map_err(
                |_| {
                    String::from(
                        "invalid Ed25519 public key length",
                    )
                },
            )?;

    VerifyingKey::from_bytes(
        &bytes,
    )
    .map_err(
        |error| {
            format!(
                "invalid Ed25519 public key: {error}"
            )
        },
    )
}

fn decode_signature(
    encoded: &str,
) -> Result<Signature, String> {
    let bytes =
        STANDARD
            .decode(
                encoded.trim(),
            )
            .map_err(
                |error| {
                    format!(
                        "invalid Base64 Ed25519 signature: {error}"
                    )
                },
            )?;

    let bytes:
        [u8; 64] =
        bytes
            .try_into()
            .map_err(
                |_| {
                    String::from(
                        "invalid Ed25519 signature length",
                    )
                },
            )?;

    Ok(
        Signature::from_bytes(
            &bytes,
        ),
    )
}

fn read_case_file(
    path: &Path,
) -> Result<CaseFile, String> {
    let data =
        fs::read_to_string(
            path,
        )
        .map_err(
            |error| {
                format!(
                    "failed to read {}: {error}",
                    path.display()
                )
            },
        )?;

    serde_json::from_str(
        &data,
    )
    .map_err(
        |error| {
            format!(
                "invalid case.json: {error}"
            )
        },
    )
}

fn read_closure(
    path: &Path,
) -> Result<CaseClosure, String> {
    let data =
        fs::read_to_string(
            path,
        )
        .map_err(
            |error| {
                format!(
                    "failed to read {}: {error}",
                    path.display()
                )
            },
        )?;

    serde_json::from_str(
        &data,
    )
    .map_err(
        |error| {
            format!(
                "invalid case_closure.json: {error}"
            )
        },
    )
}

fn read_case_signature(
    path: &Path,
) -> Result<CaseSignature, String> {
    let data =
        fs::read_to_string(
            path,
        )
        .map_err(
            |error| {
                format!(
                    "failed to read {}: {error}",
                    path.display()
                )
            },
        )?;

    serde_json::from_str(
        &data,
    )
    .map_err(
        |error| {
            format!(
                "invalid case_signature.json: {error}"
            )
        },
    )
}

fn read_and_verify_audit(
    path: &Path,

    expected_case_id: Uuid,
) -> Result<Vec<AuditEntry>, String> {
    let file =
        File::open(
            path,
        )
        .map_err(
            |error| {
                format!(
                    "failed to open {}: {error}",
                    path.display()
                )
            },
        )?;

    let reader =
        BufReader::new(
            file,
        );

    let mut entries =
        Vec::new();

    let mut expected_previous_hash:
        Option<String> =
        None;

    let mut expected_sequence =
        1u64;

    for (
        line_index,
        line,
    ) in reader
        .lines()
        .enumerate()
    {
        let line =
            line.map_err(
                |error| {
                    format!(
                        "failed reading audit line {}: {error}",
                        line_index + 1
                    )
                },
            )?;

        if line.trim()
            .is_empty()
        {
            continue;
        }

        let entry:
            AuditEntry =
            serde_json::from_str(
                &line,
            )
            .map_err(
                |error| {
                    format!(
                        "invalid audit JSON at line {}: {error}",
                        line_index + 1
                    )
                },
            )?;

        if entry.schema_version
            != AUDIT_SCHEMA_VERSION
        {
            return Err(
                format!(
                    "unsupported audit schema at line {}: expected {}, found {}",
                    line_index + 1,
                    AUDIT_SCHEMA_VERSION,
                    entry.schema_version
                ),
            );
        }

        if entry.case_id
            != expected_case_id
        {
            return Err(
                format!(
                    "case ID mismatch at audit line {}: expected {}, found {}",
                    line_index + 1,
                    expected_case_id,
                    entry.case_id
                ),
            );
        }

        if entry.sequence
            != expected_sequence
        {
            return Err(
                format!(
                    "audit sequence mismatch at line {}: expected {}, found {}",
                    line_index + 1,
                    expected_sequence,
                    entry.sequence
                ),
            );
        }

        if entry.previous_entry_hash
            != expected_previous_hash
        {
            return Err(
                format!(
                    "audit previous-entry hash mismatch at line {}",
                    line_index + 1
                ),
            );
        }

        let calculated_hash =
            calculate_entry_hash(
                &entry,
            )?;

        if calculated_hash
            != entry.entry_hash
        {
            return Err(
                format!(
                    "audit entry hash mismatch at line {}: stored={}, calculated={}",
                    line_index + 1,
                    entry.entry_hash,
                    calculated_hash
                ),
            );
        }

        expected_previous_hash =
            Some(
                entry
                    .entry_hash
                    .clone(),
            );

        expected_sequence =
            expected_sequence
                .saturating_add(
                    1,
                );

        entries.push(
            entry,
        );
    }

    Ok(entries)
}

fn calculate_entry_hash(
    entry: &AuditEntry,
) -> Result<String, String> {
    let payload =
        AuditHashPayload {
            schema_version:
                entry.schema_version,

            sequence:
                entry.sequence,

            timestamp:
                &entry.timestamp,

            case_id:
                entry.case_id,

            action:
                &entry.action,

            result:
                &entry.result,

            tool_version:
                &entry.tool_version,

            git_commit:
                &entry.git_commit,

            cargo_lock_sha256:
                &entry.cargo_lock_sha256,

            binary_sha256:
                &entry.binary_sha256,

            evidence_filename:
                entry
                    .evidence_filename
                    .as_deref(),

            evidence_sha256:
                entry
                    .evidence_sha256
                    .as_deref(),

            case_metadata_sha256:
                entry
                    .case_metadata_sha256
                    .as_deref(),

            artifact_filename:
                entry
                    .artifact_filename
                    .as_deref(),

            artifact_sha256:
                entry
                    .artifact_sha256
                    .as_deref(),

            artifact_type:
                entry
                    .artifact_type
                    .as_deref(),

            artifact_size_bytes:
                entry
                    .artifact_size_bytes,

            source_evidence_sha256:
                entry
                    .source_evidence_sha256
                    .as_deref(),

            previous_entry_hash:
                entry
                    .previous_entry_hash
                    .as_deref(),
        };

    let bytes =
        serde_json::to_vec(
            &payload,
        )
        .map_err(
            |error| {
                format!(
                    "failed to serialize audit hash payload: {error}"
                )
            },
        )?;

    let mut hasher =
        Sha256::new();

    hasher.update(
        bytes,
    );

    Ok(
        hex::encode(
            hasher.finalize(),
        ),
    )
}

fn verify_provenance_consistency(
    entries: &[AuditEntry],

    summary:
        &mut VerificationSummary,
) -> Result<(), String> {
    let Some(first) =
        entries.first()
    else {
        return Err(
            String::from(
                "cannot verify provenance: empty audit log",
            ),
        );
    };

    for entry in entries {
        if entry.tool_version
            != first.tool_version
        {
            return Err(
                format!(
                    "tool version changed inside audit at sequence {}",
                    entry.sequence
                ),
            );
        }

        if entry.git_commit
            != first.git_commit
        {
            return Err(
                format!(
                    "Git commit changed inside audit at sequence {}",
                    entry.sequence
                ),
            );
        }

        if entry.cargo_lock_sha256
            != first.cargo_lock_sha256
        {
            return Err(
                format!(
                    "Cargo.lock hash changed inside audit at sequence {}",
                    entry.sequence
                ),
            );
        }

        if entry.binary_sha256
            != first.binary_sha256
        {
            return Err(
                format!(
                    "binary hash changed inside audit at sequence {}",
                    entry.sequence
                ),
            );
        }
    }

    summary.ok(
        format!(
            "build provenance is consistent across all entries (version {}, commit {})",
            first.tool_version,
            first.git_commit
        ),
    );

    Ok(())
}

fn verify_artifact_entries(
    entries: &[AuditEntry],

    artifact_directory:
        Option<&Path>,

    summary:
        &mut VerificationSummary,
) -> Result<(), String> {
    let artifact_entries:
        Vec<&AuditEntry> =
        entries
            .iter()
            .filter(
                |entry| {
                    entry.action
                        == AuditAction::ArtifactCreated
                },
            )
            .collect();

    if artifact_entries.is_empty() {
        summary.ok(
            "no ARTIFACT_CREATED entries to verify",
        );

        return Ok(());
    }

    summary.ok(
        format!(
            "{} artifact audit entr{} present",
            artifact_entries.len(),
            if artifact_entries.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ),
    );

    let Some(directory) =
        artifact_directory
    else {
        summary.warning(
            "artifact records exist, but no --artifact-dir was supplied; artifact metadata is protected by the audit/signature, but artifact file bytes were not independently rehashed",
        );

        return Ok(());
    };

    if !directory.is_dir() {
        return Err(
            format!(
                "artifact directory does not exist or is not a directory: {}",
                directory.display()
            ),
        );
    }

    for entry in artifact_entries {
        let filename =
            entry
                .artifact_filename
                .as_deref()
                .ok_or_else(
                    || {
                        format!(
                            "ARTIFACT_CREATED sequence {} has no artifact_filename",
                            entry.sequence
                        )
                    },
                )?;

        let expected_hash =
            entry
                .artifact_sha256
                .as_deref()
                .ok_or_else(
                    || {
                        format!(
                            "ARTIFACT_CREATED sequence {} has no artifact_sha256",
                            entry.sequence
                        )
                    },
                )?;

        let expected_size =
            entry
                .artifact_size_bytes
                .ok_or_else(
                    || {
                        format!(
                            "ARTIFACT_CREATED sequence {} has no artifact_size_bytes",
                            entry.sequence
                        )
                    },
                )?;

        if entry
            .source_evidence_sha256
            .is_none()
        {
            return Err(
                format!(
                    "ARTIFACT_CREATED sequence {} is not linked to source evidence",
                    entry.sequence
                ),
            );
        }

        let path =
            directory.join(
                filename,
            );

        let metadata =
            fs::metadata(
                &path,
            )
            .map_err(
                |error| {
                    format!(
                        "artifact missing or unreadable {}: {error}",
                        path.display()
                    )
                },
            )?;

        if !metadata.is_file() {
            return Err(
                format!(
                    "artifact is not a regular file: {}",
                    path.display()
                ),
            );
        }

        if metadata.len()
            != expected_size
        {
            return Err(
                format!(
                    "artifact size mismatch for {}: audit={}, actual={}",
                    filename,
                    expected_size,
                    metadata.len()
                ),
            );
        }

        let actual_hash =
            sha256_file(
                &path,
            )
            .map_err(
                |error| {
                    format!(
                        "failed to hash artifact {}: {error}",
                        path.display()
                    )
                },
            )?;

        if actual_hash
            != expected_hash
        {
            return Err(
                format!(
                    "artifact SHA-256 mismatch for {}: audit={}, actual={}",
                    filename,
                    expected_hash,
                    actual_hash
                ),
            );
        }

        summary.ok(
            format!(
                "artifact verified: {}",
                filename
            ),
        );
    }

    Ok(())
}

fn sha256_file(
    path: &Path,
) -> io::Result<String> {
    const BUFFER_SIZE: usize =
        1024 * 1024;

    let mut file =
        File::open(
            path,
        )?;

    let mut hasher =
        Sha256::new();

    let mut buffer =
        vec![
            0u8;
            BUFFER_SIZE
        ];

    loop {
        let count =
            file.read(
                &mut buffer,
            )?;

        if count == 0 {
            break;
        }

        hasher.update(
            &buffer[..count],
        );
    }

    Ok(
        hex::encode(
            hasher.finalize(),
        ),
    )
}