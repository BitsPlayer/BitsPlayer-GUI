use base64::{
    engine::general_purpose::STANDARD,
    Engine as _,
};

use ed25519_dalek::{
    Signature,
    Signer,
    SigningKey,
    Verifier,
    VerifyingKey,
};

use rand_core::OsRng;

use serde::{
    Deserialize,
    Serialize,
};

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use uuid::Uuid;

pub const SIGNATURE_SCHEMA_VERSION: u32 = 1;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
)]
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
struct SignaturePayload<'a> {
    schema_version: u32,
    case_id: Uuid,

    final_sequence: u64,

    final_head_hash: &'a str,
    case_metadata_sha256: &'a str,
}

pub struct SigningIdentity {
    signing_key: SigningKey,
}

impl SigningIdentity {
    pub fn load_or_create() -> io::Result<Self> {
        let directory =
            signing_directory()?;

        fs::create_dir_all(
            &directory,
        )?;

        let private_path =
            directory.join(
                "private.key",
            );

        let public_path =
            directory.join(
                "public.key",
            );

        if private_path.exists() {
            let encoded =
                fs::read_to_string(
                    &private_path,
                )?;

            let bytes =
                STANDARD
                    .decode(
                        encoded.trim(),
                    )
                    .map_err(
                        io::Error::other,
                    )?;

            let key_bytes:
                [u8; 32] =
                bytes
                    .try_into()
                    .map_err(
                        |_| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid Ed25519 private key length",
                            )
                        },
                    )?;

            let signing_key =
                SigningKey::from_bytes(
                    &key_bytes,
                );

            return Ok(
                Self {
                    signing_key,
                },
            );
        }

        let signing_key =
            SigningKey::generate(
                &mut OsRng,
            );

        let verifying_key =
            signing_key
                .verifying_key();

        fs::write(
            &private_path,
            STANDARD.encode(
                signing_key
                    .to_bytes(),
            ),
        )?;

        fs::write(
            &public_path,
            STANDARD.encode(
                verifying_key
                    .to_bytes(),
            ),
        )?;

        set_private_permissions(
            &private_path,
        )?;

        Ok(
            Self {
                signing_key,
            },
        )
    }

    pub fn sign_case(
        &self,

        case_id: Uuid,

        final_sequence: u64,

        final_head_hash: &str,

        case_metadata_sha256: &str,
    ) -> io::Result<CaseSignature> {
        let payload =
            SignaturePayload {
                schema_version:
                    SIGNATURE_SCHEMA_VERSION,

                case_id,

                final_sequence,

                final_head_hash,

                case_metadata_sha256,
            };

        let bytes =
            serde_json::to_vec(
                &payload,
            )
            .map_err(
                io::Error::other,
            )?;

        let signature =
            self.signing_key
                .sign(
                    &bytes,
                );

        let public_key =
            self.signing_key
                .verifying_key();

        Ok(
            CaseSignature {
                schema_version:
                    SIGNATURE_SCHEMA_VERSION,

                algorithm:
                    String::from(
                        "Ed25519",
                    ),

                case_id,

                final_sequence,

                final_head_hash:
                    final_head_hash
                        .to_string(),

                case_metadata_sha256:
                    case_metadata_sha256
                        .to_string(),

                public_key:
                    STANDARD.encode(
                        public_key
                            .to_bytes(),
                    ),

                signature:
                    STANDARD.encode(
                        signature
                            .to_bytes(),
                    ),
            },
        )
    }
}

impl CaseSignature {
    pub fn save(
        &self,
        case_directory:
            impl AsRef<Path>,
    ) -> io::Result<PathBuf> {
        let path =
            case_directory
                .as_ref()
                .join(
                    "case_signature.json",
                );

        let json =
            serde_json::to_string_pretty(
                self,
            )
            .map_err(
                io::Error::other,
            )?;

        fs::write(
            &path,
            json,
        )?;

        Ok(path)
    }

    pub fn verify(
        &self,
    ) -> io::Result<()> {
        if self.algorithm
            != "Ed25519"
        {
            return Err(
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported signature algorithm",
                ),
            );
        }

        let public_bytes =
            STANDARD
                .decode(
                    self.public_key
                        .trim(),
                )
                .map_err(
                    io::Error::other,
                )?;

        let public_array:
            [u8; 32] =
            public_bytes
                .try_into()
                .map_err(
                    |_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid Ed25519 public key length",
                        )
                    },
                )?;

        let verifying_key =
            VerifyingKey::from_bytes(
                &public_array,
            )
            .map_err(
                io::Error::other,
            )?;

        let signature_bytes =
            STANDARD
                .decode(
                    self.signature
                        .trim(),
                )
                .map_err(
                    io::Error::other,
                )?;

        let signature_array:
            [u8; 64] =
            signature_bytes
                .try_into()
                .map_err(
                    |_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid Ed25519 signature length",
                        )
                    },
                )?;

        let signature =
            Signature::from_bytes(
                &signature_array,
            );

        let payload =
            SignaturePayload {
                schema_version:
                    self.schema_version,

                case_id:
                    self.case_id,

                final_sequence:
                    self.final_sequence,

                final_head_hash:
                    &self.final_head_hash,

                case_metadata_sha256:
                    &self.case_metadata_sha256,
            };

        let bytes =
            serde_json::to_vec(
                &payload,
            )
            .map_err(
                io::Error::other,
            )?;

        verifying_key
            .verify(
                &bytes,
                &signature,
            )
            .map_err(
                io::Error::other,
            )
    }
}

fn signing_directory(
) -> io::Result<PathBuf> {
    let home =
        std::env::var_os(
            "HOME",
        )
        .ok_or_else(
            || {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "HOME environment variable is not available",
                )
            },
        )?;

    Ok(
        PathBuf::from(
            home,
        )
        .join(".config")
        .join("bitsplayer")
        .join("signing"),
    )
}

#[cfg(unix)]
fn set_private_permissions(
    path: &Path,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions =
        fs::Permissions::from_mode(
            0o600,
        );

    fs::set_permissions(
        path,
        permissions,
    )
}

#[cfg(not(unix))]
fn set_private_permissions(
    _path: &Path,
) -> io::Result<()> {
    Ok(())
}