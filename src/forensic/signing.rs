use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
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
struct SignaturePayload<'a> {
    schema_version: u32,
    case_id: Uuid,
    final_sequence: u64,
    final_head_hash: &'a str,
    case_metadata_sha256: &'a str,
}

pub struct SigningIdentity {
    signing_key: SigningKey,
    origin: IdentityOrigin,
    directory: PathBuf,
}

impl SigningIdentity {
    pub fn load_or_create() -> io::Result<Self> {
        Self::load_or_create_in(signing_directory()?)
    }

    pub fn load_or_create_in(directory: impl AsRef<Path>) -> io::Result<Self> {
        let directory = directory.as_ref();
        ensure_private_directory(directory)?;

        let private_path = directory.join("private.key");
        let public_path = directory.join("public.key");

        if private_path.exists() {
            restrict_private_key(&private_path)?;
            let signing_key = read_signing_key(&private_path)?;
            return Ok(Self {
                signing_key,
                origin: IdentityOrigin::Loaded,
                directory: directory.to_path_buf(),
            });
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        write_private_file(
            &private_path,
            &STANDARD.encode(signing_key.to_bytes()),
        )?;
        write_public_file(
            &public_path,
            &STANDARD.encode(verifying_key.to_bytes()),
        )?;

        Ok(Self {
            signing_key,
            origin: IdentityOrigin::Created,
            directory: directory.to_path_buf(),
        })
    }

    pub fn origin(&self) -> IdentityOrigin {
        self.origin
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_path(&self) -> PathBuf {
        self.directory.join("public.key")
    }

    pub fn sign_case(
        &self,
        case_id: Uuid,
        final_sequence: u64,
        final_head_hash: &str,
        case_metadata_sha256: &str,
    ) -> io::Result<CaseSignature> {
        let payload = SignaturePayload {
            schema_version: SIGNATURE_SCHEMA_VERSION,
            case_id,
            final_sequence,
            final_head_hash,
            case_metadata_sha256,
        };

        let bytes = serde_json::to_vec(&payload).map_err(io::Error::other)?;
        let signature = self.signing_key.sign(&bytes);
        let public_key = self.signing_key.verifying_key();

        Ok(CaseSignature {
            schema_version: SIGNATURE_SCHEMA_VERSION,
            algorithm: String::from("Ed25519"),
            case_id,
            final_sequence,
            final_head_hash: final_head_hash.to_string(),
            case_metadata_sha256: case_metadata_sha256.to_string(),
            public_key: STANDARD.encode(public_key.to_bytes()),
            signature: STANDARD.encode(signature.to_bytes()),
        })
    }
}

impl CaseSignature {
    pub fn save(&self, case_directory: impl AsRef<Path>) -> io::Result<PathBuf> {
        let path = case_directory.as_ref().join("case_signature.json");
        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(path)
    }

    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let data = fs::read_to_string(path)?;
        let signature: Self = serde_json::from_str(&data).map_err(io::Error::other)?;

        if signature.schema_version != SIGNATURE_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported signature schema version {}",
                    signature.schema_version
                ),
            ));
        }

        Ok(signature)
    }

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

pub fn load_verifying_key(path: impl AsRef<Path>) -> io::Result<VerifyingKey> {
    let encoded = fs::read_to_string(path)?;
    decode_verifying_key(encoded.trim())
}

pub fn default_public_key_path() -> io::Result<PathBuf> {
    Ok(signing_directory()?.join("public.key"))
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

fn read_signing_key(path: &Path) -> io::Result<SigningKey> {
    let encoded = fs::read_to_string(path)?;
    let bytes = STANDARD
        .decode(encoded.trim())
        .map_err(io::Error::other)?;
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Ed25519 private key length",
        )
    })?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn signing_directory() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "HOME environment variable is not available",
        )
    })?;

    Ok(PathBuf::from(home)
        .join(".config")
        .join("bitsplayer")
        .join("signing"))
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }

    #[cfg(not(unix))]
    {
        fs::create_dir(path)?;
    }

    Ok(())
}

fn write_private_file(path: &Path, contents: &str) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn write_public_file(path: &Path, contents: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn restrict_private_key(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("bitsplayer_{name}_{unique}"))
    }

    #[test]
    fn creates_private_key_before_it_is_readable() {
        let directory = temp_dir("signing");
        let identity = SigningIdentity::load_or_create_in(&directory).unwrap();

        assert_eq!(identity.origin(), IdentityOrigin::Created);
        assert!(directory.join("private.key").is_file());
        assert!(directory.join("public.key").is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(directory.join("private.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let dir_mode = fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
        }

        let reloaded = SigningIdentity::load_or_create_in(&directory).unwrap();
        assert_eq!(reloaded.origin(), IdentityOrigin::Loaded);
        assert_eq!(
            reloaded.verifying_key().as_bytes(),
            identity.verifying_key().as_bytes()
        );

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn verify_requires_the_trusted_key() {
        let directory = temp_dir("signing_verify");
        let identity = SigningIdentity::load_or_create_in(&directory).unwrap();
        let signature = identity
            .sign_case(Uuid::new_v4(), 2, "head", "meta")
            .unwrap();

        signature.verify(&identity.verifying_key()).unwrap();

        let other = SigningIdentity::load_or_create_in(temp_dir("signing_other")).unwrap();
        let err = signature.verify(&other.verifying_key()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut forged = signature.clone();
        forged.public_key = STANDARD.encode(other.verifying_key().to_bytes());
        assert!(forged.verify(&other.verifying_key()).is_err());
        assert!(forged.verify(&identity.verifying_key()).is_err());

        let _ = fs::remove_dir_all(directory);
        let _ = fs::remove_dir_all(other.directory());
    }
}
