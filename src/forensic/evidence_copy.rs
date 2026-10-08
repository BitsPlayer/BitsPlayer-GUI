use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::forensic::hashing::sha256_file;

#[derive(Debug, Clone)]
pub struct VerifiedCopy {
    pub source_path: PathBuf,
    pub copy_path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

/// Create a new working copy without overwriting an existing file.
///
/// This is a best-effort copy verification, not an atomic snapshot of mutable
/// source media. Use a hardware write blocker or read-only source for evidence.
pub fn create_verified_copy(source: &Path, destination: &Path) -> io::Result<VerifiedCopy> {
    let mut input = File::open(source)?;
    let before = input.metadata()?;
    if !before.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "source is not a regular file"));
    }

    // Prevent an existing destination from being overwritten. On Unix,
    // O_NOFOLLOW also prevents the destination from being a symlink.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux O_NOFOLLOW; the project currently targets Ubuntu.
        options.custom_flags(0o400000);
    }
    let mut output = options.open(destination)?;

    let result = (|| -> io::Result<VerifiedCopy> {
        let mut source_hash = Sha256::new();
        let mut buffer = [0u8; 1024 * 1024];
        let mut count = 0u64;
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 { break; }
            output.write_all(&buffer[..n])?;
            source_hash.update(&buffer[..n]);
            count += n as u64;
        }
        output.sync_all()?;
        let after = input.metadata()?;
        if count != before.len() || after.len() != before.len()
            || before.modified().ok() != after.modified().ok()
        {
            return Err(io::Error::new(io::ErrorKind::Other, "source changed while copying"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if before.dev() != after.dev() || before.ino() != after.ino()
                || before.ctime() != after.ctime() || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(io::Error::new(io::ErrorKind::Other, "source metadata changed while copying"));
            }
        }
        let expected = hex::encode(source_hash.finalize());
        let actual = sha256_file(destination)?;
        if expected != actual {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "working-copy SHA-256 mismatch"));
        }
        Ok(VerifiedCopy {
            source_path: source.to_path_buf(),
            copy_path: destination.to_path_buf(),
            size_bytes: count,
            sha256: expected,
        })
    })();

    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(destination);
    }
    result
}

pub fn verify_working_copy(copy: &VerifiedCopy) -> io::Result<bool> {
    let metadata = fs::metadata(&copy.copy_path)?;
    if !metadata.is_file() || metadata.len() != copy.size_bytes { return Ok(false); }
    Ok(sha256_file(&copy.copy_path)? == copy.sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_and_verifies_without_overwriting() {
        let dir = std::env::temp_dir().join(format!("bitsplayer_copy_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let source = dir.join("source.mp4");
        let target = dir.join("working.mp4");
        fs::write(&source, b"test evidence bytes").unwrap();
        let copy = create_verified_copy(&source, &target).unwrap();
        assert!(verify_working_copy(&copy).unwrap());
        assert_eq!(copy.sha256, sha256_file(&source).unwrap());
        assert!(create_verified_copy(&source, &target).is_err());
        fs::write(&target, b"changed evidence").unwrap();
        assert!(!verify_working_copy(&copy).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_same_source_and_destination() {
        let dir = std::env::temp_dir().join(format!("bitsplayer_copy_same_{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let source = dir.join("source.mp4");
        fs::write(&source, b"original").unwrap();
        assert!(create_verified_copy(&source, &source).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"original");
        fs::remove_dir_all(dir).unwrap();
    }
}