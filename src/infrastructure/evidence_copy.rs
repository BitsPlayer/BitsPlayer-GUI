use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

pub use crate::domain::evidence::VerifiedCopy;
use crate::infrastructure::hashing::sha256_file;

const COPY_BUFFER_SIZE: usize = 1024 * 1024;

/// Copies `source` into a new `destination` and never overwrites an existing file.
/// This is not an atomic snapshot of a source that is still being modified.
pub fn create_verified_copy(source: &Path, destination: &Path) -> io::Result<VerifiedCopy> {
    let mut input = File::open(source)?;
    let before = input.metadata()?;
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source is not a regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut output = options.open(destination)?;

    let result = copy_and_verify(&mut input, &before, &mut output, source, destination);
    drop(output);
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn copy_and_verify(
    input: &mut File,
    before: &fs::Metadata,
    output: &mut File,
    source: &Path,
    destination: &Path,
) -> io::Result<VerifiedCopy> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    let mut size_bytes = 0_u64;

    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        size_bytes += read as u64;
    }
    output.sync_all()?;

    let after = input.metadata()?;
    if size_bytes != before.len() || !is_unchanged(before, &after) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source changed while copying",
        ));
    }

    let copy = VerifiedCopy {
        source_path: source.to_path_buf(),
        copy_path: destination.to_path_buf(),
        size_bytes,
        sha256: hex::encode(hasher.finalize()),
    };
    protect_working_copy(&copy)?;
    if !verify_working_copy(&copy)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "working copy hash does not match source",
        ));
    }
    Ok(copy)
}

fn is_unchanged(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return false;
        }
    }
    after.len() == before.len() && before.modified().ok() == after.modified().ok()
}

pub fn verify_working_copy(copy: &VerifiedCopy) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(&copy.copy_path)?;
    if !metadata.is_file() || metadata.len() != copy.size_bytes {
        return Ok(false);
    }
    Ok(sha256_file(&copy.copy_path)? == copy.sha256)
}

/// Owner-read-only permissions guard against accidental writes; they are not immutable storage.
pub fn protect_working_copy(copy: &VerifiedCopy) -> io::Result<()> {
    if !verify_working_copy(copy)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "working copy failed SHA-256 verification",
        ));
    }

    let mut permissions = fs::metadata(&copy.copy_path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o400);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    fs::set_permissions(&copy.copy_path, permissions)?;

    if !verify_working_copy(copy)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "working copy changed after protection",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bitsplayer_{name}_{}", Uuid::new_v4()))
    }

    #[test]
    fn copies_and_verifies_without_overwriting() {
        let dir = temp_dir("copy_test");
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.mp4");
        let target = dir.join("working.mp4");
        fs::write(&source, b"test evidence bytes").unwrap();

        let copy = create_verified_copy(&source, &target).unwrap();
        assert!(verify_working_copy(&copy).unwrap());
        assert_eq!(copy.sha256, sha256_file(&source).unwrap());
        assert!(create_verified_copy(&source, &target).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        let mut permissions = fs::metadata(&target).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o600);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        fs::set_permissions(&target, permissions).unwrap();

        fs::write(&target, b"changed evidence").unwrap();
        assert!(!verify_working_copy(&copy).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_destination_is_left_untouched() {
        let dir = temp_dir("copy_existing");
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.mp4");
        let target = dir.join("working.mp4");
        fs::write(&source, b"original").unwrap();
        fs::write(&target, b"other").unwrap();

        assert!(create_verified_copy(&source, &target).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"other");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_same_source_and_destination() {
        let dir = temp_dir("copy_same");
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.mp4");
        fs::write(&source, b"original").unwrap();

        assert!(create_verified_copy(&source, &source).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"original");
        fs::remove_dir_all(dir).unwrap();
    }
}
