use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

const HASH_BUFFER_SIZE: usize = 1024 * 1024;

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(HASH_BUFFER_SIZE, file);

    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let digest = hasher.finalize();

    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn calculates_known_sha256() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let path = std::env::temp_dir()
            .join(format!("bitsplayer_hash_test_{unique}.txt"));

        fs::write(&path, b"abc").unwrap();

        let hash = sha256_file(&path).unwrap();

        fs::remove_file(&path).unwrap();

        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223\
b00361a396177a9cb410ff61f20015ad"
        );
    }
}