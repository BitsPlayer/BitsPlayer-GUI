use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::infrastructure::hashing::sha256_file;
use crate::infrastructure::report::write_new;

/// Writes a new ZIP at `output` containing `files` (archive name, source path) and
/// `generated` (archive name, contents), then writes `<output>.sha256`. Both files are
/// created new; on failure, the ZIP written here is removed.
pub fn write_export_zip(
    output: &Path,
    files: &[(String, PathBuf)],
    generated: &[(&str, &str)],
) -> io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;

    if let Err(err) = write_archive(file, files, generated) {
        let _ = fs::remove_file(output);
        return Err(err);
    }

    let result = sha256_file(output).and_then(|digest| {
        let file_name = output
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        write_new(
            sha256_path(output),
            format!("SHA256: {digest}\nFILE: {file_name}\n").as_bytes(),
        )
    });
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result.map(|_| ())
}

fn write_archive(
    file: File,
    files: &[(String, PathBuf)],
    generated: &[(&str, &str)],
) -> io::Result<()> {
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default();

    for (name, source) in files {
        zip.start_file(name.as_str(), options)?;
        io::copy(&mut File::open(source)?, &mut zip)?;
    }
    for (name, contents) in generated {
        zip.start_file(*name, options)?;
        zip.write_all(contents.as_bytes())?;
    }

    let file = zip.finish()?;
    file.sync_all()
}

pub fn zip_member_names(zip_path: &Path) -> io::Result<Vec<String>> {
    let archive = open_archive(zip_path)?;
    Ok(archive.file_names().map(String::from).collect())
}

pub fn read_zip_member(zip_path: &Path, name: &str) -> io::Result<Vec<u8>> {
    let mut archive = open_archive(zip_path)?;
    let mut member = archive.by_name(name).map_err(io::Error::other)?;
    let mut data = Vec::new();
    member.read_to_end(&mut data)?;
    Ok(data)
}

pub fn zip_member_sha256(zip_path: &Path, name: &str) -> io::Result<String> {
    let data = read_zip_member(zip_path, name)?;
    Ok(hex::encode(Sha256::digest(&data)))
}

pub fn sha256_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_owned();
    path.push(".sha256");
    PathBuf::from(path)
}

fn open_archive(zip_path: &Path) -> io::Result<ZipArchive<File>> {
    ZipArchive::new(File::open(zip_path)?).map_err(io::Error::other)
}
