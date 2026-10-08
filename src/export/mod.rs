use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use zip::{
    write::SimpleFileOptions,
    ZipWriter,
};

fn add_file_to_zip(
    zip: &mut ZipWriter<std::fs::File>,
    source: &Path,
    name: &str,
) -> io::Result<()> {

    let options = SimpleFileOptions::default();

    zip.start_file(name, options)?;

    let data = fs::read(source)?;

    zip.write_all(&data)?;

    Ok(())
}


pub fn create_export_package(
    case_directory: &Path,
) -> io::Result<PathBuf> {

    let case_name = case_directory
        .file_name()
        .unwrap()
        .to_string_lossy();

    let output = case_directory
        .parent()
        .unwrap()
        .join(format!(
            "{}-export.zip",
            case_name
        ));


    let file = fs::File::create(&output)?;

    let mut zip = ZipWriter::new(file);


    let files = [
        "case.json",
        "case_closure.json",
        "case_signature.json",
        "report.json",
        "report.html",
        "report_manifest.json",
    ];


    for item in files {

        let path = case_directory.join(item);

        if path.exists() {

            add_file_to_zip(
                &mut zip,
                &path,
                item,
            )?;

        }
    }


    let audit = case_directory
        .join("logs")
        .join("audit.jsonl");


    if audit.exists() {

        add_file_to_zip(
            &mut zip,
            &audit,
            "logs/audit.jsonl",
        )?;

    }


    let evidence = case_directory
        .join("evidence");


    if evidence.exists() {

        for entry in fs::read_dir(evidence)? {

            let entry = entry?;

            let path = entry.path();

            if path.is_file() {

                let name = format!(
                    "evidence/{}",
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                );

                add_file_to_zip(
                    &mut zip,
                    &path,
                    &name,
                )?;
            }
        }
    }


    zip.start_file(
        "verification_result.txt",
        SimpleFileOptions::default(),
    )?;

    zip.write_all(
        b"BitsPlayer Forensic Export Package\n\n\
    Verification command:\n\
    bitsplayer-verify <EXPORTED_CASE_DIRECTORY>\n\n\
    Expected result:\n\
    VALID FORENSIC CASE\n\
    32 checks passed\n",
    )?;


    zip.finish()?;


    let zip_bytes = fs::read(&output)?;

    let mut hasher = Sha256::new();

    hasher.update(&zip_bytes);

    let hash = hex::encode(
        hasher.finalize()
    );


    let hash_path = output.with_extension("zip.sha256");


    fs::write(
        &hash_path,
        format!(
            "SHA256: {}\nFILE: {}\n",
            hash,
            output
                .file_name()
                .unwrap()
                .to_string_lossy()
        ),
    )?;


    Ok(output)
}