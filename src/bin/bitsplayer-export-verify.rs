use std::{
    fs,
    path::PathBuf,
};

use sha2::{Digest, Sha256};
use zip::ZipArchive;
use std::fs::File;


fn main() {

    let Some(path) = std::env::args().nth(1) else {
        eprintln!("Usage: bitsplayer-export-verify <EXPORT_ZIP>");
        std::process::exit(1);
    };


    let zip_path = PathBuf::from(path);


    if !zip_path.exists() {
        eprintln!("Export package not found");
        std::process::exit(1);
    }


    let hash_path =
        zip_path.with_extension("zip.sha256");


    let expected =
        fs::read_to_string(&hash_path)
            .expect("Missing ZIP SHA256 file");


    let data =
        fs::read(&zip_path)
            .expect("Cannot read ZIP");


    let mut hasher = Sha256::new();

    hasher.update(&data);

    let actual =
        hex::encode(hasher.finalize());


    if !expected.contains(&actual) {
        println!("INVALID EXPORT PACKAGE");
        println!("ZIP SHA256 mismatch");
        std::process::exit(1);
    }


    println!("[OK] ZIP SHA256 verified");


    let file =
        File::open(&zip_path)
            .expect("Cannot open ZIP");


    let mut archive =
        ZipArchive::new(file)
            .expect("Invalid ZIP");


    let required = [
        "case.json",
        "case_closure.json",
        "case_signature.json",
        "report.json",
        "report.html",
        "report_manifest.json",
        "logs/audit.jsonl",
        "verification_result.txt",
    ];


    for item in required {

        if archive.by_name(item).is_err() {

            println!(
                "INVALID EXPORT PACKAGE"
            );

            println!(
                "Missing file: {}",
                item
            );

            std::process::exit(1);
        }
    }


    println!("[OK] Required files present");
    println!("[OK] Export package structure valid");

    println!();
    println!("VALID EXPORT PACKAGE");
}
