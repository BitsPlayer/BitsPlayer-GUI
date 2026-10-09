use std::{env, path::Path, process::ExitCode};

use crate::application::export::verify_export_package;

pub fn run() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        [zip_path] => verify(Path::new(zip_path)),
        _ => {
            eprintln!("ERROR: exactly one export package is required");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn verify(zip_path: &Path) -> ExitCode {
    match verify_export_package(zip_path) {
        Ok(verification) => {
            for check in &verification.checks {
                println!("[OK] {check}");
            }
            println!();
            println!("VALID EXPORT PACKAGE");
            ExitCode::SUCCESS
        }
        Err(message) => {
            println!();
            eprintln!("INVALID EXPORT PACKAGE");
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("BitsPlayer export package verifier");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  bitsplayer-export-verify <EXPORT_ZIP>");
}
