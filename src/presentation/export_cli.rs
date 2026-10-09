use std::{env, path::Path, process::ExitCode};

use crate::application::export::create_export_package;

pub fn run() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        [case_directory] => export(Path::new(case_directory)),
        _ => {
            eprintln!("ERROR: exactly one case directory is required");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn export(case_directory: &Path) -> ExitCode {
    match create_export_package(case_directory) {
        Ok(output) => {
            println!("Export package created: {}", output.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Export failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("BitsPlayer forensic export package writer");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  bitsplayer-export <CASE_DIRECTORY>");
}
