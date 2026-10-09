use std::{env, path::Path, process::ExitCode};

use crate::application::report::write_case_report;

pub fn run() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [flag] if flag == "--help" || flag == "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        [case_directory] => generate(Path::new(case_directory)),
        _ => {
            eprintln!("ERROR: exactly one case directory is required");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn generate(case_directory: &Path) -> ExitCode {
    match write_case_report(case_directory) {
        Ok((json_path, html_path)) => {
            println!("Report written: {}", json_path.display());
            println!("HTML Report written: {}", html_path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Report failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("BitsPlayer forensic report writer");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  bitsplayer-report <CASE_DIRECTORY>");
}
