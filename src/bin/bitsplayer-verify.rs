use std::{env, path::PathBuf, process};

use bitsplayer::forensic::signing::default_public_key_path;
use bitsplayer::forensic::verify::verify_case;

struct Arguments {
    case_directory: PathBuf,
    artifact_directory: Option<PathBuf>,
    trusted_public_key: PathBuf,
}

fn main() {
    let args = match parse_arguments() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("ERROR: {message}");
            print_usage();
            process::exit(2);
        }
    };

    match verify_case(
        &args.case_directory,
        args.artifact_directory.as_deref(),
        &args.trusted_public_key,
    ) {
        Ok(summary) => {
            for check in &summary.checks {
                println!("[OK] {check}");
            }
            for warning in &summary.warnings {
                println!("[WARNING] {warning}");
            }
            println!();
            println!("VALID FORENSIC CASE");
            println!(
                "{} checks passed, {} warning(s)",
                summary.checks.len(),
                summary.warnings.len()
            );
            process::exit(0);
        }
        Err(error) => {
            println!();
            eprintln!("INVALID FORENSIC CASE");
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut args = env::args().skip(1);

    let Some(first) = args.next() else {
        return Err(String::from("case directory is required"));
    };

    if first == "--help" || first == "-h" {
        print_usage();
        process::exit(0);
    }

    let case_directory = PathBuf::from(first);
    let mut artifact_directory = None;
    let mut trusted_public_key = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--artifact-dir" => {
                let Some(path) = args.next() else {
                    return Err(String::from("--artifact-dir requires a directory"));
                };
                artifact_directory = Some(PathBuf::from(path));
            }
            "--public-key" => {
                let Some(path) = args.next() else {
                    return Err(String::from("--public-key requires a file path"));
                };
                trusted_public_key = Some(PathBuf::from(path));
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    let trusted_public_key = match trusted_public_key {
        Some(path) => path,
        None => default_public_key_path().map_err(|error| {
            format!("HOME environment variable is not available; use --public-key ({error})")
        })?,
    };

    Ok(Arguments {
        case_directory,
        artifact_directory,
        trusted_public_key,
    })
}

fn print_usage() {
    eprintln!("BitsPlayer standalone forensic verifier");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  bitsplayer-verify <CASE_DIRECTORY>");
    eprintln!("  bitsplayer-verify <CASE_DIRECTORY> --public-key <PUBLIC_KEY_FILE>");
    eprintln!(
        "  bitsplayer-verify <CASE_DIRECTORY> --artifact-dir <DIRECTORY> --public-key <PUBLIC_KEY_FILE>"
    );
    eprintln!();
    eprintln!("Default trusted public key:");
    eprintln!("  ~/.config/bitsplayer/signing/public.key");
}
