use sha2::{Digest, Sha256};

use std::{
    fs,
    io::{self, Read},
    path::Path,
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");

    configure_git_rerun_tracking();

    let git_commit =
        git_commit()
            .unwrap_or_else(|| {
                String::from("UNKNOWN")
            });

    let cargo_lock_sha256 =
        sha256_file(
            Path::new("Cargo.lock"),
        )
        .unwrap_or_else(|err| {
            println!(
                "cargo:warning=Failed to hash Cargo.lock: {err}"
            );

            String::from("UNKNOWN")
        });

    println!(
        "cargo:rustc-env=BITPLAYER_GIT_COMMIT={git_commit}"
    );

    println!(
        "cargo:rustc-env=BITPLAYER_CARGO_LOCK_SHA256={cargo_lock_sha256}"
    );
}

fn git_commit() -> Option<String> {
    let output =
        Command::new("git")
            .args([
                "rev-parse",
                "HEAD",
            ])
            .output()
            .ok()?;

    if !output.status.success() {
        return None;
    }

    let value =
        String::from_utf8(
            output.stdout,
        )
        .ok()?;

    let value =
        value.trim();

    if value.is_empty() {
        None
    } else {
        Some(
            value.to_string(),
        )
    }
}

fn configure_git_rerun_tracking() {
    let head =
        Path::new(".git/HEAD");

    if !head.exists() {
        return;
    }

    println!(
        "cargo:rerun-if-changed=.git/HEAD"
    );

    let Ok(contents) =
        fs::read_to_string(
            head,
        )
    else {
        return;
    };

    let Some(reference) =
        contents
            .strip_prefix("ref:")
            .map(str::trim)
    else {
        return;
    };

    let reference_path =
        Path::new(".git")
            .join(reference);

    if reference_path.exists() {
        println!(
            "cargo:rerun-if-changed={}",
            reference_path.display()
        );
    }
}

fn sha256_file(
    path: &Path,
) -> io::Result<String> {
    const BUFFER_SIZE: usize =
        1024 * 1024;

    let mut file =
        fs::File::open(
            path,
        )?;

    let mut hasher =
        Sha256::new();

    let mut buffer =
        vec![0u8; BUFFER_SIZE];

    loop {
        let count =
            file.read(
                &mut buffer,
            )?;

        if count == 0 {
            break;
        }

        hasher.update(
            &buffer[..count],
        );
    }

    Ok(
        hex::encode(
            hasher.finalize(),
        ),
    )
}