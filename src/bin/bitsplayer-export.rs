use std::path::PathBuf;

use bitsplayer::export::create_export_package;

fn main() {

    let Some(path) = std::env::args().nth(1) else {
        eprintln!("Usage: bitsplayer-export <CASE_DIRECTORY>");
        std::process::exit(1);
    };

    let case = PathBuf::from(path);

    match create_export_package(&case) {

        Ok(output) => {
            println!(
                "Export package created: {}",
                output.display()
            );
        }

        Err(err) => {
            eprintln!(
                "Export failed: {err}"
            );
            std::process::exit(1);
        }
    }
}
