use std::path::PathBuf;

use bitsplayer::forensic::report::ForensicReport;


fn main() {

    let args: Vec<String> =
        std::env::args().collect();

    if args.len() != 2 {
        eprintln!(
            "Usage: bitsplayer-report <case-directory>"
        );
        std::process::exit(1);
    }


    let case =
        PathBuf::from(&args[1]);


    let report =
        ForensicReport::generate(&case)
            .expect("failed generating report");


    let output =
        report.save_json(&case)
            .expect("failed saving report");

    println!(
        "Report written: {}",
        output.display()
    );

    let html =
        report.save_html(&case)
            .expect("failed saving html report");

    println!(
        "HTML Report written: {}",
        html.display()
    );
}

