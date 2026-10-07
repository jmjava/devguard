//! Human and JSON output helpers.

use std::io::{self, Write};
use std::path::Path;

use devguard_core::doctor::{DoctorReport, PrerequisiteStatus};
use serde::Serialize;

pub fn emit_json<T: Serialize>(value: &T) -> Result<(), devguard_core::DevGuardError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

pub fn emit_human(text: &str) {
    print!("{text}");
}

pub fn print_doctor_human(report: &DoctorReport, config_path: &Path) {
    println!("DevGuard doctor");
    println!(
        "  host: {}/{} ({})",
        report.host.os, report.host.arch, report.host.hostname_hash
    );
    println!("  config: {}", config_path.display());
    println!(
        "  ready (read-only): {}",
        if report.ready_for_readonly {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "  ready (SLM GPU metrics): {}",
        if report.ready_for_gpu_metrics {
            "yes"
        } else {
            "no"
        }
    );
    println!();
    println!("Checks:");
    for check in &report.checks {
        let mark = match check.status {
            PrerequisiteStatus::Ok => "ok",
            PrerequisiteStatus::Missing => "missing",
            PrerequisiteStatus::Warning => "warn",
            PrerequisiteStatus::Unknown => "unknown",
        };
        println!(
            "  [{mark:7}] {id:18} ({category}) {detail}",
            id = check.id,
            category = check.category,
            detail = check.detail
        );
    }
    if !report.notes.is_empty() {
        println!();
        println!("Notes:");
        for note in &report.notes {
            println!("  - {note}");
        }
    }
}
