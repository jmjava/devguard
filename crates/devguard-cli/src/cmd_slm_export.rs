//! `devguard slm export`.
//!
//! Reads stored SLM runs and writes a paper CSV and JSON table. Missing
//! latency, quality, energy, and scores stay empty. This command does not
//! call Ollama, bind a port, or call nvidia-smi.

use std::path::PathBuf;

use clap::Subcommand;
use devguard_core::exit::ExitCode;
use devguard_core::json::JsonEnvelope;
use devguard_core::slm_export::export_paper_table;
use devguard_core::{DevGuardError, DevGuardPaths};
use serde::Serialize;

use crate::cmd_slm_run::state_dir;
use crate::output::{emit_human, emit_json};

#[derive(Debug, Subcommand)]
pub enum SlmCommands {
    /// Write a paper CSV and JSON table from stored SLM runs.
    ///
    /// Columns follow the paper checklist. A field the run does not store
    /// stays empty. Does not call Ollama, bind a port, or call nvidia-smi,
    /// and does not invent latency, quality, energy, or scores.
    Export {
        /// Directory for `slm-export.csv` and `slm-export.json`.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
}

pub fn run(
    json: bool,
    paths: &DevGuardPaths,
    action: SlmCommands,
) -> Result<ExitCode, DevGuardError> {
    let SlmCommands::Export { out } = action;
    let state = state_dir(paths)?;
    let written = export_paper_table(&state, &out)?;
    let view = ExportView {
        csv: written.csv_path.display().to_string(),
        json_path: written.json_path.display().to_string(),
        rows: written.rows,
        calls_ollama: false,
        binds_port: false,
        calls_nvidia_smi: false,
    };
    if json {
        emit_json(&JsonEnvelope::success("slm export", &view))?;
    } else {
        emit_human(&format!(
            "DevGuard slm export\n  \
             rows: {rows}\n  \
             csv: {csv}\n  \
             json: {json_path}\n  \
             calls Ollama: no\n  \
             binds a port: no\n  \
             calls nvidia-smi: no\n",
            rows = view.rows,
            csv = view.csv,
            json_path = view.json_path,
        ));
    }
    Ok(ExitCode::Success)
}

#[derive(Serialize)]
struct ExportView {
    csv: String,
    json_path: String,
    rows: usize,
    calls_ollama: bool,
    binds_port: bool,
    calls_nvidia_smi: bool,
}
