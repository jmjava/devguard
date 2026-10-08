//! `devguard slm checklist`.
//!
//! Prints the ten paper-table fields for one stored run. Missing fields are
//! blank in JSON and `unavailable` in text. This command does not call Ollama.

use std::path::PathBuf;

use clap::Subcommand;
use devguard_core::exit::ExitCode;
use devguard_core::json::JsonEnvelope;
use devguard_core::slm_checklist::{format_paper_checklist, paper_checklist};
use devguard_core::{DevGuardError, DevGuardPaths};

use crate::output::{emit_human, emit_json};

#[derive(Debug, Subcommand)]
pub enum SlmCommands {
    /// Print the 10-field paper checklist for one stored run.
    ///
    /// A missing field is unavailable. This command does not call Ollama or
    /// invent latency, power, or task scores.
    Checklist {
        /// Run id printed by `slm run begin`.
        #[arg(long, value_name = "RUN_ID")]
        id: String,
    },
}

pub fn run(
    json: bool,
    paths: &DevGuardPaths,
    action: SlmCommands,
) -> Result<ExitCode, DevGuardError> {
    let SlmCommands::Checklist { id } = action;
    let state_dir = state_dir(paths)?;
    let report = paper_checklist(&state_dir, &id)?;
    let warnings = report.warnings();
    if json {
        let envelope = if warnings.is_empty() {
            JsonEnvelope::success("slm checklist", &report)
        } else {
            JsonEnvelope::success_with_warnings("slm checklist", &report, warnings)
        };
        emit_json(&envelope)?;
    } else {
        emit_human(&format_paper_checklist(&report));
    }
    Ok(report.exit_code())
}

fn state_dir(paths: &DevGuardPaths) -> Result<PathBuf, DevGuardError> {
    match std::env::var("DEVGUARD_STATE_DIR") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(&value);
            if !path.is_absolute() {
                return Err(DevGuardError::Usage(
                    "DEVGUARD_STATE_DIR must be an absolute path".into(),
                ));
            }
            Ok(path)
        }
        _ => Ok(paths.state_dir.clone()),
    }
}
