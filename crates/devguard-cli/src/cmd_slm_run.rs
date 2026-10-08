//! `devguard slm run begin|end`.
//!
//! Begin writes a run record under the DevGuard state directory and prints
//! the run id. End closes that record, stores the measured duration, and
//! optionally merges harness JSON (TTFT, tokens). Neither command calls
//! Ollama or binds a port.

use std::fs;
use std::path::PathBuf;

use clap::Subcommand;
use devguard_core::exit::ExitCode;
use devguard_core::json::JsonEnvelope;
use devguard_core::slm::SlmRunRecord;
use devguard_core::slm_run::{begin_run, end_run};
use devguard_core::{DevGuardError, DevGuardPaths};
use serde::Serialize;

use crate::output::{emit_human, emit_json};

#[derive(Debug, Subcommand)]
pub enum SlmCommands {
    /// Bracket a harness run. Does not call Ollama or bind a port.
    Run {
        #[command(subcommand)]
        action: RunCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum RunCommands {
    /// Write an open run record and print its id.
    Begin {
        /// Optional label stored on the run record.
        #[arg(long)]
        label: Option<String>,
    },
    /// Close a run, record duration, and store optional harness JSON.
    End {
        /// Run id printed by `slm run begin`.
        #[arg(long, value_name = "RUN_ID")]
        id: String,
        /// Harness JSON file. TTFT and token fields are stored when present.
        ///
        /// Omitted latency and quality numbers stay unset.
        #[arg(long, value_name = "FILE")]
        harness: Option<PathBuf>,
    },
}

pub fn run(
    json: bool,
    paths: &DevGuardPaths,
    action: SlmCommands,
) -> Result<ExitCode, DevGuardError> {
    let state_dir = state_dir(paths)?;
    match action {
        SlmCommands::Run {
            action: RunCommands::Begin { label },
        } => {
            let record = begin_run(&state_dir, label)?;
            emit_record(json, "slm run begin", &record)?;
            Ok(ExitCode::Success)
        }
        SlmCommands::Run {
            action: RunCommands::End { id, harness },
        } => {
            let harness_json = match harness {
                Some(path) => Some(fs::read_to_string(&path).map_err(|err| {
                    DevGuardError::Usage(format!(
                        "failed to read harness JSON {}: {err}",
                        path.display()
                    ))
                })?),
                None => None,
            };
            let record = end_run(&state_dir, &id, harness_json.as_deref())?;
            emit_record(json, "slm run end", &record)?;
            Ok(ExitCode::Success)
        }
    }
}

fn emit_record(json: bool, command: &str, record: &SlmRunRecord) -> Result<(), DevGuardError> {
    if json {
        let view = SlmRunView {
            record,
            calls_ollama: false,
            binds_port: false,
        };
        emit_json(&JsonEnvelope::success(command, &view))?;
    } else {
        emit_human(&format_slm_run_human(command, record));
    }
    Ok(())
}

fn format_slm_run_human(command: &str, record: &SlmRunRecord) -> String {
    let label = record.run_label.as_deref().unwrap_or("none");
    let ended = record
        .ended_at
        .map(|stamp| stamp.to_rfc3339())
        .unwrap_or_else(|| "open".to_string());
    let duration = record
        .duration_s
        .map(|seconds| format!("{seconds:.3}"))
        .unwrap_or_else(|| "none".to_string());
    let latency = if record.latency.is_some() {
        "stored"
    } else {
        "absent"
    };
    let quality = if record.quality.is_some() {
        "stored"
    } else {
        "absent"
    };
    format!(
        "DevGuard {command}\n  \
         run_id: {run_id}\n  \
         started_at: {started}\n  \
         ended_at: {ended}\n  \
         duration_s: {duration}\n  \
         label: {label}\n  \
         latency: {latency}\n  \
         quality: {quality}\n  \
         calls Ollama: no\n  \
         binds a port: no\n",
        run_id = record.run_id,
        started = record.started_at.to_rfc3339(),
    )
}

#[derive(Serialize)]
struct SlmRunView<'a> {
    #[serde(flatten)]
    record: &'a SlmRunRecord,
    calls_ollama: bool,
    binds_port: bool,
}

pub(crate) fn state_dir(paths: &DevGuardPaths) -> Result<PathBuf, DevGuardError> {
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
