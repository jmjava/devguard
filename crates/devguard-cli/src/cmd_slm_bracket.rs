//! `devguard slm bracket start|end|show`.
//!
//! Bracket a local model inference run. Start records initial GPU state,
//! end records final state and computes deltas, show prints the latest
//! bracket. Brackets are stored as JSON under
//! `~/.local/share/devguard/brackets/`. Does not call Ollama or bind a port.

use clap::Subcommand;
use devguard_core::bracket::{
    brackets_dir, find_active_bracket, find_latest_bracket, format_bracket_human, load_bracket,
    save_bracket, BracketRecord,
};
use devguard_core::exit::ExitCode;
use devguard_core::json::JsonEnvelope;
use devguard_core::{DevGuardError, DevGuardPaths};

use crate::output::{emit_human, emit_json};

#[derive(Debug, Subcommand)]
pub enum SlmCommands {
    /// Bracket a local model inference run (start/end/show).
    ///
    /// Does not call Ollama or bind a port.
    Bracket {
        #[command(subcommand)]
        action: BracketCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum BracketCommands {
    /// Start a new bracket: record initial GPU state and timestamp.
    Start {
        /// Human-readable label for this run (e.g. "qwen3.5-9b-refactor-test")
        #[arg(long)]
        label: String,
    },
    /// End the active bracket: record final GPU state, compute deltas.
    End,
    /// Show the most recent bracket record.
    Show,
}

pub fn run(
    json: bool,
    _paths: &DevGuardPaths,
    action: SlmCommands,
) -> Result<ExitCode, DevGuardError> {
    let dir = brackets_dir()?;
    match action {
        SlmCommands::Bracket {
            action: BracketCommands::Start { label },
        } => {
            let record = BracketRecord::start(label);
            let path = save_bracket(&dir, &record)?;

            #[derive(serde::Serialize)]
            struct StartData {
                bracket_id: String,
                label: String,
                started_at: String,
                gpu_count: usize,
                path: String,
            }
            let data = StartData {
                bracket_id: record.bracket_id.clone(),
                label: record.label.clone(),
                started_at: record.started_at.to_rfc3339(),
                gpu_count: record.start_snapshot.gpus.len(),
                path: path.display().to_string(),
            };
            if json {
                emit_json(&JsonEnvelope::success("slm bracket start", &data))?;
            } else {
                emit_human(&format!(
                    "Bracket started: {}\n  id: {}\n  gpus: {}\n  file: {}\n\n\
                     Run your inference, then: devguard slm bracket end\n",
                    data.label, data.bracket_id, data.gpu_count, data.path
                ));
            }
            Ok(ExitCode::Success)
        }
        SlmCommands::Bracket {
            action: BracketCommands::End,
        } => {
            let active_path = find_active_bracket(&dir)?;
            match active_path {
                None => {
                    let msg = "No active bracket found. Start one with: \
                               devguard slm bracket start --label <name>";
                    if json {
                        emit_json(&JsonEnvelope::<()>::failure("slm bracket end", msg))?;
                    } else {
                        eprintln!("{msg}");
                    }
                    Ok(ExitCode::Operational)
                }
                Some(path) => {
                    let mut record = load_bracket(&path)?;
                    record.end();
                    save_bracket(&dir, &record)?;

                    if json {
                        emit_json(&JsonEnvelope::success("slm bracket end", &record))?;
                    } else {
                        emit_human(&format_bracket_human(&record));
                    }
                    Ok(ExitCode::Success)
                }
            }
        }
        SlmCommands::Bracket {
            action: BracketCommands::Show,
        } => {
            let latest_path = find_latest_bracket(&dir)?;
            match latest_path {
                None => {
                    let msg = "No brackets found. Start one with: \
                               devguard slm bracket start --label <name>";
                    if json {
                        emit_json(&JsonEnvelope::<()>::failure("slm bracket show", msg))?;
                    } else {
                        eprintln!("{msg}");
                    }
                    Ok(ExitCode::Partial)
                }
                Some(path) => {
                    let record = load_bracket(&path)?;
                    if json {
                        emit_json(&JsonEnvelope::success("slm bracket show", &record))?;
                    } else {
                        emit_human(&format_bracket_human(&record));
                    }
                    Ok(ExitCode::Success)
                }
            }
        }
    }
}
