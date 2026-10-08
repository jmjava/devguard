//! `devguard security diff <BASELINE_ID> <CURRENT_ID>`.
//!
//! Reads two snapshot rows from the DevGuard SQLite store. Tests pass a
//! temporary directory through `DEVGUARD_STATE_DIR` and insert fixture
//! payloads. This module does not rescan the host, read the journal, or
//! change firewall rules.

use std::path::Path;

use devguard_core::json::JsonEnvelope;
use devguard_core::security_drift::{diff_stored_payloads, format_security_drift_human};
use devguard_core::{DevGuardError, ExitCode};
use devguard_store::Store;
use serde::Serialize;

use crate::output::{emit_human, emit_json};

pub fn run(
    json: bool,
    state_dir: &Path,
    baseline_id: &str,
    current_id: &str,
) -> Result<ExitCode, DevGuardError> {
    let store = open_store(state_dir)?;
    let baseline = load_snapshot(&store, baseline_id)?;
    let current = load_snapshot(&store, current_id)?;
    let report = diff_stored_payloads(&baseline.payload, &current.payload)?;
    let warnings = report.warnings();
    let data = DiffData {
        baseline_id: baseline.id,
        current_id: current.id,
        baseline_label: baseline.label.clone(),
        current_label: current.label.clone(),
        report: report.clone(),
    };
    if json {
        let envelope = if warnings.is_empty() {
            JsonEnvelope::success("security diff", &data)
        } else {
            JsonEnvelope::success_with_warnings("security diff", &data, warnings)
        };
        emit_json(&envelope)?;
    } else {
        emit_human(&format_security_drift_human(
            &data.baseline_id,
            &data.current_id,
            data.baseline_label.as_deref(),
            data.current_label.as_deref(),
            &report,
        ));
    }
    Ok(report.exit_code())
}

fn load_snapshot(store: &Store, id: &str) -> Result<devguard_store::Snapshot, DevGuardError> {
    store
        .get_snapshot(id)
        .map_err(store_err)?
        .ok_or_else(|| DevGuardError::Message(format!("snapshot {id} was not found")))
}

fn open_store(state_dir: &Path) -> Result<Store, DevGuardError> {
    let path = devguard_store::database_path(state_dir);
    Store::open(&path).map_err(store_err)
}

fn store_err(err: devguard_store::StoreError) -> DevGuardError {
    DevGuardError::Message(err.to_string())
}

#[derive(Debug, Clone, Serialize)]
struct DiffData {
    baseline_id: String,
    current_id: String,
    baseline_label: Option<String>,
    current_label: Option<String>,
    #[serde(flatten)]
    report: devguard_core::SecurityDriftReport,
}
