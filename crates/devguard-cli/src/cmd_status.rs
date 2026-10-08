//! `devguard status`.
//!
//! Reads the newest row in the DevGuard SQLite store. A missing database is
//! an empty store. This module does not scan the host, invoke sudo, or open
//! a network connection. Tests pass a temporary directory through
//! `DEVGUARD_STATE_DIR` and do not open `~/.local/state/devguard/devguard.db`.

use std::path::Path;

use devguard_core::json::JsonEnvelope;
use devguard_core::snapshot::{
    format_status_human, status_exit, status_from_stored, status_warnings, StatusSnapshot,
};
use devguard_core::{DevGuardError, ExitCode};
use devguard_store::Store;
use serde::Serialize;

use crate::output::{emit_human, emit_json};

pub fn run(json: bool, state_dir: &Path) -> Result<ExitCode, DevGuardError> {
    let snapshot = read_latest(state_dir)?;
    let warnings = status_warnings(snapshot.as_ref());
    let data = StatusData {
        snapshot: snapshot.clone(),
        rescans_host: false,
        uses_sudo: false,
        opens_network: false,
    };
    if json {
        let envelope = if warnings.is_empty() {
            JsonEnvelope::success("status", &data)
        } else {
            JsonEnvelope::success_with_warnings("status", &data, warnings)
        };
        emit_json(&envelope)?;
    } else {
        emit_human(&format_status_human(snapshot.as_ref()));
    }
    Ok(status_exit(snapshot.as_ref()))
}

fn read_latest(state_dir: &Path) -> Result<Option<StatusSnapshot>, DevGuardError> {
    let path = devguard_store::database_path(state_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let store = Store::open(&path).map_err(store_err)?;
    let Some(row) = store.latest_snapshot().map_err(store_err)? else {
        return Ok(None);
    };
    Ok(Some(status_from_stored(
        row.id,
        row.created_at,
        row.label,
        &row.payload,
    )))
}

fn store_err(err: devguard_store::StoreError) -> DevGuardError {
    DevGuardError::Message(err.to_string())
}

#[derive(Debug, Clone, Serialize)]
struct StatusData {
    snapshot: Option<StatusSnapshot>,
    /// Always false. Status reads stored rows and does not scan the host.
    rescans_host: bool,
    /// Always false. Status does not invoke sudo.
    uses_sudo: bool,
    /// Always false. Status does not open a network connection.
    opens_network: bool,
}
