//! `devguard snapshot create|list|diff`.
//!
//! The database is `devguard.db` under the state directory. Tests pass a
//! temporary directory through `DEVGUARD_STATE_DIR`. This module does not
//! open a hard-coded home-directory database.

use std::path::Path;

use chrono::SecondsFormat;
use clap::Subcommand;
use devguard_core::json::JsonEnvelope;
use devguard_core::snapshot::{
    collect_snapshot, collector_statuses, diff_payloads, format_create_human, format_diff_human,
    format_list_human, parse_payload, snapshot_warnings, summary_from_stored, CollectorStatus,
    SnapshotDiff, SnapshotSummary,
};
use devguard_core::{DevGuardError, ExitCode};
use devguard_store::Store;
use serde::Serialize;

use crate::output::{emit_human, emit_json};

#[derive(Debug, Subcommand)]
pub enum SnapshotCommands {
    /// Store one snapshot from the collectors already on this branch.
    ///
    /// Reads OS identity, packages, units, ports, gpu-id, dev env, allowlisted
    /// config hashes, and the health scan. Does not use sudo, install packages,
    /// or open a network connection. A missing collector stays in the payload
    /// as unavailable. The snapshot is partial when any collector is unavailable.
    /// `--label` is an ordinary string, such as pre-upgrade or post-upgrade.
    Create {
        /// Ordinary label string, such as pre-upgrade or post-upgrade.
        #[arg(long, value_name = "NAME")]
        label: Option<String>,
    },
    /// List stored snapshots in created-at order, then id.
    List,
    /// Diff two stored snapshots.
    ///
    /// Added, removed, and changed entries are in stable key order. Severity
    /// is a separate field from the fact. A missing snapshot id is an error.
    Diff {
        /// Baseline snapshot id.
        baseline_id: String,
        /// Current snapshot id.
        current_id: String,
    },
}

pub fn run(
    json: bool,
    allowlist: &[String],
    state_dir: &Path,
    action: SnapshotCommands,
) -> Result<ExitCode, DevGuardError> {
    match action {
        SnapshotCommands::Create { label } => run_create(json, allowlist, state_dir, label),
        SnapshotCommands::List => run_list(json, state_dir),
        SnapshotCommands::Diff {
            baseline_id,
            current_id,
        } => run_diff(json, state_dir, &baseline_id, &current_id),
    }
}

fn run_create(
    json: bool,
    allowlist: &[String],
    state_dir: &Path,
    label: Option<String>,
) -> Result<ExitCode, DevGuardError> {
    let payload = collect_snapshot(label, allowlist);
    let id = uuid::Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let store = open_store(state_dir)?;
    store
        .insert_snapshot(&devguard_store::Snapshot {
            id: id.clone(),
            created_at: created_at.clone(),
            label: payload.label.clone(),
            run_id: None,
            payload: serde_json::to_string(&payload)?,
        })
        .map_err(store_err)?;
    let data = CreateData {
        id: id.clone(),
        created_at: created_at.clone(),
        label: payload.label.clone(),
        clean: payload.clean,
        uses_sudo: payload.uses_sudo,
        installs_packages: payload.installs_packages,
        opens_network: payload.opens_network,
        collectors: collector_statuses(&payload),
    };
    let warnings = snapshot_warnings(&payload);
    if json {
        let envelope = if warnings.is_empty() {
            JsonEnvelope::success("snapshot create", &data)
        } else {
            JsonEnvelope::success_with_warnings("snapshot create", &data, warnings)
        };
        emit_json(&envelope)?;
    } else {
        emit_human(&format_create_human(&id, &created_at, &payload));
    }
    Ok(payload.exit_code())
}

fn run_list(json: bool, state_dir: &Path) -> Result<ExitCode, DevGuardError> {
    let store = open_store(state_dir)?;
    let snapshots = store.list_snapshots().map_err(store_err)?;
    let rows: Vec<SnapshotSummary> = snapshots
        .into_iter()
        .map(|row| summary_from_stored(row.id, row.created_at, row.label, &row.payload))
        .collect();
    if json {
        emit_json(&JsonEnvelope::success(
            "snapshot list",
            &ListData { snapshots: rows },
        ))?;
    } else {
        emit_human(&format_list_human(&rows));
    }
    Ok(ExitCode::Success)
}

fn run_diff(
    json: bool,
    state_dir: &Path,
    baseline_id: &str,
    current_id: &str,
) -> Result<ExitCode, DevGuardError> {
    let store = open_store(state_dir)?;
    let baseline = load_snapshot(&store, baseline_id)?;
    let current = load_snapshot(&store, current_id)?;
    let baseline_payload = parse_payload(&baseline.payload)?;
    let current_payload = parse_payload(&current.payload)?;
    let diff = diff_payloads(&baseline_payload, &current_payload);
    let partial = !baseline_payload.clean || !current_payload.clean;
    let mut warnings = Vec::new();
    if !baseline_payload.clean {
        warnings.push(format!("baseline {baseline_id} is partial"));
    }
    if !current_payload.clean {
        warnings.push(format!("current {current_id} is partial"));
    }
    let data = DiffData {
        baseline_id: baseline.id,
        current_id: current.id,
        baseline_label: baseline.label,
        current_label: current.label,
        baseline_clean: baseline_payload.clean,
        current_clean: current_payload.clean,
        diff,
    };
    if json {
        let envelope = if warnings.is_empty() {
            JsonEnvelope::success("snapshot diff", &data)
        } else {
            JsonEnvelope::success_with_warnings("snapshot diff", &data, warnings)
        };
        emit_json(&envelope)?;
    } else {
        emit_human(&format_diff_human(
            &data.baseline_id,
            &data.current_id,
            data.baseline_label.as_deref(),
            data.current_label.as_deref(),
            data.baseline_clean,
            data.current_clean,
            &data.diff,
        ));
    }
    if partial {
        Ok(ExitCode::Partial)
    } else {
        Ok(ExitCode::Success)
    }
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

#[derive(Debug, Serialize)]
struct CreateData {
    id: String,
    created_at: String,
    label: Option<String>,
    clean: bool,
    uses_sudo: bool,
    installs_packages: bool,
    opens_network: bool,
    collectors: Vec<CollectorStatus>,
}

#[derive(Debug, Serialize)]
struct ListData {
    snapshots: Vec<SnapshotSummary>,
}

#[derive(Debug, Serialize)]
struct DiffData {
    baseline_id: String,
    current_id: String,
    baseline_label: Option<String>,
    current_label: Option<String>,
    baseline_clean: bool,
    current_clean: bool,
    #[serde(flatten)]
    diff: SnapshotDiff,
}
