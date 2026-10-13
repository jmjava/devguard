//! SLM run bracketing for academic research metrics.
//!
//! Brackets capture GPU/host state before and after a local model inference run,
//! compute deltas (duration, temperature change, memory change), and persist
//! results as JSON files under `~/.local/share/devguard/brackets/`.
//!
//! See `docs/slm-research-metrics.md` for the literature mapping.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::gpu::{scan_gpu, GpuDevice, GpuScanReport};

/// Schema version for bracket records.
pub const BRACKET_SCHEMA_VERSION: u32 = 1;

/// Snapshot of GPU state at a point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuSnapshot {
    pub observed_at: DateTime<Utc>,
    pub gpus: Vec<GpuDeviceSummary>,
    pub source: String,
}

/// Summarized GPU state for bracket records (extracted from `GpuDevice` `Field` wrappers).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuDeviceSummary {
    pub index: u32,
    pub name: Option<String>,
    pub driver_version: Option<String>,
    pub temperature_c: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub utilization_percent: Option<f64>,
    pub power_draw_w: Option<f64>,
    pub power_limit_w: Option<f64>,
}

impl GpuDeviceSummary {
    /// Extract a summary from a full `GpuDevice`.
    pub fn from_device(device: &GpuDevice) -> Self {
        Self {
            index: device.index,
            name: device.name.value.clone(),
            driver_version: device.driver.value.clone(),
            temperature_c: device.temperature_c.value,
            memory_used_bytes: device.memory_used_bytes.value,
            memory_total_bytes: device.memory_total_bytes.value,
            utilization_percent: device.utilization_gpu_percent.value,
            power_draw_w: device.power_draw_w.value,
            power_limit_w: device.power_limit_w.value,
        }
    }
}

impl GpuSnapshot {
    /// Capture current GPU state via `nvidia-smi`.
    pub fn capture_now() -> Self {
        let report = scan_gpu();
        Self::from_scan_report(&report)
    }

    /// Build a snapshot from a scan report.
    pub fn from_scan_report(report: &GpuScanReport) -> Self {
        let source = if report.nvidia_smi.status == crate::gpu::CoverageStatus::Available {
            "nvidia-smi".to_string()
        } else {
            "none".to_string()
        };
        let gpus = report
            .gpus
            .iter()
            .map(GpuDeviceSummary::from_device)
            .collect();
        GpuSnapshot {
            observed_at: Utc::now(),
            gpus,
            source,
        }
    }

    /// Build an empty snapshot (for testing).
    pub fn empty() -> Self {
        GpuSnapshot {
            observed_at: Utc::now(),
            gpus: Vec::new(),
            source: "none".into(),
        }
    }
}

/// Delta between start and end GPU readings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuDelta {
    pub index: u32,
    pub name: String,
    pub temp_start_c: Option<f64>,
    pub temp_end_c: Option<f64>,
    pub temp_delta_c: Option<f64>,
    pub mem_start_bytes: Option<u64>,
    pub mem_end_bytes: Option<u64>,
    pub mem_delta_bytes: Option<i64>,
    pub util_start_percent: Option<f64>,
    pub util_end_percent: Option<f64>,
    pub power_start_w: Option<f64>,
    pub power_end_w: Option<f64>,
}

/// A complete bracket record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BracketRecord {
    pub schema_version: u32,
    pub bracket_id: String,
    pub label: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_s: Option<f64>,
    pub status: BracketStatus,
    pub start_snapshot: GpuSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_snapshot: Option<GpuSnapshot>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deltas: Vec<GpuDelta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BracketStatus {
    Started,
    Completed,
}

impl BracketRecord {
    /// Create a new bracket in "started" state with current GPU snapshot.
    pub fn start(label: String) -> Self {
        let snapshot = GpuSnapshot::capture_now();
        Self {
            schema_version: BRACKET_SCHEMA_VERSION,
            bracket_id: Uuid::new_v4().to_string(),
            label,
            started_at: Utc::now(),
            ended_at: None,
            duration_s: None,
            status: BracketStatus::Started,
            start_snapshot: snapshot,
            end_snapshot: None,
            deltas: Vec::new(),
        }
    }

    /// Create a bracket with a specific start snapshot (for testing).
    pub fn start_with_snapshot(label: String, snapshot: GpuSnapshot) -> Self {
        Self {
            schema_version: BRACKET_SCHEMA_VERSION,
            bracket_id: Uuid::new_v4().to_string(),
            label,
            started_at: snapshot.observed_at,
            ended_at: None,
            duration_s: None,
            status: BracketStatus::Started,
            start_snapshot: snapshot,
            end_snapshot: None,
            deltas: Vec::new(),
        }
    }

    /// Complete the bracket with a new GPU snapshot and compute deltas.
    pub fn end(&mut self) {
        let end_snap = GpuSnapshot::capture_now();
        self.end_with_snapshot(end_snap);
    }

    /// Complete with a specific snapshot (for testing).
    pub fn end_with_snapshot(&mut self, end_snap: GpuSnapshot) {
        let ended_at = Utc::now();
        let duration_s = (ended_at - self.started_at).num_milliseconds() as f64 / 1000.0;
        self.deltas = compute_deltas(&self.start_snapshot, &end_snap);
        self.ended_at = Some(ended_at);
        self.duration_s = Some(duration_s);
        self.status = BracketStatus::Completed;
        self.end_snapshot = Some(end_snap);
    }
}

/// Compute per-GPU deltas between two snapshots.
pub fn compute_deltas(start: &GpuSnapshot, end: &GpuSnapshot) -> Vec<GpuDelta> {
    let mut deltas = Vec::new();
    for start_gpu in &start.gpus {
        let end_gpu = end.gpus.iter().find(|g| g.index == start_gpu.index);
        if let Some(end_gpu) = end_gpu {
            let temp_delta = match (start_gpu.temperature_c, end_gpu.temperature_c) {
                (Some(s), Some(e)) => Some(e - s),
                _ => None,
            };
            let mem_delta = match (start_gpu.memory_used_bytes, end_gpu.memory_used_bytes) {
                (Some(s), Some(e)) => Some(e as i64 - s as i64),
                _ => None,
            };
            deltas.push(GpuDelta {
                index: start_gpu.index,
                name: start_gpu.name.clone().unwrap_or_default(),
                temp_start_c: start_gpu.temperature_c,
                temp_end_c: end_gpu.temperature_c,
                temp_delta_c: temp_delta,
                mem_start_bytes: start_gpu.memory_used_bytes,
                mem_end_bytes: end_gpu.memory_used_bytes,
                mem_delta_bytes: mem_delta,
                util_start_percent: start_gpu.utilization_percent,
                util_end_percent: end_gpu.utilization_percent,
                power_start_w: start_gpu.power_draw_w,
                power_end_w: end_gpu.power_draw_w,
            });
        }
    }
    deltas
}

// ---------------------------------------------------------------------------
// Bracket file persistence
// ---------------------------------------------------------------------------

/// Default bracket storage directory.
pub fn brackets_dir() -> Result<PathBuf, crate::error::DevGuardError> {
    let base = directories::BaseDirs::new().ok_or_else(|| {
        crate::error::DevGuardError::Message("unable to resolve home directory".into())
    })?;
    Ok(base.home_dir().join(".local/share/devguard/brackets"))
}

/// Save a bracket record to disk.
pub fn save_bracket(
    dir: &Path,
    record: &BracketRecord,
) -> Result<PathBuf, crate::error::DevGuardError> {
    fs::create_dir_all(dir)?;
    let filename = format!("{}.json", record.bracket_id);
    let path = dir.join(filename);
    let json = serde_json::to_string_pretty(record)?;
    fs::write(&path, json)?;
    Ok(path)
}

/// Load a bracket record from a JSON file.
pub fn load_bracket(path: &Path) -> Result<BracketRecord, crate::error::DevGuardError> {
    let contents = fs::read_to_string(path)?;
    let record: BracketRecord = serde_json::from_str(&contents)?;
    Ok(record)
}

/// Find the most recently modified bracket file in the directory.
pub fn find_latest_bracket(dir: &Path) -> Result<Option<PathBuf>, crate::error::DevGuardError> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut latest: Option<(PathBuf, std::time::SystemTime)> = None;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let modified = entry.metadata()?.modified()?;
        if latest.as_ref().is_none_or(|(_, t)| modified > *t) {
            latest = Some((path, modified));
        }
    }
    Ok(latest.map(|(p, _)| p))
}

/// Find the most recent bracket with status `Started` (for `bracket end`).
pub fn find_active_bracket(dir: &Path) -> Result<Option<PathBuf>, crate::error::DevGuardError> {
    if !dir.exists() {
        return Ok(None);
    }
    let mut candidates: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let modified = entry.metadata()?.modified()?;
        candidates.push((path, modified));
    }
    candidates.sort_by(|a, b| b.1.cmp(&a.1));

    for (path, _) in candidates {
        if let Ok(record) = load_bracket(&path) {
            if record.status == BracketStatus::Started {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

/// Format a bracket record for human display.
pub fn format_bracket_human(record: &BracketRecord) -> String {
    let mut out = String::from("DevGuard SLM bracket\n");
    out.push_str(&format!("  id: {}\n", record.bracket_id));
    out.push_str(&format!("  label: {}\n", record.label));
    out.push_str(&format!("  status: {:?}\n", record.status));
    out.push_str(&format!("  started: {}\n", record.started_at.to_rfc3339()));

    if let Some(ended) = &record.ended_at {
        out.push_str(&format!("  ended: {}\n", ended.to_rfc3339()));
    }
    if let Some(dur) = record.duration_s {
        out.push_str(&format!("  duration: {dur:.1}s\n"));
    }

    let snap_gpus = &record.start_snapshot.gpus;
    if snap_gpus.is_empty() {
        out.push_str("  gpu: none detected\n");
    } else {
        out.push_str(&format!("  gpu source: {}\n", record.start_snapshot.source));
    }

    if !record.deltas.is_empty() {
        out.push_str("\n  Deltas:\n");
        for d in &record.deltas {
            out.push_str(&format!("    GPU {}: {}\n", d.index, d.name));
            if let Some(td) = d.temp_delta_c {
                out.push_str(&format!(
                    "      temp: {:.0} → {:.0} °C (Δ {td:+.1} °C)\n",
                    d.temp_start_c.unwrap_or(0.0),
                    d.temp_end_c.unwrap_or(0.0)
                ));
            }
            if let Some(md) = d.mem_delta_bytes {
                let start_mib = d.mem_start_bytes.unwrap_or(0) as f64 / (1024.0 * 1024.0);
                let end_mib = d.mem_end_bytes.unwrap_or(0) as f64 / (1024.0 * 1024.0);
                let delta_mib = md as f64 / (1024.0 * 1024.0);
                out.push_str(&format!(
                    "      mem: {start_mib:.0} → {end_mib:.0} MiB (Δ {delta_mib:+.0} MiB)\n"
                ));
            }
            if let (Some(us), Some(ue)) = (d.util_start_percent, d.util_end_percent) {
                out.push_str(&format!("      util: {us:.0}% → {ue:.0}%\n"));
            }
            if let (Some(ps), Some(pe)) = (d.power_start_w, d.power_end_w) {
                out.push_str(&format!("      power: {ps:.1} W → {pe:.1} W\n"));
            }
        }
    } else if record.status == BracketStatus::Completed {
        out.push_str("\n  No GPU deltas (no GPU was detected at start or end).\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_gpu(index: u32, temp: f64, mem_used: u64, util: f64, power: f64) -> GpuDeviceSummary {
        GpuDeviceSummary {
            index,
            name: Some(format!("Test GPU {index}")),
            driver_version: Some("535.0".into()),
            temperature_c: Some(temp),
            memory_used_bytes: Some(mem_used),
            memory_total_bytes: Some(12 * 1024 * 1024 * 1024),
            utilization_percent: Some(util),
            power_draw_w: Some(power),
            power_limit_w: Some(170.0),
        }
    }

    fn make_snapshot(gpus: Vec<GpuDeviceSummary>) -> GpuSnapshot {
        GpuSnapshot {
            observed_at: Utc::now(),
            gpus,
            source: "test".into(),
        }
    }

    #[test]
    fn bracket_start_end_lifecycle() {
        let start_gpu = make_gpu(0, 40.0, 1024 * 1024 * 1024, 5.0, 30.0);
        let end_gpu = make_gpu(0, 72.0, 8 * 1024 * 1024 * 1024, 95.0, 250.0);

        let start_snap = make_snapshot(vec![start_gpu]);
        let end_snap = make_snapshot(vec![end_gpu]);

        let mut bracket = BracketRecord::start_with_snapshot("test-run".into(), start_snap);
        assert_eq!(bracket.status, BracketStatus::Started);
        assert!(bracket.ended_at.is_none());
        assert!(bracket.deltas.is_empty());

        bracket.end_with_snapshot(end_snap);
        assert_eq!(bracket.status, BracketStatus::Completed);
        assert!(bracket.ended_at.is_some());
        assert!(bracket.duration_s.is_some());
        assert_eq!(bracket.deltas.len(), 1);

        let delta = &bracket.deltas[0];
        assert_eq!(delta.temp_start_c, Some(40.0));
        assert_eq!(delta.temp_end_c, Some(72.0));
        assert_eq!(delta.temp_delta_c, Some(32.0));
        assert!(delta.mem_delta_bytes.unwrap() > 0);
        assert_eq!(delta.util_start_percent, Some(5.0));
        assert_eq!(delta.util_end_percent, Some(95.0));
    }

    #[test]
    fn bracket_no_gpu_graceful() {
        let start_snap = GpuSnapshot::empty();
        let end_snap = GpuSnapshot::empty();

        let mut bracket = BracketRecord::start_with_snapshot("no-gpu-test".into(), start_snap);
        bracket.end_with_snapshot(end_snap);
        assert_eq!(bracket.status, BracketStatus::Completed);
        assert!(bracket.deltas.is_empty());
    }

    #[test]
    fn save_and_load_bracket() {
        let dir = tempdir().unwrap();
        let start_snap = make_snapshot(vec![make_gpu(0, 40.0, 1024, 5.0, 30.0)]);
        let bracket = BracketRecord::start_with_snapshot("persist-test".into(), start_snap);
        let path = save_bracket(dir.path(), &bracket).unwrap();
        assert!(path.exists());

        let loaded = load_bracket(&path).unwrap();
        assert_eq!(loaded.bracket_id, bracket.bracket_id);
        assert_eq!(loaded.label, "persist-test");
        assert_eq!(loaded.status, BracketStatus::Started);
    }

    #[test]
    fn find_latest_bracket_works() {
        let dir = tempdir().unwrap();
        assert!(find_latest_bracket(dir.path()).unwrap().is_none());

        let snap = GpuSnapshot::empty();
        let b1 = BracketRecord::start_with_snapshot("first".into(), snap.clone());
        save_bracket(dir.path(), &b1).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let b2 = BracketRecord::start_with_snapshot("second".into(), snap);
        let p2 = save_bracket(dir.path(), &b2).unwrap();

        let latest = find_latest_bracket(dir.path()).unwrap().unwrap();
        assert_eq!(latest, p2);
    }

    #[test]
    fn find_active_bracket_skips_completed() {
        let dir = tempdir().unwrap();
        let snap = GpuSnapshot::empty();

        let mut completed = BracketRecord::start_with_snapshot("done".into(), snap.clone());
        completed.end_with_snapshot(snap.clone());
        save_bracket(dir.path(), &completed).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let active = BracketRecord::start_with_snapshot("active".into(), snap);
        let active_path = save_bracket(dir.path(), &active).unwrap();

        let found = find_active_bracket(dir.path()).unwrap().unwrap();
        assert_eq!(found, active_path);
    }

    #[test]
    fn compute_deltas_matches_by_index() {
        let start = make_snapshot(vec![
            make_gpu(0, 40.0, 1024, 5.0, 30.0),
            make_gpu(1, 35.0, 512, 0.0, 10.0),
        ]);
        let end = make_snapshot(vec![
            make_gpu(0, 70.0, 8192, 90.0, 200.0),
            make_gpu(1, 50.0, 4096, 60.0, 100.0),
        ]);
        let deltas = compute_deltas(&start, &end);
        assert_eq!(deltas.len(), 2);
        assert_eq!(deltas[0].temp_delta_c, Some(30.0));
        assert_eq!(deltas[1].temp_delta_c, Some(15.0));
    }

    #[test]
    fn bracket_json_roundtrip() {
        let snap = make_snapshot(vec![make_gpu(0, 42.0, 1024, 10.0, 50.0)]);
        let mut bracket = BracketRecord::start_with_snapshot("json-test".into(), snap.clone());
        bracket.end_with_snapshot(snap);

        let json = serde_json::to_string_pretty(&bracket).unwrap();
        let back: BracketRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.bracket_id, bracket.bracket_id);
        assert_eq!(back.status, BracketStatus::Completed);
        assert_eq!(back.deltas.len(), bracket.deltas.len());
    }

    #[test]
    fn human_format_completed_bracket() {
        let start_gpu = make_gpu(0, 40.0, 1024 * 1024 * 1024, 5.0, 30.0);
        let end_gpu = make_gpu(0, 72.0, 8 * 1024 * 1024 * 1024, 95.0, 250.0);

        let start_snap = make_snapshot(vec![start_gpu]);
        let end_snap = make_snapshot(vec![end_gpu]);

        let mut bracket = BracketRecord::start_with_snapshot("fmt-test".into(), start_snap);
        bracket.end_with_snapshot(end_snap);

        let text = format_bracket_human(&bracket);
        assert!(text.contains("fmt-test"));
        assert!(text.contains("Completed"));
        assert!(text.contains("Δ"));
        assert!(text.contains("°C"));
        assert!(text.contains("MiB"));
    }

    #[test]
    fn human_format_no_gpu_bracket() {
        let snap = GpuSnapshot::empty();
        let mut bracket = BracketRecord::start_with_snapshot("no-gpu".into(), snap.clone());
        bracket.end_with_snapshot(snap);

        let text = format_bracket_human(&bracket);
        assert!(text.contains("none detected"));
        assert!(text.contains("No GPU deltas"));
    }

    #[test]
    fn nonexistent_brackets_dir_returns_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent");
        assert!(find_latest_bracket(&path).unwrap().is_none());
        assert!(find_active_bracket(&path).unwrap().is_none());
    }
}
