//! Paper table export for stored SLM runs.
//!
//! Reads `slm-runs/*.json` and writes the columns from
//! `docs/slm-research-metrics.md`. A field the record does not store stays
//! empty. This module does not call Ollama, bind a port, call `nvidia-smi`,
//! or derive latency, quality, energy, or task scores.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{DevGuardError, Result};
use crate::slm::SlmRunRecord;

const RUNS_DIR: &str = "slm-runs";

/// Column order for the paper CSV and JSON table.
pub const PAPER_COLUMNS: &[&str] = &[
    "model",
    "quantization",
    "backend",
    "hardware",
    "prompt length",
    "generation length",
    "batch",
    "TTFT",
    "TPOT",
    "tokens/s",
    "peak VRAM",
    "mean GPU power",
    "J/token",
    "temperature",
    "task score",
    "benchmark name",
    "timestamp",
];

/// One paper row. Empty strings are fields the stored run did not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperRow {
    pub model: String,
    pub quantization: String,
    pub backend: String,
    pub hardware: String,
    #[serde(rename = "prompt length")]
    pub prompt_length: String,
    #[serde(rename = "generation length")]
    pub generation_length: String,
    pub batch: String,
    #[serde(rename = "TTFT")]
    pub ttft: String,
    #[serde(rename = "TPOT")]
    pub tpot: String,
    #[serde(rename = "tokens/s")]
    pub tokens_per_s: String,
    #[serde(rename = "peak VRAM")]
    pub peak_vram: String,
    #[serde(rename = "mean GPU power")]
    pub mean_gpu_power: String,
    #[serde(rename = "J/token")]
    pub joules_per_token: String,
    pub temperature: String,
    #[serde(rename = "task score")]
    pub task_score: String,
    #[serde(rename = "benchmark name")]
    pub benchmark_name: String,
    pub timestamp: String,
}

impl PaperRow {
    fn cells(&self) -> [&str; 17] {
        [
            &self.model,
            &self.quantization,
            &self.backend,
            &self.hardware,
            &self.prompt_length,
            &self.generation_length,
            &self.batch,
            &self.ttft,
            &self.tpot,
            &self.tokens_per_s,
            &self.peak_vram,
            &self.mean_gpu_power,
            &self.joules_per_token,
            &self.temperature,
            &self.task_score,
            &self.benchmark_name,
            &self.timestamp,
        ]
    }
}

/// Files written by [`export_paper_table`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenExport {
    pub csv_path: PathBuf,
    pub json_path: PathBuf,
    pub rows: usize,
}

/// Map one stored run onto a paper row.
///
/// Latency, energy, and quality are copied only when the record already
/// holds them. GPU power samples and duration do not fill those cells.
pub fn paper_row(record: &SlmRunRecord) -> PaperRow {
    let experiment = record.experiment.as_ref();
    let latency = record.latency.as_ref();
    let quality = record.quality.as_ref();
    let energy = record.energy.as_ref();
    PaperRow {
        model: text(experiment.and_then(|item| item.model_id.as_deref())),
        quantization: text(experiment.and_then(|item| item.quantization.as_deref())),
        backend: text(experiment.and_then(|item| item.backend.as_deref())),
        hardware: hardware(record),
        prompt_length: opt_u32(experiment.and_then(|item| item.prompt_tokens)),
        generation_length: opt_u32(experiment.and_then(|item| item.output_tokens)),
        batch: opt_u32(experiment.and_then(|item| item.batch_size)),
        ttft: opt_f64(latency.and_then(|item| item.ttft_ms)),
        tpot: opt_f64(latency.and_then(|item| item.tpot_ms)),
        tokens_per_s: opt_f64(latency.and_then(|item| item.tokens_per_second)),
        peak_vram: peak_vram(record),
        mean_gpu_power: opt_f64(energy.and_then(|item| item.mean_gpu_power_w)),
        joules_per_token: opt_f64(energy.and_then(|item| item.joules_per_token)),
        temperature: temperature(record),
        task_score: opt_f64(quality.and_then(|item| item.task_score)),
        benchmark_name: text(quality.and_then(|item| item.task_name.as_deref())),
        timestamp: record.started_at.to_rfc3339(),
    }
}

/// Read stored runs and write `slm-export.csv` and `slm-export.json`.
pub fn export_paper_table(state_dir: &Path, out_dir: &Path) -> Result<WrittenExport> {
    let runs = load_stored_runs(state_dir)?;
    let rows: Vec<PaperRow> = runs.iter().map(paper_row).collect();
    fs::create_dir_all(out_dir)?;
    let csv_path = out_dir.join("slm-export.csv");
    let json_path = out_dir.join("slm-export.json");
    fs::write(&csv_path, render_csv(&rows))?;
    let json = render_json(&rows)?;
    fs::write(&json_path, json)?;
    Ok(WrittenExport {
        csv_path,
        json_path,
        rows: rows.len(),
    })
}

fn load_stored_runs(state_dir: &Path) -> Result<Vec<SlmRunRecord>> {
    let dir = state_dir.join(RUNS_DIR);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut runs = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let record: SlmRunRecord = serde_json::from_str(&text).map_err(|err| {
            DevGuardError::Message(format!("invalid slm run {}: {err}", path.display()))
        })?;
        runs.push(record);
    }
    runs.sort_by(|left, right| {
        left.started_at
            .cmp(&right.started_at)
            .then_with(|| left.run_id.cmp(&right.run_id))
    });
    Ok(runs)
}

fn render_csv(rows: &[PaperRow]) -> String {
    let mut out = String::new();
    push_csv_row(&mut out, PAPER_COLUMNS);
    for row in rows {
        let cells = row.cells();
        push_csv_row(&mut out, &cells);
    }
    out
}

fn push_csv_row(out: &mut String, cells: &[&str]) {
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&csv_escape(cell));
    }
    out.push('\n');
}

fn csv_escape(cell: &str) -> String {
    if cell.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell.to_string()
    }
}

fn render_json(rows: &[PaperRow]) -> Result<String> {
    #[derive(Serialize)]
    struct PaperTable<'a> {
        columns: &'static [&'static str],
        rows: &'a [PaperRow],
    }
    let table = PaperTable {
        columns: PAPER_COLUMNS,
        rows,
    };
    let mut text = serde_json::to_string_pretty(&table)?;
    text.push('\n');
    Ok(text)
}

fn hardware(record: &SlmRunRecord) -> String {
    record
        .system
        .gpus
        .iter()
        .filter_map(|gpu| gpu.name.as_deref())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

fn peak_vram(record: &SlmRunRecord) -> String {
    match record
        .system
        .gpus
        .iter()
        .filter_map(|gpu| gpu.memory_used_bytes)
        .max()
    {
        Some(bytes) => bytes.to_string(),
        None => String::new(),
    }
}

fn temperature(record: &SlmRunRecord) -> String {
    let mut best: Option<f64> = None;
    for gpu in &record.system.gpus {
        if let Some(temp) = gpu.temperature_c {
            if temp.is_finite() {
                best = Some(match best {
                    Some(current) if current >= temp => current,
                    _ => temp,
                });
            }
        }
    }
    opt_f64(best)
}

fn text(value: Option<&str>) -> String {
    value.unwrap_or("").trim().to_string()
}

fn opt_u32(value: Option<u32>) -> String {
    value.map(|item| item.to_string()).unwrap_or_default()
}

fn opt_f64(value: Option<f64>) -> String {
    match value {
        Some(item) if item.is_finite() => format!("{item}"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slm::{EnergyMetrics, ExperimentMeta, GpuSample, LatencyMetrics, QualityMetrics};
    use chrono::TimeZone;

    fn stamp(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.timestamp_opt(seconds, 0).unwrap()
    }

    #[test]
    fn missing_metrics_stay_empty_and_power_samples_do_not_fill_energy() {
        let mut record = SlmRunRecord::begin(None);
        record.started_at = stamp(1_760_000_000);
        record.duration_s = Some(10.0);
        record.experiment = Some(ExperimentMeta {
            output_tokens: Some(100),
            ..ExperimentMeta::default()
        });
        record.system.gpus.push(GpuSample {
            index: 0,
            power_draw_w: Some(80.0),
            memory_used_bytes: Some(4096),
            temperature_c: Some(43.0),
            name: Some("NVIDIA GeForce RTX 3060".into()),
            ..GpuSample::default()
        });
        let row = paper_row(&record);
        assert_eq!(row.model, "");
        assert_eq!(row.quantization, "");
        assert_eq!(row.backend, "");
        assert_eq!(row.hardware, "NVIDIA GeForce RTX 3060");
        assert_eq!(row.prompt_length, "");
        assert_eq!(row.generation_length, "100");
        assert_eq!(row.batch, "");
        assert_eq!(row.ttft, "");
        assert_eq!(row.tpot, "");
        assert_eq!(row.tokens_per_s, "");
        assert_eq!(row.peak_vram, "4096");
        assert_eq!(row.mean_gpu_power, "");
        assert_eq!(row.joules_per_token, "");
        assert_eq!(row.temperature, "43");
        assert_eq!(row.task_score, "");
        assert_eq!(row.benchmark_name, "");
        assert!(row.timestamp.contains("T"));
    }

    #[test]
    fn stored_latency_quality_and_energy_are_copied() {
        let mut record = SlmRunRecord::begin(Some("gsm8k".into()));
        record.experiment = Some(ExperimentMeta {
            model_id: Some("llama-3.2-1b".into()),
            quantization: Some("Q4_K_M".into()),
            backend: Some("llama.cpp".into()),
            batch_size: Some(1),
            prompt_tokens: Some(32),
            output_tokens: Some(128),
            ..ExperimentMeta::default()
        });
        record.latency = Some(LatencyMetrics {
            ttft_ms: Some(120.5),
            tokens_per_second: Some(55.0),
            ..LatencyMetrics::default()
        });
        record.quality = Some(QualityMetrics {
            task_name: Some("gsm8k".into()),
            task_score: Some(0.42),
            ..QualityMetrics::default()
        });
        record.energy = Some(EnergyMetrics {
            mean_gpu_power_w: Some(80.0),
            joules_per_token: Some(6.25),
            ..EnergyMetrics::default()
        });
        let row = paper_row(&record);
        assert_eq!(row.model, "llama-3.2-1b");
        assert_eq!(row.quantization, "Q4_K_M");
        assert_eq!(row.backend, "llama.cpp");
        assert_eq!(row.prompt_length, "32");
        assert_eq!(row.generation_length, "128");
        assert_eq!(row.batch, "1");
        assert_eq!(row.ttft, "120.5");
        assert_eq!(row.tpot, "");
        assert_eq!(row.tokens_per_s, "55");
        assert_eq!(row.mean_gpu_power, "80");
        assert_eq!(row.joules_per_token, "6.25");
        assert_eq!(row.task_score, "0.42");
        assert_eq!(row.benchmark_name, "gsm8k");
    }

    #[test]
    fn export_writes_csv_and_json_from_a_temp_state_dir() {
        let state = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let runs = state.path().join(RUNS_DIR);
        fs::create_dir_all(&runs).unwrap();

        let mut early = SlmRunRecord::begin(None);
        early.run_id = "run-early".into();
        early.started_at = stamp(1_700_000_000);
        early.experiment = Some(ExperimentMeta {
            model_id: Some("model, \"quoted\"".into()),
            ..ExperimentMeta::default()
        });
        let mut late = SlmRunRecord::begin(None);
        late.run_id = "run-late".into();
        late.started_at = stamp(1_700_000_100);
        fs::write(
            runs.join("late.json"),
            serde_json::to_string(&late).unwrap(),
        )
        .unwrap();
        fs::write(
            runs.join("early.json"),
            serde_json::to_string(&early).unwrap(),
        )
        .unwrap();
        fs::write(runs.join("note.txt"), "ignore").unwrap();

        let written = export_paper_table(state.path(), out.path()).unwrap();
        assert_eq!(written.rows, 2);
        let csv = fs::read_to_string(&written.csv_path).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&written.json_path).unwrap()).unwrap();
        assert!(csv
            .lines()
            .next()
            .unwrap()
            .starts_with("model,quantization,"));
        assert!(csv.contains("\"model, \"\"quoted\"\"\""));
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].starts_with("\"model, \"\"quoted\"\"\""));
        assert!(lines[2].starts_with(','));
        assert_eq!(json["columns"][0], "model");
        assert_eq!(json["columns"][7], "TTFT");
        assert_eq!(json["columns"][12], "J/token");
        assert_eq!(json["rows"][0]["model"], "model, \"quoted\"");
        assert_eq!(json["rows"][0]["TTFT"], "");
        assert_eq!(json["rows"][0]["J/token"], "");
        assert_eq!(json["rows"][0]["task score"], "");
        assert_eq!(json["rows"][1]["model"], "");
        assert!(
            json["rows"][0]["timestamp"].as_str().unwrap()
                < json["rows"][1]["timestamp"].as_str().unwrap()
        );
    }

    #[test]
    fn missing_runs_directory_writes_an_empty_table() {
        let state = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let written = export_paper_table(state.path(), out.path()).unwrap();
        assert_eq!(written.rows, 0);
        let csv = fs::read_to_string(written.csv_path).unwrap();
        assert_eq!(csv.lines().count(), 1);
        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(written.json_path).unwrap()).unwrap();
        assert!(json["rows"].as_array().unwrap().is_empty());
    }
}
