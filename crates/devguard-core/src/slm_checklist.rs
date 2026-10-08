//! Paper checklist for one stored SLM run.
//!
//! Reads `slm-runs/<id>.json` and prints the ten fields from
//! `docs/slm-research-metrics.md`. A missing field stays blank. This module
//! does not call Ollama, sample the GPU, or fill in numbers the file omitted.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{DevGuardError, Result};
use crate::exit::ExitCode;
use crate::slm::{ExperimentMeta, SlmRunRecord};

/// Names of the ten paper-table fields, in checklist order.
pub const PAPER_FIELD_NAMES: [&str; 10] = [
    "model",
    "hardware",
    "prompt_and_generation_length",
    "ttft_and_tpot",
    "tokens_per_second",
    "peak_vram",
    "mean_gpu_power_and_joules_per_token",
    "temperature",
    "task_score_and_benchmark",
    "timestamp",
];

const RUNS_DIR: &str = "slm-runs";

/// `available` when the stored run has at least one piece of the field.
/// `unavailable` when that piece is missing. Unavailable values are blank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FieldStatus {
    Available,
    #[default]
    Unavailable,
}

/// One stored run projected onto the ten-field paper checklist.
///
/// `calls_ollama` is always false. The checklist only reads a file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaperChecklist {
    pub run_id: String,
    pub calls_ollama: bool,
    pub fields: Vec<ChecklistField>,
}

/// One checklist row. `value` is empty when `status` is unavailable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ChecklistField {
    pub name: String,
    pub status: FieldStatus,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_memory_total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttft_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttft_p50_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttft_p99_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpot_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpot_p50_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpot_p99_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_vram_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_memory_used_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_gpu_power_w: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joules_per_token: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub energy_wall_j: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_gpu_temperature_c: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_gpu_temperature_c: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_metric: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl PaperChecklist {
    pub fn exit_code(&self) -> ExitCode {
        if self.fields.len() == PAPER_FIELD_NAMES.len()
            && self
                .fields
                .iter()
                .all(|field| field.status == FieldStatus::Available)
        {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.fields
            .iter()
            .filter(|field| field.status == FieldStatus::Unavailable)
            .map(|field| format!("{} unavailable", field.name))
            .collect()
    }

    pub fn field(&self, name: &str) -> Option<&ChecklistField> {
        self.fields.iter().find(|field| field.name == name)
    }
}

/// Load one stored run and project it onto the ten paper fields.
///
/// Missing pieces stay blank. Numbers that the file does not contain are not
/// computed, including joules per token.
pub fn paper_checklist(state_dir: &Path, run_id: &str) -> Result<PaperChecklist> {
    let path = record_path(state_dir, run_id)?;
    let record = read_record(&path)?;
    if record.run_id != run_id {
        return Err(DevGuardError::Message(format!(
            "slm run {run_id} does not match the stored record"
        )));
    }
    Ok(from_record(&record))
}

/// Text form of the checklist. Unavailable fields print as `unavailable`.
pub fn format_paper_checklist(report: &PaperChecklist) -> String {
    let mut out = String::new();
    out.push_str("DevGuard slm checklist\n");
    out.push_str(&format!("  run_id: {}\n", report.run_id));
    out.push_str(&format!(
        "  calls Ollama: {}\n",
        if report.calls_ollama { "yes" } else { "no" }
    ));
    for field in &report.fields {
        let shown = if field.status == FieldStatus::Available && !field.value.is_empty() {
            field.value.as_str()
        } else {
            "unavailable"
        };
        out.push_str(&format!("  {}: {shown}\n", label(&field.name)));
    }
    out
}

fn from_record(record: &SlmRunRecord) -> PaperChecklist {
    let experiment = record.experiment.as_ref();
    let latency = record.latency.as_ref();
    let quality = record.quality.as_ref();
    let energy = record.energy.as_ref();
    let host = record.system.host.as_ref();
    PaperChecklist {
        run_id: record.run_id.clone(),
        calls_ollama: false,
        fields: vec![
            model_field(experiment),
            hardware_field(record, host.and_then(|sample| sample.memory_total_bytes)),
            prompt_field(experiment),
            latency_field(latency),
            tokens_field(latency.and_then(|item| finite_nonneg(item.tokens_per_second))),
            vram_field(record, host.and_then(|sample| sample.memory_used_bytes)),
            power_field(record, energy),
            temperature_field(record),
            task_field(quality),
            timestamp_field(record, experiment),
        ],
    }
}

fn model_field(experiment: Option<&ExperimentMeta>) -> ChecklistField {
    let Some(experiment) = experiment else {
        return ChecklistField::unavailable("model");
    };
    let model_id = owned_text(experiment.model_id.as_deref());
    let quantization = owned_text(experiment.quantization.as_deref());
    let backend = owned_text(experiment.backend.as_deref());
    let mut parts = Vec::new();
    if let Some(model_id) = &model_id {
        parts.push(model_id.clone());
    }
    if let Some(parameter_count) = experiment.parameter_count {
        parts.push(format!("params {parameter_count}"));
    }
    if let Some(quantization) = &quantization {
        parts.push(format!("quant {quantization}"));
    }
    if let Some(backend) = &backend {
        parts.push(format!("backend {backend}"));
    }
    ChecklistField {
        model_id,
        parameter_count: experiment.parameter_count,
        quantization,
        backend,
        ..ChecklistField::from_parts("model", parts)
    }
}

fn hardware_field(record: &SlmRunRecord, host_memory_total_bytes: Option<u64>) -> ChecklistField {
    let gpu_name = join_unique(record.system.gpus.iter().filter_map(|gpu| {
        let name = gpu.name.as_deref()?.trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }));
    let driver_version = join_unique(record.system.gpus.iter().filter_map(|gpu| {
        let driver = gpu.driver_version.as_deref()?.trim();
        if driver.is_empty() {
            None
        } else {
            Some(driver.to_string())
        }
    }));
    let mut parts = Vec::new();
    if let Some(gpu_name) = &gpu_name {
        parts.push(gpu_name.clone());
    }
    if let Some(driver_version) = &driver_version {
        parts.push(format!("driver {driver_version}"));
    }
    if let Some(bytes) = host_memory_total_bytes {
        parts.push(format!("host RAM {bytes} B"));
    }
    ChecklistField {
        gpu_name,
        driver_version,
        host_memory_total_bytes,
        ..ChecklistField::from_parts("hardware", parts)
    }
}

fn prompt_field(experiment: Option<&ExperimentMeta>) -> ChecklistField {
    let Some(experiment) = experiment else {
        return ChecklistField::unavailable("prompt_and_generation_length");
    };
    let mut parts = Vec::new();
    if let Some(prompt_tokens) = experiment.prompt_tokens {
        parts.push(format!("prompt {prompt_tokens}"));
    }
    if let Some(output_tokens) = experiment.output_tokens {
        parts.push(format!("generation {output_tokens}"));
    }
    if let Some(batch_size) = experiment.batch_size {
        parts.push(format!("batch {batch_size}"));
    }
    ChecklistField {
        prompt_tokens: experiment.prompt_tokens,
        output_tokens: experiment.output_tokens,
        batch_size: experiment.batch_size,
        ..ChecklistField::from_parts("prompt_and_generation_length", parts)
    }
}

fn latency_field(latency: Option<&crate::slm::LatencyMetrics>) -> ChecklistField {
    let Some(latency) = latency else {
        return ChecklistField::unavailable("ttft_and_tpot");
    };
    let ttft_ms = finite_nonneg(latency.ttft_ms);
    let ttft_p50_ms = finite_nonneg(latency.ttft_p50_ms);
    let ttft_p99_ms = finite_nonneg(latency.ttft_p99_ms);
    let tpot_ms = finite_nonneg(latency.tpot_ms);
    let tpot_p50_ms = finite_nonneg(latency.tpot_p50_ms);
    let tpot_p99_ms = finite_nonneg(latency.tpot_p99_ms);
    let mut parts = Vec::new();
    push_ms(&mut parts, "ttft", ttft_ms);
    push_ms(&mut parts, "ttft p50", ttft_p50_ms);
    push_ms(&mut parts, "ttft p99", ttft_p99_ms);
    push_ms(&mut parts, "tpot", tpot_ms);
    push_ms(&mut parts, "tpot p50", tpot_p50_ms);
    push_ms(&mut parts, "tpot p99", tpot_p99_ms);
    ChecklistField {
        ttft_ms,
        ttft_p50_ms,
        ttft_p99_ms,
        tpot_ms,
        tpot_p50_ms,
        tpot_p99_ms,
        ..ChecklistField::from_parts("ttft_and_tpot", parts)
    }
}

fn tokens_field(tokens_per_second: Option<f64>) -> ChecklistField {
    let mut parts = Vec::new();
    if let Some(tokens_per_second) = tokens_per_second {
        parts.push(format!("{} tok/s", fmt_num(tokens_per_second)));
    }
    ChecklistField {
        tokens_per_second,
        ..ChecklistField::from_parts("tokens_per_second", parts)
    }
}

fn vram_field(record: &SlmRunRecord, host_memory_used_bytes: Option<u64>) -> ChecklistField {
    let peak_vram_bytes = record
        .system
        .gpus
        .iter()
        .filter_map(|gpu| gpu.memory_used_bytes)
        .max();
    let host_memory_used_bytes = peak_vram_bytes.and(host_memory_used_bytes);
    let mut parts = Vec::new();
    if let Some(bytes) = peak_vram_bytes {
        parts.push(format!("{bytes} B"));
    }
    if let Some(bytes) = host_memory_used_bytes {
        parts.push(format!("host RAM {bytes} B"));
    }
    ChecklistField {
        peak_vram_bytes,
        host_memory_used_bytes,
        ..ChecklistField::from_parts("peak_vram", parts)
    }
}

fn power_field(
    record: &SlmRunRecord,
    energy: Option<&crate::slm::EnergyMetrics>,
) -> ChecklistField {
    let stored_mean = energy.and_then(|item| finite_nonneg(item.mean_gpu_power_w));
    let mean_gpu_power_w = stored_mean.or_else(|| mean_power_draw(record));
    let joules_per_token = energy.and_then(|item| finite_nonneg(item.joules_per_token));
    let energy_wall_j = energy.and_then(|item| finite_nonneg(item.energy_wall_j));
    let mut parts = Vec::new();
    if let Some(watts) = mean_gpu_power_w {
        parts.push(format!("{} W", fmt_num(watts)));
    }
    if let Some(joules) = joules_per_token {
        parts.push(format!("{} J/token", fmt_num(joules)));
    }
    if let Some(joules) = energy_wall_j {
        parts.push(format!("wall {} J", fmt_num(joules)));
    }
    ChecklistField {
        mean_gpu_power_w,
        joules_per_token,
        energy_wall_j,
        ..ChecklistField::from_parts("mean_gpu_power_and_joules_per_token", parts)
    }
}

fn temperature_field(record: &SlmRunRecord) -> ChecklistField {
    let samples: Vec<f64> = record
        .system
        .gpus
        .iter()
        .filter_map(|gpu| gpu.temperature_c.filter(|value| value.is_finite()))
        .collect();
    if samples.is_empty() {
        return ChecklistField::unavailable("temperature");
    }
    let sum = samples.iter().sum::<f64>();
    let mean_gpu_temperature_c = Some(sum / samples.len() as f64);
    let max_gpu_temperature_c = samples.into_iter().reduce(f64::max);
    let mut parts = Vec::new();
    if let Some(mean) = mean_gpu_temperature_c {
        parts.push(format!("mean {} C", fmt_num(mean)));
    }
    if let Some(max) = max_gpu_temperature_c {
        parts.push(format!("max {} C", fmt_num(max)));
    }
    ChecklistField {
        mean_gpu_temperature_c,
        max_gpu_temperature_c,
        ..ChecklistField::from_parts("temperature", parts)
    }
}

fn task_field(quality: Option<&crate::slm::QualityMetrics>) -> ChecklistField {
    let Some(quality) = quality else {
        return ChecklistField::unavailable("task_score_and_benchmark");
    };
    let task_score = quality.task_score.filter(|value| value.is_finite());
    let task_name = owned_text(quality.task_name.as_deref());
    let task_metric = owned_text(quality.task_metric.as_deref());
    let mut parts = Vec::new();
    if let Some(score) = task_score {
        parts.push(format!("score {}", fmt_num(score)));
    }
    if let Some(task_name) = &task_name {
        parts.push(format!("benchmark {task_name}"));
    }
    if let Some(task_metric) = &task_metric {
        parts.push(task_metric.clone());
    }
    ChecklistField {
        task_score,
        task_name,
        task_metric,
        ..ChecklistField::from_parts("task_score_and_benchmark", parts)
    }
}

fn timestamp_field(record: &SlmRunRecord, experiment: Option<&ExperimentMeta>) -> ChecklistField {
    let started_at = Some(record.started_at.to_rfc3339());
    let ended_at = record.ended_at.map(|stamp| stamp.to_rfc3339());
    let git_commit = experiment.and_then(|item| owned_text(item.git_commit.as_deref()));
    let notes = experiment.and_then(|item| owned_text(item.notes.as_deref()));
    let mut parts = Vec::new();
    if let Some(started_at) = &started_at {
        parts.push(started_at.clone());
    }
    if let Some(ended_at) = &ended_at {
        parts.push(format!("ended {ended_at}"));
    }
    if let Some(git_commit) = &git_commit {
        parts.push(format!("commit {git_commit}"));
    }
    if let Some(notes) = &notes {
        parts.push(format!("notes {notes}"));
    }
    ChecklistField {
        started_at,
        ended_at,
        git_commit,
        notes,
        ..ChecklistField::from_parts("timestamp", parts)
    }
}

impl ChecklistField {
    fn unavailable(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Self::default()
        }
    }

    fn from_parts(name: &str, parts: Vec<String>) -> Self {
        if parts.is_empty() {
            Self::unavailable(name)
        } else {
            Self {
                name: name.to_string(),
                status: FieldStatus::Available,
                value: parts.join(" "),
                ..Self::default()
            }
        }
    }
}

fn mean_power_draw(record: &SlmRunRecord) -> Option<f64> {
    let samples: Vec<f64> = record
        .system
        .gpus
        .iter()
        .filter_map(|gpu| finite_nonneg(gpu.power_draw_w))
        .collect();
    if samples.is_empty() {
        return None;
    }
    let sum = samples.iter().sum::<f64>();
    Some(sum / samples.len() as f64)
}

fn push_ms(parts: &mut Vec<String>, label: &str, value: Option<f64>) {
    if let Some(value) = value {
        parts.push(format!("{label} {} ms", fmt_num(value)));
    }
}

fn finite_nonneg(value: Option<f64>) -> Option<f64> {
    value.filter(|item| item.is_finite() && *item >= 0.0)
}

fn owned_text(value: Option<&str>) -> Option<String> {
    let text = value?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn join_unique(values: impl Iterator<Item = String>) -> Option<String> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.iter().any(|seen: &String| seen == &value) {
            unique.push(value);
        }
    }
    if unique.is_empty() {
        None
    } else {
        Some(unique.join(", "))
    }
}

fn fmt_num(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

fn label(name: &str) -> &str {
    match name {
        "model" => "model",
        "hardware" => "hardware",
        "prompt_and_generation_length" => "prompt and generation length, batch",
        "ttft_and_tpot" => "TTFT and TPOT",
        "tokens_per_second" => "tokens/s",
        "peak_vram" => "peak VRAM",
        "mean_gpu_power_and_joules_per_token" => "mean GPU power and J/token",
        "temperature" => "temperature",
        "task_score_and_benchmark" => "task score and benchmark",
        "timestamp" => "timestamp",
        _ => name,
    }
}

fn record_path(state_dir: &Path, run_id: &str) -> Result<PathBuf> {
    validate_run_id(run_id)?;
    Ok(state_dir.join(RUNS_DIR).join(format!("{run_id}.json")))
}

fn validate_run_id(run_id: &str) -> Result<()> {
    let ok = !run_id.is_empty()
        && run_id.len() <= 128
        && run_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-');
    if ok {
        Ok(())
    } else {
        Err(DevGuardError::Usage(format!("invalid slm run id {run_id}")))
    }
}

fn read_record(path: &Path) -> Result<SlmRunRecord> {
    let text = fs::read_to_string(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            DevGuardError::Message(format!("slm run not found: {}", path.display()))
        } else {
            DevGuardError::Io(err)
        }
    })?;
    Ok(serde_json::from_str(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slm::{
        EnergyMetrics, ExperimentMeta, GpuSample, HostSample, LatencyMetrics, QualityMetrics,
        SystemObservation,
    };
    use chrono::{DateTime, Utc};

    fn stamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-07T20:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn write_fixture(dir: &Path, record: &SlmRunRecord) {
        let path = dir.join("slm-runs").join(format!("{}.json", record.run_id));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_vec_pretty(record).unwrap()).unwrap();
    }

    fn full_record() -> SlmRunRecord {
        let mut record = SlmRunRecord::begin(Some("cell".into()));
        record.run_id = "fixture-run".into();
        record.started_at = stamp();
        record.ended_at = Some(
            DateTime::parse_from_rfc3339("2026-10-07T20:00:10Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        record.experiment = Some(ExperimentMeta {
            model_id: Some("llama-3.2-1b".into()),
            parameter_count: Some(1_000_000_000),
            quantization: Some("Q4_K_M".into()),
            backend: Some("llama.cpp".into()),
            batch_size: Some(1),
            prompt_tokens: Some(32),
            output_tokens: Some(128),
            git_commit: Some("abc123".into()),
            notes: Some("cool-down 10s".into()),
            ..ExperimentMeta::default()
        });
        record.latency = Some(LatencyMetrics {
            ttft_ms: Some(120.5),
            ttft_p99_ms: Some(240.0),
            tpot_ms: Some(18.0),
            tpot_p99_ms: Some(40.0),
            tokens_per_second: Some(55.0),
            ..LatencyMetrics::default()
        });
        record.quality = Some(QualityMetrics {
            task_name: Some("gsm8k".into()),
            task_metric: Some("exact_match".into()),
            task_score: Some(0.5),
            ..QualityMetrics::default()
        });
        record.energy = Some(EnergyMetrics {
            mean_gpu_power_w: Some(80.0),
            joules_per_token: Some(8.0),
            energy_wall_j: Some(900.0),
            ..EnergyMetrics::default()
        });
        record.system = SystemObservation {
            host: Some(HostSample {
                memory_used_bytes: Some(8_000_000_000),
                memory_total_bytes: Some(16_000_000_000),
                ..HostSample::default()
            }),
            gpus: vec![
                GpuSample {
                    index: 0,
                    name: Some("NVIDIA GeForce RTX 3060".into()),
                    driver_version: Some("555.42".into()),
                    memory_used_bytes: Some(4_000_000_000),
                    temperature_c: Some(70.0),
                    power_draw_w: Some(10.0),
                    ..GpuSample::default()
                },
                GpuSample {
                    index: 1,
                    name: Some("NVIDIA GeForce RTX 3060".into()),
                    driver_version: Some("555.42".into()),
                    memory_used_bytes: Some(5_000_000_000),
                    temperature_c: Some(80.0),
                    power_draw_w: Some(90.0),
                    ..GpuSample::default()
                },
            ],
            ..SystemObservation::default()
        };
        record
    }

    #[test]
    fn fixture_run_fills_ten_fields_without_calling_ollama() {
        let dir = tempfile::tempdir().unwrap();
        let record = full_record();
        write_fixture(dir.path(), &record);
        let before = fs::read(dir.path().join("slm-runs/fixture-run.json")).unwrap();

        let report = paper_checklist(dir.path(), "fixture-run").unwrap();
        assert_eq!(
            fs::read(dir.path().join("slm-runs/fixture-run.json")).unwrap(),
            before
        );
        assert_eq!(report.fields.len(), 10);
        assert_eq!(
            report
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            PAPER_FIELD_NAMES
        );
        assert!(!report.calls_ollama);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());

        let model = report.field("model").unwrap();
        assert_eq!(model.model_id.as_deref(), Some("llama-3.2-1b"));
        assert_eq!(model.parameter_count, Some(1_000_000_000));
        assert_eq!(model.quantization.as_deref(), Some("Q4_K_M"));
        assert_eq!(model.backend.as_deref(), Some("llama.cpp"));

        let hardware = report.field("hardware").unwrap();
        assert_eq!(
            hardware.gpu_name.as_deref(),
            Some("NVIDIA GeForce RTX 3060")
        );
        assert_eq!(hardware.driver_version.as_deref(), Some("555.42"));
        assert_eq!(hardware.host_memory_total_bytes, Some(16_000_000_000));

        let prompt = report.field("prompt_and_generation_length").unwrap();
        assert_eq!(prompt.prompt_tokens, Some(32));
        assert_eq!(prompt.output_tokens, Some(128));
        assert_eq!(prompt.batch_size, Some(1));

        let latency = report.field("ttft_and_tpot").unwrap();
        assert_eq!(latency.ttft_ms, Some(120.5));
        assert_eq!(latency.ttft_p99_ms, Some(240.0));
        assert_eq!(latency.tpot_ms, Some(18.0));
        assert_eq!(latency.tpot_p99_ms, Some(40.0));
        assert!(latency.ttft_p50_ms.is_none());

        assert_eq!(
            report.field("tokens_per_second").unwrap().tokens_per_second,
            Some(55.0)
        );
        let vram = report.field("peak_vram").unwrap();
        assert_eq!(vram.peak_vram_bytes, Some(5_000_000_000));
        assert_eq!(vram.host_memory_used_bytes, Some(8_000_000_000));

        let power = report.field("mean_gpu_power_and_joules_per_token").unwrap();
        assert_eq!(power.mean_gpu_power_w, Some(80.0));
        assert_eq!(power.joules_per_token, Some(8.0));
        assert_eq!(power.energy_wall_j, Some(900.0));

        let temperature = report.field("temperature").unwrap();
        assert_eq!(temperature.mean_gpu_temperature_c, Some(75.0));
        assert_eq!(temperature.max_gpu_temperature_c, Some(80.0));

        let task = report.field("task_score_and_benchmark").unwrap();
        assert_eq!(task.task_score, Some(0.5));
        assert_eq!(task.task_name.as_deref(), Some("gsm8k"));

        let timestamp = report.field("timestamp").unwrap();
        let started = stamp().to_rfc3339();
        assert_eq!(timestamp.started_at.as_deref(), Some(started.as_str()));
        assert_eq!(timestamp.git_commit.as_deref(), Some("abc123"));
        assert_eq!(timestamp.notes.as_deref(), Some("cool-down 10s"));

        let text = format_paper_checklist(&report);
        assert!(text.contains("calls Ollama: no"));
        assert!(text.contains("llama-3.2-1b"));
        assert!(text.contains("batch 1"));
        assert!(text.contains("ttft 120.5 ms"));
        assert!(text.contains("55 tok/s"));
        assert!(text.contains("8 J/token"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn missing_fields_stay_blank_and_joules_are_not_invented() {
        let dir = tempfile::tempdir().unwrap();
        let mut record = SlmRunRecord::begin(None);
        record.run_id = "sparse-run".into();
        record.started_at = stamp();
        record.system.gpus.push(GpuSample {
            index: 0,
            power_draw_w: Some(40.0),
            temperature_c: Some(60.0),
            ..GpuSample::default()
        });
        record.experiment = Some(ExperimentMeta {
            output_tokens: Some(100),
            ..ExperimentMeta::default()
        });
        write_fixture(dir.path(), &record);

        let report = paper_checklist(dir.path(), "sparse-run").unwrap();
        assert_eq!(report.exit_code(), ExitCode::Partial);
        for name in [
            "model",
            "hardware",
            "ttft_and_tpot",
            "tokens_per_second",
            "peak_vram",
            "task_score_and_benchmark",
        ] {
            let field = report.field(name).unwrap();
            assert_eq!(field.status, FieldStatus::Unavailable, "{name}");
            assert!(field.value.is_empty(), "{name}");
        }
        let prompt = report.field("prompt_and_generation_length").unwrap();
        assert_eq!(prompt.output_tokens, Some(100));
        assert!(prompt.prompt_tokens.is_none());
        assert!(prompt.batch_size.is_none());
        assert!(!prompt.value.contains("prompt"));
        assert!(!prompt.value.contains("batch"));

        let power = report.field("mean_gpu_power_and_joules_per_token").unwrap();
        assert_eq!(power.mean_gpu_power_w, Some(40.0));
        assert!(power.joules_per_token.is_none());
        assert!(power.energy_wall_j.is_none());
        assert!(!power.value.contains("J/token"));

        let text = format_paper_checklist(&report);
        assert!(text.contains("model: unavailable"));
        assert!(text.contains("task score and benchmark: unavailable"));
        assert!(text.contains("timestamp: "));
        let power_line = text
            .lines()
            .find(|line| line.contains("mean GPU power"))
            .unwrap();
        assert_eq!(power_line.trim(), "mean GPU power and J/token: 40 W");
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|field| field.get("joules_per_token").is_none() || field["name"] != "model"));
        assert!(json["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["name"] == "mean_gpu_power_and_joules_per_token")
            .unwrap()
            .get("joules_per_token")
            .is_none());
        assert!(json["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["name"] == "task_score_and_benchmark")
            .unwrap()
            .get("task_score")
            .is_none());
    }

    #[test]
    fn missing_run_and_path_ids_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = paper_checklist(dir.path(), "missing-run").unwrap_err();
        assert!(missing.to_string().contains("not found"));
        let escaped = paper_checklist(dir.path(), "../outside").unwrap_err();
        assert!(matches!(escaped, DevGuardError::Usage(_)));
        assert!(!dir.path().join("outside.json").exists());
    }
}
