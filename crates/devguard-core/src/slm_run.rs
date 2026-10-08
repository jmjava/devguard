//! Bracket an SLM harness run.
//!
//! `begin_run` writes a [`SlmRunRecord`] under the DevGuard state directory
//! and returns it. `end_run` closes that record and stores the measured
//! duration. Optional harness JSON may supply TTFT and token counts.
//! Missing harness fields stay unset. This module does not call Ollama,
//! bind a port, or invent latency, quality, or GPU samples.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Deserialize;

use crate::error::{DevGuardError, Result};
use crate::slm::{
    ExperimentMeta, LatencyMetrics, MeasurementPlane, QualityMetrics, SlmRunRecord, ThroughputKind,
};

const RUNS_DIR: &str = "slm-runs";

/// Open a run record, store it, and return it (including `run_id`).
pub fn begin_run(state_dir: &Path, run_label: Option<String>) -> Result<SlmRunRecord> {
    let run_label = clean_label(run_label)?;
    let record = SlmRunRecord::begin(run_label);
    write_record(&record_path(state_dir, &record.run_id)?, &record)?;
    Ok(record)
}

/// Close an open run, record duration, and store harness annotations when present.
///
/// `harness_json` is optional. When it is absent, latency and quality stay unset.
pub fn end_run(state_dir: &Path, run_id: &str, harness_json: Option<&str>) -> Result<SlmRunRecord> {
    let path = record_path(state_dir, run_id)?;
    let mut record = read_record(&path)?;
    if record.run_id != run_id {
        return Err(DevGuardError::Message(format!(
            "slm run {run_id} does not match the stored record"
        )));
    }
    if record.ended_at.is_some() {
        return Err(DevGuardError::Message(format!(
            "slm run {run_id} is already closed"
        )));
    }
    let ended_at = Utc::now();
    let duration_ms = ended_at
        .signed_duration_since(record.started_at)
        .num_milliseconds();
    if duration_ms < 0 {
        return Err(DevGuardError::Message(
            "slm run end is earlier than its start".into(),
        ));
    }
    if let Some(harness_json) = harness_json {
        merge_harness(&mut record, harness_json)?;
    }
    record.ended_at = Some(ended_at);
    record.duration_s = Some(duration_ms as f64 / 1000.0);
    write_record(&path, &record)?;
    Ok(record)
}

/// Copy harness-supplied TTFT, tokens, and related annotations onto a record.
///
/// Numbers that the JSON omits stay `None`. This does not derive energy or
/// fill quality scores.
pub fn merge_harness(record: &mut SlmRunRecord, harness_json: &str) -> Result<()> {
    let doc: HarnessDoc = serde_json::from_str(harness_json)
        .map_err(|err| DevGuardError::Usage(format!("invalid harness JSON: {err}")))?;
    if let Some(latency) = extract_latency(&doc)? {
        record.latency = Some(latency);
    }
    if let Some(experiment) = extract_experiment(&doc)? {
        record.experiment = Some(experiment);
    }
    if let Some(quality) = extract_quality(&doc)? {
        record.quality = Some(quality);
    }
    if let Some(plane) = doc.measurement_plane {
        record.measurement_plane = plane;
    }
    Ok(())
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

fn clean_label(run_label: Option<String>) -> Result<Option<String>> {
    match run_label {
        None => Ok(None),
        Some(label) => {
            let label = label.trim();
            if label.is_empty() {
                Err(DevGuardError::Usage("run label must not be empty".into()))
            } else {
                Ok(Some(label.to_string()))
            }
        }
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

fn write_record(path: &Path, record: &SlmRunRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        serde_json::to_writer_pretty(&mut file, record)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct LatencyDoc {
    ttft_ms: Option<f64>,
    ttft_p50_ms: Option<f64>,
    ttft_p99_ms: Option<f64>,
    tpot_ms: Option<f64>,
    tpot_p50_ms: Option<f64>,
    tpot_p99_ms: Option<f64>,
    e2e_latency_ms: Option<f64>,
    tokens_per_second: Option<f64>,
    throughput_kind: ThroughputKind,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct ExperimentDoc {
    model_id: Option<String>,
    parameter_count: Option<u64>,
    quantization: Option<String>,
    backend: Option<String>,
    batch_size: Option<u32>,
    context_length: Option<u32>,
    prompt_tokens: Option<u32>,
    output_tokens: Option<u32>,
    git_commit: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct QualityDoc {
    task_name: Option<String>,
    task_metric: Option<String>,
    task_score: Option<f64>,
    higher_is_better: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct HarnessDoc {
    #[serde(default)]
    latency: Option<LatencyDoc>,
    #[serde(default)]
    experiment: Option<ExperimentDoc>,
    #[serde(default)]
    quality: Option<QualityDoc>,
    #[serde(default)]
    measurement_plane: Option<MeasurementPlane>,
    #[serde(default)]
    ttft_ms: Option<f64>,
    #[serde(default)]
    ttft_p50_ms: Option<f64>,
    #[serde(default)]
    ttft_p99_ms: Option<f64>,
    #[serde(default)]
    tpot_ms: Option<f64>,
    #[serde(default)]
    tpot_p50_ms: Option<f64>,
    #[serde(default)]
    tpot_p99_ms: Option<f64>,
    #[serde(default)]
    e2e_latency_ms: Option<f64>,
    #[serde(default)]
    tokens_per_second: Option<f64>,
    #[serde(default)]
    throughput_kind: Option<ThroughputKind>,
    #[serde(default)]
    tokens: Option<u32>,
    #[serde(default)]
    output_tokens: Option<u32>,
    #[serde(default)]
    prompt_tokens: Option<u32>,
    #[serde(default)]
    batch_size: Option<u32>,
    #[serde(default)]
    context_length: Option<u32>,
    #[serde(default)]
    quantization: Option<String>,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    model_id: Option<String>,
    #[serde(default)]
    parameter_count: Option<u64>,
    #[serde(default)]
    git_commit: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    task_name: Option<String>,
    #[serde(default)]
    task_metric: Option<String>,
    #[serde(default)]
    task_score: Option<f64>,
    #[serde(default)]
    higher_is_better: Option<bool>,
}

fn extract_latency(doc: &HarnessDoc) -> Result<Option<LatencyMetrics>> {
    let source = doc.latency.clone().unwrap_or_default();
    let mut latency = LatencyMetrics {
        ttft_ms: fill_f64(source.ttft_ms, doc.ttft_ms),
        ttft_p50_ms: fill_f64(source.ttft_p50_ms, doc.ttft_p50_ms),
        ttft_p99_ms: fill_f64(source.ttft_p99_ms, doc.ttft_p99_ms),
        tpot_ms: fill_f64(source.tpot_ms, doc.tpot_ms),
        tpot_p50_ms: fill_f64(source.tpot_p50_ms, doc.tpot_p50_ms),
        tpot_p99_ms: fill_f64(source.tpot_p99_ms, doc.tpot_p99_ms),
        e2e_latency_ms: fill_f64(source.e2e_latency_ms, doc.e2e_latency_ms),
        tokens_per_second: fill_f64(source.tokens_per_second, doc.tokens_per_second),
        throughput_kind: source.throughput_kind,
    };
    if latency.throughput_kind == ThroughputKind::Unspecified {
        if let Some(kind) = doc.throughput_kind {
            latency.throughput_kind = kind;
        }
    }
    latency.ttft_ms = reject_latency("ttft_ms", latency.ttft_ms)?;
    latency.ttft_p50_ms = reject_latency("ttft_p50_ms", latency.ttft_p50_ms)?;
    latency.ttft_p99_ms = reject_latency("ttft_p99_ms", latency.ttft_p99_ms)?;
    latency.tpot_ms = reject_latency("tpot_ms", latency.tpot_ms)?;
    latency.tpot_p50_ms = reject_latency("tpot_p50_ms", latency.tpot_p50_ms)?;
    latency.tpot_p99_ms = reject_latency("tpot_p99_ms", latency.tpot_p99_ms)?;
    latency.e2e_latency_ms = reject_latency("e2e_latency_ms", latency.e2e_latency_ms)?;
    latency.tokens_per_second = reject_latency("tokens_per_second", latency.tokens_per_second)?;
    let has_number = latency.ttft_ms.is_some()
        || latency.ttft_p50_ms.is_some()
        || latency.ttft_p99_ms.is_some()
        || latency.tpot_ms.is_some()
        || latency.tpot_p50_ms.is_some()
        || latency.tpot_p99_ms.is_some()
        || latency.e2e_latency_ms.is_some()
        || latency.tokens_per_second.is_some();
    let has_kind = latency.throughput_kind != ThroughputKind::Unspecified;
    if has_number || has_kind {
        Ok(Some(latency))
    } else {
        Ok(None)
    }
}

fn extract_experiment(doc: &HarnessDoc) -> Result<Option<ExperimentMeta>> {
    let source = doc.experiment.clone().unwrap_or_default();
    let experiment = ExperimentMeta {
        model_id: prefer_text("model_id", source.model_id, doc.model_id.clone())?,
        parameter_count: fill_u64(source.parameter_count, doc.parameter_count),
        quantization: prefer_text(
            "quantization",
            source.quantization,
            doc.quantization.clone(),
        )?,
        backend: prefer_text("backend", source.backend, doc.backend.clone())?,
        batch_size: reject_min_u32("batch_size", fill_u32(source.batch_size, doc.batch_size), 1)?,
        context_length: reject_min_u32(
            "context_length",
            fill_u32(source.context_length, doc.context_length),
            1,
        )?,
        prompt_tokens: fill_u32(source.prompt_tokens, doc.prompt_tokens),
        output_tokens: fill_u32(source.output_tokens, doc.output_tokens.or(doc.tokens)),
        git_commit: prefer_text("git_commit", source.git_commit, doc.git_commit.clone())?,
        notes: prefer_text("notes", source.notes, doc.notes.clone())?,
    };
    if experiment_is_empty(&experiment) {
        Ok(None)
    } else {
        Ok(Some(experiment))
    }
}

fn extract_quality(doc: &HarnessDoc) -> Result<Option<QualityMetrics>> {
    let source = doc.quality.clone().unwrap_or_default();
    let quality = QualityMetrics {
        task_name: prefer_text("task_name", source.task_name, doc.task_name.clone())?,
        task_metric: prefer_text("task_metric", source.task_metric, doc.task_metric.clone())?,
        task_score: reject_finite("task_score", fill_f64(source.task_score, doc.task_score))?,
        higher_is_better: source.higher_is_better.or(doc.higher_is_better),
    };
    if quality.task_name.is_none()
        && quality.task_metric.is_none()
        && quality.task_score.is_none()
        && quality.higher_is_better.is_none()
    {
        Ok(None)
    } else {
        Ok(Some(quality))
    }
}

fn prefer_text(
    name: &str,
    current: Option<String>,
    fallback: Option<String>,
) -> Result<Option<String>> {
    match current {
        Some(text) => clean_text(name, Some(text)),
        None => clean_text(name, fallback),
    }
}

fn experiment_is_empty(experiment: &ExperimentMeta) -> bool {
    experiment.model_id.is_none()
        && experiment.parameter_count.is_none()
        && experiment.quantization.is_none()
        && experiment.backend.is_none()
        && experiment.batch_size.is_none()
        && experiment.context_length.is_none()
        && experiment.prompt_tokens.is_none()
        && experiment.output_tokens.is_none()
        && experiment.git_commit.is_none()
        && experiment.notes.is_none()
}

fn fill_f64(current: Option<f64>, fallback: Option<f64>) -> Option<f64> {
    current.or(fallback)
}

fn fill_u32(current: Option<u32>, fallback: Option<u32>) -> Option<u32> {
    current.or(fallback)
}

fn fill_u64(current: Option<u64>, fallback: Option<u64>) -> Option<u64> {
    current.or(fallback)
}

fn clean_text(name: &str, value: Option<String>) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(text) => {
            let text = text.trim();
            if text.is_empty() {
                Err(DevGuardError::Usage(format!("{name} must not be empty")))
            } else {
                Ok(Some(text.to_string()))
            }
        }
    }
}

fn reject_latency(name: &str, value: Option<f64>) -> Result<Option<f64>> {
    if let Some(value) = value {
        if !value.is_finite() || value < 0.0 {
            return Err(DevGuardError::Usage(format!(
                "{name} must be a finite number >= 0"
            )));
        }
    }
    Ok(value)
}

fn reject_finite(name: &str, value: Option<f64>) -> Result<Option<f64>> {
    if let Some(value) = value {
        if !value.is_finite() {
            return Err(DevGuardError::Usage(format!(
                "{name} must be a finite number"
            )));
        }
    }
    Ok(value)
}

fn reject_min_u32(name: &str, value: Option<u32>, min: u32) -> Result<Option<u32>> {
    if let Some(value) = value {
        if value < min {
            return Err(DevGuardError::Usage(format!("{name} must be >= {min}")));
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slm::MeasurementPlane;
    use serde_json::json;

    fn state_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp state dir")
    }

    #[test]
    fn begin_writes_an_open_record_without_invented_metrics() {
        let dir = state_dir();
        let record = begin_run(dir.path(), Some("gsm8k".into())).expect("begin");
        assert!(!record.run_id.is_empty());
        uuid::Uuid::parse_str(&record.run_id).expect("uuid");
        assert_eq!(record.run_label.as_deref(), Some("gsm8k"));
        assert!(record.ended_at.is_none());
        assert!(record.duration_s.is_none());
        assert!(record.latency.is_none());
        assert!(record.quality.is_none());
        assert!(record.experiment.is_none());
        assert!(record.energy.is_none());

        let path = dir
            .path()
            .join("slm-runs")
            .join(format!("{}.json", record.run_id));
        let stored: SlmRunRecord =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(stored, record);
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(value.get("latency").is_none());
        assert!(value.get("quality").is_none());
        assert!(value.get("energy").is_none());
    }

    #[test]
    fn end_records_duration_and_leaves_metrics_absent() {
        let dir = state_dir();
        let opened = begin_run(dir.path(), None).expect("begin");
        let closed = end_run(dir.path(), &opened.run_id, None).expect("end");
        assert!(closed.ended_at.is_some());
        let duration = closed.duration_s.expect("duration");
        assert!(duration >= 0.0);
        assert!(closed.latency.is_none());
        assert!(closed.quality.is_none());
        assert!(closed.energy.is_none());
        assert!(closed.experiment.is_none());

        let again = end_run(dir.path(), &opened.run_id, None);
        assert!(again.is_err());
    }

    #[test]
    fn end_stores_harness_ttft_and_tokens_without_inventing_quality() {
        let dir = state_dir();
        let opened = begin_run(dir.path(), Some("cell".into())).expect("begin");
        let harness = json!({
            "ttft_ms": 120.5,
            "ttft_p50_ms": 110.0,
            "ttft_p99_ms": 240.0,
            "tpot_ms": 18.0,
            "tokens_per_second": 55.0,
            "tokens": 128,
            "prompt_tokens": 32,
            "batch_size": 1,
            "context_length": 4096,
            "quantization": "Q4_K_M",
            "backend": "llama.cpp"
        })
        .to_string();
        let closed = end_run(dir.path(), &opened.run_id, Some(&harness)).expect("end");
        let latency = closed.latency.expect("latency");
        assert_eq!(latency.ttft_ms, Some(120.5));
        assert_eq!(latency.ttft_p99_ms, Some(240.0));
        assert_eq!(latency.tpot_ms, Some(18.0));
        assert_eq!(latency.tokens_per_second, Some(55.0));
        assert!(latency.e2e_latency_ms.is_none());
        let experiment = closed.experiment.expect("experiment");
        assert_eq!(experiment.output_tokens, Some(128));
        assert_eq!(experiment.prompt_tokens, Some(32));
        assert_eq!(experiment.batch_size, Some(1));
        assert_eq!(experiment.context_length, Some(4096));
        assert_eq!(experiment.quantization.as_deref(), Some("Q4_K_M"));
        assert_eq!(experiment.backend.as_deref(), Some("llama.cpp"));
        assert!(closed.quality.is_none());
        assert!(closed.energy.is_none());
        assert!(closed.duration_s.is_some());
    }

    #[test]
    fn tokens_only_harness_does_not_invent_latency() {
        let dir = state_dir();
        let opened = begin_run(dir.path(), None).expect("begin");
        let closed =
            end_run(dir.path(), &opened.run_id, Some(r#"{"output_tokens": 4}"#)).expect("end");
        assert!(closed.latency.is_none());
        assert!(closed.quality.is_none());
        assert_eq!(closed.experiment.and_then(|e| e.output_tokens), Some(4));
    }

    #[test]
    fn nested_harness_quality_is_stored_when_supplied() {
        let dir = state_dir();
        let opened = begin_run(dir.path(), None).expect("begin");
        let harness =
            r#"{"latency":{"ttft_ms":10.0},"quality":{"task_name":"gsm8k","task_score":0.42}}"#;
        let closed = end_run(dir.path(), &opened.run_id, Some(harness)).expect("end");
        assert_eq!(closed.latency.unwrap().ttft_ms, Some(10.0));
        let quality = closed.quality.expect("quality");
        assert_eq!(quality.task_name.as_deref(), Some("gsm8k"));
        assert_eq!(quality.task_score, Some(0.42));
    }

    #[test]
    fn negative_ttft_does_not_close_the_run() {
        let dir = state_dir();
        let opened = begin_run(dir.path(), None).expect("begin");
        let err = end_run(dir.path(), &opened.run_id, Some(r#"{"ttft_ms": -1}"#)).unwrap_err();
        assert!(err.to_string().contains("ttft_ms"));
        let path = dir
            .path()
            .join("slm-runs")
            .join(format!("{}.json", opened.run_id));
        let stored: SlmRunRecord =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert!(stored.ended_at.is_none());
        assert!(stored.latency.is_none());
    }

    #[test]
    fn rejects_path_like_run_ids() {
        let dir = state_dir();
        let err = end_run(dir.path(), "../outside", None).unwrap_err();
        assert!(matches!(err, DevGuardError::Usage(_)));
        assert!(!dir.path().join("outside.json").exists());
        assert!(end_run(dir.path(), "missing-run", None).is_err());
    }

    #[test]
    fn empty_harness_object_does_not_invent_metrics() {
        let mut record = SlmRunRecord::begin(None);
        merge_harness(&mut record, "{}").unwrap();
        assert!(record.latency.is_none());
        assert!(record.quality.is_none());
        assert!(record.experiment.is_none());
        assert_eq!(record.measurement_plane, MeasurementPlane::GpuRail);
    }
}
