//! Research-oriented SLM run records and metric helpers.
//!
//! See `docs/slm-research-metrics.md` for the literature mapping.
//! DevGuard captures host/GPU observations; latency/quality fields are
//! harness annotations so papers can combine both without inventing scores.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema version for SLM run records.
pub const SLM_RUN_SCHEMA_VERSION: u32 = 1;

/// Where power/energy numbers were measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementPlane {
    /// `nvidia-smi` / GPU board power rail.
    GpuRail,
    /// Process-scoped estimates only.
    HostProcess,
    /// External AC watt-meter (MLPerf Power style).
    WallAc,
    /// Combination of sources; fields must say which is which.
    Mixed,
    #[default]
    Unknown,
}

/// Throughput definition for `tokens_per_second`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputKind {
    Decode,
    E2e,
    Prefill,
    #[default]
    Unspecified,
}

/// Experiment cell identity (lock these for comparable paper rows).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExperimentMeta {
    pub model_id: Option<String>,
    pub parameter_count: Option<u64>,
    pub quantization: Option<String>,
    pub backend: Option<String>,
    pub batch_size: Option<u32>,
    pub context_length: Option<u32>,
    pub prompt_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub git_commit: Option<String>,
    pub notes: Option<String>,
}

/// Harness-supplied latency / throughput (never invented by DevGuard).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LatencyMetrics {
    pub ttft_ms: Option<f64>,
    pub ttft_p50_ms: Option<f64>,
    pub ttft_p99_ms: Option<f64>,
    pub tpot_ms: Option<f64>,
    pub tpot_p50_ms: Option<f64>,
    pub tpot_p99_ms: Option<f64>,
    pub e2e_latency_ms: Option<f64>,
    pub tokens_per_second: Option<f64>,
    #[serde(default)]
    pub throughput_kind: ThroughputKind,
}

/// Optional task-quality pointer from an eval harness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct QualityMetrics {
    pub task_name: Option<String>,
    pub task_metric: Option<String>,
    pub task_score: Option<f64>,
    pub higher_is_better: Option<bool>,
}

/// Energy fields (GPU-rail approximate and/or wall meter).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct EnergyMetrics {
    pub mean_gpu_power_w: Option<f64>,
    pub energy_gpu_approx_j: Option<f64>,
    pub energy_wall_j: Option<f64>,
    pub joules_per_token: Option<f64>,
    pub tokens_per_joule: Option<f64>,
    pub throughput_per_watt: Option<f64>,
}

/// One GPU sample suitable for academic system tables.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GpuSample {
    pub index: u32,
    pub name: Option<String>,
    pub driver_version: Option<String>,
    pub utilization_percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub temperature_c: Option<f64>,
    pub power_draw_w: Option<f64>,
    pub power_limit_w: Option<f64>,
}

/// Host sample alongside GPU data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct HostSample {
    pub cpu_percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
}

/// System observation block attached to a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemObservation {
    pub status: crate::collector::CollectionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<HostSample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpus: Vec<GpuSample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Default for SystemObservation {
    fn default() -> Self {
        Self {
            status: crate::collector::CollectionStatus::Unavailable,
            host: None,
            gpus: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

/// Full research run record (JSON schema `slm-run-metrics`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlmRunRecord {
    pub schema_version: u32,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_label: Option<String>,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_s: Option<f64>,
    pub measurement_plane: MeasurementPlane,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experiment: Option<ExperimentMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<LatencyMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<QualityMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub energy: Option<EnergyMetrics>,
    pub system: SystemObservation,
}

impl SlmRunRecord {
    pub fn begin(run_label: Option<String>) -> Self {
        Self {
            schema_version: SLM_RUN_SCHEMA_VERSION,
            run_id: Uuid::new_v4().to_string(),
            run_label,
            started_at: Utc::now(),
            ended_at: None,
            duration_s: None,
            measurement_plane: MeasurementPlane::GpuRail,
            experiment: None,
            latency: None,
            quality: None,
            energy: None,
            system: SystemObservation::default(),
        }
    }

    /// Approximate GPU-rail energy and derived efficiency metrics.
    ///
    /// `energy_j ≈ mean_power_w * duration_s`. This is **not** wall AC energy.
    pub fn derive_energy_from_gpu_rail(&mut self) {
        let mean_power = self
            .system
            .gpus
            .iter()
            .filter_map(|g| g.power_draw_w)
            .collect::<Vec<_>>();
        if mean_power.is_empty() {
            return;
        }
        let mean = mean_power.iter().sum::<f64>() / mean_power.len() as f64;
        let duration = self.duration_s.unwrap_or(0.0);
        if duration <= 0.0 || !mean.is_finite() {
            return;
        }
        let energy_j = mean * duration;
        let output_tokens = self
            .experiment
            .as_ref()
            .and_then(|e| e.output_tokens)
            .map(f64::from);
        let tokens_per_second = self.latency.as_ref().and_then(|l| l.tokens_per_second);

        let mut energy = self.energy.take().unwrap_or_default();
        energy.mean_gpu_power_w = Some(mean);
        energy.energy_gpu_approx_j = Some(energy_j);
        if let Some(tokens) = output_tokens {
            if tokens > 0.0 {
                energy.joules_per_token = Some(energy_j / tokens);
                energy.tokens_per_joule = Some(tokens / energy_j);
            }
        }
        if let Some(tps) = tokens_per_second {
            if mean > 0.0 {
                energy.throughput_per_watt = Some(tps / mean);
            }
        }
        self.measurement_plane = MeasurementPlane::GpuRail;
        self.energy = Some(energy);
    }
}

/// Metrics checklist used by doctor / docs (ids only).
pub fn academic_metric_checklist() -> &'static [&'static str] {
    &[
        "model_id+params+quantization+backend",
        "gpu_name+driver+host_mem",
        "prompt_tokens+output_tokens+batch_size",
        "ttft_ms (+ p99 if interactive)",
        "tpot_ms (+ p99 if interactive)",
        "tokens_per_second",
        "peak_vram_bytes",
        "mean_gpu_power_w + joules_per_token",
        "gpu_temperature_c",
        "task_name+task_score (from harness)",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_energy_computes_j_per_token() {
        let mut run = SlmRunRecord::begin(Some("gsm8k-q4".into()));
        run.duration_s = Some(10.0);
        run.experiment = Some(ExperimentMeta {
            model_id: Some("llama-3.2-1b".into()),
            output_tokens: Some(100),
            ..ExperimentMeta::default()
        });
        run.latency = Some(LatencyMetrics {
            tokens_per_second: Some(50.0),
            throughput_kind: ThroughputKind::Decode,
            ..LatencyMetrics::default()
        });
        run.system.gpus.push(GpuSample {
            index: 0,
            power_draw_w: Some(80.0),
            memory_used_bytes: Some(4_000_000_000),
            memory_total_bytes: Some(12_000_000_000),
            temperature_c: Some(72.0),
            ..GpuSample::default()
        });
        run.derive_energy_from_gpu_rail();
        let energy = run.energy.expect("energy");
        assert_eq!(energy.mean_gpu_power_w, Some(80.0));
        assert_eq!(energy.energy_gpu_approx_j, Some(800.0));
        assert_eq!(energy.joules_per_token, Some(8.0));
        assert_eq!(energy.tokens_per_joule, Some(0.125));
        assert_eq!(energy.throughput_per_watt, Some(0.625));
    }

    #[test]
    fn checklist_covers_paper_minimum() {
        let items = academic_metric_checklist();
        assert!(items.iter().any(|i| i.contains("ttft")));
        assert!(items.iter().any(|i| i.contains("tpot")));
        assert!(items.iter().any(|i| i.contains("joules_per_token")));
    }

    #[test]
    fn run_record_roundtrips_json() {
        let run = SlmRunRecord::begin(None);
        let json = serde_json::to_string(&run).unwrap();
        let back: SlmRunRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, SLM_RUN_SCHEMA_VERSION);
    }
}
