//! DevGuard core library: configuration, errors, JSON envelopes, and collector contracts.

pub mod collector;
pub mod config;
pub mod doctor;
pub mod energy;
pub mod error;
pub mod exit;
pub mod fan;
pub mod gpu;
pub mod host_sample;
pub mod json;
pub mod paths;
pub mod redact;
pub mod remote;
pub mod runaway;
pub mod sensors;
pub mod slm;
pub mod slm_export;
pub mod slm_run;
pub mod thresholds;
pub mod watch;

pub use collector::{Collection, CollectionStatus, Collector};
pub use config::{Config, ConfigError, ConfigPaths};
pub use doctor::{DoctorReport, PrerequisiteCheck, PrerequisiteStatus};
pub use error::{DevGuardError, Result};
pub use exit::ExitCode;
pub use fan::{diagnose, format_fan_human, scan_fan, FanReport};
pub use gpu::{format_gpu_human, scan_gpu, GpuScanReport};
pub use json::{JsonEnvelope, SCHEMA_VERSION};
pub use paths::DevGuardPaths;
pub use redact::{redact_env_value, redact_text, SENSITIVE_ENV_HINTS};
pub use remote::{
    collect_status, fetch_ollama_tags, format_remote_status, format_tunnel, tunnel_down, tunnel_up,
    RemoteSample, RemoteStatusReport, RemoteTarget, TunnelReport, ALLOWLIST,
};
pub use runaway::{
    format_runaway_human, scan_runaways, RunawayProcess, RunawayReport, RunawayThresholds,
};
pub use sensors::{format_sensors_human, read_hwmon_sensors, scan_sensors, SensorsReport};
pub use slm::{
    academic_metric_checklist, EnergyMetrics, ExperimentMeta, GpuSample, HostSample,
    LatencyMetrics, MeasurementPlane, QualityMetrics, SlmRunRecord, SystemObservation,
    SLM_RUN_SCHEMA_VERSION,
};
pub use slm_export::{export_paper_table, paper_row, PaperRow, WrittenExport, PAPER_COLUMNS};
pub use thresholds::{evaluate_thresholds, ThresholdSample, ThresholdWarning, RULES_OF_THUMB};
pub use watch::{
    format_interval, parse_watch_interval, refresh, render_watch, WatchSample, MAX_WATCH_INTERVAL,
    MIN_WATCH_INTERVAL,
};
