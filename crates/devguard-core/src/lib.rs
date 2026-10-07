//! DevGuard core library: configuration, errors, JSON envelopes, and collector contracts.

pub mod collector;
pub mod config;
pub mod doctor;
pub mod error;
pub mod exit;
pub mod fan;
pub mod gpu;
pub mod json;
pub mod paths;
pub mod redact;
pub mod remote;
pub mod slm;

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
pub use slm::{
    academic_metric_checklist, EnergyMetrics, ExperimentMeta, GpuSample, HostSample,
    LatencyMetrics, MeasurementPlane, QualityMetrics, SlmRunRecord, SystemObservation,
    SLM_RUN_SCHEMA_VERSION,
};
