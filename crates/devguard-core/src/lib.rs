//! DevGuard core library: configuration, errors, JSON envelopes, and collector contracts.

pub mod collector;
pub mod config;
pub mod doctor;
pub mod error;
pub mod exit;
pub mod fan;
pub mod json;
pub mod paths;
pub mod redact;
pub mod slm;

pub use collector::{Collection, CollectionStatus, Collector};
pub use config::{Config, ConfigError, ConfigPaths};
pub use doctor::{DoctorReport, PrerequisiteCheck, PrerequisiteStatus};
pub use error::{DevGuardError, Result};
pub use exit::ExitCode;
pub use fan::{diagnose, format_fan_human, scan_fan, FanReport};
pub use json::{JsonEnvelope, SCHEMA_VERSION};
pub use paths::DevGuardPaths;
pub use redact::{redact_env_value, redact_text, SENSITIVE_ENV_HINTS};
pub use slm::{
    academic_metric_checklist, EnergyMetrics, ExperimentMeta, GpuSample, HostSample,
    LatencyMetrics, MeasurementPlane, QualityMetrics, SlmRunRecord, SystemObservation,
    SLM_RUN_SCHEMA_VERSION,
};
