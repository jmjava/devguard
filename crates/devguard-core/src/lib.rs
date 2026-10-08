//! DevGuard core library: configuration, errors, JSON envelopes, and collector contracts.

pub mod backup_plan;
pub mod collector;
pub mod config;
pub mod dev_deps;
pub mod dev_env;
pub mod dev_repos;
pub mod doctor;
pub mod energy;
pub mod error;
pub mod exit;
pub mod fan;
pub mod files;
pub mod firewall;
pub mod gpu;
pub mod gpu_id;
pub mod health_scan;
pub mod host_sample;
pub mod json;
pub mod os_identity;
pub mod packages;
pub mod path_perms;
pub mod paths;
pub mod ports;
pub mod redact;
pub mod remote;
pub mod runaway;
pub mod security_drift;
pub mod security_scan;
pub mod security_updates;
pub mod sensors;
pub mod slm;
pub mod slm_checklist;
pub mod slm_export;
pub mod slm_run;
pub mod snapshot;
pub mod ssh_auth;
pub mod thresholds;
pub mod units;
pub mod watch;

pub use backup_plan::{
    format_backup_plan_human, plan_backup, BackupPlanReport, PlanCoverage, PlannedInclude,
    UnreadablePath,
};
pub use collector::{Collection, CollectionStatus, Collector};
pub use config::{Config, ConfigError, ConfigPaths};
pub use dev_deps::{
    format_deps_audit_human, scan_deps_audit, AuditAdapter, DepsAuditReport, NetworkAudit,
};
pub use dev_env::{format_dev_env_human, scan_dev_env, version_line, DevEnvReport};
pub use dev_repos::{format_dev_repos_human, scan_dev_repos, DevReposReport};
pub use doctor::{DoctorReport, PrerequisiteCheck, PrerequisiteStatus};
pub use error::{DevGuardError, Result};
pub use exit::ExitCode;
pub use fan::{diagnose, format_fan_human, scan_fan, FanReport};
pub use files::{format_files_human, scan_config_files, FilesReport, HashedFile};
pub use firewall::{format_firewall_human, scan_firewall, FirewallReport};
pub use gpu::{format_gpu_human, scan_gpu, GpuScanReport};
pub use gpu_id::{format_gpu_id_human, report_from_query, scan_gpu_id, GpuIdReport};
pub use health_scan::{format_health_scan_human, scan_health, HealthScanReport};
pub use json::{JsonEnvelope, SCHEMA_VERSION};
pub use os_identity::{format_os_human, read_os_identity, scan_os, OsIdentityReport};
pub use packages::{format_packages_human, read_package_inventory, scan_packages, PackagesReport};
pub use path_perms::{
    format_path_perms_human, scan_path_permissions, PathPermission, PathPermsReport,
};
pub use paths::DevGuardPaths;
pub use ports::{
    format_ports_human, report_from_listing, scan_ports, Attribution, ListenSocket, PortsReport,
};
pub use redact::{redact_env_value, redact_text, SENSITIVE_ENV_HINTS};
pub use remote::{
    collect_status, fetch_ollama_tags, format_remote_status, format_tunnel, tunnel_down, tunnel_up,
    RemoteSample, RemoteStatusReport, RemoteTarget, TunnelReport, ALLOWLIST,
};
pub use runaway::{
    format_runaway_human, scan_runaways, RunawayProcess, RunawayReport, RunawayThresholds,
};
pub use security_drift::{
    diff_stored_payloads, diff_stored_payloads_with_rules, format_security_drift_human,
    DriftFinding, DriftRules, SecurityDriftReport,
};
pub use security_scan::{
    filter_findings, findings_from, format_security_findings_human, format_security_scan_human,
    scan_security, Finding, FindingSeverity, SecurityFindingsReport, SecurityScanReport,
};
pub use security_updates::{
    format_security_updates_human, read_security_updates, scan_security_updates,
    SecurityUpdatesReport,
};
pub use sensors::{format_sensors_human, read_hwmon_sensors, scan_sensors, SensorsReport};
pub use slm::{
    academic_metric_checklist, EnergyMetrics, ExperimentMeta, GpuSample, HostSample,
    LatencyMetrics, MeasurementPlane, QualityMetrics, SlmRunRecord, SystemObservation,
    SLM_RUN_SCHEMA_VERSION,
};
pub use slm_checklist::{format_paper_checklist, paper_checklist, PaperChecklist};
pub use slm_export::{export_paper_table, paper_row, PaperRow, WrittenExport, PAPER_COLUMNS};
pub use snapshot::{
    collect_snapshot, collector_statuses, diff_payloads, format_create_human, format_diff_human,
    format_list_human, parse_payload, snapshot_warnings, summary_from_stored,
    CollectorAvailability, CollectorStatus, DiffEntry, SeverityHint, SnapshotDiff, SnapshotPayload,
    SnapshotSummary,
};
pub use ssh_auth::{format_ssh_auth_human, report_from_texts, scan_ssh_auth, SshAuthReport};
pub use thresholds::{evaluate_thresholds, ThresholdSample, ThresholdWarning, RULES_OF_THUMB};
pub use units::{format_units_human, parse_systemctl_listing, scan_units, UnitRecord, UnitsReport};
pub use watch::{
    format_interval, parse_watch_interval, refresh, render_watch, WatchSample, MAX_WATCH_INTERVAL,
    MIN_WATCH_INTERVAL,
};
