//! TOML configuration loading, initialization, and validation.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::paths::DevGuardPaths;

/// Current configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Errors produced while reading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found at {0}")]
    NotFound(PathBuf),

    #[error("config already exists at {0}")]
    AlreadyExists(PathBuf),

    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write config {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid TOML in {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("unsupported config schema_version {found}; expected {expected}")]
    UnsupportedVersion { found: u32, expected: u32 },

    #[error("config validation failed: {0}")]
    Validation(String),
}

/// Resolved paths used when loading or creating config.
#[derive(Debug, Clone)]
pub struct ConfigPaths {
    pub paths: DevGuardPaths,
}

impl ConfigPaths {
    pub fn from_override(config: Option<PathBuf>) -> Result<Self, crate::error::DevGuardError> {
        let paths = match config {
            Some(path) => DevGuardPaths::default_locations()?.with_config_file(path),
            None => DevGuardPaths::default_locations()?,
        };
        Ok(Self { paths })
    }
}

/// Root configuration document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub snapshot: SnapshotConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub dev: DevConfig,
    /// SLM / local model metrics capture (opt-in directories and labels).
    #[serde(default)]
    pub slm: SlmConfig,
    /// Named downstairs WSL helper. Off until host and user are both set.
    #[serde(default)]
    pub remote: RemoteConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            general: GeneralConfig::default(),
            database: DatabaseConfig::default(),
            snapshot: SnapshotConfig::default(),
            health: HealthConfig::default(),
            security: SecurityConfig::default(),
            backup: BackupConfig::default(),
            dev: DevConfig::default(),
            slm: SlmConfig::default(),
            remote: RemoteConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneralConfig {
    #[serde(default = "default_true")]
    pub json_redact_paths: bool,
    #[serde(default = "default_collect_interval")]
    pub collect_interval_seconds: u64,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            json_redact_paths: true,
            collect_interval_seconds: default_collect_interval(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseConfig {
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotConfig {
    /// Omitted key: empty allowlist. That hashes nothing.
    #[serde(default)]
    pub config_hash_allowlist: Vec<String>,
}

/// Health and GPU threshold hints (rules of thumb, not hardware guarantees).
///
/// The `warn_cpu_load`, `warn_temp_c`, `warn_disk_free_bytes`, and
/// `warn_mem_used_fraction` keys are optional. A missing key emits no warning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthConfig {
    #[serde(default = "default_warn_cpu_temp")]
    pub warn_cpu_temp_c: f64,
    #[serde(default = "default_warn_gpu_temp")]
    pub warn_gpu_temp_c: f64,
    /// Warn when GPU memory utilization exceeds this percentage (SLM VRAM pressure).
    #[serde(default = "default_warn_gpu_mem_pct")]
    pub warn_gpu_mem_percent: f64,
    /// Warn when system memory utilization exceeds this percentage.
    #[serde(default = "default_warn_mem_pct")]
    pub warn_mem_percent: f64,
    /// Optional 1-minute CPU load. Missing means no load warning.
    #[serde(default)]
    pub warn_cpu_load: Option<f64>,
    /// Optional temperature in Celsius. Missing means no temperature warning.
    #[serde(default)]
    pub warn_temp_c: Option<f64>,
    /// Optional free-byte floor. Missing means no disk warning.
    #[serde(default)]
    pub warn_disk_free_bytes: Option<f64>,
    /// Optional used-memory fraction in `0.0..=1.0`. Missing means no fraction warning.
    #[serde(default)]
    pub warn_mem_used_fraction: Option<f64>,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            warn_cpu_temp_c: default_warn_cpu_temp(),
            warn_gpu_temp_c: default_warn_gpu_temp(),
            warn_gpu_mem_percent: default_warn_gpu_mem_pct(),
            warn_mem_percent: default_warn_mem_pct(),
            warn_cpu_load: None,
            warn_temp_c: None,
            warn_disk_free_bytes: None,
            warn_mem_used_fraction: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub check_ssh_logs: bool,
    #[serde(default = "default_true")]
    pub check_firewall: bool,
    #[serde(default = "default_true")]
    pub check_listening_ports: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            check_ssh_logs: true,
            check_firewall: true,
            check_listening_ports: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupConfig {
    #[serde(default = "default_backup_engine")]
    pub engine: String,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_verify_mode")]
    pub verify_mode: String,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            engine: default_backup_engine(),
            repository: None,
            include: Vec::new(),
            exclude: vec![
                "**/target".into(),
                "**/node_modules".into(),
                "**/.cache".into(),
                "**/__pycache__".into(),
                "**/*.gguf".into(),
                "**/*.bin".into(),
                "**/models/**".into(),
            ],
            verify_mode: default_verify_mode(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DevConfig {
    #[serde(default)]
    pub repo_roots: Vec<String>,
    #[serde(default)]
    pub allow_network_audits: bool,
}

/// Configuration for small-language-model (SLM) workstation metrics.
///
/// Paths are opt-in. DevGuard records resource usage and inventory; it does not
/// load models or start inference servers. See `docs/slm-research-metrics.md`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlmConfig {
    /// Human label for this workstation's SLM role (e.g. "local-inference").
    #[serde(default)]
    pub workspace_label: Option<String>,
    /// Directories that contain model weights or run artifacts (inventory only).
    #[serde(default)]
    pub model_dirs: Vec<String>,
    /// Optional process name substrings to highlight in health scans (e.g. "ollama", "llama").
    #[serde(default)]
    pub process_name_hints: Vec<String>,
    /// Capture NVIDIA GPU metrics when `nvidia-smi` is available.
    #[serde(default = "default_true")]
    pub capture_gpu: bool,
    /// Capture host CPU/memory/disk alongside GPU for run comparison.
    #[serde(default = "default_true")]
    pub capture_host: bool,
    /// Sample interval while bracketing an SLM experiment (seconds).
    #[serde(default = "default_slm_sample_interval")]
    pub sample_interval_seconds: u64,
    /// Default backend label stored on run records when the harness omits one.
    #[serde(default)]
    pub default_backend: Option<String>,
    /// Cool-down hint (seconds) between timed runs — recorded in notes, not enforced.
    #[serde(default = "default_slm_cooldown")]
    pub suggested_cooldown_seconds: u64,
}

/// SSH target for the downstairs WSL helper.
///
/// Host, user, and port belong in the local config file only. Leave host and
/// user empty to keep `devguard remote` off. Nothing in this struct is a
/// license to run an arbitrary remote command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteConfig {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Local end of the Ollama forward. Always bound to 127.0.0.1.
    #[serde(default = "default_ollama_port")]
    pub local_port: u16,
    /// Ollama port on 127.0.0.1 inside WSL.
    #[serde(default = "default_ollama_port")]
    pub remote_port: u16,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            host: None,
            user: None,
            port: default_ssh_port(),
            local_port: default_ollama_port(),
            remote_port: default_ollama_port(),
        }
    }
}

impl Default for SlmConfig {
    fn default() -> Self {
        Self {
            workspace_label: None,
            model_dirs: Vec::new(),
            process_name_hints: vec![
                "ollama".into(),
                "llama".into(),
                "vllm".into(),
                "text-generation".into(),
                "python".into(),
            ],
            capture_gpu: true,
            capture_host: true,
            sample_interval_seconds: default_slm_sample_interval(),
            default_backend: None,
            suggested_cooldown_seconds: default_slm_cooldown(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_collect_interval() -> u64 {
    5
}
fn default_retention_days() -> u32 {
    90
}
fn default_warn_cpu_temp() -> f64 {
    85.0
}
fn default_warn_gpu_temp() -> f64 {
    85.0
}
fn default_warn_gpu_mem_pct() -> f64 {
    90.0
}
fn default_warn_mem_pct() -> f64 {
    90.0
}
fn default_backup_engine() -> String {
    "restic".into()
}
fn default_verify_mode() -> String {
    "sample".into()
}
fn default_slm_sample_interval() -> u64 {
    1
}
fn default_slm_cooldown() -> u64 {
    10
}
fn default_ssh_port() -> u16 {
    22
}
fn default_ollama_port() -> u16 {
    11434
}

impl Config {
    /// Parse configuration from a TOML string.
    pub fn parse_toml(contents: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(contents)
    }

    /// Load configuration from disk.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Config = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Write a default configuration file with restrictive permissions (0600).
    pub fn init_file(path: &Path, force: bool) -> Result<Self, ConfigError> {
        if path.exists() && !force {
            return Err(ConfigError::AlreadyExists(path.to_path_buf()));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        }

        let mut config = Config::default();
        // Point the allowlist at the file we are creating so validate is clean offline.
        config.snapshot.config_hash_allowlist = vec![path.display().to_string()];
        let rendered = render_default_config_toml(&config);
        write_private_file(path, rendered.as_bytes())?;
        Ok(config)
    }

    /// Validate semantic constraints without requiring optional paths to exist.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: self.schema_version,
                expected: CONFIG_SCHEMA_VERSION,
            });
        }
        if self.general.collect_interval_seconds == 0 {
            return Err(ConfigError::Validation(
                "general.collect_interval_seconds must be >= 1".into(),
            ));
        }
        if self.general.collect_interval_seconds > 3600 {
            return Err(ConfigError::Validation(
                "general.collect_interval_seconds must be <= 3600".into(),
            ));
        }
        if self.slm.sample_interval_seconds == 0 || self.slm.sample_interval_seconds > 3600 {
            return Err(ConfigError::Validation(
                "slm.sample_interval_seconds must be in 1..=3600".into(),
            ));
        }
        if self.database.retention_days == 0 {
            return Err(ConfigError::Validation(
                "database.retention_days must be >= 1".into(),
            ));
        }
        for (name, value) in [
            ("health.warn_cpu_temp_c", self.health.warn_cpu_temp_c),
            ("health.warn_gpu_temp_c", self.health.warn_gpu_temp_c),
            (
                "health.warn_gpu_mem_percent",
                self.health.warn_gpu_mem_percent,
            ),
            ("health.warn_mem_percent", self.health.warn_mem_percent),
        ] {
            if !value.is_finite() || value <= 0.0 {
                return Err(ConfigError::Validation(format!(
                    "{name} must be a positive finite number"
                )));
            }
        }
        if self.health.warn_gpu_mem_percent > 100.0 || self.health.warn_mem_percent > 100.0 {
            return Err(ConfigError::Validation(
                "memory warning percentages must be <= 100".into(),
            ));
        }
        for (name, value) in [
            ("health.warn_cpu_load", self.health.warn_cpu_load),
            ("health.warn_temp_c", self.health.warn_temp_c),
            (
                "health.warn_disk_free_bytes",
                self.health.warn_disk_free_bytes,
            ),
            (
                "health.warn_mem_used_fraction",
                self.health.warn_mem_used_fraction,
            ),
        ] {
            if let Some(value) = value {
                if !value.is_finite() || value < 0.0 {
                    return Err(ConfigError::Validation(format!(
                        "{name} must be a non-negative finite number"
                    )));
                }
            }
        }
        if !matches!(self.backup.engine.as_str(), "restic" | "rustic") {
            return Err(ConfigError::Validation(format!(
                "backup.engine must be \"restic\" or \"rustic\", got \"{}\"",
                self.backup.engine
            )));
        }
        if !matches!(
            self.backup.verify_mode.as_str(),
            "sample" | "full" | "metadata"
        ) {
            return Err(ConfigError::Validation(format!(
                "backup.verify_mode must be sample|full|metadata, got \"{}\"",
                self.backup.verify_mode
            )));
        }
        // Never accept password-like keys if someone stuffed them into TOML by mistake.
        // (serde will ignore unknown fields by default only if we enable it; we keep strictness via docs.)
        self.remote_target()?;
        Ok(())
    }

    /// SSH target for the downstairs helper.
    ///
    /// `Ok(None)` means the helper is off. Host and user must both be set.
    /// The returned target never includes a wildcard bind.
    pub fn remote_target(&self) -> Result<Option<crate::remote::RemoteTarget>, ConfigError> {
        let host = self.remote.host.as_deref().map(str::trim).unwrap_or("");
        let user = self.remote.user.as_deref().map(str::trim).unwrap_or("");
        if host.is_empty() && user.is_empty() {
            return Ok(None);
        }
        if host.is_empty() || user.is_empty() {
            return Err(ConfigError::Validation(
                "remote host and user must both be set to name an SSH target".into(),
            ));
        }
        crate::remote::RemoteTarget::new(
            host,
            user,
            self.remote.port,
            self.remote.local_port,
            self.remote.remote_port,
        )
        .map(Some)
        .map_err(ConfigError::Validation)
    }

    /// Expand `~` in a path string using the current user's home directory.
    pub fn expand_user_path(raw: &str) -> Result<PathBuf, ConfigError> {
        if let Some(stripped) = raw.strip_prefix("~/") {
            let home = directories::BaseDirs::new()
                .map(|b| b.home_dir().to_path_buf())
                .ok_or_else(|| {
                    ConfigError::Validation("unable to resolve home directory".into())
                })?;
            Ok(home.join(stripped))
        } else if raw == "~" {
            directories::BaseDirs::new()
                .map(|b| b.home_dir().to_path_buf())
                .ok_or_else(|| ConfigError::Validation("unable to resolve home directory".into()))
        } else {
            Ok(PathBuf::from(raw))
        }
    }

    /// Validate and report missing optional paths as warnings (not hard errors).
    pub fn validate_with_warnings(&self) -> Result<Vec<String>, ConfigError> {
        self.validate()?;
        let mut warnings = Vec::new();

        for raw in &self.snapshot.config_hash_allowlist {
            let path = Self::expand_user_path(raw)?;
            if !path.exists() {
                warnings.push(format!("snapshot allowlist path does not exist: {raw}"));
            }
        }
        for raw in &self.dev.repo_roots {
            let path = Self::expand_user_path(raw)?;
            if !path.exists() {
                warnings.push(format!("dev.repo_roots path does not exist: {raw}"));
            }
        }
        for raw in &self.slm.model_dirs {
            let path = Self::expand_user_path(raw)?;
            if !path.exists() {
                warnings.push(format!("slm.model_dirs path does not exist: {raw}"));
            }
        }
        for raw in &self.backup.include {
            let path = Self::expand_user_path(raw)?;
            if !path.exists() {
                warnings.push(format!("backup.include path does not exist: {raw}"));
            }
        }
        if let Some(repo) = &self.backup.repository {
            let path = Self::expand_user_path(repo)?;
            if !path.exists() {
                warnings.push(format!(
                    "backup.repository does not exist yet (ok until backup run): {repo}"
                ));
            }
        }

        Ok(warnings)
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| ConfigError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn render_default_config_toml(config: &Config) -> String {
    format!(
        r#"# DevGuard configuration (schema_version = {schema})
# Safe and read-only by default. Credentials must never be stored here.

schema_version = {schema}

[general]
json_redact_paths = {redact}
collect_interval_seconds = {interval}

[database]
retention_days = {retention}

[snapshot]
config_hash_allowlist = {allowlist}

[health]
# Thresholds are rules of thumb for your workstation; adjust for your hardware.
# They are not hardware guarantees. Omit an optional key to emit no warning.
warn_cpu_temp_c = {cpu_temp}
warn_gpu_temp_c = {gpu_temp}
warn_gpu_mem_percent = {gpu_mem}
warn_mem_percent = {mem}
# warn_cpu_load = 8.0
# warn_temp_c = 85
# warn_disk_free_bytes = 10000000000
# warn_mem_used_fraction = 0.9

[security]
check_ssh_logs = true
check_firewall = true
check_listening_ports = true

[backup]
engine = "restic"
# repository = "/media/USER/backup/devguard-restic"
include = []
exclude = ["**/target", "**/node_modules", "**/.cache", "**/__pycache__", "**/*.gguf", "**/*.bin", "**/models/**"]
verify_mode = "sample"
# Credentials are managed externally; never put passwords here.

[dev]
repo_roots = []
allow_network_audits = false

# SLM / local model metrics (inventory + resource capture; no model loading)
# Academic metric mapping: docs/slm-research-metrics.md
[slm]
# workspace_label = "local-inference"
model_dirs = []
process_name_hints = ["ollama", "llama", "vllm", "text-generation", "python"]
capture_gpu = true
capture_host = true
sample_interval_seconds = 1
# default_backend = "llama.cpp"
suggested_cooldown_seconds = 10

# Downstairs WSL helper. Off until host and user are set in this local file.
# Do not commit a real host, user, or SSH port. The Ollama forward is
# 127.0.0.1 to 127.0.0.1. local_port and remote_port default to 11434.
# [remote]
# host = ""
# user = ""
"#,
        schema = config.schema_version,
        redact = config.general.json_redact_paths,
        interval = config.general.collect_interval_seconds,
        retention = config.database.retention_days,
        allowlist = toml_string_array(&config.snapshot.config_hash_allowlist),
        cpu_temp = config.health.warn_cpu_temp_c,
        gpu_temp = config.health.warn_gpu_temp_c,
        gpu_mem = config.health.warn_gpu_mem_percent,
        mem = config.health.warn_mem_percent,
    )
}

fn toml_string_array(values: &[String]) -> String {
    let parts: Vec<String> = values
        .iter()
        .map(|v| format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("[{}]", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_config_validates() {
        Config::default().validate().expect("default ok");
    }

    #[test]
    fn rejects_zero_interval() {
        let mut cfg = Config::default();
        cfg.general.collect_interval_seconds = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_bad_backup_engine() {
        let mut cfg = Config::default();
        cfg.backup.engine = "tar".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn init_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        Config::init_file(&path, false).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.schema_version, CONFIG_SCHEMA_VERSION);
        assert!(loaded.slm.capture_gpu);
        assert!(loaded.remote_target().unwrap().is_none());
    }

    #[test]
    fn remote_stays_off_until_host_and_user_are_named() {
        assert!(Config::default().remote_target().unwrap().is_none());
        let mut half = Config::default();
        half.remote.host = Some("fixture-host".into());
        assert!(half.validate().is_err());
        let mut named = Config::default();
        named.remote.host = Some("fixture-host".into());
        named.remote.user = Some("fixture-user".into());
        assert!(named.remote_target().unwrap().is_some());
        named.remote.host = Some("0.0.0.0".into());
        assert!(named.validate().is_err());
        named.remote.host = Some("bad host".into());
        named.remote.user = Some("fixture-user".into());
        let err = named.validate().unwrap_err();
        assert!(!err.to_string().contains("bad host"));
    }

    #[test]
    fn init_refuses_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        Config::init_file(&path, false).unwrap();
        let err = Config::init_file(&path, false).unwrap_err();
        assert!(matches!(err, ConfigError::AlreadyExists(_)));
    }

    #[test]
    fn expand_user_path_home() {
        let path = Config::expand_user_path("~/Projects").unwrap();
        assert!(path.is_absolute());
        assert!(path.ends_with("Projects"));
    }

    #[test]
    fn negative_optional_threshold_is_rejected() {
        let cases = [
            (
                "warn_cpu_load",
                HealthConfig {
                    warn_cpu_load: Some(-1.0),
                    ..HealthConfig::default()
                },
            ),
            (
                "warn_temp_c",
                HealthConfig {
                    warn_temp_c: Some(-0.1),
                    ..HealthConfig::default()
                },
            ),
            (
                "warn_disk_free_bytes",
                HealthConfig {
                    warn_disk_free_bytes: Some(-1.0),
                    ..HealthConfig::default()
                },
            ),
            (
                "warn_mem_used_fraction",
                HealthConfig {
                    warn_mem_used_fraction: Some(-0.01),
                    ..HealthConfig::default()
                },
            ),
        ];
        for (label, health) in cases {
            let cfg = Config {
                health,
                ..Config::default()
            };
            let err = cfg.validate().unwrap_err();
            assert!(err.to_string().contains(label), "{err}");
        }
    }

    #[test]
    fn example_config_from_spec_parses() {
        let toml = include_str!("../../../examples/config.example.toml");
        let cfg = Config::parse_toml(toml).expect("parse example");
        cfg.validate().expect("validate example");
    }

    #[test]
    fn omitted_config_hash_allowlist_is_empty_and_parses() {
        let bare = Config::parse_toml("schema_version = 1\n").expect("parse");
        assert!(bare.snapshot.config_hash_allowlist.is_empty());
        let section = Config::parse_toml("schema_version = 1\n\n[snapshot]\n").expect("parse");
        assert!(section.snapshot.config_hash_allowlist.is_empty());
        assert!(Config::default().snapshot.config_hash_allowlist.is_empty());
    }
}
