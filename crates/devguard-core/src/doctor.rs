//! Prerequisite and coverage checks for `devguard doctor`.

use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::paths::DevGuardPaths;

/// Overall doctor report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorReport {
    pub host: HostSummary,
    pub checks: Vec<PrerequisiteCheck>,
    /// True when every required check passed (optional tools may be missing).
    pub ready_for_readonly: bool,
    /// True when NVIDIA tooling is available for SLM GPU metrics.
    pub ready_for_gpu_metrics: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostSummary {
    pub os: String,
    pub arch: String,
    pub hostname_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrerequisiteCheck {
    pub id: String,
    pub category: String,
    pub status: PrerequisiteStatus,
    pub detail: String,
    /// Whether this check is required for basic read-only operation.
    pub required: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrerequisiteStatus {
    Ok,
    Missing,
    Warning,
    Unknown,
}

/// Run doctor checks without requiring root.
pub fn run_doctor(paths: &DevGuardPaths, config: Option<&Config>) -> DoctorReport {
    let mut checks = Vec::new();

    checks.push(check_path_writable(
        "xdg_config_dir",
        "paths",
        &paths.config_dir,
        true,
    ));
    checks.push(check_path_writable(
        "xdg_state_dir",
        "paths",
        &paths.state_dir,
        true,
    ));

    match config {
        Some(_) => checks.push(PrerequisiteCheck {
            id: "config".into(),
            category: "config".into(),
            status: PrerequisiteStatus::Ok,
            detail: format!("loaded {}", paths.config_file.display()),
            required: false,
        }),
        None => checks.push(PrerequisiteCheck {
            id: "config".into(),
            category: "config".into(),
            status: if paths.config_file.exists() {
                PrerequisiteStatus::Warning
            } else {
                PrerequisiteStatus::Missing
            },
            detail: if paths.config_file.exists() {
                format!(
                    "config exists at {} but failed to load earlier",
                    paths.config_file.display()
                )
            } else {
                format!(
                    "no config at {}; run `devguard config init`",
                    paths.config_file.display()
                )
            },
            required: false,
        }),
    }

    // Core CLI dependencies (optional until feature used).
    checks.push(check_binary("git", "dev", false));
    checks.push(check_binary("ss", "security", false));
    checks.push(check_binary("systemctl", "host", false));
    checks.push(check_binary("sensors", "health", false));

    // SLM / GPU metrics tooling — optional but highlighted.
    checks.push(check_binary("nvidia-smi", "slm-gpu", false));
    checks.push(check_nvidia_query());

    checks.push(check_binary("restic", "backup", false));
    checks.push(check_binary("rustic", "backup", false));

    if let Some(cfg) = config {
        if cfg.slm.capture_gpu {
            let gpu_ok = checks
                .iter()
                .any(|c| c.id == "nvidia-smi" && c.status == PrerequisiteStatus::Ok);
            if !gpu_ok {
                checks.push(PrerequisiteCheck {
                    id: "slm_gpu_capture".into(),
                    category: "slm".into(),
                    status: PrerequisiteStatus::Warning,
                    detail: "slm.capture_gpu=true but nvidia-smi is unavailable; GPU metrics will be marked unavailable".into(),
                    required: false,
                });
            }
        }
        for hint in &cfg.slm.process_name_hints {
            if hint.trim().is_empty() {
                checks.push(PrerequisiteCheck {
                    id: "slm_process_hint".into(),
                    category: "slm".into(),
                    status: PrerequisiteStatus::Warning,
                    detail: "empty process_name_hints entry".into(),
                    required: false,
                });
            }
        }
    }

    let ready_for_readonly = checks
        .iter()
        .filter(|c| c.required)
        .all(|c| c.status == PrerequisiteStatus::Ok);

    let ready_for_gpu_metrics = checks
        .iter()
        .any(|c| c.id == "nvidia-smi" && c.status == PrerequisiteStatus::Ok)
        && checks.iter().any(|c| {
            c.id == "nvidia-smi-query"
                && matches!(
                    c.status,
                    PrerequisiteStatus::Ok | PrerequisiteStatus::Warning
                )
        });

    let mut notes = vec![
        "DevGuard is read-only by default; backup/restore require explicit configuration.".into(),
        "Missing optional tools are reported as unavailable coverage, never as healthy.".into(),
        "Academic SLM runs should record TTFT/TPOT/tokens/s + VRAM/power/temp; see docs/slm-research-metrics.md."
            .into(),
    ];
    if ready_for_gpu_metrics {
        notes.push(
            "NVIDIA tooling detected: GPU utilization, VRAM, temperature, and power can be collected for SLM runs."
                .into(),
        );
    } else {
        notes.push(
            "Install NVIDIA drivers and nvidia-smi to enable SLM GPU metric capture on this host."
                .into(),
        );
    }

    DoctorReport {
        host: HostSummary {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            hostname_hash: hostname_hash(),
        },
        checks,
        ready_for_readonly,
        ready_for_gpu_metrics,
        notes,
    }
}

fn hostname_hash() -> String {
    let host = hostname_raw();
    // Privacy-preserving short fingerprint (not a security boundary).
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in host.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("hn-{:016x}", hash)
}

fn hostname_raw() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| {
            Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|_| "unknown".into())
}

fn check_path_writable(
    id: &str,
    category: &str,
    path: &std::path::Path,
    required: bool,
) -> PrerequisiteCheck {
    match std::fs::create_dir_all(path) {
        Ok(()) => {
            let probe = path.join(".devguard-write-probe");
            match std::fs::write(&probe, b"ok") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&probe);
                    PrerequisiteCheck {
                        id: id.into(),
                        category: category.into(),
                        status: PrerequisiteStatus::Ok,
                        detail: format!("writable {}", path.display()),
                        required,
                    }
                }
                Err(err) => PrerequisiteCheck {
                    id: id.into(),
                    category: category.into(),
                    status: PrerequisiteStatus::Missing,
                    detail: format!("not writable {}: {err}", path.display()),
                    required,
                },
            }
        }
        Err(err) => PrerequisiteCheck {
            id: id.into(),
            category: category.into(),
            status: PrerequisiteStatus::Missing,
            detail: format!("cannot create {}: {err}", path.display()),
            required,
        },
    }
}

fn check_binary(name: &str, category: &str, required: bool) -> PrerequisiteCheck {
    match which(name) {
        Some(path) => PrerequisiteCheck {
            id: name.into(),
            category: category.into(),
            status: PrerequisiteStatus::Ok,
            detail: path,
            required,
        },
        None => PrerequisiteCheck {
            id: name.into(),
            category: category.into(),
            status: PrerequisiteStatus::Missing,
            detail: format!("`{name}` not found on PATH"),
            required,
        },
    }
}

fn which(name: &str) -> Option<String> {
    if let Ok(output) = Command::new("which").arg(name).output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }
    None
}

fn check_nvidia_query() -> PrerequisiteCheck {
    match which("nvidia-smi") {
        None => PrerequisiteCheck {
            id: "nvidia-smi-query".into(),
            category: "slm-gpu".into(),
            status: PrerequisiteStatus::Missing,
            detail: "skipped; nvidia-smi not installed".into(),
            required: false,
        },
        Some(_) => {
            // Bounded, read-only query used later for SLM VRAM/util metrics.
            let output = Command::new("nvidia-smi")
                .args([
                    "--query-gpu=name,driver_version,memory.total",
                    "--format=csv,noheader",
                ])
                .output();
            match output {
                Ok(out) if out.status.success() => {
                    let detail = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    let detail = if detail.is_empty() {
                        "nvidia-smi query succeeded".into()
                    } else {
                        // Keep short; avoid dumping excessive device noise.
                        detail.lines().next().unwrap_or("ok").to_string()
                    };
                    PrerequisiteCheck {
                        id: "nvidia-smi-query".into(),
                        category: "slm-gpu".into(),
                        status: PrerequisiteStatus::Ok,
                        detail,
                        required: false,
                    }
                }
                Ok(out) => {
                    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    PrerequisiteCheck {
                        id: "nvidia-smi-query".into(),
                        category: "slm-gpu".into(),
                        status: PrerequisiteStatus::Warning,
                        detail: if err.is_empty() {
                            "nvidia-smi present but query failed".into()
                        } else {
                            format!("nvidia-smi query failed: {err}")
                        },
                        required: false,
                    }
                }
                Err(err) => PrerequisiteCheck {
                    id: "nvidia-smi-query".into(),
                    category: "slm-gpu".into(),
                    status: PrerequisiteStatus::Unknown,
                    detail: format!("failed to execute nvidia-smi: {err}"),
                    required: false,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn doctor_runs_offline_without_config() {
        let dir = tempdir().unwrap();
        let paths = DevGuardPaths {
            config_dir: dir.path().join("config"),
            config_file: dir.path().join("config/config.toml"),
            state_dir: dir.path().join("state"),
            database_file: dir.path().join("state/devguard.db"),
        };
        let report = run_doctor(&paths, None);
        assert!(report.ready_for_readonly);
        assert!(!report.checks.is_empty());
        assert_eq!(report.host.os, std::env::consts::OS);
        assert!(report.checks.iter().any(|c| c.id == "nvidia-smi"));
    }

    #[test]
    fn hostname_hash_is_stable_format() {
        let h = hostname_hash();
        assert!(h.starts_with("hn-"));
        assert_eq!(h.len(), 3 + 16);
    }
}
