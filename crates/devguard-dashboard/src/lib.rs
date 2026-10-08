//! Text snapshot of doctor and status data from `devguard-core`.
//!
//! The window and `devguard-dashboard --smoke` both render this snapshot.
//! Building it does not open a display, start a daemon, or open a remote shell.

use devguard_core::config::{Config, ConfigPaths};
use devguard_core::doctor::{DoctorReport, PrerequisiteStatus};
use devguard_core::{DevGuardError, DevGuardPaths};

/// Doctor report plus the status facts the library can answer today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardSnapshot {
    pub doctor: DoctorReport,
    /// `paths.config_file.exists()` after the doctor check.
    pub config_present: bool,
    /// Path when a config file exists, otherwise the same hint `devguard status` prints.
    pub config_display: String,
}

/// Load config if it parses, run doctor, and record whether the config file exists.
pub fn build_snapshot(paths: &DevGuardPaths) -> DashboardSnapshot {
    let loaded = Config::load(&paths.config_file).ok();
    let doctor = devguard_core::doctor::run_doctor(paths, loaded.as_ref());
    let config_present = paths.config_file.exists();
    let config_display = if config_present {
        paths.config_file.display().to_string()
    } else {
        "not initialized (run `devguard config init`)".to_string()
    };
    DashboardSnapshot {
        doctor,
        config_present,
        config_display,
    }
}

/// Snapshot for the default XDG paths. Does not open a display.
pub fn live_snapshot() -> Result<String, DevGuardError> {
    let paths = ConfigPaths::from_override(None)?;
    Ok(render_snapshot(&build_snapshot(&paths.paths)))
}

/// Plain-text view used by `--smoke` and the window.
pub fn render_snapshot(snapshot: &DashboardSnapshot) -> String {
    let report = &snapshot.doctor;
    let mut out = String::new();
    out.push_str("DevGuard dashboard\n");
    out.push_str("  read-only: yes\n");
    out.push('\n');
    out.push_str("DevGuard doctor\n");
    out.push_str(&format!(
        "  host: {}/{} ({})\n",
        report.host.os, report.host.arch, report.host.hostname_hash
    ));
    out.push_str(&format!("  config: {}\n", snapshot.config_display));
    out.push_str(&format!(
        "  ready (read-only): {}\n",
        yes_no(report.ready_for_readonly)
    ));
    out.push_str(&format!(
        "  ready (SLM GPU metrics): {}\n",
        yes_no(report.ready_for_gpu_metrics)
    ));
    out.push('\n');
    out.push_str("Checks:\n");
    for check in &report.checks {
        let mark = match check.status {
            PrerequisiteStatus::Ok => "ok",
            PrerequisiteStatus::Missing => "missing",
            PrerequisiteStatus::Warning => "warn",
            PrerequisiteStatus::Unknown => "unknown",
        };
        out.push_str(&format!(
            "  [{mark:7}] {id:18} ({category}) {detail}\n",
            id = check.id,
            category = check.category,
            detail = check.detail
        ));
    }
    if !report.notes.is_empty() {
        out.push('\n');
        out.push_str("Notes:\n");
        for note in &report.notes {
            out.push_str(&format!("  - {note}\n"));
        }
    }
    out.push('\n');
    out.push_str("DevGuard status\n");
    out.push_str(&format!("  config: {}\n", snapshot.config_display));
    out.push_str("  recorded scans: 0\n");
    out
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use devguard_core::doctor::{HostSummary, PrerequisiteCheck};

    fn empty_paths(dir: &std::path::Path) -> DevGuardPaths {
        DevGuardPaths {
            config_dir: dir.join("config"),
            config_file: dir.join("config/config.toml"),
            state_dir: dir.join("state"),
            database_file: dir.join("state/devguard.db"),
        }
    }

    #[test]
    fn snapshot_builder_reports_doctor_and_status() {
        let dir = tempfile::tempdir().unwrap();
        let paths = empty_paths(dir.path());
        let snapshot = build_snapshot(&paths);
        let text = render_snapshot(&snapshot);

        assert!(snapshot.doctor.ready_for_readonly);
        assert!(!snapshot.config_present);
        assert!(text.contains("DevGuard dashboard"));
        assert!(text.contains("  read-only: yes\n"));
        assert!(text.contains("DevGuard doctor"));
        assert!(text.contains("DevGuard status"));
        assert!(text.contains("  ready (read-only): yes\n"));
        assert!(text.contains("  recorded scans: 0\n"));
        assert!(text.contains("xdg_config_dir"));
        assert!(text.contains("not initialized (run `devguard config init`)"));
        assert!(snapshot
            .doctor
            .checks
            .iter()
            .any(|check| check.id == "nvidia-smi"));
    }

    #[test]
    fn render_snapshot_lists_a_present_config_path() {
        let snapshot = DashboardSnapshot {
            doctor: DoctorReport {
                host: HostSummary {
                    os: "linux".into(),
                    arch: "x86_64".into(),
                    hostname_hash: "hn-0123456789abcdef".into(),
                },
                checks: vec![PrerequisiteCheck {
                    id: "config".into(),
                    category: "config".into(),
                    status: PrerequisiteStatus::Ok,
                    detail: "loaded /tmp/devguard/config.toml".into(),
                    required: false,
                }],
                ready_for_readonly: true,
                ready_for_gpu_metrics: false,
                notes: vec!["DevGuard is read-only by default.".into()],
            },
            config_present: true,
            config_display: "/tmp/devguard/config.toml".into(),
        };

        let text = render_snapshot(&snapshot);
        assert!(text.contains("  host: linux/x86_64 (hn-0123456789abcdef)\n"));
        assert!(text.contains("  [ok     ] config"));
        assert!(text.contains("  config: /tmp/devguard/config.toml\n"));
        assert!(text.contains("  ready (SLM GPU metrics): no\n"));
        assert!(text.contains("  - DevGuard is read-only by default.\n"));
        assert!(text.contains("  recorded scans: 0\n"));
    }
}
