//! Backup-audit dotfiles checker for `devguard audit dotfiles`.
//!
//! Checks for common config files that should be backed up. Reports
//! existence and last-modified date only. Never reads or outputs file
//! contents (security). Does not use sudo.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

const CHECKED_DOTFILES: &[&str] = &["~/.bashrc", "~/.zshrc", "~/.gitconfig", "~/.ssh/config"];

const CHECKED_CONFIG_DIRS: &[&str] = &[
    "~/.config/nvim",
    "~/.config/Code",
    "~/.config/cursor",
    "~/.config/fish",
    "~/.config/systemd",
    "~/.config/htop",
    "~/.config/tmux",
    "~/.config/devguard",
];

const RECENTLY_MODIFIED_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DotfileStatus {
    Present,
    Missing,
}

/// One checked dotfile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DotfileEntry {
    pub path: String,
    pub status: DotfileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// One checked `~/.config/` subdirectory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigDirEntry {
    pub path: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    pub recently_modified: bool,
}

/// Report for `devguard audit dotfiles`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditDotfilesReport {
    pub uses_sudo: bool,
    pub reads_content: bool,
    pub checked_count: usize,
    pub present_count: usize,
    pub missing_count: usize,
    pub coverage_percent: u32,
    pub dotfiles: Vec<DotfileEntry>,
    pub config_dirs: Vec<ConfigDirEntry>,
}

impl AuditDotfilesReport {
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::Success
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for df in &self.dotfiles {
            if df.status == DotfileStatus::Missing {
                warnings.push(format!("dotfile not found: {}", df.path));
            }
        }
        warnings
    }
}

/// Scan for dotfiles and config dirs. Uses provided home_dir override for testability.
pub fn scan_audit_dotfiles_with_home(home_dir: &Path) -> AuditDotfilesReport {
    let now = Utc::now();

    let dotfiles: Vec<DotfileEntry> = CHECKED_DOTFILES
        .iter()
        .map(|raw| {
            let expanded = expand_home(raw, home_dir);
            check_dotfile(&expanded, raw)
        })
        .collect();

    let config_dirs: Vec<ConfigDirEntry> = CHECKED_CONFIG_DIRS
        .iter()
        .map(|raw| {
            let expanded = expand_home(raw, home_dir);
            check_config_dir(&expanded, raw, now)
        })
        .collect();

    let present_count = dotfiles
        .iter()
        .filter(|d| d.status == DotfileStatus::Present)
        .count();
    let checked_count = dotfiles.len();
    let missing_count = checked_count - present_count;
    let coverage_percent = if checked_count > 0 {
        ((present_count as f64 / checked_count as f64) * 100.0).round() as u32
    } else {
        0
    };

    AuditDotfilesReport {
        uses_sudo: false,
        reads_content: false,
        checked_count,
        present_count,
        missing_count,
        coverage_percent,
        dotfiles,
        config_dirs,
    }
}

/// Scan using the real home directory.
pub fn scan_audit_dotfiles() -> AuditDotfilesReport {
    let home = directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"));
    scan_audit_dotfiles_with_home(&home)
}

pub fn format_audit_dotfiles_human(report: &AuditDotfilesReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard audit dotfiles\n");
    out.push_str(&format!(
        "  coverage: {}% ({}/{} present)\n",
        report.coverage_percent, report.present_count, report.checked_count
    ));
    out.push_str("  reads content: no\n  uses sudo: no\n\n");
    out.push_str("Dotfiles:\n");
    for df in &report.dotfiles {
        let mark = match df.status {
            DotfileStatus::Present => "✓",
            DotfileStatus::Missing => "✗",
        };
        let mtime = df.last_modified.as_deref().unwrap_or("(n/a)");
        out.push_str(&format!(
            "  {mark} {path}  last modified: {mtime}\n",
            path = df.path
        ));
    }

    if report.config_dirs.iter().any(|d| d.exists) {
        out.push_str("\nConfig directories:\n");
        for cd in &report.config_dirs {
            if cd.exists {
                let recent = if cd.recently_modified {
                    " [recently modified]"
                } else {
                    ""
                };
                let mtime = cd.last_modified.as_deref().unwrap_or("(n/a)");
                out.push_str(&format!(
                    "  ✓ {path}  last modified: {mtime}{recent}\n",
                    path = cd.path
                ));
            }
        }
    }

    out
}

fn expand_home(raw: &str, home: &Path) -> PathBuf {
    if let Some(stripped) = raw.strip_prefix("~/") {
        home.join(stripped)
    } else if raw == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(raw)
    }
}

fn check_dotfile(path: &Path, display: &str) -> DotfileEntry {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let mtime = meta.modified().ok().and_then(system_time_to_rfc3339);
            DotfileEntry {
                path: display.to_string(),
                status: DotfileStatus::Present,
                last_modified: mtime,
            }
        }
        Err(_) => DotfileEntry {
            path: display.to_string(),
            status: DotfileStatus::Missing,
            last_modified: None,
        },
    }
}

fn check_config_dir(path: &Path, display: &str, now: DateTime<Utc>) -> ConfigDirEntry {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            let mtime = meta.modified().ok();
            let mtime_rfc = mtime.and_then(system_time_to_rfc3339);
            let recently_modified = mtime
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| {
                    let mtime_utc = DateTime::<Utc>::from(SystemTime::UNIX_EPOCH + d);
                    let age = now.signed_duration_since(mtime_utc);
                    age.num_days() <= RECENTLY_MODIFIED_DAYS
                })
                .unwrap_or(false);
            ConfigDirEntry {
                path: display.to_string(),
                exists: true,
                last_modified: mtime_rfc,
                recently_modified,
            }
        }
        _ => ConfigDirEntry {
            path: display.to_string(),
            exists: false,
            last_modified: None,
            recently_modified: false,
        },
    }
}

fn system_time_to_rfc3339(t: SystemTime) -> Option<String> {
    let duration = t.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    let dt = DateTime::<Utc>::from(SystemTime::UNIX_EPOCH + duration);
    Some(dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_home_with_bashrc() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".bashrc"), "# mock\n").unwrap();
        let report = scan_audit_dotfiles_with_home(home.path());
        assert!(!report.reads_content);
        assert!(!report.uses_sudo);
        let bashrc = report
            .dotfiles
            .iter()
            .find(|d| d.path == "~/.bashrc")
            .expect("bashrc entry");
        assert_eq!(bashrc.status, DotfileStatus::Present);
        assert!(bashrc.last_modified.is_some());
    }

    #[test]
    fn missing_dotfile_reported() {
        let home = tempfile::tempdir().unwrap();
        let report = scan_audit_dotfiles_with_home(home.path());
        let bashrc = report
            .dotfiles
            .iter()
            .find(|d| d.path == "~/.bashrc")
            .expect("bashrc entry");
        assert_eq!(bashrc.status, DotfileStatus::Missing);
        assert!(bashrc.last_modified.is_none());
    }

    #[test]
    fn coverage_percent_calculated() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".bashrc"), "").unwrap();
        std::fs::write(home.path().join(".gitconfig"), "").unwrap();
        let report = scan_audit_dotfiles_with_home(home.path());
        assert_eq!(report.present_count, 2);
        assert_eq!(report.checked_count, 4);
        assert_eq!(report.coverage_percent, 50);
    }

    #[test]
    fn config_dir_detected() {
        let home = tempfile::tempdir().unwrap();
        let config = home.path().join(".config").join("devguard");
        std::fs::create_dir_all(&config).unwrap();
        let report = scan_audit_dotfiles_with_home(home.path());
        let devguard_dir = report
            .config_dirs
            .iter()
            .find(|d| d.path.contains("devguard"))
            .expect("devguard config dir");
        assert!(devguard_dir.exists);
        assert!(devguard_dir.recently_modified);
    }

    #[test]
    fn missing_config_dir_reported() {
        let home = tempfile::tempdir().unwrap();
        let report = scan_audit_dotfiles_with_home(home.path());
        let nvim = report
            .config_dirs
            .iter()
            .find(|d| d.path.contains("nvim"))
            .expect("nvim config dir");
        assert!(!nvim.exists);
    }

    #[test]
    fn json_envelope_format() {
        let home = tempfile::tempdir().unwrap();
        let report = scan_audit_dotfiles_with_home(home.path());
        let envelope = crate::json::JsonEnvelope::success("audit dotfiles", &report);
        let value = serde_json::to_value(&envelope).expect("serialize");
        assert_eq!(value["ok"], true);
        assert_eq!(value["command"], "audit dotfiles");
        assert!(value["data"]["dotfiles"].is_array());
        assert!(value["data"]["coverage_percent"].is_number());
    }

    #[test]
    fn human_format_contains_key_info() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".bashrc"), "").unwrap();
        let report = scan_audit_dotfiles_with_home(home.path());
        let human = format_audit_dotfiles_human(&report);
        assert!(human.contains("coverage:"));
        assert!(human.contains("reads content: no"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("~/.bashrc"));
    }

    #[test]
    fn ssh_config_with_dir() {
        let home = tempfile::tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("config"), "Host *\n").unwrap();
        let report = scan_audit_dotfiles_with_home(home.path());
        let ssh = report
            .dotfiles
            .iter()
            .find(|d| d.path == "~/.ssh/config")
            .expect("ssh config");
        assert_eq!(ssh.status, DotfileStatus::Present);
    }
}
