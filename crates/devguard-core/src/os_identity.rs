//! OS identity record for `devguard health os`.
//!
//! The command reports kernel release, boot id, and uptime from a `/proc`
//! tree. The hostname is stored only as a privacy-preserving hash. A missing
//! `/proc` source is `unavailable`, and that result is not clean.
//!
//! It does not use sudo, open a port, or collect package lists.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

/// `available` or `unavailable`. A missing source is never a clean result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Available,
    Unavailable,
}

/// One sampled field. Missing readings stay `unavailable` and keep no value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Reading<T> {
    pub status: SourceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
}

impl<T> Reading<T> {
    fn from_value(value: Option<T>) -> Self {
        match value {
            Some(value) => Self {
                status: SourceStatus::Available,
                value: Some(value),
            },
            None => Self {
                status: SourceStatus::Unavailable,
                value: None,
            },
        }
    }

    fn is_available(&self) -> bool {
        self.status == SourceStatus::Available && self.value.is_some()
    }
}

/// Human and JSON body for `devguard health os`.
///
/// The raw hostname is never a field on this record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsIdentityReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never opens a port.
    pub opens_port: bool,
    /// Always false. This command never collects a package list.
    pub collects_packages: bool,
    /// False when kernel release, boot id, uptime, or the hostname hash is missing.
    pub clean: bool,
    pub kernel_release: Reading<String>,
    pub boot_id: Reading<String>,
    pub uptime_seconds: Reading<f64>,
    pub hostname_hash: Reading<String>,
}

impl OsIdentityReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        push_missing(
            &mut warnings,
            "kernel release",
            self.kernel_release.is_available(),
        );
        push_missing(&mut warnings, "boot id", self.boot_id.is_available());
        push_missing(&mut warnings, "uptime", self.uptime_seconds.is_available());
        push_missing(
            &mut warnings,
            "hostname hash",
            self.hostname_hash.is_available(),
        );
        warnings
    }
}

/// Read this host once. `DEVGUARD_PROC_ROOT` selects a fixture `/proc` tree.
///
/// This function never invokes sudo, binds a socket, or reads a package database.
pub fn scan_os() -> OsIdentityReport {
    read_os_identity(&proc_root())
}

/// Read kernel release, boot id, uptime, and a hostname hash under `root`.
///
/// Expected files, relative to a `/proc` root:
/// `sys/kernel/osrelease`, `sys/kernel/random/boot_id`, `uptime`, and
/// `sys/kernel/hostname`. The hostname file is hashed and discarded.
pub fn read_os_identity(root: &Path) -> OsIdentityReport {
    let kernel_release = Reading::from_value(read_line(&root.join("sys/kernel/osrelease")));
    let boot_id = Reading::from_value(read_line(&root.join("sys/kernel/random/boot_id")));
    let uptime_seconds = Reading::from_value(read_uptime(&root.join("uptime")));
    let hostname_hash = Reading::from_value(
        read_line(&root.join("sys/kernel/hostname")).map(|host| privacy_hash(&host)),
    );
    let clean = kernel_release.is_available()
        && boot_id.is_available()
        && uptime_seconds.is_available()
        && hostname_hash.is_available();
    OsIdentityReport {
        uses_sudo: false,
        opens_port: false,
        collects_packages: false,
        clean,
        kernel_release,
        boot_id,
        uptime_seconds,
        hostname_hash,
    }
}

/// Human report. Does not describe a missing reading as healthy, and does not
/// print the raw hostname.
pub fn format_os_human(report: &OsIdentityReport) -> String {
    format!(
        "\
DevGuard health os
  kernel: {kernel}
  boot id: {boot_id}
  uptime: {uptime}
  hostname hash: {hostname_hash}
  uses sudo: no
  opens a port: no
  collects packages: no
  clean: {clean}
",
        kernel = text(&report.kernel_release),
        boot_id = text(&report.boot_id),
        uptime = uptime_text(&report.uptime_seconds),
        hostname_hash = text(&report.hostname_hash),
        clean = if report.clean { "yes" } else { "no" },
    )
}

/// FNV-1a 64-bit fingerprint, prefixed `hn-`. This is a privacy-preserving
/// label, not a security boundary. The raw hostname is not returned.
pub fn privacy_hash(host: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in host.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("hn-{hash:016x}")
}

fn push_missing(warnings: &mut Vec<String>, name: &str, available: bool) {
    if !available {
        warnings.push(format!("{name} is unavailable"));
    }
}

fn text(reading: &Reading<String>) -> String {
    match (&reading.status, reading.value.as_deref()) {
        (SourceStatus::Available, Some(value)) => value.to_string(),
        _ => "unavailable".to_string(),
    }
}

fn uptime_text(reading: &Reading<f64>) -> String {
    match (&reading.status, reading.value) {
        (SourceStatus::Available, Some(seconds)) => format!("{seconds:.2} seconds"),
        _ => "unavailable".to_string(),
    }
}

fn proc_root() -> PathBuf {
    match std::env::var("DEVGUARD_PROC_ROOT") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from("/proc"),
    }
}

fn read_line(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}

fn read_uptime(path: &Path) -> Option<f64> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_uptime(&text)
}

fn parse_uptime(text: &str) -> Option<f64> {
    let raw = text.split_whitespace().next()?.parse::<f64>().ok()?;
    if !raw.is_finite() || raw < 0.0 {
        return None;
    }
    Some((raw * 100.0).round() / 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTNAME: &str = "secret-workstation-name";
    const KERNEL: &str = "7.0.0-38-generic";
    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const EXPECTED_HASH: &str = "hn-9e2595de8ac1de6d";

    fn write_fixture(root: &Path) {
        let random = root.join("sys/kernel/random");
        std::fs::create_dir_all(&random).expect("proc dirs");
        std::fs::write(root.join("sys/kernel/osrelease"), format!("{KERNEL}\n"))
            .expect("osrelease");
        std::fs::write(root.join("sys/kernel/hostname"), format!("{HOSTNAME}\n"))
            .expect("hostname");
        std::fs::write(
            root.join("sys/kernel/random/boot_id"),
            format!("{BOOT_ID}\n"),
        )
        .expect("boot_id");
        std::fs::write(root.join("uptime"), "12345.67 890.12\n").expect("uptime");
    }

    fn full_report(root: &Path) -> OsIdentityReport {
        read_os_identity(root)
    }

    #[test]
    fn fixture_reports_kernel_boot_id_uptime_and_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_fixture(dir.path());
        let report = full_report(dir.path());
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert!(!report.uses_sudo);
        assert!(!report.opens_port);
        assert!(!report.collects_packages);
        assert_eq!(report.kernel_release.value.as_deref(), Some(KERNEL));
        assert_eq!(report.boot_id.value.as_deref(), Some(BOOT_ID));
        assert_eq!(report.uptime_seconds.value, Some(12345.67));
        assert_eq!(report.hostname_hash.value.as_deref(), Some(EXPECTED_HASH));
        assert_eq!(privacy_hash(HOSTNAME), EXPECTED_HASH);
    }

    #[test]
    fn hostname_is_hashed_and_absent_from_human_and_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_fixture(dir.path());
        let report = full_report(dir.path());
        let human = format_os_human(&report);
        let json = serde_json::to_string(&report).expect("json");
        assert!(human.contains(EXPECTED_HASH));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("opens a port: no"));
        assert!(human.contains("collects packages: no"));
        assert!(human.contains("clean: yes"));
        assert!(!human.contains(HOSTNAME));
        assert!(!json.contains(HOSTNAME));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
        assert!(!json.to_ascii_lowercase().contains("healthy"));
        let value: serde_json::Value = serde_json::from_str(&json).expect("value");
        assert!(value.get("hostname").is_none());
        assert_eq!(value["hostname_hash"]["value"], EXPECTED_HASH);
        assert_eq!(value["uses_sudo"], false);
        assert_eq!(value["opens_port"], false);
        assert_eq!(value["collects_packages"], false);
    }

    #[test]
    fn missing_proc_source_is_unavailable_and_not_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_fixture(dir.path());
        std::fs::remove_file(dir.path().join("sys/kernel/random/boot_id")).expect("remove");
        let report = read_os_identity(dir.path());
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.boot_id.status, SourceStatus::Unavailable);
        assert!(report.boot_id.value.is_none());
        assert_eq!(report.kernel_release.value.as_deref(), Some(KERNEL));
        assert_eq!(report.uptime_seconds.value, Some(12345.67));
        assert_eq!(report.hostname_hash.value.as_deref(), Some(EXPECTED_HASH));
        let human = format_os_human(&report);
        assert!(human.contains("boot id: unavailable"));
        assert!(human.contains("clean: no"));
        assert!(!human.contains(HOSTNAME));
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("boot id")));
    }

    #[test]
    fn empty_proc_dir_marks_every_source_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = read_os_identity(dir.path());
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.kernel_release.status, SourceStatus::Unavailable);
        assert_eq!(report.boot_id.status, SourceStatus::Unavailable);
        assert_eq!(report.uptime_seconds.status, SourceStatus::Unavailable);
        assert_eq!(report.hostname_hash.status, SourceStatus::Unavailable);
        assert_eq!(report.warnings().len(), 4);
        let human = format_os_human(&report);
        assert!(human.contains("kernel: unavailable"));
        assert!(human.contains("hostname hash: unavailable"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn blank_hostname_is_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_fixture(dir.path());
        std::fs::write(dir.path().join("sys/kernel/hostname"), " \n").expect("blank");
        let report = read_os_identity(dir.path());
        assert_eq!(report.hostname_hash.status, SourceStatus::Unavailable);
        assert!(!report.clean);
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains(HOSTNAME));
    }

    #[test]
    fn malformed_uptime_is_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_fixture(dir.path());
        std::fs::write(dir.path().join("uptime"), "not-a-number 1.0\n").expect("uptime");
        let report = read_os_identity(dir.path());
        assert_eq!(report.uptime_seconds.status, SourceStatus::Unavailable);
        assert_eq!(report.kernel_release.value.as_deref(), Some(KERNEL));
        assert!(!report.clean);
    }

    #[test]
    fn zero_uptime_is_a_real_reading() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_fixture(dir.path());
        std::fs::write(dir.path().join("uptime"), "0.0 0.0\n").expect("uptime");
        let report = read_os_identity(dir.path());
        assert_eq!(report.uptime_seconds.status, SourceStatus::Available);
        assert_eq!(report.uptime_seconds.value, Some(0.0));
        assert!(report.clean);
    }

    #[test]
    fn different_hostnames_hash_differently() {
        assert_ne!(privacy_hash(HOSTNAME), privacy_hash("other-host"));
        assert!(privacy_hash(HOSTNAME).starts_with("hn-"));
        assert_eq!(privacy_hash(HOSTNAME).len(), 19);
    }
}
