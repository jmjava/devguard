//! Read-only systemd inventory for `devguard health units`.
//!
//! The command reports each unit's name, enabled state (`UnitFileState`),
//! active state (`ActiveState`), and whether the unit is failed. It reads one
//! `systemctl show` listing. It does not start, stop, enable, or disable
//! units, and it does not use sudo.
//!
//! If `systemctl` is missing or the listing is unreadable, the result is
//! `unavailable` and not clean. Tests parse a fixture listing and do not
//! query the host.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

const TOOL_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Read-only `systemctl show` invocation. No start, stop, enable, or disable.
const SYSTEMCTL_ARGS: &[&str] = &[
    "show",
    "--no-pager",
    "--property=Id,UnitFileState,ActiveState,SubState",
    "*",
];

/// `available` or `unavailable`. A missing tool or listing is never clean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceCoverage {
    pub status: CoverageStatus,
    pub detail: String,
}

/// One unit from a systemctl listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnitRecord {
    pub name: String,
    /// `UnitFileState` (`enabled`, `disabled`, `static`, and the rest). Empty
    /// when systemd reports no unit-file state.
    pub enabled: String,
    /// `ActiveState` (`active`, `inactive`, `failed`, and the rest).
    pub active: String,
    /// True when the active state or sub state is `failed`.
    pub failed: bool,
}

/// Human and JSON body for `devguard health units`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnitsReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never starts a unit.
    pub starts_units: bool,
    /// Always false. This command never stops a unit.
    pub stops_units: bool,
    /// Always false. This command never enables a unit.
    pub enables_units: bool,
    /// Always false. This command never disables a unit.
    pub disables_units: bool,
    /// False when `systemctl` is missing or the listing is unreadable.
    pub clean: bool,
    pub status: CoverageStatus,
    pub systemctl: SourceCoverage,
    pub units: Vec<UnitRecord>,
}

impl UnitsReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        if self.clean {
            return Vec::new();
        }
        vec![format!("systemctl unavailable: {}", self.systemctl.detail)]
    }
}

/// Read this host once. `DEVGUARD_SYSTEMCTL_LISTING` selects a fixture file
/// and skips `systemctl`. `DEVGUARD_SYSTEMCTL_BIN` selects the binary.
/// Neither path starts, stops, enables, or disables a unit.
pub fn scan_units() -> UnitsReport {
    if let Some(path) = listing_override() {
        return report_from_file(&path);
    }
    match systemctl_bin() {
        Some(path) => report_from_command(&path),
        None => unavailable("`systemctl` is not on PATH"),
    }
}

/// Parse a `systemctl show` property listing.
///
/// A missing required property, a bad unit-name escape, or a listing with no
/// units is unreadable. An unreadable listing is unavailable and not clean.
pub fn parse_systemctl_listing(text: &str) -> UnitsReport {
    match parse_units(text) {
        Some(units) => available(units),
        None => unavailable("`systemctl` listing was unreadable"),
    }
}

pub fn format_units_human(report: &UnitsReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard health units\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  starts units: no\n");
    out.push_str("  stops units: no\n");
    out.push_str("  enables units: no\n");
    out.push_str("  disables units: no\n");
    out.push_str(&format!(
        "  systemctl: {} — {}\n",
        status_word(report.systemctl.status),
        report.systemctl.detail
    ));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    out.push_str("\nUnits\n");
    if report.units.is_empty() {
        out.push_str("  unavailable\n");
        return out;
    }
    for unit in &report.units {
        let enabled = if unit.enabled.is_empty() {
            "(empty)"
        } else {
            unit.enabled.as_str()
        };
        out.push_str(&format!(
            "- {}  enabled: {enabled}  active: {}  failed: {}\n",
            unit.name,
            unit.active,
            if unit.failed { "yes" } else { "no" }
        ));
    }
    out
}

fn available(mut units: Vec<UnitRecord>) -> UnitsReport {
    units.sort_by(|left, right| {
        (&left.name, &left.enabled, &left.active).cmp(&(&right.name, &right.enabled, &right.active))
    });
    let count = units.len();
    UnitsReport {
        uses_sudo: false,
        starts_units: false,
        stops_units: false,
        enables_units: false,
        disables_units: false,
        clean: true,
        status: CoverageStatus::Available,
        systemctl: SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("parsed {count} unit(s)"),
        },
        units,
    }
}

fn unavailable(detail: impl Into<String>) -> UnitsReport {
    UnitsReport {
        uses_sudo: false,
        starts_units: false,
        stops_units: false,
        enables_units: false,
        disables_units: false,
        clean: false,
        status: CoverageStatus::Unavailable,
        systemctl: SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: detail.into(),
        },
        units: Vec::new(),
    }
}

fn report_from_file(path: &Path) -> UnitsReport {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_systemctl_listing(&text),
        Err(_) => unavailable("`systemctl` listing was unreadable"),
    }
}

fn report_from_command(program: &Path) -> UnitsReport {
    match run_show(program) {
        Ok(text) => parse_systemctl_listing(&text),
        Err(_) => unavailable("`systemctl` listing was unreadable"),
    }
}

fn listing_override() -> Option<PathBuf> {
    let value = std::env::var_os("DEVGUARD_SYSTEMCTL_LISTING")?;
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

fn systemctl_bin() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("DEVGUARD_SYSTEMCTL_BIN") {
        if value.is_empty() {
            return None;
        }
        let path = PathBuf::from(value);
        return path.is_file().then_some(path);
    }
    find_tool("systemctl")
}

fn find_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn parse_units(text: &str) -> Option<Vec<UnitRecord>> {
    let mut units = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut in_block = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            if in_block {
                units.push(finish_unit(&fields)?);
                fields.clear();
                in_block = false;
            }
            continue;
        }
        let (key, value) = line.split_once('=')?;
        if !is_property_key(key) {
            return None;
        }
        in_block = true;
        fields.insert(key.to_string(), value.to_string());
    }
    if in_block {
        units.push(finish_unit(&fields)?);
    }
    if units.is_empty() {
        return None;
    }
    Some(units)
}

fn finish_unit(fields: &BTreeMap<String, String>) -> Option<UnitRecord> {
    let name = unescape_unit_name(fields.get("Id")?)?;
    let enabled = fields.get("UnitFileState")?.clone();
    let active = fields.get("ActiveState")?.clone();
    let sub = fields.get("SubState")?.clone();
    if active.is_empty() || sub.is_empty() {
        return None;
    }
    let failed = active == "failed" || sub == "failed";
    Some(UnitRecord {
        name,
        enabled,
        active,
        failed,
    })
}

fn is_property_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric())
}

fn unescape_unit_name(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('x') => {
                let hi = chars.next()?;
                let lo = chars.next()?;
                let hex = format!("{hi}{lo}");
                let byte = u8::from_str_radix(&hex, 16).ok()?;
                if !byte.is_ascii() || byte == 0 {
                    return None;
                }
                out.push(byte as char);
            }
            _ => return None,
        }
    }
    if out.is_empty() || out.chars().any(|ch| ch.is_control()) {
        return None;
    }
    Some(out)
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn run_show(program: &Path) -> std::io::Result<String> {
    let mut child = Command::new(program)
        .args(SYSTEMCTL_ARGS)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let truncated = Arc::new(AtomicBool::new(false));
    let stdout_flag = Arc::clone(&truncated);
    let stderr_flag = Arc::clone(&truncated);
    let stdout_handle =
        thread::spawn(move || read_bounded(stdout, MAX_CAPTURE_BYTES, &stdout_flag));
    let stderr_handle =
        thread::spawn(move || read_bounded(stderr, MAX_CAPTURE_BYTES, &stderr_flag));
    let started = Instant::now();
    loop {
        if truncated.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "systemctl listing truncated",
            ));
        }
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_handle.join().unwrap_or_default();
            let _ = stderr_handle.join();
            if truncated.load(Ordering::Relaxed) || !status.success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "systemctl listing unreadable",
                ));
            }
            let text = std::str::from_utf8(&stdout)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
            return Ok(text.to_string());
        }
        if started.elapsed() > TOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "systemctl timed out",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_bounded(pipe: Option<impl Read>, limit: usize, truncated: &AtomicBool) -> Vec<u8> {
    let Some(mut pipe) = pipe else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if out.len() >= limit {
            let mut extra = [0u8; 1];
            match pipe.read(&mut extra) {
                Ok(0) => {}
                Ok(_) => truncated.store(true, Ordering::Relaxed),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {}
            }
            break;
        }
        let room = limit - out.len();
        let want = room.min(buf.len());
        match pipe.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../fixtures/systemctl-show.txt");

    #[test]
    fn systemctl_args_do_not_change_units() {
        assert_eq!(
            SYSTEMCTL_ARGS,
            [
                "show",
                "--no-pager",
                "--property=Id,UnitFileState,ActiveState,SubState",
                "*",
            ]
        );
        for arg in SYSTEMCTL_ARGS {
            let verb = arg.split('=').next().unwrap_or(arg);
            assert!(verb != "start");
            assert!(verb != "stop");
            assert!(verb != "enable");
            assert!(verb != "disable");
            assert!(verb != "sudo");
        }
    }

    #[test]
    fn fixture_listing_reports_name_enabled_active_and_failed() {
        let report = parse_systemctl_listing(FIXTURE);
        assert!(report.clean);
        assert_eq!(report.status, CoverageStatus::Available);
        assert!(!report.uses_sudo);
        assert!(!report.starts_units);
        assert!(!report.stops_units);
        assert!(!report.enables_units);
        assert!(!report.disables_units);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert_eq!(report.units.len(), 6);

        let apport = find(&report, "apport.service");
        assert_eq!(apport.enabled, "enabled");
        assert_eq!(apport.active, "failed");
        assert!(apport.failed);

        let cron = find(&report, "cron.service");
        assert_eq!(cron.enabled, "enabled");
        assert_eq!(cron.active, "active");
        assert!(!cron.failed);

        let fixture = find(&report, "devguard-fixture.service");
        assert_eq!(fixture.enabled, "static");
        assert_eq!(fixture.active, "inactive");
        assert!(!fixture.failed);

        let snap = find(&report, "snap-obs-studio-1322.mount");
        assert_eq!(snap.enabled, "enabled");
        assert_eq!(snap.active, "active");
        assert!(!snap.failed);

        let ssh = find(&report, "ssh.service");
        assert_eq!(ssh.enabled, "disabled");
        assert_eq!(ssh.active, "inactive");
        assert!(!ssh.failed);

        let device = find(&report, "sys-devices-virtual-block-loop30.device");
        assert_eq!(device.enabled, "");
        assert_eq!(device.active, "active");
        assert!(!device.failed);

        let names: Vec<&str> = report.units.iter().map(|unit| unit.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);

        let human = format_units_human(&report);
        assert!(human.contains("DevGuard health units"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("starts units: no"));
        assert!(human.contains("stops units: no"));
        assert!(human.contains("enables units: no"));
        assert!(human.contains("disables units: no"));
        assert!(human.contains("clean: yes"));
        assert!(human.contains("apport.service  enabled: enabled  active: failed  failed: yes"));
        assert!(human.contains("enabled: (empty)"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn empty_or_tabular_listing_is_unavailable() {
        for text in [
            "",
            "\n",
            "UNIT LOAD ACTIVE SUB DESCRIPTION\nfoo.service loaded active running Foo\n",
        ] {
            let report = parse_systemctl_listing(text);
            assert!(!report.clean, "{text:?}");
            assert_eq!(report.status, CoverageStatus::Unavailable);
            assert!(report.units.is_empty());
            assert_eq!(report.exit_code(), ExitCode::Partial);
            assert!(report.warnings()[0].contains("unavailable"));
            let human = format_units_human(&report);
            assert!(human.contains("clean: no"));
            assert!(human.contains("unavailable"));
        }
    }

    #[test]
    fn missing_property_or_bad_escape_is_unreadable() {
        let missing = "\
Id=foo.service
ActiveState=active
SubState=running
";
        let bad_escape = "\
Id=foo\\xzz.service
ActiveState=active
SubState=running
UnitFileState=enabled
";
        for text in [missing, bad_escape] {
            let report = parse_systemctl_listing(text);
            assert!(!report.clean);
            assert!(report.units.is_empty());
        }
    }

    fn find<'a>(report: &'a UnitsReport, name: &str) -> &'a UnitRecord {
        report
            .units
            .iter()
            .find(|unit| unit.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    }
}
