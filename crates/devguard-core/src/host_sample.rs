//! Host companion sample for `devguard slm host`.
//!
//! Production reads `/proc/stat` twice, `/proc/meminfo`, and the free bytes on
//! `/`. A missing file, field, or disk query is `unavailable`. That result is
//! not clean.

use std::path::Path;
use std::thread;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

const CPU_SAMPLE: Duration = Duration::from_millis(200);

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

/// Human and JSON body for `devguard slm host`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostSampleReport {
    /// RFC3339 UTC timestamp of this sample.
    pub observed_at: DateTime<Utc>,
    /// False when CPU, RAM, swap, or disk free could not be read.
    pub clean: bool,
    pub cpu_percent: Reading<f64>,
    pub memory_used_bytes: Reading<u64>,
    pub memory_total_bytes: Reading<u64>,
    pub swap_used_bytes: Reading<u64>,
    pub disk_free_bytes: Reading<u64>,
}

impl HostSampleReport {
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
            "CPU percent",
            self.cpu_percent.is_available(),
        );
        push_missing(
            &mut warnings,
            "memory used",
            self.memory_used_bytes.is_available(),
        );
        push_missing(
            &mut warnings,
            "memory total",
            self.memory_total_bytes.is_available(),
        );
        push_missing(
            &mut warnings,
            "swap used",
            self.swap_used_bytes.is_available(),
        );
        push_missing(
            &mut warnings,
            "disk free",
            self.disk_free_bytes.is_available(),
        );
        warnings
    }
}

/// Read the live host. CPU uses two `/proc/stat` samples about 200ms apart.
pub fn sample_host() -> HostSampleReport {
    let stat_before = read_to_string(Path::new("/proc/stat"));
    let stat_after = if stat_before.is_some() {
        thread::sleep(CPU_SAMPLE);
        read_to_string(Path::new("/proc/stat"))
    } else {
        None
    };
    let meminfo = read_to_string(Path::new("/proc/meminfo"));
    sample_from_text(
        Utc::now(),
        stat_before.as_deref(),
        stat_after.as_deref(),
        meminfo.as_deref(),
        disk_free_bytes(Path::new("/")),
    )
}

/// Build a sample from injected `/proc` text and an optional disk-free byte count.
pub fn sample_from_text(
    observed_at: DateTime<Utc>,
    stat_before: Option<&str>,
    stat_after: Option<&str>,
    meminfo: Option<&str>,
    disk_free_bytes: Option<u64>,
) -> HostSampleReport {
    let cpu_percent = Reading::from_value(cpu_percent(stat_before, stat_after));
    let (memory_used_bytes, memory_total_bytes, swap_used_bytes) = match meminfo {
        Some(text) => memory_fields(text),
        None => (
            Reading::from_value(None),
            Reading::from_value(None),
            Reading::from_value(None),
        ),
    };
    let disk_free_bytes = Reading::from_value(disk_free_bytes);
    let clean = cpu_percent.is_available()
        && memory_used_bytes.is_available()
        && memory_total_bytes.is_available()
        && swap_used_bytes.is_available()
        && disk_free_bytes.is_available();
    HostSampleReport {
        observed_at,
        clean,
        cpu_percent,
        memory_used_bytes,
        memory_total_bytes,
        swap_used_bytes,
        disk_free_bytes,
    }
}

/// Read a temporary proc layout: `stat`, `stat2`, `meminfo`, and `disk_free`.
///
/// `disk_free` is a decimal byte count. A missing file leaves that field unavailable.
pub fn sample_proc_dir(proc_root: &Path, observed_at: DateTime<Utc>) -> HostSampleReport {
    let stat_before = read_to_string(&proc_root.join("stat"));
    let stat_after = read_to_string(&proc_root.join("stat2"));
    let meminfo = read_to_string(&proc_root.join("meminfo"));
    let disk = read_disk_file(&proc_root.join("disk_free"));
    sample_from_text(
        observed_at,
        stat_before.as_deref(),
        stat_after.as_deref(),
        meminfo.as_deref(),
        disk,
    )
}

pub fn format_host_human(report: &HostSampleReport) -> String {
    let stamp = report
        .observed_at
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    format!(
        "\
DevGuard SLM host
  observed_at: {stamp}
  cpu: {cpu}
  memory used: {memory_used}
  memory total: {memory_total}
  swap used: {swap_used}
  disk free: {disk_free}
  clean: {clean}
",
        cpu = percent_text(&report.cpu_percent),
        memory_used = bytes_text(&report.memory_used_bytes),
        memory_total = bytes_text(&report.memory_total_bytes),
        swap_used = bytes_text(&report.swap_used_bytes),
        disk_free = bytes_text(&report.disk_free_bytes),
        clean = if report.clean { "yes" } else { "no" },
    )
}

fn push_missing(warnings: &mut Vec<String>, name: &str, available: bool) {
    if !available {
        warnings.push(format!("{name} is unavailable"));
    }
}

fn percent_text(reading: &Reading<f64>) -> String {
    match (&reading.status, reading.value) {
        (SourceStatus::Available, Some(value)) => format!("{value}%"),
        _ => "unavailable".to_string(),
    }
}

fn bytes_text(reading: &Reading<u64>) -> String {
    match (&reading.status, reading.value) {
        (SourceStatus::Available, Some(bytes)) => format!("{bytes} bytes"),
        _ => "unavailable".to_string(),
    }
}

fn read_to_string(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn read_disk_file(path: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    text.split_whitespace().next()?.parse().ok()
}

/// Bytes available to an unprivileged caller (`f_bavail * f_frsize`).
fn disk_free_bytes(path: &Path) -> Option<u64> {
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
    let c_path = std::ffi::CString::new(bytes).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is NUL-terminated. On success, `statvfs` initializes `stat`.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: `statvfs` returned 0, so `stat` is initialized.
    let stat = unsafe { stat.assume_init() };
    if stat.f_frsize == 0 {
        return None;
    }
    Some(stat.f_bavail.saturating_mul(stat.f_frsize))
}

struct CpuTimes {
    idle: u64,
    total: u64,
}

fn cpu_percent(before: Option<&str>, after: Option<&str>) -> Option<f64> {
    let before = parse_aggregate_cpu(before?)?;
    let after = parse_aggregate_cpu(after?)?;
    let total = after.total.checked_sub(before.total)?;
    if total == 0 {
        return None;
    }
    let idle = after.idle.checked_sub(before.idle)?;
    if idle > total {
        return None;
    }
    let busy = total - idle;
    let pct = (busy as f64) * 100.0 / (total as f64);
    if !pct.is_finite() || !(0.0..=100.0).contains(&pct) {
        return None;
    }
    Some((pct * 100.0).round() / 100.0)
}

/// Aggregate `cpu` line. Idle includes iowait. Guest time is already inside user/nice.
fn parse_aggregate_cpu(stat: &str) -> Option<CpuTimes> {
    for line in stat.lines() {
        let Some(rest) = line.trim().strip_prefix("cpu ") else {
            continue;
        };
        let mut nums = Vec::new();
        for token in rest.split_whitespace() {
            nums.push(token.parse::<u64>().ok()?);
        }
        if nums.len() < 4 {
            return None;
        }
        let user = nums[0];
        let nice = nums[1];
        let system = nums[2];
        let idle = nums[3];
        let iowait = nums.get(4).copied().unwrap_or(0);
        let irq = nums.get(5).copied().unwrap_or(0);
        let softirq = nums.get(6).copied().unwrap_or(0);
        let steal = nums.get(7).copied().unwrap_or(0);
        return Some(CpuTimes {
            idle: idle.saturating_add(iowait),
            total: user
                .saturating_add(nice)
                .saturating_add(system)
                .saturating_add(idle)
                .saturating_add(iowait)
                .saturating_add(irq)
                .saturating_add(softirq)
                .saturating_add(steal),
        });
    }
    None
}

fn memory_fields(meminfo: &str) -> (Reading<u64>, Reading<u64>, Reading<u64>) {
    let total_kib = meminfo_kib(meminfo, "MemTotal");
    let available_kib = meminfo_kib(meminfo, "MemAvailable");
    let swap_total = meminfo_kib(meminfo, "SwapTotal");
    let swap_free = meminfo_kib(meminfo, "SwapFree");
    let total = total_kib.map(|kib| kib.saturating_mul(1024));
    let used = match (total_kib, available_kib) {
        (Some(total_kib), Some(available)) if available <= total_kib => {
            Some(total_kib.saturating_sub(available).saturating_mul(1024))
        }
        _ => None,
    };
    let swap_used = match (swap_total, swap_free) {
        (Some(total_kib), Some(free)) if free <= total_kib => {
            Some(total_kib.saturating_sub(free).saturating_mul(1024))
        }
        _ => None,
    };
    (
        Reading::from_value(used),
        Reading::from_value(total),
        Reading::from_value(swap_used),
    )
}

fn meminfo_kib(text: &str, key: &str) -> Option<u64> {
    let prefix = format!("{key}:");
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(prefix.as_str()) {
            return parts.next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT_BEFORE: &str = "\
cpu  100 0 100 800 0 0 0 0 0 0
cpu0 50 0 50 400 0 0 0 0 0 0
";
    const STAT_AFTER: &str = "\
cpu  200 0 200 1400 0 0 0 0 0 0
cpu0 100 0 100 700 0 0 0 0 0 0
";
    const MEMINFO: &str = "\
MemTotal:        2048 kB
MemFree:          512 kB
MemAvailable:    1024 kB
SwapTotal:        512 kB
SwapFree:         128 kB
";

    fn fixed_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-07T20:16:00Z")
            .expect("timestamp")
            .with_timezone(&Utc)
    }

    fn full_sample() -> HostSampleReport {
        sample_from_text(
            fixed_time(),
            Some(STAT_BEFORE),
            Some(STAT_AFTER),
            Some(MEMINFO),
            Some(4096),
        )
    }

    #[test]
    fn injected_text_samples_cpu_ram_swap_and_disk() {
        let report = full_sample();
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert_eq!(report.cpu_percent.value, Some(25.0));
        assert_eq!(report.memory_total_bytes.value, Some(2_097_152));
        assert_eq!(report.memory_used_bytes.value, Some(1_048_576));
        assert_eq!(report.swap_used_bytes.value, Some(393_216));
        assert_eq!(report.disk_free_bytes.value, Some(4096));
        assert_eq!(
            report
                .observed_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            "2026-10-07T20:16:00Z"
        );
    }

    #[test]
    fn timestamp_serializes_as_rfc3339() {
        let report = full_sample();
        let value = serde_json::to_value(&report).expect("json");
        let stamp = value["observed_at"].as_str().expect("stamp");
        assert!(DateTime::parse_from_rfc3339(stamp).is_ok());
        assert!(stamp.starts_with("2026-10-07T20:16:00"));
        let human = format_host_human(&report);
        assert!(human.contains("2026-10-07T20:16:00"));
        assert!(human.contains("1048576 bytes"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
        assert!(!serde_json::to_string(&value)
            .expect("json text")
            .to_ascii_lowercase()
            .contains("healthy"));
    }

    #[test]
    fn missing_stat_is_unavailable_not_clean() {
        let report = sample_from_text(fixed_time(), None, None, Some(MEMINFO), Some(4096));
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.cpu_percent.status, SourceStatus::Unavailable);
        assert!(report.cpu_percent.value.is_none());
        assert_eq!(report.memory_total_bytes.value, Some(2_097_152));
        let human = format_host_human(&report);
        assert!(human.contains("cpu: unavailable"));
        assert!(human.contains("clean: no"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("CPU percent")));
    }

    #[test]
    fn missing_meminfo_marks_ram_and_swap_unavailable() {
        let report = sample_from_text(
            fixed_time(),
            Some(STAT_BEFORE),
            Some(STAT_AFTER),
            None,
            Some(1),
        );
        assert_eq!(report.memory_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.memory_total_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.swap_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.cpu_percent.value, Some(25.0));
        assert!(!report.clean);
    }

    #[test]
    fn missing_mem_available_keeps_total_and_drops_used() {
        let meminfo = "\
MemTotal:        2048 kB
MemFree:          512 kB
SwapTotal:        512 kB
SwapFree:         128 kB
";
        let report = sample_from_text(
            fixed_time(),
            Some(STAT_BEFORE),
            Some(STAT_AFTER),
            Some(meminfo),
            Some(1),
        );
        assert_eq!(report.memory_total_bytes.value, Some(2_097_152));
        assert_eq!(report.memory_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.swap_used_bytes.value, Some(393_216));
        assert!(!report.clean);
    }

    #[test]
    fn missing_swap_keys_are_unavailable() {
        let meminfo = "\
MemTotal:        2048 kB
MemAvailable:    1024 kB
";
        let report = sample_from_text(
            fixed_time(),
            Some(STAT_BEFORE),
            Some(STAT_AFTER),
            Some(meminfo),
            Some(1),
        );
        assert_eq!(report.swap_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.memory_used_bytes.value, Some(1_048_576));
        assert!(!report.clean);
    }

    #[test]
    fn zero_swap_is_a_real_reading() {
        let meminfo = "\
MemTotal:        2048 kB
MemAvailable:    1024 kB
SwapTotal:          0 kB
SwapFree:           0 kB
";
        let report = sample_from_text(
            fixed_time(),
            Some(STAT_BEFORE),
            Some(STAT_AFTER),
            Some(meminfo),
            Some(0),
        );
        assert_eq!(report.swap_used_bytes.status, SourceStatus::Available);
        assert_eq!(report.swap_used_bytes.value, Some(0));
        assert_eq!(report.disk_free_bytes.value, Some(0));
        assert!(report.clean);
    }

    #[test]
    fn missing_disk_is_unavailable() {
        let report = sample_from_text(
            fixed_time(),
            Some(STAT_BEFORE),
            Some(STAT_AFTER),
            Some(MEMINFO),
            None,
        );
        assert_eq!(report.disk_free_bytes.status, SourceStatus::Unavailable);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn flat_cpu_counters_are_unavailable() {
        let report = sample_from_text(
            fixed_time(),
            Some(STAT_BEFORE),
            Some(STAT_BEFORE),
            Some(MEMINFO),
            Some(1),
        );
        assert_eq!(report.cpu_percent.status, SourceStatus::Unavailable);
        assert!(!report.clean);
    }

    #[test]
    fn malformed_stat_is_unavailable() {
        let report = sample_from_text(
            fixed_time(),
            Some("cpu  not-a-number 0 0 0\n"),
            Some(STAT_AFTER),
            Some(MEMINFO),
            Some(1),
        );
        assert_eq!(report.cpu_percent.status, SourceStatus::Unavailable);
    }

    #[test]
    fn temp_proc_fixture_matches_injected_text() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("stat"), STAT_BEFORE).expect("stat");
        std::fs::write(dir.path().join("stat2"), STAT_AFTER).expect("stat2");
        std::fs::write(dir.path().join("meminfo"), MEMINFO).expect("meminfo");
        std::fs::write(dir.path().join("disk_free"), "4096\n").expect("disk");
        let report = sample_proc_dir(dir.path(), fixed_time());
        assert_eq!(report, full_sample());
    }

    #[test]
    fn empty_proc_dir_is_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = sample_proc_dir(dir.path(), fixed_time());
        assert!(!report.clean);
        assert_eq!(report.cpu_percent.status, SourceStatus::Unavailable);
        assert_eq!(report.memory_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.memory_total_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.swap_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.disk_free_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let human = format_host_human(&report);
        assert!(!human.to_ascii_lowercase().contains("healthy"));
    }
}
