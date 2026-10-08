//! One-shot host reading for `devguard health scan`.
//!
//! The command reports CPU count, memory used and total, swap used, disk free
//! bytes, uptime, and the busiest process names. Process names come from the
//! `comm` field in `/proc/<pid>/stat`. Command arguments are not read.
//!
//! It does not use sudo, send a signal, load a kernel module, or write BIOS.
//! A missing `/proc` source is `unavailable`, and that result is not clean.

use std::collections::HashMap;
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

const PROCESS_SAMPLE: Duration = Duration::from_millis(200);
const PROCESS_LIMIT: usize = 8;
const NAME_LIMIT: usize = 64;

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

/// Busiest process names. The list is names only; arguments are not stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessNames {
    pub status: SourceStatus,
    pub names: Vec<String>,
}

impl ProcessNames {
    fn available(names: Vec<String>) -> Self {
        Self {
            status: SourceStatus::Available,
            names,
        }
    }

    fn unavailable() -> Self {
        Self {
            status: SourceStatus::Unavailable,
            names: Vec::new(),
        }
    }

    fn is_available(&self) -> bool {
        self.status == SourceStatus::Available
    }
}

/// Human and JSON body for `devguard health scan`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthScanReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never sends a signal.
    pub sends_signals: bool,
    /// Always false. This command never loads a kernel module.
    pub loads_modules: bool,
    /// Always false. This command never writes BIOS settings.
    pub writes_bios: bool,
    /// False when any `/proc` source or the disk-free reading is unavailable.
    pub clean: bool,
    pub cpu_count: Reading<u32>,
    pub memory_used_bytes: Reading<u64>,
    pub memory_total_bytes: Reading<u64>,
    pub swap_used_bytes: Reading<u64>,
    pub disk_free_bytes: Reading<u64>,
    pub uptime_seconds: Reading<f64>,
    pub processes: ProcessNames,
}

impl HealthScanReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        push_missing(&mut warnings, "CPU count", self.cpu_count.is_available());
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
        push_missing(&mut warnings, "uptime", self.uptime_seconds.is_available());
        push_missing(
            &mut warnings,
            "busiest processes",
            self.processes.is_available(),
        );
        warnings
    }
}

/// Read the live host. Process names are a short `/proc/<pid>/stat` delta.
pub fn scan_health() -> HealthScanReport {
    let cpuinfo = read_to_string(Path::new("/proc/cpuinfo"));
    let meminfo = read_to_string(Path::new("/proc/meminfo"));
    let uptime = read_to_string(Path::new("/proc/uptime"));
    let disk = disk_free_bytes(Path::new("/"));
    let exclude = Some(std::process::id());
    let before = snapshot_ticks(Path::new("/proc"), exclude);
    let after = if before.is_some() {
        thread::sleep(PROCESS_SAMPLE);
        snapshot_ticks(Path::new("/proc"), exclude)
    } else {
        None
    };
    assemble(
        cpuinfo.as_deref(),
        meminfo.as_deref(),
        uptime.as_deref(),
        disk,
        before.as_deref(),
        after.as_deref(),
    )
}

/// Parse a fixture directory. Tests use this instead of the live host.
///
/// Expected files: `cpuinfo`, `meminfo`, `uptime`, `disk_free`, plus `before/`
/// and `after/` trees of `<pid>/stat`. A `cmdline` file is never opened.
pub fn scan_fixture(root: &Path) -> HealthScanReport {
    let cpuinfo = read_to_string(&root.join("cpuinfo"));
    let meminfo = read_to_string(&root.join("meminfo"));
    let uptime = read_to_string(&root.join("uptime"));
    let disk = read_disk_file(&root.join("disk_free"));
    let before = snapshot_ticks(&root.join("before"), None);
    let after = snapshot_ticks(&root.join("after"), None);
    assemble(
        cpuinfo.as_deref(),
        meminfo.as_deref(),
        uptime.as_deref(),
        disk,
        before.as_deref(),
        after.as_deref(),
    )
}

pub fn format_health_scan_human(report: &HealthScanReport) -> String {
    format!(
        "\
DevGuard health scan
  cpu count: {cpu}
  memory used: {memory_used}
  memory total: {memory_total}
  swap used: {swap_used}
  disk free: {disk_free}
  uptime: {uptime}
  busiest: {busiest}
  uses sudo: no
  sends signals: no
  loads modules: no
  writes BIOS: no
  clean: {clean}
",
        cpu = count_text(&report.cpu_count),
        memory_used = bytes_text(&report.memory_used_bytes),
        memory_total = bytes_text(&report.memory_total_bytes),
        swap_used = bytes_text(&report.swap_used_bytes),
        disk_free = bytes_text(&report.disk_free_bytes),
        uptime = uptime_text(&report.uptime_seconds),
        busiest = names_text(&report.processes),
        clean = if report.clean { "yes" } else { "no" },
    )
}

fn assemble(
    cpuinfo: Option<&str>,
    meminfo: Option<&str>,
    uptime: Option<&str>,
    disk_free_bytes: Option<u64>,
    before: Option<&[Tick]>,
    after: Option<&[Tick]>,
) -> HealthScanReport {
    let cpu_count = Reading::from_value(cpuinfo.and_then(parse_cpu_count));
    let (memory_used_bytes, memory_total_bytes, swap_used_bytes) = match meminfo {
        Some(text) => memory_fields(text),
        None => (
            Reading::from_value(None),
            Reading::from_value(None),
            Reading::from_value(None),
        ),
    };
    let disk_free_bytes = Reading::from_value(disk_free_bytes);
    let uptime_seconds = Reading::from_value(uptime.and_then(parse_uptime));
    let processes = match (before, after) {
        (Some(before), Some(after)) => ProcessNames::available(busiest_names(before, after)),
        _ => ProcessNames::unavailable(),
    };
    let clean = cpu_count.is_available()
        && memory_used_bytes.is_available()
        && memory_total_bytes.is_available()
        && swap_used_bytes.is_available()
        && disk_free_bytes.is_available()
        && uptime_seconds.is_available()
        && processes.is_available();
    HealthScanReport {
        uses_sudo: false,
        sends_signals: false,
        loads_modules: false,
        writes_bios: false,
        clean,
        cpu_count,
        memory_used_bytes,
        memory_total_bytes,
        swap_used_bytes,
        disk_free_bytes,
        uptime_seconds,
        processes,
    }
}

fn push_missing(warnings: &mut Vec<String>, name: &str, available: bool) {
    if !available {
        warnings.push(format!("{name} is unavailable"));
    }
}

fn count_text(reading: &Reading<u32>) -> String {
    match (&reading.status, reading.value) {
        (SourceStatus::Available, Some(value)) => value.to_string(),
        _ => "unavailable".to_string(),
    }
}

fn bytes_text(reading: &Reading<u64>) -> String {
    match (&reading.status, reading.value) {
        (SourceStatus::Available, Some(bytes)) => format!("{bytes} bytes"),
        _ => "unavailable".to_string(),
    }
}

fn uptime_text(reading: &Reading<f64>) -> String {
    match (&reading.status, reading.value) {
        (SourceStatus::Available, Some(seconds)) => format!("{seconds:.2} seconds"),
        _ => "unavailable".to_string(),
    }
}

fn names_text(processes: &ProcessNames) -> String {
    if !processes.is_available() {
        return "unavailable".to_string();
    }
    if processes.names.is_empty() {
        return "none".to_string();
    }
    processes.names.join(", ")
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

fn parse_cpu_count(cpuinfo: &str) -> Option<u32> {
    let count = cpuinfo
        .lines()
        .filter(|line| line.starts_with("processor"))
        .count();
    u32::try_from(count).ok().filter(|count| *count > 0)
}

fn parse_uptime(text: &str) -> Option<f64> {
    let raw = text.split_whitespace().next()?.parse::<f64>().ok()?;
    if !raw.is_finite() || raw < 0.0 {
        return None;
    }
    Some((raw * 100.0).round() / 100.0)
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

#[derive(Debug, Clone)]
struct Tick {
    pid: u32,
    name: String,
    cpu_ticks: u64,
}

/// Read `/proc/<pid>/stat` only. `cmdline` is never opened.
fn snapshot_ticks(proc_root: &Path, exclude: Option<u32>) -> Option<Vec<Tick>> {
    let entries = std::fs::read_dir(proc_root).ok()?;
    let mut ticks = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|text| text.parse::<u32>().ok())
        else {
            continue;
        };
        if exclude == Some(pid) {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(parsed) = parse_proc_stat(&raw) else {
            continue;
        };
        let name = sanitize_process_name(&parsed.comm);
        if name.is_empty() {
            continue;
        }
        ticks.push(Tick {
            pid,
            name,
            cpu_ticks: parsed.utime.saturating_add(parsed.stime),
        });
    }
    Some(ticks)
}

fn busiest_names(before: &[Tick], after: &[Tick]) -> Vec<String> {
    let prior: HashMap<u32, u64> = before
        .iter()
        .map(|tick| (tick.pid, tick.cpu_ticks))
        .collect();
    let mut ranked = Vec::new();
    for tick in after {
        let Some(previous) = prior.get(&tick.pid) else {
            continue;
        };
        let delta = tick.cpu_ticks.saturating_sub(*previous);
        if delta == 0 || tick.name.is_empty() {
            continue;
        }
        ranked.push((delta, tick.name.clone()));
    }
    ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    ranked.truncate(PROCESS_LIMIT);
    ranked.into_iter().map(|(_, name)| name).collect()
}

struct ParsedStat {
    comm: String,
    utime: u64,
    stime: u64,
}

fn parse_proc_stat(raw: &str) -> Option<ParsedStat> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = raw[open + 1..close].to_string();
    let fields: Vec<&str> = raw[close + 1..].split_whitespace().collect();
    if fields.len() < 13 {
        return None;
    }
    Some(ParsedStat {
        comm,
        utime: fields[11].parse().ok()?,
        stime: fields[12].parse().ok()?,
    })
}

fn sanitize_process_name(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_control() {
            continue;
        }
        out.push(ch);
        if out.chars().count() >= NAME_LIMIT {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPUINFO: &str = "\
processor\t: 0
processor\t: 1
processor\t: 2
processor\t: 3
";
    const MEMINFO: &str = "\
MemTotal:        2048 kB
MemFree:          512 kB
MemAvailable:    1024 kB
SwapTotal:        512 kB
SwapFree:         128 kB
";
    const UPTIME: &str = "12345.67 999.00\n";
    const SECRET: &str = "do-not-collect --secret-token=abc";

    fn stat_line(pid: u32, name: &str, ticks: u64) -> String {
        format!("{pid} ({name}) R 1 1 1 0 -1 0 0 0 0 0 {ticks} 0\n")
    }

    fn write_proc(root: &Path, pid: u32, name: &str, before: u64, after: u64) {
        for (side, ticks) in [("before", before), ("after", after)] {
            let dir = root.join(side).join(pid.to_string());
            std::fs::create_dir_all(&dir).expect("pid dir");
            std::fs::write(dir.join("stat"), stat_line(pid, name, ticks)).expect("stat");
        }
    }

    fn full_fixture(root: &Path) {
        std::fs::write(root.join("cpuinfo"), CPUINFO).expect("cpuinfo");
        std::fs::write(root.join("meminfo"), MEMINFO).expect("meminfo");
        std::fs::write(root.join("uptime"), UPTIME).expect("uptime");
        std::fs::write(root.join("disk_free"), "4096\n").expect("disk");
        write_proc(root, 10, "cargo", 100, 400);
        write_proc(root, 11, "rustc", 50, 150);
        write_proc(root, 12, "idle", 10, 10);
        let cmdline = root.join("before").join("10").join("cmdline");
        std::fs::write(cmdline, SECRET).expect("cmdline");
        std::fs::write(root.join("after").join("10").join("cmdline"), SECRET).expect("cmdline");
    }

    fn full_report(root: &Path) -> HealthScanReport {
        scan_fixture(root)
    }

    #[test]
    fn fixture_reports_counts_memory_swap_disk_uptime_and_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        let report = full_report(dir.path());
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert!(!report.uses_sudo);
        assert!(!report.sends_signals);
        assert!(!report.loads_modules);
        assert!(!report.writes_bios);
        assert_eq!(report.cpu_count.value, Some(4));
        assert_eq!(report.memory_total_bytes.value, Some(2_097_152));
        assert_eq!(report.memory_used_bytes.value, Some(1_048_576));
        assert_eq!(report.swap_used_bytes.value, Some(393_216));
        assert_eq!(report.disk_free_bytes.value, Some(4096));
        assert_eq!(report.uptime_seconds.value, Some(12345.67));
        assert_eq!(
            report.processes.names,
            vec!["cargo".to_string(), "rustc".to_string()]
        );
        let human = format_health_scan_human(&report);
        assert!(human.contains("DevGuard health scan"));
        assert!(human.contains("cpu count: 4"));
        assert!(human.contains("1048576 bytes"));
        assert!(human.contains("2097152 bytes"));
        assert!(human.contains("393216 bytes"));
        assert!(human.contains("4096 bytes"));
        assert!(human.contains("12345.67 seconds"));
        assert!(human.contains("busiest: cargo, rustc"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("sends signals: no"));
        assert!(human.contains("loads modules: no"));
        assert!(human.contains("writes BIOS: no"));
        assert!(human.contains("clean: yes"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains(SECRET));
        assert!(!json.contains("cmdline"));
        assert!(!json.contains("secret-token"));
        assert!(!human.contains(SECRET));
        assert!(!json.to_ascii_lowercase().contains("healthy"));
        let value: serde_json::Value = serde_json::from_str(&json).expect("value");
        assert!(value.get("cmdline").is_none());
        assert!(value.get("args").is_none());
        assert!(value["processes"].get("cmdline").is_none());
        assert!(value["processes"].get("args").is_none());
        for name in value["processes"]["names"].as_array().expect("names") {
            assert!(name.is_string());
        }
    }

    #[test]
    fn missing_cpuinfo_is_unavailable_and_not_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        std::fs::remove_file(dir.path().join("cpuinfo")).expect("remove");
        let report = scan_fixture(dir.path());
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.cpu_count.status, SourceStatus::Unavailable);
        assert!(report.cpu_count.value.is_none());
        assert_eq!(report.memory_used_bytes.value, Some(1_048_576));
        let human = format_health_scan_human(&report);
        assert!(human.contains("cpu count: unavailable"));
        assert!(human.contains("clean: no"));
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("CPU count")));
    }

    #[test]
    fn missing_meminfo_marks_ram_and_swap_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        std::fs::remove_file(dir.path().join("meminfo")).expect("remove");
        let report = scan_fixture(dir.path());
        assert_eq!(report.memory_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.memory_total_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.swap_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.cpu_count.value, Some(4));
        assert!(!report.clean);
    }

    #[test]
    fn missing_uptime_is_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        std::fs::remove_file(dir.path().join("uptime")).expect("remove");
        let report = scan_fixture(dir.path());
        assert_eq!(report.uptime_seconds.status, SourceStatus::Unavailable);
        assert!(!report.clean);
        assert!(format_health_scan_human(&report).contains("uptime: unavailable"));
    }

    #[test]
    fn missing_disk_is_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        std::fs::remove_file(dir.path().join("disk_free")).expect("remove");
        let report = scan_fixture(dir.path());
        assert_eq!(report.disk_free_bytes.status, SourceStatus::Unavailable);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn missing_proc_sample_is_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        std::fs::remove_dir_all(dir.path().join("after")).expect("remove");
        let report = scan_fixture(dir.path());
        assert_eq!(report.processes.status, SourceStatus::Unavailable);
        assert!(report.processes.names.is_empty());
        assert!(!report.clean);
        assert!(format_health_scan_human(&report).contains("busiest: unavailable"));
    }

    #[test]
    fn empty_fixture_is_not_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = scan_fixture(dir.path());
        assert!(!report.clean);
        assert_eq!(report.cpu_count.status, SourceStatus::Unavailable);
        assert_eq!(report.memory_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.memory_total_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.swap_used_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.disk_free_bytes.status, SourceStatus::Unavailable);
        assert_eq!(report.uptime_seconds.status, SourceStatus::Unavailable);
        assert_eq!(report.processes.status, SourceStatus::Unavailable);
        assert!(!report.sends_signals);
        let human = format_health_scan_human(&report);
        assert!(human.contains("clean: no"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn zero_swap_and_idle_processes_stay_available() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        let meminfo = "\
MemTotal:        2048 kB
MemAvailable:    1024 kB
SwapTotal:          0 kB
SwapFree:           0 kB
";
        std::fs::write(dir.path().join("meminfo"), meminfo).expect("meminfo");
        std::fs::write(dir.path().join("disk_free"), "0\n").expect("disk");
        for side in ["before", "after"] {
            let stat = dir.path().join(side).join("10").join("stat");
            std::fs::write(stat, stat_line(10, "cargo", 100)).expect("stat");
            let stat = dir.path().join(side).join("11").join("stat");
            std::fs::write(stat, stat_line(11, "rustc", 50)).expect("stat");
        }
        let report = scan_fixture(dir.path());
        assert_eq!(report.swap_used_bytes.status, SourceStatus::Available);
        assert_eq!(report.swap_used_bytes.value, Some(0));
        assert_eq!(report.disk_free_bytes.value, Some(0));
        assert_eq!(report.processes.status, SourceStatus::Available);
        assert!(report.processes.names.is_empty());
        assert!(report.clean);
        assert!(format_health_scan_human(&report).contains("busiest: none"));
    }

    #[test]
    fn missing_mem_available_keeps_total_and_drops_used() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        let meminfo = "\
MemTotal:        2048 kB
MemFree:          512 kB
SwapTotal:        512 kB
SwapFree:         128 kB
";
        std::fs::write(dir.path().join("meminfo"), meminfo).expect("meminfo");
        let report = scan_fixture(dir.path());
        assert_eq!(report.memory_total_bytes.value, Some(2_097_152));
        assert_eq!(report.memory_used_bytes.status, SourceStatus::Unavailable);
        assert!(!report.clean);
    }

    #[test]
    fn busiest_list_keeps_eight_names_and_ignores_arguments() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("cpuinfo"), CPUINFO).expect("cpuinfo");
        std::fs::write(dir.path().join("meminfo"), MEMINFO).expect("meminfo");
        std::fs::write(dir.path().join("uptime"), UPTIME).expect("uptime");
        std::fs::write(dir.path().join("disk_free"), "1\n").expect("disk");
        for pid in 1..=9 {
            let name = format!("worker-{pid:02}");
            write_proc(dir.path(), pid, &name, 0, u64::from(pid) * 10);
            let cmdline = dir
                .path()
                .join("before")
                .join(pid.to_string())
                .join("cmdline");
            std::fs::write(cmdline, format!("worker --arg {pid}")).expect("cmdline");
        }
        write_proc(dir.path(), 20, "only-after", 0, 0);
        std::fs::remove_dir_all(dir.path().join("before").join("20")).expect("drop before");
        let report = scan_fixture(dir.path());
        assert_eq!(report.processes.names.len(), 8);
        assert_eq!(report.processes.names[0], "worker-09");
        assert!(!report
            .processes
            .names
            .iter()
            .any(|name| name == "worker-01"));
        assert!(!report
            .processes
            .names
            .iter()
            .any(|name| name == "only-after"));
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains("--arg"));
        assert!(!json.contains("cmdline"));
    }

    #[test]
    fn comm_with_spaces_and_control_chars_is_the_name_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        full_fixture(dir.path());
        let noisy = "bad\nname with spaces";
        std::fs::write(
            dir.path().join("before").join("10").join("stat"),
            stat_line(10, noisy, 1),
        )
        .expect("before");
        std::fs::write(
            dir.path().join("after").join("10").join("stat"),
            stat_line(10, noisy, 500),
        )
        .expect("after");
        let report = scan_fixture(dir.path());
        assert_eq!(report.processes.names[0], "badname with spaces");
        assert!(!report.processes.names[0].contains('\n'));
    }
}
