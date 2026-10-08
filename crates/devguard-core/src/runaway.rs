//! Read-only runaway-process scan.
//!
//! Same rules as the Cursor hook `runaway_detector.py`: a process is a
//! runaway when it is using at least 6 cores and has been alive for at least
//! 10 minutes, or when its resident set is at least 12 GiB. This module
//! reports. It does not send signals.

use std::fs;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::redact::redact_text;

/// Thresholds copied from the Cursor runaway hook.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct RunawayThresholds {
    /// Sustained cores that count as hot.
    pub cores: f64,
    /// Seconds a hot process must have been alive.
    pub min_elapsed_s: f64,
    /// Resident memory, in GiB, that counts on its own.
    pub rss_gib: f64,
    /// CPU sampling window, in seconds.
    pub sample_seconds: f64,
}

impl RunawayThresholds {
    /// Defaults used by `~/.cursor/hooks/runaway_detector.py`.
    pub fn hook_defaults() -> Self {
        Self {
            cores: 6.0,
            min_elapsed_s: 600.0,
            rss_gib: 12.0,
            sample_seconds: 1.0,
        }
    }
}

/// One process that crossed a runaway rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunawayProcess {
    pub pid: u32,
    pub name: String,
    pub cores: f64,
    pub rss_gib: f64,
    pub elapsed_s: u64,
    /// Redacted, truncated command line. Arguments that look like secrets are removed.
    pub cmdline: String,
    pub advice: String,
    /// Text a person can run. DevGuard does not execute it.
    pub stop_hint: String,
}

/// Result of one sample.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunawayReport {
    pub thresholds: RunawayThresholds,
    /// Always false. The scan is observe-only.
    pub stops_processes: bool,
    pub processes: Vec<RunawayProcess>,
}

impl RunawayReport {
    pub fn has_findings(&self) -> bool {
        !self.processes.is_empty()
    }
}

#[derive(Debug, Clone)]
struct ProcSnap {
    pid: u32,
    comm: String,
    cpu_seconds: f64,
    start_s: f64,
    rss_kib: u64,
}

/// Scan `/proc` twice and return processes that cross the thresholds.
pub fn scan_runaways(thresholds: &RunawayThresholds) -> Result<RunawayReport> {
    let ticks = clock_ticks_per_sec();
    let uptime = read_uptime()?;
    let first = snapshot(ticks, thresholds)?;
    let sample = thresholds.sample_seconds.max(0.05);
    thread::sleep(Duration::from_secs_f64(sample));
    let uptime_after = read_uptime().unwrap_or(uptime + sample);
    let mut processes = Vec::new();
    for before in first {
        let Some(after) = read_snap(before.pid, ticks) else {
            continue;
        };
        let cores = cores_between(before.cpu_seconds, after.cpu_seconds, sample);
        let elapsed = (uptime_after - after.start_s).max(0.0);
        let rss_gib = after.rss_kib as f64 / (1024.0 * 1024.0);
        if !is_runaway(cores, rss_gib, elapsed, thresholds) {
            continue;
        }
        let cmdline_raw = read_cmdline(before.pid);
        let advice = advice_for(&after.comm, &cmdline_raw);
        processes.push(RunawayProcess {
            pid: after.pid,
            name: after.comm,
            cores: round2(cores),
            rss_gib: round2(rss_gib),
            elapsed_s: elapsed as u64,
            cmdline: truncate_redacted(&cmdline_raw, 200),
            advice,
            stop_hint: format!("kill {}", after.pid),
        });
    }
    processes.sort_by(|a, b| {
        b.cores
            .partial_cmp(&a.cores)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                b.rss_gib
                    .partial_cmp(&a.rss_gib)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    Ok(RunawayReport {
        thresholds: *thresholds,
        stops_processes: false,
        processes,
    })
}

pub fn format_runaway_human(report: &RunawayReport) -> String {
    let t = &report.thresholds;
    let mut out = format!(
        "DevGuard health runaway\n  rules: >= {cores:.0} cores for >= {mins:.0} min, or RSS >= {rss:.0} GiB\n  sample: {sample:.1}s\n  stops processes: no\n",
        cores = t.cores,
        mins = t.min_elapsed_s / 60.0,
        rss = t.rss_gib,
        sample = t.sample_seconds,
    );
    if report.processes.is_empty() {
        out.push_str("\nNo runaway processes.\n");
        return out;
    }
    out.push_str(&format!(
        "\n{} runaway process(es):\n",
        report.processes.len()
    ));
    for proc in &report.processes {
        let hours = proc.elapsed_s as f64 / 3600.0;
        out.push_str(&format!(
            "- PID {pid} {name}: {cores:.1} cores, {rss:.1} GiB RSS, alive {hours:.1} h.\n",
            pid = proc.pid,
            name = proc.name,
            cores = proc.cores,
            rss = proc.rss_gib,
            hours = hours,
        ));
        if !proc.advice.is_empty() {
            out.push_str(&format!("  {}\n", proc.advice));
        }
        out.push_str(&format!("  Stop hint (not executed): {}\n", proc.stop_hint));
    }
    out.push_str("\nDo not start a build, agent, or kind cluster until this process is gone.\n");
    out
}

/// Hot CPU only counts after the process has been alive long enough.
/// A large resident set counts on its own.
pub fn is_runaway(
    cores: f64,
    rss_gib: f64,
    elapsed_s: f64,
    thresholds: &RunawayThresholds,
) -> bool {
    let hot = cores >= thresholds.cores && elapsed_s >= thresholds.min_elapsed_s;
    let fat = rss_gib >= thresholds.rss_gib;
    hot || fat
}

pub fn cores_between(cpu0: f64, cpu1: f64, sample_s: f64) -> f64 {
    if sample_s <= 0.0 {
        return 0.0;
    }
    ((cpu1 - cpu0) / sample_s).max(0.0)
}

fn snapshot(ticks: f64, thresholds: &RunawayThresholds) -> Result<Vec<ProcSnap>> {
    let mut found = Vec::new();
    let me = std::process::id();
    let cpu_floor = (thresholds.cores * thresholds.min_elapsed_s).min(600.0);
    let rss_floor_kib = 512 * 1024;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Some(snap) = read_snap(pid, ticks) else {
            continue;
        };
        if snap.rss_kib < rss_floor_kib && snap.cpu_seconds < cpu_floor {
            continue;
        }
        found.push(snap);
    }
    Ok(found)
}

fn read_snap(pid: u32, ticks: f64) -> Option<ProcSnap> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let parsed = parse_proc_stat(&raw)?;
    let ticks = if ticks <= 0.0 { 100.0 } else { ticks };
    let cpu_seconds = (parsed.utime + parsed.stime) as f64 / ticks;
    let start_s = parsed.start_ticks as f64 / ticks;
    let rss_kib = read_vm_rss_kib(pid).unwrap_or_else(|| {
        let page = page_size_bytes();
        parsed.rss_pages.saturating_mul(page) / 1024
    });
    Some(ProcSnap {
        pid,
        comm: parsed.comm,
        cpu_seconds,
        start_s,
        rss_kib,
    })
}

struct ParsedStat {
    comm: String,
    utime: u64,
    stime: u64,
    start_ticks: u64,
    rss_pages: u64,
}

fn parse_proc_stat(raw: &str) -> Option<ParsedStat> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = raw[open + 1..close].to_string();
    let fields: Vec<&str> = raw[close + 1..].split_whitespace().collect();
    if fields.len() < 22 {
        return None;
    }
    Some(ParsedStat {
        comm,
        utime: fields[11].parse().ok()?,
        stime: fields[12].parse().ok()?,
        start_ticks: fields[19].parse().ok()?,
        rss_pages: fields[21].parse().ok()?,
    })
}

fn read_vm_rss_kib(pid: u32) -> Option<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in raw.lines() {
        let Some(rest) = line.strip_prefix("VmRSS:") else {
            continue;
        };
        let kb = rest.split_whitespace().next()?;
        return kb.parse().ok();
    }
    None
}

fn read_cmdline(pid: u32) -> String {
    let Ok(bytes) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return String::new();
    };
    String::from_utf8_lossy(&bytes)
        .replace('\0', " ")
        .trim()
        .to_string()
}

fn read_uptime() -> Result<f64> {
    let raw = fs::read_to_string("/proc/uptime")?;
    let first = raw
        .split_whitespace()
        .next()
        .ok_or_else(|| std::io::Error::other("empty /proc/uptime"))?;
    first
        .parse::<f64>()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err).into())
}

fn truncate_redacted(cmdline: &str, max_chars: usize) -> String {
    let redacted = redact_text(cmdline);
    let mut out: String = redacted.chars().take(max_chars).collect();
    if redacted.chars().count() > max_chars {
        out.push('…');
    }
    out
}

fn advice_for(comm: &str, cmdline: &str) -> String {
    let hay = format!("{comm} {cmdline}").to_ascii_lowercase();
    const RULES: &[(&str, &str)] = &[
        (
            "kotlinlanguageserver",
            "Kotlin language server (fwcd.kotlin). Disable the extension for this workspace; it only helps skgraph.",
        ),
        (
            "fwcd.kotlin",
            "Kotlin language server (fwcd.kotlin). Disable the extension for this workspace; it only helps skgraph.",
        ),
        (
            "jdt.ls",
            "Java language server (redhat.java). Disable it or limit the workspace folders.",
        ),
        (
            "jdtls",
            "Java language server (redhat.java). Disable it or limit the workspace folders.",
        ),
        (
            "redhat.java",
            "Java language server (redhat.java). Disable it or limit the workspace folders.",
        ),
        (
            "rust-analyzer",
            "rust-analyzer. Disable it for this workspace.",
        ),
        (
            "tsserver.js",
            "TypeScript server. Exclude large trees (node_modules, UnrealEngine) from the workspace.",
        ),
        (
            "typescript-language",
            "TypeScript server. Exclude large trees (node_modules, UnrealEngine) from the workspace.",
        ),
        (
            "pyright",
            "Pyright/Pylance. Narrow python.analysis.include.",
        ),
        (
            "pylance",
            "Pyright/Pylance. Narrow python.analysis.include.",
        ),
        (
            "gopls",
            "gopls. Narrow the Go workspace.",
        ),
        (
            "mutmut",
            "mutmut. Must run under systemd-run MemoryMax=2G.",
        ),
    ];
    for (needle, advice) in RULES {
        if hay.contains(needle) {
            return (*advice).to_string();
        }
    }
    String::new()
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn clock_ticks_per_sec() -> f64 {
    // Linux `_SC_CLK_TCK` is 2 in glibc's confname list.
    const SC_CLK_TCK: i32 = 2;
    unsafe {
        let hz = sysconf(SC_CLK_TCK);
        if hz > 0 {
            hz as f64
        } else {
            100.0
        }
    }
}

fn page_size_bytes() -> u64 {
    const SC_PAGESIZE: i32 = 30;
    unsafe {
        let page = sysconf(SC_PAGESIZE);
        if page > 0 {
            page as u64
        } else {
            4096
        }
    }
}

extern "C" {
    fn sysconf(name: i32) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thresholds() -> RunawayThresholds {
        RunawayThresholds::hook_defaults()
    }

    #[test]
    fn kotlin_shaped_process_is_a_runaway() {
        let t = thresholds();
        assert!(is_runaway(14.3, 16.0, 32.0 * 3600.0, &t));
    }

    #[test]
    fn short_cpu_spike_is_not_a_runaway() {
        let t = thresholds();
        assert!(!is_runaway(14.0, 0.4, 30.0, &t));
    }

    #[test]
    fn large_rss_counts_without_cpu() {
        let t = thresholds();
        assert!(is_runaway(0.1, 12.0, 5.0, &t));
        assert!(!is_runaway(0.1, 11.9, 5.0, &t));
    }

    #[test]
    fn sustained_cores_need_the_elapsed_gate() {
        let t = thresholds();
        assert!(!is_runaway(6.0, 0.2, 599.0, &t));
        assert!(is_runaway(6.0, 0.2, 600.0, &t));
    }

    #[test]
    fn cores_between_clamps_negative_deltas() {
        assert_eq!(cores_between(10.0, 9.0, 1.0), 0.0);
        assert!((cores_between(10.0, 24.3, 1.0) - 14.3).abs() < 1e-9);
    }

    #[test]
    fn parse_stat_keeps_comm_with_spaces() {
        let raw = "42 (Web Content) R 1 1 1 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0 400 0 9\n";
        let parsed = parse_proc_stat(raw).expect("stat");
        assert_eq!(parsed.comm, "Web Content");
        assert_eq!(parsed.utime, 100);
        assert_eq!(parsed.stime, 50);
        assert_eq!(parsed.start_ticks, 400);
        assert_eq!(parsed.rss_pages, 9);
    }

    #[test]
    fn kotlin_cmdline_gets_the_known_advice() {
        let advice = advice_for(
            "java",
            "java -DkotlinLanguageServer.version=1.3.13 org.javacs.kt.MainKt",
        );
        assert!(advice.contains("fwcd.kotlin"));
        assert!(advice.contains("skgraph"));
    }

    #[test]
    fn cmdline_redacts_secrets_and_truncates() {
        let raw = format!("python token=supersecret {}", "x".repeat(400));
        let shown = truncate_redacted(&raw, 80);
        assert!(!shown.contains("supersecret"));
        assert!(shown.contains("[REDACTED]"));
        assert!(shown.chars().count() <= 81);
    }

    #[test]
    fn human_report_says_it_does_not_stop_processes() {
        let report = RunawayReport {
            thresholds: thresholds(),
            stops_processes: false,
            processes: vec![RunawayProcess {
                pid: 357501,
                name: "java".into(),
                cores: 14.3,
                rss_gib: 16.0,
                elapsed_s: 32 * 3600,
                cmdline: "java org.javacs.kt.MainKt".into(),
                advice: "Kotlin language server (fwcd.kotlin).".into(),
                stop_hint: "kill 357501".into(),
            }],
        };
        let text = format_runaway_human(&report);
        assert!(text.contains("stops processes: no"));
        assert!(text.contains("not executed"));
        assert!(text.contains("PID 357501"));
        assert!(text.contains("kind cluster"));
    }
}
