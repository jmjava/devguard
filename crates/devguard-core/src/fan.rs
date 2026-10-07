//! Read-only fan diagnostic.
//!
//! `devguard health fan` records observations and hypotheses. It does not use
//! sudo, write a fan curve, load a kernel module, or change BIOS settings.
//! Process output is the comm name from `/proc/<pid>/stat` only.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::redact::redact_text;

const PROCESS_SAMPLE: Duration = Duration::from_millis(200);
const TOOL_TIMEOUT: Duration = Duration::from_secs(3);
const PROCESS_LIMIT: usize = 8;
/// Load per CPU at or above this is an elevated-load hypothesis.
const ELEVATED_LOAD_PER_CPU: f64 = 0.75;
const GPU_COOL_C: f64 = 55.0;
const GPU_IDLE_FAN_PERCENT: f64 = 5.0;
const GPU_HOT_C: f64 = 80.0;
const GPU_ACTIVE_FAN_PERCENT: f64 = 40.0;

const CAVEAT: &str = "One sample is context. It does not prove an Ubuntu upgrade changed the fan curve. Clean coverage only means sensors, nvidia-smi, and a chassis tachometer answered.";

/// `available` or `unavailable`. Missing tools are never a clean result.
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModulePresence {
    Listed,
    Absent,
    Unreadable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HwmonChip {
    pub id: String,
    pub name: String,
    pub temps: Vec<LabeledTemp>,
    pub fans: Vec<LabeledRpm>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LabeledTemp {
    pub label: String,
    pub celsius: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LabeledRpm {
    pub label: String,
    pub rpm: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpuReading {
    pub name: String,
    pub temperature_c: Option<f64>,
    pub fan_percent: Option<f64>,
    pub utilization_percent: Option<f64>,
    pub power_w: Option<f64>,
}

/// A process comm name and its sampled CPU share. Arguments are not stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NamedProcess {
    pub name: String,
    pub cpu_percent: f64,
}

/// Facts collected before hypotheses are written.
#[derive(Debug, Clone, PartialEq)]
pub struct FanFacts {
    pub kernel: String,
    pub cpu_count: u32,
    pub load_1m: f64,
    pub sensors: SourceCoverage,
    pub nvidia_smi: SourceCoverage,
    pub hwmon: Vec<HwmonChip>,
    pub gpus: Vec<GpuReading>,
    pub nvidia_module: ModulePresence,
    pub processes: Vec<NamedProcess>,
}

/// Human and JSON body for `devguard health fan`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FanReport {
    /// Always false. This command never writes a fan curve.
    pub changes_fan_curve: bool,
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never loads a kernel module.
    pub loads_modules: bool,
    /// Always false. This command never writes BIOS settings.
    pub writes_bios: bool,
    /// False when `sensors`, `nvidia-smi`, or a chassis tachometer is unavailable.
    pub clean: bool,
    pub kernel: String,
    pub cpu_count: u32,
    pub load_1m: f64,
    pub sensors: SourceCoverage,
    pub nvidia_smi: SourceCoverage,
    pub chassis_fan: SourceCoverage,
    pub hwmon: Vec<HwmonChip>,
    pub gpus: Vec<GpuReading>,
    pub nvidia_module: ModulePresence,
    pub processes: Vec<NamedProcess>,
    pub observations: Vec<String>,
    pub hypotheses: Vec<String>,
    pub caveat: String,
}

impl FanReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        push_unavailable(&mut warnings, "sensors", &self.sensors);
        push_unavailable(&mut warnings, "nvidia-smi", &self.nvidia_smi);
        push_unavailable(&mut warnings, "chassis fan RPM", &self.chassis_fan);
        warnings
    }
}

fn push_unavailable(warnings: &mut Vec<String>, label: &str, source: &SourceCoverage) {
    if source.status == CoverageStatus::Unavailable {
        warnings.push(format!("{label} unavailable: {}", source.detail));
    }
}

/// Turn collected facts into observations, hypotheses, and a coverage verdict.
pub fn diagnose(facts: FanFacts) -> FanReport {
    let chassis_fan = chassis_coverage(&facts.hwmon);
    let gpus = if facts.nvidia_smi.status == CoverageStatus::Available {
        facts.gpus.clone()
    } else {
        Vec::new()
    };
    let clean = facts.sensors.status == CoverageStatus::Available
        && facts.nvidia_smi.status == CoverageStatus::Available
        && chassis_fan.status == CoverageStatus::Available;
    let observations = observations_of(&facts, &chassis_fan, &gpus);
    let hypotheses = hypotheses_of(&facts, &chassis_fan, &gpus);
    FanReport {
        changes_fan_curve: false,
        uses_sudo: false,
        loads_modules: false,
        writes_bios: false,
        clean,
        kernel: facts.kernel,
        cpu_count: facts.cpu_count,
        load_1m: facts.load_1m,
        sensors: facts.sensors,
        nvidia_smi: facts.nvidia_smi,
        chassis_fan,
        hwmon: facts.hwmon,
        gpus,
        nvidia_module: facts.nvidia_module,
        processes: facts.processes,
        observations,
        hypotheses,
        caveat: CAVEAT.to_string(),
    }
}

/// Read this host once. Optional tools that are missing stay `unavailable`.
pub fn scan_fan() -> FanReport {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut cpu_count = cpu_count_from_cpuinfo(&cpuinfo);
    if cpu_count == 0 {
        cpu_count = std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(1))
            .unwrap_or(1);
    }
    let load_1m = fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| parse_load1(&text))
        .unwrap_or(0.0);
    let hwmon = read_hwmon(Path::new("/sys/class/hwmon"));
    let sensors = probe_sensors();
    let (nvidia_smi, gpus) = probe_nvidia();
    let nvidia_module = read_nvidia_module(Path::new("/proc/modules"));
    let processes = sample_processes();
    diagnose(FanFacts {
        kernel,
        cpu_count,
        load_1m,
        sensors,
        nvidia_smi,
        hwmon,
        gpus,
        nvidia_module,
        processes,
    })
}

pub fn format_fan_human(report: &FanReport) -> String {
    let per = per_cpu(report.load_1m, report.cpu_count);
    let mut out = String::new();
    out.push_str("DevGuard health fan\n");
    out.push_str(&format!("  kernel: {}\n", report.kernel));
    out.push_str(&format!(
        "  load (1 min): {load:.2} across {cpus} CPUs ({per:.2} per CPU)\n",
        load = report.load_1m,
        cpus = report.cpu_count,
        per = per,
    ));
    out.push_str("  changes fan curve: no\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  loads modules: no\n");
    out.push_str("  writes BIOS: no\n");
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    out.push_str("\nObservations\n");
    for item in &report.observations {
        out.push_str(&format!("- {item}\n"));
    }
    out.push_str("\nHypotheses\n");
    for item in &report.hypotheses {
        out.push_str(&format!("- {item}\n"));
    }
    out.push_str("\nCoverage\n");
    out.push_str(&format!(
        "  sensors: {} — {}\n",
        status_word(report.sensors.status),
        report.sensors.detail
    ));
    out.push_str(&format!(
        "  nvidia-smi: {} — {}\n",
        status_word(report.nvidia_smi.status),
        report.nvidia_smi.detail
    ));
    out.push_str(&format!(
        "  chassis fan RPM: {} — {}\n",
        status_word(report.chassis_fan.status),
        report.chassis_fan.detail
    ));
    if !report.processes.is_empty() {
        out.push_str("\nProcesses (names only)\n");
        for proc in &report.processes {
            out.push_str(&format!(
                "- {} ({:.0}% of one core)\n",
                proc.name, proc.cpu_percent
            ));
        }
    }
    out.push_str(&format!("\n{}\n", report.caveat));
    out
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn observations_of(facts: &FanFacts, chassis: &SourceCoverage, gpus: &[GpuReading]) -> Vec<String> {
    let mut notes = Vec::new();
    notes.push(format!("Kernel release is {}.", facts.kernel));
    notes.push(format!(
        "Load average (1 min) is {load:.2} across {cpus} CPUs ({per:.2} per CPU).",
        load = facts.load_1m,
        cpus = facts.cpu_count,
        per = per_cpu(facts.load_1m, facts.cpu_count),
    ));
    if facts.hwmon.is_empty() {
        notes.push("No hwmon chips were readable.".into());
    } else {
        for chip in &facts.hwmon {
            notes.push(format!(
                "hwmon {} ({}): {}.",
                chip.id,
                chip.name,
                chip_summary(chip)
            ));
        }
    }
    notes.push(format!(
        "Chassis fan tachometer is {} — {}.",
        status_word(chassis.status),
        chassis.detail
    ));
    notes.push(format!(
        "sensors is {} — {}.",
        status_word(facts.sensors.status),
        facts.sensors.detail
    ));
    notes.push(format!(
        "nvidia-smi is {} — {}.",
        status_word(facts.nvidia_smi.status),
        facts.nvidia_smi.detail
    ));
    for gpu in gpus {
        notes.push(gpu_observation(gpu));
    }
    notes.push(match facts.nvidia_module {
        ModulePresence::Listed => "The nvidia kernel module is listed in /proc/modules.".into(),
        ModulePresence::Absent => "The nvidia kernel module is not listed in /proc/modules.".into(),
        ModulePresence::Unreadable => "The kernel module list was unreadable.".into(),
    });
    if facts.processes.is_empty() {
        notes.push(
            "No busy process names were sampled. Command arguments were not collected.".into(),
        );
    } else {
        let names = facts
            .processes
            .iter()
            .map(|proc| format!("{} ({:.0}% of one core)", proc.name, proc.cpu_percent))
            .collect::<Vec<_>>()
            .join(", ");
        notes.push(format!(
            "Busiest process names: {names}. Command arguments were not collected."
        ));
    }
    notes
}

fn hypotheses_of(facts: &FanFacts, chassis: &SourceCoverage, gpus: &[GpuReading]) -> Vec<String> {
    let mut notes = Vec::new();
    let per = per_cpu(facts.load_1m, facts.cpu_count);
    if per >= ELEVATED_LOAD_PER_CPU {
        notes.push(
            "CPU load is elevated for this CPU count. That can spin chassis fans on its own."
                .into(),
        );
    } else {
        notes.push(
            "CPU load is not elevated in this sample, so load alone is a weak explanation for loud fans."
                .into(),
        );
    }
    if chassis.status == CoverageStatus::Unavailable {
        notes.push(
            "The missing chassis tachometer is separate from CPU load. This sample cannot show case-fan RPM, so it cannot confirm a fan-curve change."
                .into(),
        );
    }
    if facts.sensors.status == CoverageStatus::Unavailable {
        notes.push(
            "The sensors tool is unavailable. Missing lm-sensors coverage is not a clean thermal result."
                .into(),
        );
    }
    if facts.nvidia_smi.status == CoverageStatus::Unavailable {
        notes.push(
            "nvidia-smi is unavailable. GPU fan speed is unknown. Unknown is not idle and is not a clean result."
                .into(),
        );
    } else {
        for gpu in gpus {
            notes.push(gpu_hypothesis(gpu));
        }
    }
    notes.push(CAVEAT.to_string());
    notes
}

fn gpu_observation(gpu: &GpuReading) -> String {
    format!(
        "GPU {}: temperature {}, fan {}, utilization {}, power {}.",
        gpu.name,
        format_optional_c(gpu.temperature_c),
        format_optional_percent(gpu.fan_percent),
        format_optional_percent(gpu.utilization_percent),
        format_optional_watts(gpu.power_w),
    )
}

fn gpu_hypothesis(gpu: &GpuReading) -> String {
    match (gpu.fan_percent, gpu.temperature_c) {
        (Some(fan), Some(temp)) if fan <= GPU_IDLE_FAN_PERCENT && temp < GPU_COOL_C => format!(
            "GPU {} reports fan speed {fan:.0}% and {temp:.1} C. That GPU fan is unlikely to be the chassis noise in this sample.",
            gpu.name
        ),
        (Some(fan), Some(temp)) if temp >= GPU_HOT_C || fan >= GPU_ACTIVE_FAN_PERCENT => format!(
            "GPU {} is warm or its fan is moving ({temp:.1} C, fan {fan:.0}%). GPU cooling is a candidate contributor.",
            gpu.name
        ),
        (None, _) => format!(
            "GPU {} did not expose a fan speed. That reading is unavailable, not zero.",
            gpu.name
        ),
        (Some(fan), temp) => format!(
            "GPU {} fan speed is {fan:.0}% at {}. This sample does not treat that as proof of a curve change.",
            gpu.name,
            format_optional_c(temp),
        ),
    }
}

fn format_optional_c(value: Option<f64>) -> String {
    match value {
        Some(c) => format!("{c:.1} C"),
        None => "unavailable".to_string(),
    }
}

fn format_optional_percent(value: Option<f64>) -> String {
    match value {
        Some(pct) => format!("{pct:.0}%"),
        None => "unavailable".to_string(),
    }
}

fn format_optional_watts(value: Option<f64>) -> String {
    match value {
        Some(watts) => format!("{watts:.1} W"),
        None => "unavailable".to_string(),
    }
}

fn chip_summary(chip: &HwmonChip) -> String {
    let temps = if chip.temps.is_empty() {
        "no temperature files".to_string()
    } else {
        chip.temps
            .iter()
            .map(|temp| format!("{} {:.1} C", temp.label, temp.celsius))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let fans = if chip.fans.is_empty() {
        "no fan RPM files".to_string()
    } else {
        chip.fans
            .iter()
            .map(|fan| format!("{} {} RPM", fan.label, fan.rpm))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("{temps}; {fans}")
}

fn chassis_coverage(chips: &[HwmonChip]) -> SourceCoverage {
    let count: usize = chips.iter().map(|chip| chip.fans.len()).sum();
    if count == 0 {
        SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: "no hwmon fan RPM file was readable".to_string(),
        }
    } else {
        SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("{count} tachometer file(s)"),
        }
    }
}

fn per_cpu(load: f64, cpus: u32) -> f64 {
    load / f64::from(cpus.max(1))
}

fn probe_sensors() -> SourceCoverage {
    probe_tool("sensors", &[])
}

fn probe_nvidia() -> (SourceCoverage, Vec<GpuReading>) {
    let Some(path) = find_tool("nvidia-smi") else {
        return (
            SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: "`nvidia-smi` is not on PATH".to_string(),
            },
            Vec::new(),
        );
    };
    match run_readonly(
        &path,
        &[
            "--query-gpu=name,temperature.gpu,fan.speed,utilization.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ],
        TOOL_TIMEOUT,
    ) {
        Ok(run) if run.success => {
            let gpus = parse_nvidia_csv(&run.stdout);
            if gpus.is_empty() {
                (
                    SourceCoverage {
                        status: CoverageStatus::Unavailable,
                        detail: "nvidia-smi returned no GPU rows".to_string(),
                    },
                    Vec::new(),
                )
            } else {
                (
                    SourceCoverage {
                        status: CoverageStatus::Available,
                        detail: format!("nvidia-smi returned {} GPU row(s)", gpus.len()),
                    },
                    gpus,
                )
            }
        }
        Ok(run) => (
            SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: short_detail(&run.stderr, "nvidia-smi exited non-zero"),
            },
            Vec::new(),
        ),
        Err(err) => (
            SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: short_detail(&err.to_string(), "nvidia-smi failed"),
            },
            Vec::new(),
        ),
    }
}

fn probe_tool(name: &str, args: &[&str]) -> SourceCoverage {
    let Some(path) = find_tool(name) else {
        return SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: format!("`{name}` is not on PATH"),
        };
    };
    match run_readonly(&path, args, TOOL_TIMEOUT) {
        Ok(run) if run.success => SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("`{name}` exited 0"),
        },
        Ok(run) => SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: short_detail(&run.stderr, &format!("`{name}` exited non-zero")),
        },
        Err(err) => SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: short_detail(&err.to_string(), &format!("`{name}` failed")),
        },
    }
}

fn short_detail(text: &str, fallback: &str) -> String {
    let redacted = redact_text(text);
    let line = redacted.lines().find(|line| !line.trim().is_empty());
    let Some(line) = line else {
        return fallback.to_string();
    };
    let trimmed = line.trim();
    let mut out: String = trimmed.chars().take(160).collect();
    if trimmed.chars().count() > 160 {
        out.push('…');
    }
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
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

struct ToolOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_readonly(program: &Path, args: &[&str], timeout: Duration) -> std::io::Result<ToolOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_handle = thread::spawn(move || read_pipe(stdout));
    let stderr_handle = thread::spawn(move || read_pipe(stderr));
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_handle.join().unwrap_or_default();
            let stderr = stderr_handle.join().unwrap_or_default();
            return Ok(ToolOutput {
                success: status.success(),
                stdout,
                stderr,
            });
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{} timed out", program.display()),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_pipe(pipe: Option<impl Read>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buf = Vec::new();
    let _ = pipe.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn read_hwmon(root: &Path) -> Vec<HwmonChip> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut chips = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        if let Some(chip) = read_hwmon_chip(&path, &id) {
            chips.push(chip);
        }
    }
    chips.sort_by(|a, b| a.id.cmp(&b.id));
    chips
}

fn read_hwmon_chip(dir: &Path, id: &str) -> Option<HwmonChip> {
    let name = fs::read_to_string(dir.join("name"))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| id.to_string());
    let entries = fs::read_dir(dir).ok()?;
    let mut temps = Vec::new();
    let mut fans = Vec::new();
    for entry in entries.flatten() {
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        if let Some(index) = indexed_file(filename, "temp", "_input") {
            if let Some(celsius) = read_millicelsius(&entry.path()) {
                temps.push(LabeledTemp {
                    label: label_or(dir, "temp", index),
                    celsius,
                });
            }
        } else if let Some(index) = indexed_file(filename, "fan", "_input") {
            if let Some(rpm) = read_rpm(&entry.path()) {
                fans.push(LabeledRpm {
                    label: label_or(dir, "fan", index),
                    rpm,
                });
            }
        }
    }
    if temps.is_empty() && fans.is_empty() && name == id {
        return None;
    }
    temps.sort_by(|a, b| a.label.cmp(&b.label));
    fans.sort_by(|a, b| a.label.cmp(&b.label));
    Some(HwmonChip {
        id: id.to_string(),
        name,
        temps,
        fans,
    })
}

fn label_or(dir: &Path, prefix: &str, index: u32) -> String {
    fs::read_to_string(dir.join(format!("{prefix}{index}_label")))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| format!("{prefix}{index}"))
}

fn read_millicelsius(path: &Path) -> Option<f64> {
    let raw = fs::read_to_string(path).ok()?;
    let milli: f64 = raw.trim().parse().ok()?;
    if !milli.is_finite() {
        return None;
    }
    Some(round1(milli / 1000.0))
}

fn read_rpm(path: &Path) -> Option<u32> {
    let raw = fs::read_to_string(path).ok()?;
    raw.trim().parse().ok()
}

fn indexed_file(name: &str, prefix: &str, suffix: &str) -> Option<u32> {
    let rest = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if rest.is_empty() || !rest.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

fn read_nvidia_module(path: &Path) -> ModulePresence {
    match fs::read_to_string(path) {
        Ok(text) => {
            if nvidia_module_listed(&text) {
                ModulePresence::Listed
            } else {
                ModulePresence::Absent
            }
        }
        Err(_) => ModulePresence::Unreadable,
    }
}

fn nvidia_module_listed(text: &str) -> bool {
    text.lines().any(|line| {
        let name = line.split_whitespace().next().unwrap_or("");
        name == "nvidia" || name.starts_with("nvidia_")
    })
}

pub fn parse_nvidia_csv(stdout: &str) -> Vec<GpuReading> {
    stdout
        .lines()
        .filter_map(|line| parse_nvidia_line(line.trim()))
        .collect()
}

fn parse_nvidia_line(line: &str) -> Option<GpuReading> {
    if line.is_empty() {
        return None;
    }
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    if parts.len() < 5 {
        return None;
    }
    let split_at = parts.len() - 4;
    let name = parts[..split_at].join(", ");
    if name.is_empty() {
        return None;
    }
    Some(GpuReading {
        name,
        temperature_c: parse_metric(parts[split_at]),
        fan_percent: parse_metric(parts[split_at + 1]),
        utilization_percent: parse_metric(parts[split_at + 2]),
        power_w: parse_metric(parts[split_at + 3]),
    })
}

fn parse_metric(raw: &str) -> Option<f64> {
    let trimmed = raw.trim().trim_matches(|ch| ch == '[' || ch == ']');
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("n/a")
        || trimmed.eq_ignore_ascii_case("not supported")
    {
        return None;
    }
    trimmed
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

pub fn parse_load1(text: &str) -> Option<f64> {
    let value = text.split_whitespace().next()?.parse::<f64>().ok()?;
    value.is_finite().then_some(value)
}

pub fn cpu_count_from_cpuinfo(text: &str) -> u32 {
    u32::try_from(
        text.lines()
            .filter(|line| line.starts_with("processor"))
            .count(),
    )
    .unwrap_or(0)
}

#[derive(Debug, Clone)]
struct Tick {
    pid: u32,
    name: String,
    cpu_ticks: u64,
}

fn sample_processes() -> Vec<NamedProcess> {
    let before = snapshot_ticks(Path::new("/proc"));
    let started = Instant::now();
    thread::sleep(PROCESS_SAMPLE);
    let elapsed = started.elapsed().as_secs_f64().max(0.05);
    let after = snapshot_ticks(Path::new("/proc"));
    diff_process_names(
        &before,
        &after,
        elapsed,
        clock_ticks_per_sec(),
        PROCESS_LIMIT,
    )
}

/// Read `/proc/<pid>/stat` only. The name is the comm field, never `cmdline`.
fn snapshot_ticks(proc_root: &Path) -> Vec<Tick> {
    let Ok(entries) = fs::read_dir(proc_root) else {
        return Vec::new();
    };
    let me = std::process::id();
    let mut ticks = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|text| text.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(raw) = fs::read_to_string(entry.path().join("stat")) else {
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
    ticks
}

fn diff_process_names(
    before: &[Tick],
    after: &[Tick],
    elapsed_s: f64,
    hz: f64,
    limit: usize,
) -> Vec<NamedProcess> {
    let prior: HashMap<u32, u64> = before
        .iter()
        .map(|tick| (tick.pid, tick.cpu_ticks))
        .collect();
    let hz = if hz <= 0.0 { 100.0 } else { hz };
    let mut ranked = Vec::new();
    for tick in after {
        let Some(previous) = prior.get(&tick.pid) else {
            continue;
        };
        let delta = tick.cpu_ticks.saturating_sub(*previous) as f64;
        let cpu_percent = if elapsed_s <= 0.0 {
            0.0
        } else {
            (delta / hz) / elapsed_s * 100.0
        };
        if cpu_percent < 1.0 || tick.name.is_empty() {
            continue;
        }
        ranked.push(NamedProcess {
            name: tick.name.clone(),
            cpu_percent: round1(cpu_percent),
        });
    }
    ranked.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    ranked.truncate(limit);
    ranked
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
        if out.chars().count() >= 64 {
            break;
        }
    }
    out
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn clock_ticks_per_sec() -> f64 {
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

extern "C" {
    fn sysconf(name: i32) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn coverage(status: CoverageStatus, detail: &str) -> SourceCoverage {
        SourceCoverage {
            status,
            detail: detail.to_string(),
        }
    }

    fn base_facts() -> FanFacts {
        FanFacts {
            kernel: "7.0.0-38-generic".into(),
            cpu_count: 16,
            load_1m: 2.0,
            sensors: coverage(CoverageStatus::Available, "`sensors` exited 0"),
            nvidia_smi: coverage(
                CoverageStatus::Available,
                "nvidia-smi returned 1 GPU row(s)",
            ),
            hwmon: vec![HwmonChip {
                id: "hwmon4".into(),
                name: "asus".into(),
                temps: vec![LabeledTemp {
                    label: "CPU".into(),
                    celsius: 47.0,
                }],
                fans: vec![LabeledRpm {
                    label: "chassis".into(),
                    rpm: 1200,
                }],
            }],
            gpus: vec![GpuReading {
                name: "NVIDIA GeForce RTX 3060".into(),
                temperature_c: Some(42.0),
                fan_percent: Some(0.0),
                utilization_percent: Some(2.0),
                power_w: Some(15.0),
            }],
            nvidia_module: ModulePresence::Listed,
            processes: vec![NamedProcess {
                name: "cargo".into(),
                cpu_percent: 40.0,
            }],
        }
    }

    #[test]
    fn missing_sensors_or_nvidia_are_unavailable_and_not_clean() {
        let mut facts = base_facts();
        facts.sensors = coverage(CoverageStatus::Unavailable, "`sensors` is not on PATH");
        facts.nvidia_smi = coverage(CoverageStatus::Unavailable, "`nvidia-smi` is not on PATH");
        facts.gpus.clear();
        let report = diagnose(facts);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.sensors.status, CoverageStatus::Unavailable);
        assert_eq!(report.nvidia_smi.status, CoverageStatus::Unavailable);
        assert!(report.gpus.is_empty());
        let value = serde_json::to_value(&report).expect("json");
        assert_eq!(value["sensors"]["status"], "unavailable");
        assert_eq!(value["nvidia_smi"]["status"], "unavailable");
        assert_eq!(value["clean"], false);
        let hypotheses = report.hypotheses.join(" ");
        assert!(hypotheses.contains("sensors tool is unavailable"));
        assert!(hypotheses.contains("nvidia-smi is unavailable"));
        assert!(!hypotheses.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn high_load_is_separate_from_a_missing_tachometer() {
        let mut facts = base_facts();
        facts.load_1m = 24.0;
        facts.cpu_count = 16;
        facts.hwmon[0].fans.clear();
        let report = diagnose(facts);
        assert!(!report.clean);
        assert_eq!(report.chassis_fan.status, CoverageStatus::Unavailable);
        let load = report
            .hypotheses
            .iter()
            .find(|item| item.contains("CPU load"))
            .expect("load hypothesis");
        let tach = report
            .hypotheses
            .iter()
            .find(|item| item.contains("tachometer"))
            .expect("tachometer hypothesis");
        assert_ne!(load, tach);
        assert!(load.contains("elevated"));
        assert!(tach.contains("separate from CPU load"));
        let text = format_fan_human(&report);
        assert!(text.contains("Observations"));
        assert!(text.contains("Hypotheses"));
        assert!(text.contains("changes fan curve: no"));
        assert!(text.contains("uses sudo: no"));
        assert!(text.contains("loads modules: no"));
        assert!(text.contains("writes BIOS: no"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn cool_gpu_with_stopped_fan_is_not_blamed_for_chassis_noise() {
        let report = diagnose(base_facts());
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        let hypothesis = report
            .hypotheses
            .iter()
            .find(|item| item.contains("RTX 3060"))
            .expect("gpu hypothesis");
        assert!(hypothesis.contains("unlikely to be the chassis noise"));
        assert!(hypothesis.contains("0%"));
    }

    #[test]
    fn missing_gpu_fan_speed_is_unavailable_not_zero() {
        let mut facts = base_facts();
        facts.gpus[0].fan_percent = None;
        let report = diagnose(facts);
        let hypothesis = report
            .hypotheses
            .iter()
            .find(|item| item.contains("RTX 3060"))
            .expect("gpu hypothesis");
        assert!(hypothesis.contains("unavailable, not zero"));
        assert!(!hypothesis.contains("0%"));
    }

    #[test]
    fn unavailable_nvidia_does_not_invent_a_zero_fan() {
        let mut facts = base_facts();
        facts.nvidia_smi = coverage(CoverageStatus::Unavailable, "`nvidia-smi` is not on PATH");
        let report = diagnose(facts);
        assert!(report.gpus.is_empty());
        assert!(!report.clean);
        let joined = report.hypotheses.join(" ");
        assert!(joined.contains("not idle"));
        assert!(!joined.contains("unlikely to be the chassis noise"));
    }

    #[test]
    fn report_never_claims_it_changes_the_machine() {
        let report = diagnose(base_facts());
        assert!(!report.changes_fan_curve);
        assert!(!report.uses_sudo);
        assert!(!report.loads_modules);
        assert!(!report.writes_bios);
    }

    #[test]
    fn process_report_has_names_only() {
        let report = diagnose(base_facts());
        let value = serde_json::to_value(&report).expect("json");
        let proc = &value["processes"][0];
        assert_eq!(proc["name"], "cargo");
        assert!(proc.get("cmdline").is_none());
        assert!(proc.get("args").is_none());
        let text = serde_json::to_string(&value).expect("string");
        assert!(!text.contains("cmdline"));
        assert!(text.contains("Command arguments were not collected"));
    }

    #[test]
    fn snapshot_reads_the_stat_name_and_not_command_arguments() {
        let dir = tempdir().unwrap();
        let pid_dir = dir.path().join("42");
        fs::create_dir(&pid_dir).unwrap();
        fs::write(pid_dir.join("cmdline"), b"python\0--token\0supersecret\0").unwrap();
        fs::write(
            pid_dir.join("stat"),
            "42 (python) R 1 1 1 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0 400 0 9\n",
        )
        .unwrap();
        let ticks = snapshot_ticks(dir.path());
        assert_eq!(ticks.len(), 1);
        assert_eq!(ticks[0].name, "python");
        let dumped = format!("{ticks:?}");
        assert!(!dumped.contains("supersecret"));
        assert!(!dumped.contains("--token"));
    }

    #[test]
    fn diff_ranks_names_by_cpu_share() {
        let before = vec![Tick {
            pid: 7,
            name: "python".into(),
            cpu_ticks: 100,
        }];
        let after = vec![
            Tick {
                pid: 7,
                name: "python".into(),
                cpu_ticks: 300,
            },
            Tick {
                pid: 8,
                name: "cargo".into(),
                cpu_ticks: 50,
            },
        ];
        let ranked = diff_process_names(&before, &after, 1.0, 100.0, 8);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].name, "python");
        assert!((ranked[0].cpu_percent - 200.0).abs() < 0.2);
    }

    #[test]
    fn parse_stat_keeps_a_name_with_spaces() {
        let raw = "42 (Web Content) R 1 1 1 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0 400 0 9\n";
        let parsed = parse_proc_stat(raw).expect("stat");
        assert_eq!(parsed.comm, "Web Content");
        assert_eq!(parsed.utime, 100);
        assert_eq!(parsed.stime, 50);
    }

    #[test]
    fn nvidia_csv_treats_missing_fan_as_absent() {
        let gpus = parse_nvidia_csv("NVIDIA GeForce RTX 3060, 42, [N/A], 3, 18.50\n");
        assert_eq!(gpus.len(), 1);
        assert_eq!(gpus[0].name, "NVIDIA GeForce RTX 3060");
        assert_eq!(gpus[0].temperature_c, Some(42.0));
        assert_eq!(gpus[0].fan_percent, None);
        assert_eq!(gpus[0].utilization_percent, Some(3.0));
        assert_eq!(gpus[0].power_w, Some(18.5));
    }

    #[test]
    fn hwmon_without_fan_files_is_an_unavailable_tachometer() {
        let dir = tempdir().unwrap();
        let asus = dir.path().join("hwmon2");
        fs::create_dir_all(&asus).unwrap();
        fs::write(asus.join("name"), "asus\n").unwrap();
        fs::write(asus.join("temp1_input"), "47000\n").unwrap();
        fs::write(asus.join("temp1_label"), "CPU\n").unwrap();
        fs::write(asus.join("pwm1"), "128\n").unwrap();
        let core = dir.path().join("hwmon0");
        fs::create_dir_all(&core).unwrap();
        fs::write(core.join("name"), "coretemp\n").unwrap();
        fs::write(core.join("temp1_input"), "61000\n").unwrap();
        fs::write(core.join("temp1_label"), "Package id 0\n").unwrap();
        let chips = read_hwmon(dir.path());
        assert_eq!(chips.len(), 2);
        assert!(chips.iter().all(|chip| chip.fans.is_empty()));
        assert_eq!(chips[1].name, "asus");
        assert_eq!(chips[1].temps[0].celsius, 47.0);
        let coverage = chassis_coverage(&chips);
        assert_eq!(coverage.status, CoverageStatus::Unavailable);
        let joined = chips.iter().map(chip_summary).collect::<Vec<_>>().join(" ");
        assert!(joined.contains("no fan RPM files"));
        assert!(!joined.contains("128"));
    }

    #[test]
    fn load_and_cpu_count_parsers() {
        assert_eq!(parse_load1("24.10 18.00 12.00 5/100 1\n"), Some(24.10));
        assert_eq!(
            cpu_count_from_cpuinfo("processor\t: 0\nprocessor\t: 1\n"),
            2
        );
    }
}
