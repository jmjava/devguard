//! One-shot NVIDIA reading for `devguard gpu scan`.
//!
//! The command does not use sudo or load a kernel module. It hashes each GPU
//! UUID and never stores or prints the raw value. A missing `nvidia-smi` or a
//! missing field is `unavailable`, and that result is not clean.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::exit::ExitCode;
use crate::redact::redact_text;

const TOOL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
/// Columns after the GPU name. The name itself may contain commas.
const TRAILING_FIELDS: usize = 13;
const GPU_QUERY: &str = "index,uuid,name,driver_version,utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw,power.limit,clocks.sm,clocks.mem,fan.speed,ecc.mode.current,clocks_event_reasons.active";

const THROTTLE_BITS: &[(u64, &str)] = &[
    (0x1, "gpu_idle"),
    (0x2, "applications_clocks_setting"),
    (0x4, "sw_power_cap"),
    (0x8, "hw_slowdown"),
    (0x10, "sync_boost"),
    (0x20, "sw_thermal_slowdown"),
    (0x40, "hw_thermal_slowdown"),
    (0x80, "hw_power_brake_slowdown"),
    (0x100, "display_clock_setting"),
];

/// `available` or `unavailable`. A missing tool is never a clean result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCoverage {
    pub status: CoverageStatus,
    pub detail: String,
}

/// One nvidia-smi field. Missing readings stay `unavailable` and keep no value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Field<T> {
    pub status: CoverageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
}

impl<T> Field<T> {
    fn available(value: T) -> Self {
        Self {
            status: CoverageStatus::Available,
            value: Some(value),
        }
    }

    fn unavailable() -> Self {
        Self {
            status: CoverageStatus::Unavailable,
            value: None,
        }
    }

    fn is_available(&self) -> bool {
        self.status == CoverageStatus::Available && self.value.is_some()
    }
}

/// One GPU row. `index` is the nvidia-smi index, kept in ascending order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpuDevice {
    pub index: u32,
    pub name: Field<String>,
    /// SHA-256 hex of the trimmed UUID. The raw UUID is not retained.
    pub uuid_hash: Field<String>,
    pub driver: Field<String>,
    pub utilization_gpu_percent: Field<f64>,
    pub utilization_memory_percent: Field<f64>,
    pub memory_used_bytes: Field<u64>,
    pub memory_total_bytes: Field<u64>,
    pub temperature_c: Field<f64>,
    pub power_draw_w: Field<f64>,
    pub power_limit_w: Field<f64>,
    pub clocks_sm_mhz: Field<f64>,
    pub clocks_mem_mhz: Field<f64>,
    pub fan_speed_percent: Field<f64>,
    pub ecc: Field<String>,
    pub throttle_reasons: Field<String>,
}

impl GpuDevice {
    fn fields_available(&self) -> bool {
        self.name.is_available()
            && self.uuid_hash.is_available()
            && self.driver.is_available()
            && self.utilization_gpu_percent.is_available()
            && self.utilization_memory_percent.is_available()
            && self.memory_used_bytes.is_available()
            && self.memory_total_bytes.is_available()
            && self.temperature_c.is_available()
            && self.power_draw_w.is_available()
            && self.power_limit_w.is_available()
            && self.clocks_sm_mhz.is_available()
            && self.clocks_mem_mhz.is_available()
            && self.fan_speed_percent.is_available()
            && self.ecc.is_available()
            && self.throttle_reasons.is_available()
    }
}

/// Human and JSON body for `devguard gpu scan`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GpuScanReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never loads a kernel module.
    pub loads_modules: bool,
    /// False when `nvidia-smi` is missing or any field is unavailable.
    pub clean: bool,
    pub nvidia_smi: ToolCoverage,
    pub cuda_version: Field<String>,
    pub gpus: Vec<GpuDevice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub row_warnings: Vec<String>,
}

impl GpuScanReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.nvidia_smi.status == CoverageStatus::Unavailable {
            warnings.push(format!(
                "nvidia-smi unavailable: {}",
                self.nvidia_smi.detail
            ));
        }
        if !self.cuda_version.is_available() {
            warnings.push("CUDA version is unavailable".to_string());
        }
        warnings.extend(self.row_warnings.iter().cloned());
        for gpu in &self.gpus {
            push_missing(&mut warnings, gpu.index, "name", gpu.name.is_available());
            push_missing(
                &mut warnings,
                gpu.index,
                "uuid hash",
                gpu.uuid_hash.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "driver",
                gpu.driver.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "utilization",
                gpu.utilization_gpu_percent.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "memory utilization",
                gpu.utilization_memory_percent.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "memory used",
                gpu.memory_used_bytes.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "memory total",
                gpu.memory_total_bytes.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "temperature",
                gpu.temperature_c.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "power draw",
                gpu.power_draw_w.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "power limit",
                gpu.power_limit_w.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "SM clock",
                gpu.clocks_sm_mhz.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "memory clock",
                gpu.clocks_mem_mhz.is_available(),
            );
            push_missing(
                &mut warnings,
                gpu.index,
                "fan speed",
                gpu.fan_speed_percent.is_available(),
            );
            push_missing(&mut warnings, gpu.index, "ECC", gpu.ecc.is_available());
            push_missing(
                &mut warnings,
                gpu.index,
                "throttle reasons",
                gpu.throttle_reasons.is_available(),
            );
        }
        warnings
    }
}

fn push_missing(warnings: &mut Vec<String>, index: u32, label: &str, available: bool) {
    if !available {
        warnings.push(format!("GPU {index} {label} is unavailable"));
    }
}

/// Read this host once. A missing tool or field stays `unavailable`.
pub fn scan_gpu() -> GpuScanReport {
    let Some(path) = find_tool("nvidia-smi") else {
        return missing_tool_report();
    };
    let csv = run_readonly(
        &path,
        &[
            &format!("--query-gpu={GPU_QUERY}"),
            "--format=csv,noheader,nounits",
        ],
        TOOL_TIMEOUT,
        MAX_CAPTURE_BYTES,
    );
    let cuda = run_readonly(&path, &["--version"], TOOL_TIMEOUT, MAX_CAPTURE_BYTES);
    report_from_captures(csv, cuda)
}

fn missing_tool_report() -> GpuScanReport {
    report_from_parsed(
        ToolCoverage {
            status: CoverageStatus::Unavailable,
            detail: "`nvidia-smi` is not on PATH".to_string(),
        },
        Field::unavailable(),
        Vec::new(),
        Vec::new(),
    )
}

fn report_from_captures(
    csv: std::io::Result<ToolOutput>,
    cuda: std::io::Result<ToolOutput>,
) -> GpuScanReport {
    let cuda_version = match cuda {
        Ok(run) if run.success && !run.truncated => parse_cuda_version(&run.stdout),
        _ => Field::unavailable(),
    };
    match csv {
        Ok(run) if run.truncated => report_from_parsed(
            ToolCoverage {
                status: CoverageStatus::Unavailable,
                detail: "nvidia-smi output exceeded the capture limit".to_string(),
            },
            cuda_version,
            Vec::new(),
            Vec::new(),
        ),
        Ok(run) if run.success => {
            let parsed = parse_gpu_csv(&run.stdout);
            let status = if parsed.gpus.is_empty() {
                ToolCoverage {
                    status: CoverageStatus::Unavailable,
                    detail: "nvidia-smi returned no GPU rows".to_string(),
                }
            } else {
                ToolCoverage {
                    status: CoverageStatus::Available,
                    detail: format!("nvidia-smi returned {} GPU row(s)", parsed.gpus.len()),
                }
            };
            report_from_parsed(status, cuda_version, parsed.gpus, parsed.row_warnings)
        }
        Ok(run) => report_from_parsed(
            ToolCoverage {
                status: CoverageStatus::Unavailable,
                detail: short_detail(&run.stderr, "nvidia-smi exited non-zero"),
            },
            cuda_version,
            Vec::new(),
            Vec::new(),
        ),
        Err(err) => report_from_parsed(
            ToolCoverage {
                status: CoverageStatus::Unavailable,
                detail: short_detail(&err.to_string(), "nvidia-smi failed"),
            },
            cuda_version,
            Vec::new(),
            Vec::new(),
        ),
    }
}

fn report_from_parsed(
    nvidia_smi: ToolCoverage,
    cuda_version: Field<String>,
    gpus: Vec<GpuDevice>,
    row_warnings: Vec<String>,
) -> GpuScanReport {
    let clean = nvidia_smi.status == CoverageStatus::Available
        && cuda_version.is_available()
        && !gpus.is_empty()
        && row_warnings.is_empty()
        && gpus.iter().all(GpuDevice::fields_available);
    GpuScanReport {
        uses_sudo: false,
        loads_modules: false,
        clean,
        nvidia_smi,
        cuda_version,
        gpus,
        row_warnings,
    }
}

#[derive(Debug)]
struct ParsedCsv {
    gpus: Vec<GpuDevice>,
    row_warnings: Vec<String>,
}

/// Parse sanitized `nvidia-smi --query-gpu=... --format=csv,noheader,nounits` output.
///
/// Memory values are MiB in that format and are converted to bytes. Rows are
/// sorted by the nvidia-smi index. The raw UUID is hashed and dropped.
fn parse_gpu_csv(stdout: &str) -> ParsedCsv {
    let mut indexed = Vec::new();
    let mut row_warnings = Vec::new();
    for (order, line) in stdout.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_gpu_line(line) {
            Ok(device) => indexed.push((order, device)),
            Err(reason) => row_warnings.push(format!("skipped GPU row {}: {reason}", order + 1)),
        }
    }
    indexed.sort_by(|a, b| a.1.index.cmp(&b.1.index).then(a.0.cmp(&b.0)));
    ParsedCsv {
        gpus: indexed.into_iter().map(|(_, device)| device).collect(),
        row_warnings,
    }
}

fn parse_gpu_line(line: &str) -> Result<GpuDevice, &'static str> {
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    if parts.len() < 2 + TRAILING_FIELDS {
        return Err("too few columns");
    }
    let trailing_at = parts.len() - TRAILING_FIELDS;
    if trailing_at < 2 {
        return Err("too few columns");
    }
    let index: u32 = parts[0].parse().map_err(|_| "index is not a number")?;
    let name = parts[2..trailing_at].join(", ");
    let tail = &parts[trailing_at..];
    Ok(GpuDevice {
        index,
        name: text_field(&name),
        uuid_hash: uuid_hash_field(parts[1]),
        driver: text_field(tail[0]),
        utilization_gpu_percent: number_field(tail[1]),
        utilization_memory_percent: number_field(tail[2]),
        memory_used_bytes: mib_field(tail[3]),
        memory_total_bytes: mib_field(tail[4]),
        temperature_c: number_field(tail[5]),
        power_draw_w: number_field(tail[6]),
        power_limit_w: number_field(tail[7]),
        clocks_sm_mhz: number_field(tail[8]),
        clocks_mem_mhz: number_field(tail[9]),
        fan_speed_percent: number_field(tail[10]),
        ecc: text_field(tail[11]),
        throttle_reasons: throttle_field(tail[12]),
    })
}

fn uuid_hash_field(raw: &str) -> Field<String> {
    let trimmed = strip_brackets(raw);
    if is_missing_token(trimmed) {
        return Field::unavailable();
    }
    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    Field::available(format!("{:x}", hasher.finalize()))
}

fn text_field(raw: &str) -> Field<String> {
    let trimmed = strip_brackets(raw);
    if is_missing_token(trimmed) {
        Field::unavailable()
    } else {
        Field::available(redact_text(trimmed))
    }
}

fn number_field(raw: &str) -> Field<f64> {
    match parse_number(raw) {
        Some(value) => Field::available(value),
        None => Field::unavailable(),
    }
}

fn mib_field(raw: &str) -> Field<u64> {
    match parse_number(raw).and_then(mib_to_bytes) {
        Some(bytes) => Field::available(bytes),
        None => Field::unavailable(),
    }
}

fn throttle_field(raw: &str) -> Field<String> {
    let trimmed = strip_brackets(raw);
    if is_missing_token(trimmed) {
        return Field::unavailable();
    }
    if trimmed.eq_ignore_ascii_case("not active") {
        return Field::available("none".to_string());
    }
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));
    if let Some(hex) = hex {
        return match u64::from_str_radix(hex, 16) {
            Ok(bits) => Field::available(decode_throttle(bits)),
            Err(_) => Field::unavailable(),
        };
    }
    Field::available(redact_text(trimmed))
}

fn decode_throttle(bits: u64) -> String {
    if bits == 0 {
        return "none".to_string();
    }
    let mut names = Vec::new();
    let mut known = 0u64;
    for (bit, name) in THROTTLE_BITS {
        if bits & bit != 0 {
            names.push(*name);
            known |= bit;
        }
    }
    let unknown = bits & !known;
    if unknown != 0 {
        names.push("unknown");
    }
    if names.is_empty() {
        "unknown".to_string()
    } else {
        names.join(", ")
    }
}

fn parse_cuda_version(text: &str) -> Field<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(start) = lower.find("cuda version") else {
            continue;
        };
        let rest = line[start + "cuda version".len()..].trim();
        let value = rest.trim_start_matches(':').trim();
        let value = strip_brackets(value);
        if !is_missing_token(value) {
            return Field::available(redact_text(value));
        }
    }
    Field::unavailable()
}

fn parse_number(raw: &str) -> Option<f64> {
    let trimmed = strip_brackets(raw);
    if is_missing_token(trimmed) {
        return None;
    }
    trimmed
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
}

fn mib_to_bytes(mib: f64) -> Option<u64> {
    if !mib.is_finite() || mib < 0.0 {
        return None;
    }
    let bytes = mib * 1024.0 * 1024.0;
    if !bytes.is_finite() || bytes > u64::MAX as f64 {
        return None;
    }
    Some(bytes.round() as u64)
}

fn strip_brackets(raw: &str) -> &str {
    raw.trim().trim_matches(|ch| ch == '[' || ch == ']').trim()
}

fn is_missing_token(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("n/a")
        || trimmed.eq_ignore_ascii_case("na")
        || trimmed.eq_ignore_ascii_case("not supported")
        || trimmed.eq_ignore_ascii_case("not available")
        || trimmed.eq_ignore_ascii_case("unknown")
}

/// Replace a raw `GPU-…` UUID so captured stderr cannot leak it.
fn strip_gpu_uuids(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(len) = gpu_uuid_len(&text[i..]) {
            out.push_str("[uuid]");
            i += len;
        } else {
            let Some(ch) = text[i..].chars().next() else {
                break;
            };
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    redact_text(&out)
}

fn gpu_uuid_len(text: &str) -> Option<usize> {
    let rest = text.strip_prefix("GPU-")?;
    let widths = [8, 4, 4, 4, 12];
    let mut offset = 0;
    for (index, width) in widths.iter().enumerate() {
        if index > 0 {
            if !rest[offset..].starts_with('-') {
                return None;
            }
            offset += 1;
        }
        let chunk = rest.get(offset..offset + width)?;
        if !chunk.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return None;
        }
        offset += width;
    }
    Some("GPU-".len() + offset)
}

fn short_detail(text: &str, fallback: &str) -> String {
    let redacted = strip_gpu_uuids(text);
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

pub fn format_gpu_human(report: &GpuScanReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard GPU scan\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  loads modules: no\n");
    out.push_str(&format!(
        "  nvidia-smi: {} — {}\n",
        status_word(report.nvidia_smi.status),
        report.nvidia_smi.detail
    ));
    out.push_str(&format!(
        "  cuda version: {}\n",
        field_text(&report.cuda_version)
    ));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    if report.gpus.is_empty() {
        out.push_str("\nNo GPU rows.\n");
    }
    for gpu in &report.gpus {
        out.push_str(&format!("\nGPU {}\n", gpu.index));
        out.push_str(&format!("  name: {}\n", field_text(&gpu.name)));
        out.push_str(&format!("  uuid hash: {}\n", field_text(&gpu.uuid_hash)));
        out.push_str(&format!("  driver: {}\n", field_text(&gpu.driver)));
        out.push_str(&format!(
            "  utilization: gpu {}%, memory {}%\n",
            num_field(&gpu.utilization_gpu_percent),
            num_field(&gpu.utilization_memory_percent)
        ));
        out.push_str(&format!(
            "  memory: {} used / {} total\n",
            bytes_field(&gpu.memory_used_bytes),
            bytes_field(&gpu.memory_total_bytes)
        ));
        out.push_str(&format!(
            "  temperature: {}\n",
            with_unit(&gpu.temperature_c, "C")
        ));
        out.push_str(&format!(
            "  power: {} draw / {} limit\n",
            with_unit(&gpu.power_draw_w, "W"),
            with_unit(&gpu.power_limit_w, "W")
        ));
        out.push_str(&format!(
            "  clocks: sm {}, memory {}\n",
            with_unit(&gpu.clocks_sm_mhz, "MHz"),
            with_unit(&gpu.clocks_mem_mhz, "MHz")
        ));
        out.push_str(&format!(
            "  fan speed: {}\n",
            with_unit(&gpu.fan_speed_percent, "%")
        ));
        out.push_str(&format!("  ecc: {}\n", field_text(&gpu.ecc)));
        out.push_str(&format!(
            "  throttle reasons: {}\n",
            field_text(&gpu.throttle_reasons)
        ));
    }
    for warning in &report.row_warnings {
        out.push_str(&format!("\n- {warning}\n"));
    }
    if !report.clean {
        out.push_str("\nA missing tool or field is unavailable, not a clean result.\n");
    }
    out
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn field_text(field: &Field<String>) -> String {
    match (&field.status, &field.value) {
        (CoverageStatus::Available, Some(value)) => value.clone(),
        _ => "unavailable".to_string(),
    }
}

fn num_field(field: &Field<f64>) -> String {
    match (&field.status, field.value) {
        (CoverageStatus::Available, Some(value)) => fmt_num(value),
        _ => "unavailable".to_string(),
    }
}

fn with_unit(field: &Field<f64>, unit: &str) -> String {
    match (&field.status, field.value) {
        (CoverageStatus::Available, Some(value)) => format!("{} {unit}", fmt_num(value)),
        _ => "unavailable".to_string(),
    }
}

fn bytes_field(field: &Field<u64>) -> String {
    match (&field.status, field.value) {
        (CoverageStatus::Available, Some(bytes)) => format!("{bytes} bytes"),
        _ => "unavailable".to_string(),
    }
}

fn fmt_num(value: f64) -> String {
    if !value.is_finite() {
        return "unavailable".to_string();
    }
    if (value - value.round()).abs() < 1e-6 {
        return format!("{}", value.round() as i64);
    }
    let text = format!("{value:.2}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
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

#[derive(Debug)]
struct ToolOutput {
    success: bool,
    stdout: String,
    stderr: String,
    truncated: bool,
}

fn run_readonly(
    program: &Path,
    args: &[&str],
    timeout: Duration,
    limit: usize,
) -> std::io::Result<ToolOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let truncated = Arc::new(AtomicBool::new(false));
    let stdout_flag = Arc::clone(&truncated);
    let stderr_flag = Arc::clone(&truncated);
    let stdout_handle = thread::spawn(move || read_bounded(stdout, limit, &stdout_flag));
    let stderr_handle = thread::spawn(move || read_bounded(stderr, limit, &stderr_flag));
    let started = Instant::now();
    loop {
        if truncated.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = stdout_handle.join().unwrap_or_default();
            let stderr = stderr_handle.join().unwrap_or_default();
            return Ok(ToolOutput {
                success: false,
                stdout,
                stderr,
                truncated: true,
            });
        }
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_handle.join().unwrap_or_default();
            let stderr = stderr_handle.join().unwrap_or_default();
            return Ok(ToolOutput {
                success: status.success() && !truncated.load(Ordering::Relaxed),
                stdout,
                stderr,
                truncated: truncated.load(Ordering::Relaxed),
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

fn read_bounded(pipe: Option<impl Read>, limit: usize, truncated: &AtomicBool) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
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
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../fixtures/nvidia-smi-gpu-scan.csv");
    const MISSING: &str = include_str!("../fixtures/nvidia-smi-gpu-scan-missing.csv");
    const VERSION: &str = include_str!("../fixtures/nvidia-smi-version.txt");
    const UUID_A: &str = "GPU-00000000-0000-4000-8000-000000000001";
    const UUID_B: &str = "GPU-00000000-0000-4000-8000-000000000002";
    const HASH_A: &str = "b6e5efe3a3d5a3103b3d7f7b8b50d0b5dae3c6799faf40159fca748305ae1aeb";
    const HASH_B: &str = "a975476395a1c9d83ee8f72570c8d4c9b95484707de43a1e792becca8076f5d3";

    fn fixture_report() -> GpuScanReport {
        let parsed = parse_gpu_csv(FIXTURE);
        report_from_parsed(
            ToolCoverage {
                status: CoverageStatus::Available,
                detail: format!("nvidia-smi returned {} GPU row(s)", parsed.gpus.len()),
            },
            parse_cuda_version(VERSION),
            parsed.gpus,
            parsed.row_warnings,
        )
    }

    #[test]
    fn fixture_keeps_index_order_and_hashes_uuids() {
        let report = fixture_report();
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(!report.uses_sudo);
        assert!(!report.loads_modules);
        assert_eq!(report.gpus.len(), 2);
        assert_eq!(report.gpus[0].index, 0);
        assert_eq!(report.gpus[1].index, 1);
        assert_eq!(
            report.gpus[0].name.value.as_deref(),
            Some("NVIDIA Example GPU A")
        );
        assert_eq!(
            report.gpus[1].name.value.as_deref(),
            Some("NVIDIA Example GPU B")
        );
        assert_eq!(report.gpus[0].uuid_hash.value.as_deref(), Some(HASH_A));
        assert_eq!(report.gpus[1].uuid_hash.value.as_deref(), Some(HASH_B));
        assert_eq!(report.cuda_version.value.as_deref(), Some("12.4"));
        assert_eq!(report.gpus[0].fan_speed_percent.value, Some(0.0));
        assert_eq!(
            report.gpus[0].memory_used_bytes.value,
            Some(512 * 1024 * 1024)
        );
        assert_eq!(
            report.gpus[0].memory_total_bytes.value,
            Some(8192 * 1024 * 1024)
        );
        assert_eq!(
            report.gpus[0].throttle_reasons.value.as_deref(),
            Some("none")
        );
        assert_eq!(
            report.gpus[1].throttle_reasons.value.as_deref(),
            Some("sw_power_cap")
        );
        assert_eq!(report.gpus[0].ecc.value.as_deref(), Some("Disabled"));
        assert_eq!(report.gpus[1].ecc.value.as_deref(), Some("Enabled"));
        let dumped = format!(
            "{}{}",
            serde_json::to_string(&report).expect("json"),
            format_gpu_human(&report)
        );
        assert!(!dumped.contains(UUID_A));
        assert!(!dumped.contains(UUID_B));
        assert!(!dumped.contains("\"uuid\""));
        assert!(dumped.contains(HASH_A));
    }

    #[test]
    fn missing_field_is_unavailable_and_not_clean() {
        let parsed = parse_gpu_csv(MISSING);
        let report = report_from_parsed(
            ToolCoverage {
                status: CoverageStatus::Available,
                detail: "nvidia-smi returned 1 GPU row(s)".to_string(),
            },
            parse_cuda_version(VERSION),
            parsed.gpus,
            parsed.row_warnings,
        );
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let gpu = &report.gpus[0];
        assert_eq!(gpu.utilization_gpu_percent.value, Some(1.0));
        assert!(!gpu.utilization_memory_percent.is_available());
        assert!(gpu.memory_used_bytes.is_available());
        assert!(!gpu.memory_total_bytes.is_available());
        assert!(!gpu.temperature_c.is_available());
        assert!(gpu.power_draw_w.is_available());
        assert!(!gpu.power_limit_w.is_available());
        assert!(gpu.clocks_sm_mhz.is_available());
        assert!(!gpu.clocks_mem_mhz.is_available());
        assert!(!gpu.fan_speed_percent.is_available());
        assert!(!gpu.ecc.is_available());
        assert!(!gpu.throttle_reasons.is_available());
        let text = format_gpu_human(&report);
        assert!(text.contains("fan speed: unavailable"));
        assert!(text.contains("not a clean result"));
        assert!(!text.contains(UUID_A));
        assert!(report
            .warnings()
            .iter()
            .any(|item| item.contains("fan speed")));
    }

    #[test]
    fn zero_fan_speed_stays_a_reading() {
        let report = fixture_report();
        assert!(report.gpus[0].fan_speed_percent.is_available());
        assert_eq!(report.gpus[0].fan_speed_percent.value, Some(0.0));
        assert!(format_gpu_human(&report).contains("fan speed: 0 %"));
    }

    #[test]
    fn name_with_commas_stays_intact() {
        let line = "0, GPU-00000000-0000-4000-8000-000000000001, NVIDIA Example, Laptop GPU, 550.54.00, 1, 2, 512, 8192, 40, 15.00, 170.00, 210, 405, 0, Disabled, 0x0000000000000000\n";
        let parsed = parse_gpu_csv(line);
        assert!(parsed.row_warnings.is_empty());
        assert_eq!(
            parsed.gpus[0].name.value.as_deref(),
            Some("NVIDIA Example, Laptop GPU")
        );
        assert!(!format!("{parsed:?}").contains(UUID_A));
    }

    #[test]
    fn missing_tool_is_not_a_clean_result() {
        let report = missing_tool_report();
        assert!(!report.clean);
        assert!(report.gpus.is_empty());
        assert_eq!(report.nvidia_smi.status, CoverageStatus::Unavailable);
        assert!(!report.cuda_version.is_available());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let text = format_gpu_human(&report);
        assert!(text.contains("uses sudo: no"));
        assert!(text.contains("loads modules: no"));
        assert!(text.contains("unavailable"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn missing_cuda_version_is_not_clean() {
        let parsed = parse_gpu_csv(FIXTURE);
        let report = report_from_parsed(
            ToolCoverage {
                status: CoverageStatus::Available,
                detail: "nvidia-smi returned 2 GPU row(s)".to_string(),
            },
            parse_cuda_version("NVIDIA-SMI version  : 550.54.00\n"),
            parsed.gpus,
            parsed.row_warnings,
        );
        assert!(!report.cuda_version.is_available());
        assert!(!report.clean);
    }

    #[test]
    fn truncated_capture_is_unavailable() {
        let report = report_from_captures(
            Ok(ToolOutput {
                success: true,
                stdout: FIXTURE.to_string(),
                stderr: String::new(),
                truncated: true,
            }),
            Ok(ToolOutput {
                success: true,
                stdout: VERSION.to_string(),
                stderr: String::new(),
                truncated: false,
            }),
        );
        assert!(!report.clean);
        assert!(report.gpus.is_empty());
        assert_eq!(report.nvidia_smi.status, CoverageStatus::Unavailable);
        assert!(report.nvidia_smi.detail.contains("capture limit"));
        assert!(!format_gpu_human(&report).contains(UUID_A));
    }

    #[test]
    fn stderr_detail_strips_a_raw_uuid() {
        let report = report_from_captures(
            Ok(ToolOutput {
                success: false,
                stdout: String::new(),
                stderr: format!("failed for {UUID_A}\n"),
                truncated: false,
            }),
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "nvidia-smi timed out",
            )),
        );
        assert!(!report.clean);
        assert!(!report.nvidia_smi.detail.contains(UUID_A));
        assert!(report.nvidia_smi.detail.contains("[uuid]"));
        assert!(!report.cuda_version.is_available());
    }

    #[test]
    fn unreadable_index_does_not_invent_order() {
        let parsed = parse_gpu_csv("nope, GPU-00000000-0000-4000-8000-000000000001, Name, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, Disabled, 0x0\n");
        assert!(parsed.gpus.is_empty());
        assert!(!parsed.row_warnings.is_empty());
        assert!(!parsed.row_warnings[0].contains(UUID_A));
    }

    #[test]
    fn readonly_command_times_out() {
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .expect("sleep");
        let started = Instant::now();
        let err = run_readonly(sleep, &["30"], Duration::from_millis(300), 1024).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn readonly_command_bounds_capture() {
        let dd = ["/bin/dd", "/usr/bin/dd"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .expect("dd");
        let run = run_readonly(
            dd,
            &["if=/dev/zero", "bs=1024", "count=128"],
            Duration::from_secs(3),
            4096,
        )
        .expect("dd");
        assert!(run.truncated);
        assert!(run.stdout.len() <= 4096);
    }

    #[test]
    fn gpu_name_from_tool_text_hides_token_shapes() {
        let secret = format!("sk-{}", "c".repeat(32));
        let line = format!(
            "0, deadbeef, {secret}, 550.54.14, 0, 0, 1, 2, 40, 15, 170, 1000, 5000, 0, Enabled, 0x0"
        );
        let device = parse_gpu_line(&line).expect("row");
        let shown = device.name.value.unwrap_or_default();
        assert!(!shown.contains(&secret), "gpu report kept a fixture secret");
        assert!(shown.contains("[REDACTED]"));
    }
}
