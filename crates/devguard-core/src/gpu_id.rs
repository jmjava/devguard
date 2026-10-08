//! NVIDIA identity for `devguard health gpu-id`.
//!
//! The record is the driver version, GPU name, and PCI bus id used to diff an
//! upgrade. It reads one `nvidia-smi` query and does not use sudo or load a
//! kernel module. A missing `nvidia-smi` or a missing field is `unavailable`,
//! and that result is not clean.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::redact::redact_text;

const TOOL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
/// `driver_version` and `pci.bus_id`. The GPU name may contain commas.
const TRAILING_FIELDS: usize = 2;
/// Columns requested from `nvidia-smi --query-gpu`.
pub const GPU_ID_QUERY: &str = "name,driver_version,pci.bus_id";

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

/// One query field. A missing reading stays `unavailable` and keeps no value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Field {
    pub status: CoverageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl Field {
    fn available(value: impl Into<String>) -> Self {
        Self {
            status: CoverageStatus::Available,
            value: Some(value.into()),
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

/// One GPU identity row, ordered by PCI bus id when that field is present.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuIdentity {
    pub name: Field,
    pub driver_version: Field,
    pub pci_bus_id: Field,
}

impl GpuIdentity {
    fn complete(&self) -> bool {
        self.name.is_available()
            && self.driver_version.is_available()
            && self.pci_bus_id.is_available()
    }
}

/// Human and JSON body for `devguard health gpu-id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuIdReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never loads a kernel module.
    pub loads_modules: bool,
    /// False when `nvidia-smi` is missing or any identity field is unavailable.
    pub clean: bool,
    pub nvidia_smi: ToolCoverage,
    pub gpus: Vec<GpuIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub row_warnings: Vec<String>,
}

impl GpuIdReport {
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
        warnings.extend(self.row_warnings.iter().cloned());
        for (index, gpu) in self.gpus.iter().enumerate() {
            let label = gpu_label(gpu, index);
            if !gpu.name.is_available() {
                warnings.push(format!("{label} name is unavailable"));
            }
            if !gpu.driver_version.is_available() {
                warnings.push(format!("{label} driver version is unavailable"));
            }
            if !gpu.pci_bus_id.is_available() {
                warnings.push(format!("{label} pci bus id is unavailable"));
            }
        }
        warnings
    }
}

fn gpu_label(gpu: &GpuIdentity, index: usize) -> String {
    if let Some(bus) = gpu.pci_bus_id.value.as_deref() {
        format!("GPU {bus}")
    } else if let Some(name) = gpu.name.value.as_deref() {
        format!("GPU {name}")
    } else {
        format!("GPU row {}", index + 1)
    }
}

/// Read this host once. A missing tool or field stays `unavailable`.
///
/// `DEVGUARD_NVIDIA_SMI_BIN`, when set, must be an absolute path to the
/// program that prints the identity query. Tests point it at a fixture
/// printer so they do not call `nvidia-smi`.
pub fn scan_gpu_id() -> GpuIdReport {
    match locate_nvidia_smi() {
        NvidiaBin::Found(path) => scan_program(&path),
        NvidiaBin::Missing(detail) => missing_tool_report(detail),
    }
}

/// Identity record parsed from an `nvidia-smi` query fixture.
///
/// The text is `nvidia-smi --query-gpu=name,driver_version,pci.bus_id
/// --format=csv,noheader`. The tool is treated as present.
pub fn report_from_query(stdout: &str) -> GpuIdReport {
    let parsed = parse_gpu_id_query(stdout);
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
    finish(status, parsed.gpus, parsed.row_warnings)
}

fn missing_tool_report(detail: impl Into<String>) -> GpuIdReport {
    finish(
        ToolCoverage {
            status: CoverageStatus::Unavailable,
            detail: detail.into(),
        },
        Vec::new(),
        Vec::new(),
    )
}

pub fn format_gpu_id_human(report: &GpuIdReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard health gpu-id\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  loads modules: no\n");
    out.push_str(&format!(
        "  nvidia-smi: {} — {}\n",
        status_word(report.nvidia_smi.status),
        report.nvidia_smi.detail
    ));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    if report.gpus.is_empty() {
        out.push_str("\nNo GPU rows.\n");
    }
    for gpu in &report.gpus {
        out.push_str("\nGPU\n");
        out.push_str(&format!("  name: {}\n", field_text(&gpu.name)));
        out.push_str(&format!(
            "  driver version: {}\n",
            field_text(&gpu.driver_version)
        ));
        out.push_str(&format!("  pci bus id: {}\n", field_text(&gpu.pci_bus_id)));
    }
    for warning in &report.row_warnings {
        out.push_str(&format!("\n- {warning}\n"));
    }
    if !report.clean {
        out.push_str("\nA missing tool or field is unavailable, not a clean result.\n");
    }
    out
}

fn finish(
    nvidia_smi: ToolCoverage,
    mut gpus: Vec<GpuIdentity>,
    row_warnings: Vec<String>,
) -> GpuIdReport {
    gpus.sort_by_key(identity_key);
    let clean = nvidia_smi.status == CoverageStatus::Available
        && !gpus.is_empty()
        && row_warnings.is_empty()
        && gpus.iter().all(GpuIdentity::complete);
    GpuIdReport {
        uses_sudo: false,
        loads_modules: false,
        clean,
        nvidia_smi,
        gpus,
        row_warnings,
    }
}

fn identity_key(gpu: &GpuIdentity) -> (u8, String, String) {
    let pci = gpu.pci_bus_id.value.clone().unwrap_or_default();
    let name = gpu.name.value.clone().unwrap_or_default();
    let missing = u8::from(!gpu.pci_bus_id.is_available());
    (missing, pci, name)
}

#[derive(Debug)]
struct ParsedQuery {
    gpus: Vec<GpuIdentity>,
    row_warnings: Vec<String>,
}

/// Parse `nvidia-smi --query-gpu=name,driver_version,pci.bus_id --format=csv,noheader`.
///
/// Rows are not sorted here. [`report_from_query`] orders them by PCI bus id.
fn parse_gpu_id_query(stdout: &str) -> ParsedQuery {
    let mut gpus = Vec::new();
    let mut row_warnings = Vec::new();
    for (order, line) in stdout.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_identity_line(line) {
            Ok(gpu) => gpus.push(gpu),
            Err(reason) => row_warnings.push(format!("skipped GPU row {}: {reason}", order + 1)),
        }
    }
    ParsedQuery { gpus, row_warnings }
}

fn parse_identity_line(line: &str) -> Result<GpuIdentity, &'static str> {
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    if parts.len() < 1 + TRAILING_FIELDS {
        return Err("too few columns");
    }
    let name_end = parts.len() - TRAILING_FIELDS;
    let name = parts[..name_end].join(", ");
    let driver = parts[name_end];
    let pci = parts[name_end + 1];
    Ok(GpuIdentity {
        name: text_field(&name),
        driver_version: text_field(driver),
        pci_bus_id: pci_field(pci),
    })
}

fn text_field(raw: &str) -> Field {
    let trimmed = strip_brackets(raw);
    if is_missing_token(trimmed) {
        Field::unavailable()
    } else {
        Field::available(redact_text(trimmed))
    }
}

fn pci_field(raw: &str) -> Field {
    let trimmed = strip_brackets(raw);
    if is_missing_token(trimmed) {
        return Field::unavailable();
    }
    match canonical_pci_bus_id(trimmed) {
        Some(bus) => Field::available(bus),
        None => Field::unavailable(),
    }
}

/// `domain:bus:device.function` as printed by `nvidia-smi`, stored in lowercase.
fn canonical_pci_bus_id(raw: &str) -> Option<String> {
    let (prefix, function) = raw.rsplit_once('.')?;
    let mut parts = prefix.split(':');
    let domain = parts.next()?;
    let bus = parts.next()?;
    let device = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !hex_width(domain, 4, 8) || !hex_width(bus, 2, 2) || !hex_width(device, 2, 2) {
        return None;
    }
    if !hex_width(function, 1, 1) {
        return None;
    }
    Some(format!(
        "{}:{}:{}.{}",
        domain.to_ascii_lowercase(),
        bus.to_ascii_lowercase(),
        device.to_ascii_lowercase(),
        function.to_ascii_lowercase()
    ))
}

fn hex_width(token: &str, min: usize, max: usize) -> bool {
    let len = token.len();
    (min..=max).contains(&len) && token.chars().all(|ch| ch.is_ascii_hexdigit())
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

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn field_text(field: &Field) -> String {
    match (&field.status, &field.value) {
        (CoverageStatus::Available, Some(value)) => value.clone(),
        _ => "unavailable".to_string(),
    }
}

enum NvidiaBin {
    Found(PathBuf),
    Missing(String),
}

fn locate_nvidia_smi() -> NvidiaBin {
    if let Ok(value) = std::env::var("DEVGUARD_NVIDIA_SMI_BIN") {
        if value.is_empty() {
            return NvidiaBin::Missing("`nvidia-smi` is not on PATH".into());
        }
        let path = PathBuf::from(&value);
        if !path.is_absolute() {
            return NvidiaBin::Missing("DEVGUARD_NVIDIA_SMI_BIN must be an absolute path".into());
        }
        if !path.is_file() {
            return NvidiaBin::Missing("`nvidia-smi` is not available".into());
        }
        return NvidiaBin::Found(path);
    }
    match find_on_path("nvidia-smi") {
        Some(path) => NvidiaBin::Found(path),
        None => NvidiaBin::Missing("`nvidia-smi` is not on PATH".into()),
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
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

fn scan_program(program: &Path) -> GpuIdReport {
    if !program.is_file() {
        return missing_tool_report("`nvidia-smi` is not available");
    }
    let query = format!("--query-gpu={GPU_ID_QUERY}");
    report_from_tool_output(run_readonly(
        program,
        &[&query, "--format=csv,noheader"],
        TOOL_TIMEOUT,
        MAX_CAPTURE_BYTES,
    ))
}

fn report_from_tool_output(run: std::io::Result<ToolOutput>) -> GpuIdReport {
    match run {
        Ok(run) if run.truncated => {
            missing_tool_report("nvidia-smi output exceeded the capture limit")
        }
        Ok(run) if run.success => report_from_query(&run.stdout),
        Ok(run) => missing_tool_report(short_detail(&run.stderr, "nvidia-smi exited non-zero")),
        Err(err) => missing_tool_report(short_detail(&err.to_string(), "nvidia-smi failed")),
    }
}

fn short_detail(text: &str, fallback: &str) -> String {
    let redacted = strip_gpu_uuids(&redact_text(text));
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
    out
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

    const FIXTURE: &str = include_str!("../fixtures/nvidia-smi-gpu-id.csv");
    const MISSING: &str = include_str!("../fixtures/nvidia-smi-gpu-id-missing.csv");

    #[test]
    fn query_asks_for_name_driver_and_pci_bus_id() {
        assert_eq!(GPU_ID_QUERY, "name,driver_version,pci.bus_id");
    }

    #[test]
    fn fixture_query_reports_driver_name_and_bus_in_pci_order() {
        let report = report_from_query(FIXTURE);
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(!report.uses_sudo);
        assert!(!report.loads_modules);
        assert_eq!(report.gpus.len(), 2);
        assert_eq!(
            report.gpus[0].name.value.as_deref(),
            Some("NVIDIA Example, Laptop GPU")
        );
        assert_eq!(
            report.gpus[0].driver_version.value.as_deref(),
            Some("550.54.14")
        );
        assert_eq!(
            report.gpus[0].pci_bus_id.value.as_deref(),
            Some("00000000:01:00.0")
        );
        assert_eq!(
            report.gpus[1].name.value.as_deref(),
            Some("NVIDIA Example GPU B")
        );
        assert_eq!(
            report.gpus[1].driver_version.value.as_deref(),
            Some("550.90.07")
        );
        assert_eq!(
            report.gpus[1].pci_bus_id.value.as_deref(),
            Some("00000000:02:00.0")
        );
        let text = format_gpu_id_human(&report);
        assert!(text.contains("DevGuard health gpu-id"));
        assert!(text.contains("uses sudo: no"));
        assert!(text.contains("loads modules: no"));
        assert!(text.contains("driver version: 550.54.14"));
        assert!(text.contains("pci bus id: 00000000:01:00.0"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.contains("550.54.14"));
        assert!(!json.contains("sudo "));
    }

    #[test]
    fn missing_field_is_unavailable_and_not_clean() {
        let report = report_from_query(MISSING);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.nvidia_smi.status, CoverageStatus::Available);
        assert!(report.gpus[0].name.is_available());
        assert!(!report.gpus[0].driver_version.is_available());
        assert!(report.gpus[0].pci_bus_id.is_available());
        assert!(report.gpus[1].driver_version.is_available());
        assert!(!report.gpus[1].pci_bus_id.is_available());
        let text = format_gpu_id_human(&report);
        assert!(text.contains("driver version: unavailable"));
        assert!(text.contains("pci bus id: unavailable"));
        assert!(text.contains("not a clean result"));
        assert!(report
            .warnings()
            .iter()
            .any(|item| item.contains("driver version")));
        assert!(report
            .warnings()
            .iter()
            .any(|item| item.contains("pci bus id")));
    }

    #[test]
    fn missing_tool_is_not_a_clean_result() {
        let report = missing_tool_report("`nvidia-smi` is not on PATH");
        assert!(!report.clean);
        assert!(report.gpus.is_empty());
        assert_eq!(report.nvidia_smi.status, CoverageStatus::Unavailable);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let text = format_gpu_id_human(&report);
        assert!(text.contains("uses sudo: no"));
        assert!(text.contains("loads modules: no"));
        assert!(text.contains("unavailable"));
        assert!(text.contains("not a clean result"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn malformed_bus_id_is_unavailable() {
        let report = report_from_query("NVIDIA Example GPU A, 550.54.14, not-a-bus\n");
        assert!(!report.clean);
        assert!(!report.gpus[0].pci_bus_id.is_available());
        assert_eq!(
            report.gpus[0].driver_version.value.as_deref(),
            Some("550.54.14")
        );
    }

    #[test]
    fn unparsable_row_is_not_clean() {
        let report = report_from_query("only-a-name\n");
        assert!(!report.clean);
        assert!(report.gpus.is_empty());
        assert_eq!(report.nvidia_smi.status, CoverageStatus::Unavailable);
        assert!(report
            .row_warnings
            .iter()
            .any(|item| item.contains("too few")));
    }

    #[test]
    fn pci_bus_id_is_stored_in_lowercase() {
        let report = report_from_query("NVIDIA Example GPU A, 550.54.14, 00000000:0A:00.0\n");
        assert!(report.clean);
        assert_eq!(
            report.gpus[0].pci_bus_id.value.as_deref(),
            Some("00000000:0a:00.0")
        );
    }

    #[test]
    fn stderr_detail_strips_a_raw_uuid() {
        let uuid = "GPU-00000000-0000-4000-8000-000000000001";
        let report = report_from_tool_output(Ok(ToolOutput {
            success: false,
            stdout: String::new(),
            stderr: format!("failed for {uuid}\n"),
            truncated: false,
        }));
        assert!(!report.clean);
        assert!(!report.nvidia_smi.detail.contains(uuid));
        assert!(report.nvidia_smi.detail.contains("[uuid]"));
    }

    #[test]
    fn truncated_capture_is_unavailable() {
        let report = report_from_tool_output(Ok(ToolOutput {
            success: true,
            stdout: FIXTURE.to_string(),
            stderr: String::new(),
            truncated: true,
        }));
        assert!(!report.clean);
        assert!(report.gpus.is_empty());
        assert!(report.nvidia_smi.detail.contains("capture limit"));
    }

    #[test]
    fn readonly_command_times_out_without_nvidia_smi() {
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
    fn query_report_hides_token_shapes() {
        let secret = format!("sk-proj-{}", "d".repeat(24));
        let report = report_from_query(&format!("{secret}, 550.54.14, 00000000:0A:00.0\n"));
        let human = format_gpu_id_human(&report);
        let json = serde_json::to_string(&report).expect("json");
        assert!(
            !human.contains(&secret),
            "gpu-id report kept a fixture secret"
        );
        assert!(!json.contains(&secret), "gpu-id json kept a fixture secret");
        assert!(human.contains("[REDACTED]"));
        assert!(json.contains("[REDACTED]"));
    }
}
