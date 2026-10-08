//! Read-only lm-sensors style reading from hwmon sysfs.
//!
//! `devguard health sensors` reports package, CPU, and board temperatures and
//! fan RPM when those files exist. It does not install packages, use sudo,
//! load a kernel module, or change a fan curve. If `sensors` is missing and
//! no hwmon file is readable, the reading is unavailable and not clean.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

/// `available` or `unavailable`. A missing reading is never clean.
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

/// One temperature file that matched package, CPU, or board.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TempReading {
    pub id: String,
    pub chip: String,
    pub label: String,
    pub celsius: f64,
}

/// One `fan*_input` file, in RPM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FanReading {
    pub id: String,
    pub chip: String,
    pub label: String,
    pub rpm: u32,
}

/// Human and JSON body for `devguard health sensors`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SensorsReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never loads a kernel module.
    pub loads_modules: bool,
    /// Always false. This command never writes a fan curve.
    pub changes_fan_curve: bool,
    /// False when no hwmon temperature or fan file was readable.
    pub clean: bool,
    /// `unavailable` when no hwmon temperature or fan file was readable.
    pub status: CoverageStatus,
    pub sensors: SourceCoverage,
    pub hwmon: SourceCoverage,
    pub package: Vec<TempReading>,
    pub cpu: Vec<TempReading>,
    pub board: Vec<TempReading>,
    pub fans: Vec<FanReading>,
}

impl SensorsReport {
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
        let mut warnings = Vec::new();
        if self.sensors.status == CoverageStatus::Unavailable {
            warnings.push(format!("sensors unavailable: {}", self.sensors.detail));
        }
        if self.hwmon.status == CoverageStatus::Unavailable {
            warnings.push(format!("hwmon unavailable: {}", self.hwmon.detail));
        }
        warnings
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TempClass {
    Package,
    Cpu,
    Board,
}

struct RawTemp {
    id: String,
    chip: String,
    label: String,
    celsius: f64,
}

struct RawFan {
    id: String,
    chip: String,
    label: String,
    rpm: u32,
}

/// Read this host once. `DEVGUARD_HWMON_ROOT` selects a fixture tree.
/// `DEVGUARD_SENSORS_BIN` selects the `sensors` binary. Neither is executed
/// as a module loader, and this function never writes a fan curve.
pub fn scan_sensors() -> SensorsReport {
    read_hwmon_sensors(&hwmon_root(), sensors_present())
}

/// Read temperature and fan RPM files under `root`.
///
/// Package, CPU, and board temperatures and fan RPM are reported when those
/// files exist. The reading is unavailable and not clean when `sensors` is
/// missing and no hwmon file is readable. Other unreadable trees are also
/// unavailable and not clean, because there is no temperature or RPM to report.
pub fn read_hwmon_sensors(root: &Path, sensors_present: bool) -> SensorsReport {
    let sensors = if sensors_present {
        SourceCoverage {
            status: CoverageStatus::Available,
            detail: "`sensors` is available".to_string(),
        }
    } else {
        SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: "`sensors` is not on PATH".to_string(),
        }
    };
    let (temps, fans, readable) = read_tree(root);
    let hwmon = if readable == 0 {
        SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: "no hwmon temperature or fan file was readable".to_string(),
        }
    } else {
        SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("{readable} temperature or fan file(s)"),
        }
    };
    let mut package = Vec::new();
    let mut cpu = Vec::new();
    let mut board = Vec::new();
    for temp in temps {
        let reading = TempReading {
            id: temp.id,
            chip: temp.chip.clone(),
            label: temp.label.clone(),
            celsius: temp.celsius,
        };
        match classify_temp(&temp.chip, &temp.label) {
            Some(TempClass::Package) => package.push(reading),
            Some(TempClass::Cpu) => cpu.push(reading),
            Some(TempClass::Board) => board.push(reading),
            None => {}
        }
    }
    sort_temps(&mut package);
    sort_temps(&mut cpu);
    sort_temps(&mut board);
    let mut fans: Vec<FanReading> = fans
        .into_iter()
        .map(|fan| FanReading {
            id: fan.id,
            chip: fan.chip,
            label: fan.label,
            rpm: fan.rpm,
        })
        .collect();
    fans.sort_by(|a, b| (&a.id, &a.label).cmp(&(&b.id, &b.label)));
    let status = hwmon.status;
    let clean = status == CoverageStatus::Available;
    SensorsReport {
        uses_sudo: false,
        loads_modules: false,
        changes_fan_curve: false,
        clean,
        status,
        sensors,
        hwmon,
        package,
        cpu,
        board,
        fans,
    }
}

/// Human report. Does not describe a missing reading as healthy.
pub fn format_sensors_human(report: &SensorsReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard health sensors\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  loads modules: no\n");
    out.push_str("  changes fan curve: no\n");
    out.push_str(&format!(
        "  sensors: {} — {}\n",
        status_word(report.sensors.status),
        report.sensors.detail
    ));
    out.push_str(&format!(
        "  hwmon: {} — {}\n",
        status_word(report.hwmon.status),
        report.hwmon.detail
    ));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    push_temps(&mut out, "Package", &report.package);
    push_temps(&mut out, "CPU", &report.cpu);
    push_temps(&mut out, "Board", &report.board);
    out.push_str("\nFans\n");
    if report.fans.is_empty() {
        out.push_str("  unavailable\n");
    } else {
        for fan in &report.fans {
            out.push_str(&format!(
                "- {} {} {}: {} RPM\n",
                fan.id, fan.chip, fan.label, fan.rpm
            ));
        }
    }
    out
}

fn push_temps(out: &mut String, title: &str, temps: &[TempReading]) {
    out.push_str(&format!("\n{title}\n"));
    if temps.is_empty() {
        out.push_str("  unavailable\n");
        return;
    }
    for temp in temps {
        out.push_str(&format!(
            "- {} {} {}: {:.1} C\n",
            temp.id, temp.chip, temp.label, temp.celsius
        ));
    }
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn sort_temps(temps: &mut [TempReading]) {
    temps.sort_by(|a, b| (&a.id, &a.label).cmp(&(&b.id, &b.label)));
}

fn hwmon_root() -> PathBuf {
    match std::env::var("DEVGUARD_HWMON_ROOT") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from("/sys/class/hwmon"),
    }
}

fn sensors_present() -> bool {
    match std::env::var("DEVGUARD_SENSORS_BIN") {
        Ok(value) if !value.is_empty() => Path::new(&value).is_file(),
        Ok(_) => false,
        Err(_) => find_tool("sensors").is_some(),
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

fn read_tree(root: &Path) -> (Vec<RawTemp>, Vec<RawFan>, usize) {
    let Ok(entries) = fs::read_dir(root) else {
        return (Vec::new(), Vec::new(), 0);
    };
    let mut temps = Vec::new();
    let mut fans = Vec::new();
    let mut readable = 0usize;
    let mut chips: Vec<_> = entries.flatten().collect();
    chips.sort_by_key(|entry| entry.file_name());
    for entry in chips {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        let (chip_temps, chip_fans, count) = read_chip(&path, &id);
        readable = readable.saturating_add(count);
        temps.extend(chip_temps);
        fans.extend(chip_fans);
    }
    (temps, fans, readable)
}

fn read_chip(dir: &Path, id: &str) -> (Vec<RawTemp>, Vec<RawFan>, usize) {
    let chip = fs::read_to_string(dir.join("name"))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| id.to_string());
    let Ok(entries) = fs::read_dir(dir) else {
        return (Vec::new(), Vec::new(), 0);
    };
    let mut temps = Vec::new();
    let mut fans = Vec::new();
    let mut readable = 0usize;
    for entry in entries.flatten() {
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        if let Some(index) = indexed_file(filename, "temp", "_input") {
            if let Some(celsius) = read_millicelsius(&entry.path()) {
                readable = readable.saturating_add(1);
                temps.push(RawTemp {
                    id: id.to_string(),
                    chip: chip.clone(),
                    label: label_or(dir, "temp", index),
                    celsius,
                });
            }
        } else if let Some(index) = indexed_file(filename, "fan", "_input") {
            if let Some(rpm) = read_rpm(&entry.path()) {
                readable = readable.saturating_add(1);
                fans.push(RawFan {
                    id: id.to_string(),
                    chip: chip.clone(),
                    label: label_or(dir, "fan", index),
                    rpm,
                });
            }
        }
    }
    (temps, fans, readable)
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

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn classify_temp(chip: &str, label: &str) -> Option<TempClass> {
    let name = chip.trim().to_ascii_lowercase();
    let label_l = label.trim().to_ascii_lowercase();
    if label_l.contains("package") {
        return Some(TempClass::Package);
    }
    if label_l.contains("core")
        || label_l.contains("tctl")
        || label_l.contains("tdie")
        || label_l.contains("tccd")
        || label_l.contains("cputin")
        || label_l == "cpu"
        || label_l.starts_with("cpu ")
    {
        return Some(TempClass::Cpu);
    }
    if is_cpu_chip(&name) {
        return Some(TempClass::Cpu);
    }
    if label_l.contains("systin")
        || label_l.contains("board")
        || label_l.contains("motherboard")
        || label_l.contains("mb temp")
        || is_acpi_board(&name)
    {
        return Some(TempClass::Board);
    }
    None
}

fn is_cpu_chip(name: &str) -> bool {
    matches!(
        name,
        "coretemp" | "k10temp" | "k8temp" | "zenpower" | "cpu_thermal"
    )
}

fn is_acpi_board(name: &str) -> bool {
    name == "acpitz" || name.starts_with("acpi")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn desktop_tree(root: &Path) {
        let core = root.join("hwmon4");
        write(&core.join("name"), "coretemp\n");
        write(&core.join("temp1_input"), "54000\n");
        write(&core.join("temp1_label"), "Package id 0\n");
        write(&core.join("temp2_input"), "45000\n");
        write(&core.join("temp2_label"), "Core 0\n");
        write(&core.join("temp3_input"), "46100\n");
        write(&core.join("temp3_label"), "Core 1\n");
        write(&core.join("temp1_max"), "100000\n");

        let board = root.join("hwmon0");
        write(&board.join("name"), "acpitz\n");
        write(&board.join("temp1_input"), "27800\n");

        let superio = root.join("hwmon3");
        write(&superio.join("name"), "nct6798\n");
        write(&superio.join("temp1_input"), "32000\n");
        write(&superio.join("temp1_label"), "SYSTIN\n");
        write(&superio.join("temp2_input"), "41000\n");
        write(&superio.join("temp2_label"), "CPUTIN\n");
        write(&superio.join("fan1_input"), "820\n");
        write(&superio.join("fan1_label"), "cpu_fan\n");
        write(&superio.join("fan2_input"), "640\n");
        write(&superio.join("fan2_label"), "chassis\n");
        write(&superio.join("pwm1"), "128\n");

        let nvme = root.join("hwmon1");
        write(&nvme.join("name"), "nvme\n");
        write(&nvme.join("temp1_input"), "39900\n");
        write(&nvme.join("temp1_label"), "Composite\n");
    }

    #[test]
    fn fixture_reports_package_cpu_board_and_fan_rpm() {
        let dir = tempdir().unwrap();
        desktop_tree(dir.path());
        let report = read_hwmon_sensors(dir.path(), false);
        assert!(!report.uses_sudo);
        assert!(!report.loads_modules);
        assert!(!report.changes_fan_curve);
        assert!(report.clean);
        assert_eq!(report.status, CoverageStatus::Available);
        assert_eq!(report.sensors.status, CoverageStatus::Unavailable);
        assert_eq!(report.package.len(), 1);
        assert_eq!(report.package[0].chip, "coretemp");
        assert_eq!(report.package[0].label, "Package id 0");
        assert_eq!(report.package[0].celsius, 54.0);
        assert_eq!(report.cpu.len(), 3);
        assert_eq!(report.cpu[0].label, "CPUTIN");
        assert_eq!(report.cpu[0].celsius, 41.0);
        assert_eq!(report.cpu[1].label, "Core 0");
        assert_eq!(report.cpu[1].celsius, 45.0);
        assert_eq!(report.cpu[2].label, "Core 1");
        assert_eq!(report.cpu[2].celsius, 46.1);
        assert_eq!(report.board.len(), 2);
        assert_eq!(report.board[0].chip, "acpitz");
        assert_eq!(report.board[0].label, "temp1");
        assert_eq!(report.board[0].celsius, 27.8);
        assert_eq!(report.board[1].label, "SYSTIN");
        assert_eq!(report.board[1].celsius, 32.0);
        assert_eq!(report.fans.len(), 2);
        assert_eq!(report.fans[0].label, "chassis");
        assert_eq!(report.fans[0].rpm, 640);
        assert_eq!(report.fans[1].label, "cpu_fan");
        assert_eq!(report.fans[1].rpm, 820);
        assert!(report
            .package
            .iter()
            .chain(report.cpu.iter())
            .chain(report.board.iter())
            .all(|temp| temp.label != "Composite"));
        let text = format_sensors_human(&report);
        assert!(text.contains("Package id 0: 54.0 C"));
        assert!(text.contains("Core 0: 45.0 C"));
        assert!(text.contains("acpitz temp1: 27.8 C"));
        assert!(text.contains("chassis: 640 RPM"));
        assert!(text.contains("changes fan curve: no"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
        assert!(report.warnings().is_empty());
    }

    #[test]
    fn missing_sensors_and_no_hwmon_file_is_unavailable_and_not_clean() {
        let dir = tempdir().unwrap();
        let empty = dir.path().join("hwmon0");
        fs::create_dir_all(&empty).unwrap();
        write(&empty.join("name"), "asus\n");
        write(&empty.join("pwm1"), "0\n");
        write(&empty.join("temp1_input"), "not-a-number\n");
        let report = read_hwmon_sensors(dir.path(), false);
        assert_eq!(report.sensors.status, CoverageStatus::Unavailable);
        assert_eq!(report.hwmon.status, CoverageStatus::Unavailable);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert!(!report.clean);
        assert!(report.package.is_empty());
        assert!(report.cpu.is_empty());
        assert!(report.board.is_empty());
        assert!(report.fans.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let warnings = report.warnings();
        assert!(warnings.iter().any(|line| line.contains("sensors")));
        assert!(warnings.iter().any(|line| line.contains("hwmon")));
        let text = format_sensors_human(&report);
        assert!(text.contains("clean: no"));
        assert!(text.contains("unavailable"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn missing_hwmon_root_is_unavailable_even_when_sensors_exists() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("absent");
        let report = read_hwmon_sensors(&missing, true);
        assert_eq!(report.sensors.status, CoverageStatus::Available);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn k10temp_tctl_is_a_cpu_temperature() {
        let dir = tempdir().unwrap();
        let chip = dir.path().join("hwmon2");
        write(&chip.join("name"), "k10temp\n");
        write(&chip.join("temp1_input"), "61250\n");
        write(&chip.join("temp1_label"), "Tctl\n");
        write(&chip.join("temp2_input"), "60500\n");
        write(&chip.join("temp2_label"), "Tdie\n");
        let report = read_hwmon_sensors(dir.path(), true);
        assert!(report.clean);
        assert!(report.package.is_empty());
        assert_eq!(report.cpu.len(), 2);
        assert_eq!(report.cpu[0].celsius, 61.3);
        assert_eq!(report.cpu[1].label, "Tdie");
        assert_eq!(report.cpu[1].celsius, 60.5);
    }

    #[test]
    fn nvme_only_tree_does_not_invent_package_cpu_or_board() {
        let dir = tempdir().unwrap();
        let nvme = dir.path().join("hwmon1");
        write(&nvme.join("name"), "nvme\n");
        write(&nvme.join("temp1_input"), "49900\n");
        write(&nvme.join("temp1_label"), "Composite\n");
        let report = read_hwmon_sensors(dir.path(), false);
        assert!(report.clean);
        assert_eq!(report.hwmon.status, CoverageStatus::Available);
        assert!(report.package.is_empty());
        assert!(report.cpu.is_empty());
        assert!(report.board.is_empty());
        assert!(report.fans.is_empty());
    }
}
