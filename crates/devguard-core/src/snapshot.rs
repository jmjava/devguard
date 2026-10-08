//! Workstation snapshot payload and diff.
//!
//! `create` stores one JSON payload built from the collectors already in this
//! crate: OS identity, packages, units, ports, gpu-id, dev env, allowlisted
//! config hashes, and health scan. A missing collector stays in the payload
//! as `unavailable`. The snapshot is partial when any collector is unavailable.
//!
//! `diff` returns added, removed, and changed entries in key order. Severity
//! is a separate field from the fact. Labels such as `pre-upgrade` and
//! `post-upgrade` are ordinary strings.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::dev_env::{scan_dev_env, CoverageStatus as ToolStatus, DevEnvReport, ToolVersion};
use crate::exit::ExitCode;
use crate::files::{scan_config_files, FileCoverage, FilesReport, HashedFile};
use crate::gpu_id::{scan_gpu_id, CoverageStatus as GpuStatus, Field, GpuIdReport, GpuIdentity};
use crate::health_scan::{
    scan_health, HealthScanReport, ProcessNames, Reading as HealthReading,
    SourceStatus as HealthSource,
};
use crate::os_identity::{
    scan_os, OsIdentityReport, Reading as OsReading, SourceStatus as OsSource,
};
use crate::packages::{
    scan_packages, CoverageStatus as PackageStatus, InstalledPackage, PackagesReport, PendingUpdate,
};
use crate::ports::{
    scan_ports, Attribution, CoverageStatus as PortStatus, ListenSocket, PortsReport,
};
use crate::units::{scan_units, CoverageStatus as UnitStatus, UnitRecord, UnitsReport};

/// `available` or `unavailable`. An unavailable collector stays in the payload.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectorAvailability {
    Available,
    Unavailable,
}

/// Severity hint for one diff entry. This is not the fact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SeverityHint {
    Info,
    Warning,
    Critical,
    Unknown,
}

impl SeverityHint {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

/// One collector inside a snapshot. `report` is present even when `status` is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Collected<T> {
    pub status: CollectorAvailability,
    pub report: T,
}

/// Collectors stored in one snapshot, in a fixed order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnapshotCollectors {
    pub os: Collected<OsIdentityReport>,
    pub packages: Collected<PackagesReport>,
    pub units: Collected<UnitsReport>,
    pub ports: Collected<PortsReport>,
    pub gpu_id: Collected<GpuIdReport>,
    pub dev_env: Collected<DevEnvReport>,
    pub files: Collected<FilesReport>,
    pub health: Collected<HealthScanReport>,
}

/// JSON body stored on a snapshot row.
///
/// `label` is an ordinary string. `pre-upgrade` and `post-upgrade` have no
/// special meaning here. `clean` is false when any collector is unavailable
/// or any collector report is partial. [`parse_payload`] recomputes `clean`
/// from that coverage, so a stored `true` cannot mark a partial snapshot clean.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnapshotPayload {
    pub label: Option<String>,
    pub clean: bool,
    /// Always false. Snapshot collection does not invoke sudo.
    pub uses_sudo: bool,
    /// Always false. Snapshot collection does not install or upgrade packages.
    pub installs_packages: bool,
    /// Always false. Snapshot collection does not open a network connection.
    pub opens_network: bool,
    pub collectors: SnapshotCollectors,
}

impl SnapshotPayload {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }
}

/// Name and inventory status for one collector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorStatus {
    pub name: &'static str,
    pub status: CollectorAvailability,
}

/// One added, removed, or changed fact.
///
/// `severity` is a hint. It is not encoded into `fact`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffEntry {
    pub key: String,
    pub fact: String,
    pub severity: SeverityHint,
}

/// Added, removed, and changed entries. Each vector is ordered by `key`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotDiff {
    pub added: Vec<DiffEntry>,
    pub removed: Vec<DiffEntry>,
    pub changed: Vec<DiffEntry>,
}

/// One row of `snapshot list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotSummary {
    pub id: String,
    pub created_at: String,
    pub label: Option<String>,
    pub clean: bool,
}

/// Read the collectors on this host and build one payload.
///
/// This calls the existing scan functions only. It does not add a collector,
/// invoke sudo, install packages, or open a network connection.
pub fn collect_snapshot(label: Option<String>, allowlist: &[String]) -> SnapshotPayload {
    assemble_snapshot(
        label,
        HostReports {
            os: scan_os(),
            packages: scan_packages(),
            units: scan_units(),
            ports: scan_ports(),
            gpu_id: scan_gpu_id(),
            dev_env: scan_dev_env(),
            files: scan_config_files(allowlist),
            health: scan_health(),
        },
    )
}

/// Parse a payload stored in the snapshot table.
///
/// `clean` is recomputed from collector coverage. A stored `true` does not
/// mark the snapshot clean when any collector is unavailable or any collector
/// report is partial.
pub fn parse_payload(text: &str) -> Result<SnapshotPayload, serde_json::Error> {
    let mut payload: SnapshotPayload = serde_json::from_str(text)?;
    payload.clean = coverage_is_clean(&payload);
    Ok(payload)
}

/// List-row summary. An unreadable payload is partial.
pub fn summary_from_stored(
    id: String,
    created_at: String,
    label: Option<String>,
    payload: &str,
) -> SnapshotSummary {
    let clean = parse_payload(payload)
        .map(|parsed| parsed.clean)
        .unwrap_or(false);
    SnapshotSummary {
        id,
        created_at,
        label,
        clean,
    }
}

/// Collector inventory status in payload order.
pub fn collector_statuses(payload: &SnapshotPayload) -> Vec<CollectorStatus> {
    coverage(payload)
        .into_iter()
        .map(|row| CollectorStatus {
            name: row.name,
            status: row.status,
        })
        .collect()
}

/// Warnings for collectors that are unavailable or only partially covered.
pub fn snapshot_warnings(payload: &SnapshotPayload) -> Vec<String> {
    coverage(payload)
        .into_iter()
        .filter_map(|row| match row.status {
            CollectorAvailability::Unavailable => Some(format!("{} is unavailable", row.name)),
            CollectorAvailability::Available if !row.clean => {
                Some(format!("{} coverage is partial", row.name))
            }
            CollectorAvailability::Available => None,
        })
        .collect()
}

/// Diff two payloads. Entries are ordered by key inside each vector.
///
/// When either side of a collector is unavailable, the diff records that
/// collector status and does not treat the missing inventory as added or
/// removed facts.
pub fn diff_payloads(baseline: &SnapshotPayload, current: &SnapshotPayload) -> SnapshotDiff {
    let left = fact_groups(baseline);
    let right = fact_groups(current);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for (before, after) in left.iter().zip(right.iter()) {
        debug_assert_eq!(before.id, after.id);
        if !before.available || !after.available {
            let previous = availability_word(before.available);
            let next = availability_word(after.available);
            if previous != next {
                let key = format!("collector:{}", before.id);
                changed.push(entry(
                    key,
                    format!("{previous} -> {next}"),
                    SeverityHint::Unknown,
                ));
            }
            continue;
        }
        diff_maps(
            &before.facts,
            &after.facts,
            &mut added,
            &mut removed,
            &mut changed,
        );
    }
    added.sort_by(|a, b| a.key.cmp(&b.key));
    removed.sort_by(|a, b| a.key.cmp(&b.key));
    changed.sort_by(|a, b| a.key.cmp(&b.key));
    SnapshotDiff {
        added,
        removed,
        changed,
    }
}

pub fn format_create_human(id: &str, created_at: &str, payload: &SnapshotPayload) -> String {
    let label = payload.label.as_deref().unwrap_or("(none)");
    let mut out = format!(
        "\
DevGuard snapshot create
  id: {id}
  created: {created_at}
  label: {label}
  clean: {clean}
  uses sudo: no
  installs packages: no
  opens a network connection: no
",
        clean = yes_no(payload.clean),
    );
    out.push_str("\nCollectors\n");
    for row in collector_statuses(payload) {
        out.push_str(&format!(
            "  {name}: {status}\n",
            name = row.name,
            status = availability_word(row.status == CollectorAvailability::Available),
        ));
    }
    out
}

pub fn format_list_human(rows: &[SnapshotSummary]) -> String {
    let mut out = String::from("DevGuard snapshot list\n");
    if rows.is_empty() {
        out.push_str("  no snapshots\n");
        return out;
    }
    for row in rows {
        let label = row.label.as_deref().unwrap_or("(none)");
        out.push_str(&format!(
            "  {id}  {created}  label={label}  clean={clean}\n",
            id = row.id,
            created = row.created_at,
            clean = yes_no(row.clean),
        ));
    }
    out
}

pub fn format_diff_human(
    baseline_id: &str,
    current_id: &str,
    baseline_label: Option<&str>,
    current_label: Option<&str>,
    baseline_clean: bool,
    current_clean: bool,
    diff: &SnapshotDiff,
) -> String {
    let baseline_label = baseline_label.unwrap_or("(none)");
    let current_label = current_label.unwrap_or("(none)");
    let baseline_clean = yes_no(baseline_clean);
    let current_clean = yes_no(current_clean);
    let mut out = format!(
        "\
DevGuard snapshot diff
  baseline: {baseline_id} ({baseline_label})
  baseline clean: {baseline_clean}
  current: {current_id} ({current_label})
  current clean: {current_clean}
"
    );
    push_section(&mut out, "Added", &diff.added);
    push_section(&mut out, "Removed", &diff.removed);
    push_section(&mut out, "Changed", &diff.changed);
    out
}

struct HostReports {
    os: OsIdentityReport,
    packages: PackagesReport,
    units: UnitsReport,
    ports: PortsReport,
    gpu_id: GpuIdReport,
    dev_env: DevEnvReport,
    files: FilesReport,
    health: HealthScanReport,
}

struct CoverageRow {
    name: &'static str,
    status: CollectorAvailability,
    clean: bool,
}

struct FactGroup {
    id: &'static str,
    available: bool,
    facts: BTreeMap<String, String>,
}

enum ChangeKind {
    Added,
    Removed,
    Changed,
}

fn assemble_snapshot(label: Option<String>, reports: HostReports) -> SnapshotPayload {
    let HostReports {
        os,
        packages,
        units,
        ports,
        gpu_id,
        dev_env,
        files,
        health,
    } = reports;
    let os_status = status_from(os_inventory_available(&os));
    let packages_status = status_from(packages_inventory_available(&packages));
    let units_status = status_from(units.status == UnitStatus::Available);
    let ports_status = status_from(ports.ss.status == PortStatus::Available);
    let gpu_status = status_from(gpu_id.nvidia_smi.status == GpuStatus::Available);
    let dev_env_status = CollectorAvailability::Available;
    let files_status = status_from(files_inventory_available(&files));
    let health_status = status_from(health_inventory_available(&health));
    let mut payload = SnapshotPayload {
        label: normalize_label(label),
        clean: false,
        uses_sudo: false,
        installs_packages: false,
        opens_network: false,
        collectors: SnapshotCollectors {
            os: Collected {
                status: os_status,
                report: os,
            },
            packages: Collected {
                status: packages_status,
                report: packages,
            },
            units: Collected {
                status: units_status,
                report: units,
            },
            ports: Collected {
                status: ports_status,
                report: ports,
            },
            gpu_id: Collected {
                status: gpu_status,
                report: gpu_id,
            },
            dev_env: Collected {
                status: dev_env_status,
                report: dev_env,
            },
            files: Collected {
                status: files_status,
                report: files,
            },
            health: Collected {
                status: health_status,
                report: health,
            },
        },
    };
    payload.clean = coverage_is_clean(&payload);
    payload
}

fn coverage_is_clean(payload: &SnapshotPayload) -> bool {
    coverage(payload)
        .iter()
        .all(|row| row.status == CollectorAvailability::Available && row.clean)
}

fn coverage(payload: &SnapshotPayload) -> Vec<CoverageRow> {
    let collectors = &payload.collectors;
    vec![
        CoverageRow {
            name: "os",
            status: collectors.os.status,
            clean: collectors.os.report.clean,
        },
        CoverageRow {
            name: "packages",
            status: collectors.packages.status,
            clean: collectors.packages.report.clean,
        },
        CoverageRow {
            name: "units",
            status: collectors.units.status,
            clean: collectors.units.report.clean,
        },
        CoverageRow {
            name: "ports",
            status: collectors.ports.status,
            clean: collectors.ports.report.clean,
        },
        CoverageRow {
            name: "gpu_id",
            status: collectors.gpu_id.status,
            clean: collectors.gpu_id.report.clean,
        },
        CoverageRow {
            name: "dev_env",
            status: collectors.dev_env.status,
            clean: collectors.dev_env.report.clean,
        },
        CoverageRow {
            name: "files",
            status: collectors.files.status,
            clean: collectors.files.report.clean,
        },
        CoverageRow {
            name: "health",
            status: collectors.health.status,
            clean: collectors.health.report.clean,
        },
    ]
}

fn fact_groups(payload: &SnapshotPayload) -> Vec<FactGroup> {
    let collectors = &payload.collectors;
    vec![
        group("os", collectors.os.status, os_facts(&collectors.os.report)),
        group(
            "packages",
            collectors.packages.status,
            package_facts(&collectors.packages.report),
        ),
        group(
            "units",
            collectors.units.status,
            unit_facts(&collectors.units.report),
        ),
        group(
            "ports",
            collectors.ports.status,
            port_facts(&collectors.ports.report),
        ),
        group(
            "gpu_id",
            collectors.gpu_id.status,
            gpu_facts(&collectors.gpu_id.report),
        ),
        group(
            "dev_env",
            collectors.dev_env.status,
            tool_facts(&collectors.dev_env.report),
        ),
        group(
            "files",
            collectors.files.status,
            file_facts(&collectors.files.report),
        ),
        group(
            "health",
            collectors.health.status,
            health_facts(&collectors.health.report),
        ),
    ]
}

fn group(
    id: &'static str,
    status: CollectorAvailability,
    facts: BTreeMap<String, String>,
) -> FactGroup {
    let available = status == CollectorAvailability::Available;
    FactGroup {
        id,
        available,
        facts: if available { facts } else { BTreeMap::new() },
    }
}

fn diff_maps(
    left: &BTreeMap<String, String>,
    right: &BTreeMap<String, String>,
    added: &mut Vec<DiffEntry>,
    removed: &mut Vec<DiffEntry>,
    changed: &mut Vec<DiffEntry>,
) {
    let keys: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
    for key in keys {
        match (left.get(key), right.get(key)) {
            (None, Some(after)) => added.push(entry(
                key.clone(),
                after.clone(),
                severity(key, ChangeKind::Added, "", after),
            )),
            (Some(before), None) => removed.push(entry(
                key.clone(),
                before.clone(),
                severity(key, ChangeKind::Removed, before, ""),
            )),
            (Some(before), Some(after)) if before != after => changed.push(entry(
                key.clone(),
                format!("{before} -> {after}"),
                severity(key, ChangeKind::Changed, before, after),
            )),
            _ => {}
        }
    }
}

fn severity(key: &str, kind: ChangeKind, before: &str, after: &str) -> SeverityHint {
    if key.starts_with("collector:") || before == "unavailable" || after == "unavailable" {
        return SeverityHint::Unknown;
    }
    if key == "os:kernel_release" || key == "os:hostname_hash" {
        return SeverityHint::Warning;
    }
    if key.starts_with("port:") && matches!(kind, ChangeKind::Added) {
        return SeverityHint::Warning;
    }
    if key.starts_with("gpu:")
        && key.ends_with(":driver_version")
        && matches!(kind, ChangeKind::Changed)
    {
        return SeverityHint::Warning;
    }
    if key.starts_with("unit:") {
        let failed_before = before.contains("failed=true");
        let failed_after = after.contains("failed=true");
        if failed_after && !failed_before {
            return SeverityHint::Warning;
        }
    }
    if key.starts_with("file:") && matches!(kind, ChangeKind::Changed) {
        return SeverityHint::Warning;
    }
    SeverityHint::Info
}

fn entry(key: String, fact: String, severity: SeverityHint) -> DiffEntry {
    DiffEntry {
        key,
        fact,
        severity,
    }
}

fn os_facts(report: &OsIdentityReport) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    facts.insert("os:kernel_release".into(), os_text(&report.kernel_release));
    facts.insert("os:boot_id".into(), os_text(&report.boot_id));
    facts.insert("os:hostname_hash".into(), os_text(&report.hostname_hash));
    facts.insert("os:uptime_seconds".into(), os_f64(&report.uptime_seconds));
    facts
}

fn package_facts(report: &PackagesReport) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    facts.insert(
        "packages:updates".into(),
        package_word(report.updates.status).into(),
    );
    for package in &report.packages {
        facts.insert(package_key(package), package.version.clone());
    }
    if report.updates.status == PackageStatus::Available {
        for pending in &report.pending {
            facts.insert(
                pending_key(pending),
                format!(
                    "installed {installed}, available {available}",
                    installed = pending.installed,
                    available = pending.available,
                ),
            );
        }
    }
    facts
}

fn unit_facts(report: &UnitsReport) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    for unit in &report.units {
        facts.insert(format!("unit:{}", unit.name), unit_fact(unit));
    }
    facts
}

fn port_facts(report: &PortsReport) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    for socket in &report.sockets {
        facts.insert(port_key(socket), port_fact(socket));
    }
    facts
}

fn gpu_facts(report: &GpuIdReport) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    for (index, gpu) in report.gpus.iter().enumerate() {
        facts.insert(gpu_key(gpu, index, "name"), field_text(&gpu.name));
        facts.insert(
            gpu_key(gpu, index, "driver_version"),
            field_text(&gpu.driver_version),
        );
    }
    facts
}

fn tool_facts(report: &DevEnvReport) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    for tool in &report.tools {
        facts.insert(format!("tool:{}", tool.name), tool_fact(tool));
    }
    facts
}

fn file_facts(report: &FilesReport) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    for file in &report.files {
        facts.insert(format!("file:{}", file.path), file_fact(file));
    }
    facts
}

fn health_facts(report: &HealthScanReport) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    facts.insert("health:cpu_count".into(), health_u32(&report.cpu_count));
    facts.insert(
        "health:memory_used_bytes".into(),
        health_u64(&report.memory_used_bytes),
    );
    facts.insert(
        "health:memory_total_bytes".into(),
        health_u64(&report.memory_total_bytes),
    );
    facts.insert(
        "health:swap_used_bytes".into(),
        health_u64(&report.swap_used_bytes),
    );
    facts.insert(
        "health:disk_free_bytes".into(),
        health_u64(&report.disk_free_bytes),
    );
    facts.insert(
        "health:uptime_seconds".into(),
        health_f64(&report.uptime_seconds),
    );
    facts.insert("health:processes".into(), process_fact(&report.processes));
    facts
}

fn package_key(package: &InstalledPackage) -> String {
    format!("package:{}:{}", package.name, package.architecture)
}

fn pending_key(pending: &PendingUpdate) -> String {
    format!("pending:{}:{}", pending.name, pending.architecture)
}

fn unit_fact(unit: &UnitRecord) -> String {
    format!(
        "enabled={} active={} failed={}",
        unit.enabled, unit.active, unit.failed
    )
}

fn port_key(socket: &ListenSocket) -> String {
    format!(
        "port:{}:{}:{}",
        socket.protocol, socket.address, socket.port
    )
}

fn port_fact(socket: &ListenSocket) -> String {
    match socket.attribution {
        Attribution::Present => format!(
            "process={}",
            socket.process.as_deref().unwrap_or("unavailable")
        ),
        Attribution::Missing => "attribution missing".into(),
    }
}

fn gpu_key(gpu: &GpuIdentity, index: usize, field: &str) -> String {
    if gpu.pci_bus_id.status == GpuStatus::Available {
        if let Some(bus) = gpu.pci_bus_id.value.as_deref() {
            return format!("gpu:{bus}:{field}");
        }
    }
    format!("gpu:row:{index}:{field}")
}

fn tool_fact(tool: &ToolVersion) -> String {
    match tool.status {
        ToolStatus::Available => tool
            .version_line
            .clone()
            .unwrap_or_else(|| "unavailable".into()),
        ToolStatus::Unavailable => "unavailable".into(),
    }
}

fn file_fact(file: &HashedFile) -> String {
    match file.status {
        FileCoverage::Available => file.hash.clone().unwrap_or_else(|| "unavailable".into()),
        FileCoverage::Unavailable => "unavailable".into(),
    }
}

fn process_fact(names: &ProcessNames) -> String {
    if names.status == HealthSource::Available {
        names.names.join(", ")
    } else {
        "unavailable".into()
    }
}

fn os_inventory_available(report: &OsIdentityReport) -> bool {
    os_text(&report.kernel_release) != "unavailable"
}

fn packages_inventory_available(report: &PackagesReport) -> bool {
    report.installed.status == PackageStatus::Available
}

fn files_inventory_available(report: &FilesReport) -> bool {
    report
        .files
        .iter()
        .any(|file| file.status == FileCoverage::Available)
}

fn health_inventory_available(report: &HealthScanReport) -> bool {
    health_u32(&report.cpu_count) != "unavailable"
}

fn os_text(reading: &OsReading<String>) -> String {
    match (&reading.status, reading.value.as_deref()) {
        (OsSource::Available, Some(value)) => value.to_string(),
        _ => "unavailable".into(),
    }
}

fn os_f64(reading: &OsReading<f64>) -> String {
    match (&reading.status, reading.value) {
        (OsSource::Available, Some(value)) => format!("{value:.2}"),
        _ => "unavailable".into(),
    }
}

fn health_u32(reading: &HealthReading<u32>) -> String {
    match (&reading.status, reading.value) {
        (HealthSource::Available, Some(value)) => value.to_string(),
        _ => "unavailable".into(),
    }
}

fn health_u64(reading: &HealthReading<u64>) -> String {
    match (&reading.status, reading.value) {
        (HealthSource::Available, Some(value)) => value.to_string(),
        _ => "unavailable".into(),
    }
}

fn health_f64(reading: &HealthReading<f64>) -> String {
    match (&reading.status, reading.value) {
        (HealthSource::Available, Some(value)) => format!("{value:.2}"),
        _ => "unavailable".into(),
    }
}

fn field_text(field: &Field) -> String {
    match (&field.status, field.value.as_deref()) {
        (GpuStatus::Available, Some(value)) => value.to_string(),
        _ => "unavailable".into(),
    }
}

fn package_word(status: PackageStatus) -> &'static str {
    match status {
        PackageStatus::Available => "available",
        PackageStatus::Unavailable => "unavailable",
    }
}

fn status_from(available: bool) -> CollectorAvailability {
    if available {
        CollectorAvailability::Available
    } else {
        CollectorAvailability::Unavailable
    }
}

fn availability_word(available: bool) -> &'static str {
    if available {
        "available"
    } else {
        "unavailable"
    }
}

fn yes_no(flag: bool) -> &'static str {
    if flag {
        "yes"
    } else {
        "no"
    }
}

fn normalize_label(label: Option<String>) -> Option<String> {
    label.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn push_section(out: &mut String, title: &str, entries: &[DiffEntry]) {
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    if entries.is_empty() {
        out.push_str("  (none)\n");
        return;
    }
    for entry in entries {
        out.push_str(&format!("- {}\n", entry.key));
        out.push_str(&format!("    fact: {}\n", entry.fact));
        out.push_str(&format!("    severity: {}\n", entry.severity.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_env::CoverageStatus as ToolStatus;
    use crate::files::FileCoverage;
    use crate::gpu_id::{CoverageStatus as GpuStatus, ToolCoverage};
    use crate::health_scan::SourceStatus as HealthSource;
    use crate::os_identity::SourceStatus as OsSource;
    use crate::packages::{CoverageStatus as PackageStatus, SourceCoverage};
    use crate::ports::CoverageStatus as PortStatus;
    use crate::units::CoverageStatus as UnitStatus;

    #[test]
    fn unavailable_collector_stays_in_the_payload_and_the_snapshot_is_partial() {
        let source = full_payload("pre-upgrade");
        let payload = assemble_snapshot(
            Some("pre-upgrade".into()),
            HostReports {
                os: source.collectors.os.report,
                packages: source.collectors.packages.report,
                units: source.collectors.units.report,
                ports: source.collectors.ports.report,
                gpu_id: gpu_unavailable(),
                dev_env: source.collectors.dev_env.report,
                files: source.collectors.files.report,
                health: source.collectors.health.report,
            },
        );
        assert!(!payload.clean);
        assert_eq!(
            payload.collectors.gpu_id.status,
            CollectorAvailability::Unavailable
        );
        assert_eq!(
            payload.collectors.gpu_id.report.nvidia_smi.status,
            GpuStatus::Unavailable
        );
        assert!(!payload.uses_sudo);
        assert!(!payload.installs_packages);
        assert!(!payload.opens_network);
        let json = serde_json::to_value(&payload).expect("json");
        assert_eq!(json["collectors"]["gpu_id"]["status"], "unavailable");
        assert!(json["collectors"]["gpu_id"]["report"].is_object());
        assert_eq!(payload.exit_code(), ExitCode::Partial);
        assert!(snapshot_warnings(&payload)
            .iter()
            .any(|warning| warning == "gpu_id is unavailable"));
    }

    #[test]
    fn labels_are_ordinary_strings_and_do_not_change_the_diff() {
        let baseline = full_payload("pre-upgrade");
        let current = full_payload("post-upgrade");
        assert_eq!(baseline.label.as_deref(), Some("pre-upgrade"));
        assert_eq!(current.label.as_deref(), Some("post-upgrade"));
        let diff = diff_payloads(&baseline, &current);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_is_stable_and_severity_is_separate_from_the_fact() {
        let baseline = full_payload("pre-upgrade");
        let mut current = baseline.clone();
        current.collectors.os.report.kernel_release.value = Some("7.0.0".into());
        current.collectors.packages.report.packages[0].version = "2.0".into();
        current
            .collectors
            .packages
            .report
            .packages
            .push(InstalledPackage {
                name: "mmm".into(),
                version: "1".into(),
                architecture: "amd64".into(),
            });
        current.collectors.packages.report.packages.insert(
            0,
            InstalledPackage {
                name: "aaa".into(),
                version: "1".into(),
                architecture: "amd64".into(),
            },
        );
        current
            .collectors
            .packages
            .report
            .packages
            .retain(|package| package.name != "gone");
        current.collectors.units.report.units[0].failed = true;
        current.collectors.ports.report.sockets.push(ListenSocket {
            protocol: "tcp".into(),
            address: "127.0.0.1".into(),
            port: 9,
            process: Some("discard".into()),
            attribution: Attribution::Present,
        });
        current.collectors.gpu_id.report.gpus[0]
            .driver_version
            .value = Some("999.0".into());
        current.collectors.files.report.files[0].hash = Some("ff".into());

        let diff = diff_payloads(&baseline, &current);
        let added_keys: Vec<_> = diff.added.iter().map(|entry| entry.key.as_str()).collect();
        assert_eq!(
            added_keys,
            vec![
                "package:aaa:amd64",
                "package:mmm:amd64",
                "port:tcp:127.0.0.1:9"
            ]
        );
        assert_eq!(
            diff.removed
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["package:gone:amd64"]
        );
        let changed_keys: Vec<_> = diff
            .changed
            .iter()
            .map(|entry| entry.key.as_str())
            .collect();
        let mut sorted = changed_keys.clone();
        sorted.sort_unstable();
        assert_eq!(changed_keys, sorted);

        let kernel = diff
            .changed
            .iter()
            .find(|entry| entry.key == "os:kernel_release")
            .expect("kernel");
        assert_eq!(kernel.fact, "6.8.0 -> 7.0.0");
        assert_eq!(kernel.severity, SeverityHint::Warning);
        assert!(!kernel.fact.contains("warning"));
        assert_ne!(kernel.fact, kernel.severity.as_str());

        let port = diff
            .added
            .iter()
            .find(|entry| entry.key == "port:tcp:127.0.0.1:9")
            .expect("port");
        assert_eq!(port.severity, SeverityHint::Warning);
        assert_eq!(port.fact, "process=discard");

        let unit = diff
            .changed
            .iter()
            .find(|entry| entry.key == "unit:ssh.service")
            .expect("unit");
        assert_eq!(unit.severity, SeverityHint::Warning);
        assert!(unit.fact.contains("failed=false -> "));
        assert!(unit.fact.contains("failed=true"));
        assert!(!unit.fact.contains("warning"));

        let driver = diff
            .changed
            .iter()
            .find(|entry| entry.key.ends_with(":driver_version"))
            .expect("driver");
        assert_eq!(driver.severity, SeverityHint::Warning);
        assert_eq!(driver.fact, "580.0 -> 999.0");

        let file = diff
            .changed
            .iter()
            .find(|entry| entry.key == "file:/etc/example.conf")
            .expect("file");
        assert_eq!(file.severity, SeverityHint::Warning);
        assert_eq!(file.fact, "aa -> ff");
    }

    #[test]
    fn unavailable_inventory_does_not_become_removed_facts() {
        let baseline = full_payload("pre-upgrade");
        let mut current = baseline.clone();
        current.collectors.ports = Collected {
            status: CollectorAvailability::Unavailable,
            report: ports_unavailable(),
        };
        let diff = diff_payloads(&baseline, &current);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].key, "collector:ports");
        assert_eq!(diff.changed[0].fact, "available -> unavailable");
        assert_eq!(diff.changed[0].severity, SeverityHint::Unknown);
        assert!(!diff.changed[0].fact.contains("unknown"));
    }

    #[test]
    fn installed_packages_still_diff_when_updates_are_unavailable() {
        let baseline = full_payload("pre-upgrade");
        let mut current = baseline.clone();
        current.collectors.packages.report.packages[0].version = "9".into();
        current.collectors.packages.report.updates.status = PackageStatus::Unavailable;
        current.collectors.packages.report.clean = false;
        current.collectors.packages.report.status = PackageStatus::Unavailable;
        current.collectors.packages.report.pending.clear();
        current.clean = false;
        let diff = diff_payloads(&baseline, &current);
        let version = diff
            .changed
            .iter()
            .find(|entry| entry.key == "package:bash:amd64")
            .expect("bash");
        assert_eq!(version.fact, "1.0 -> 9");
        assert_eq!(version.severity, SeverityHint::Info);
        let updates = diff
            .changed
            .iter()
            .find(|entry| entry.key == "packages:updates")
            .expect("updates");
        assert_eq!(updates.fact, "available -> unavailable");
        assert_eq!(updates.severity, SeverityHint::Unknown);
        assert!(diff
            .changed
            .iter()
            .all(|entry| entry.key != "collector:packages"));
    }

    const PRE_UPGRADE: &str = include_str!("../fixtures/snapshots/pre-upgrade.json");
    const POST_UPGRADE: &str = include_str!("../fixtures/snapshots/post-upgrade.json");
    const PARTIAL_COVERAGE: &str = include_str!("../fixtures/snapshots/partial-coverage.json");

    #[test]
    fn upgrade_fixtures_diff_kernel_driver_port_and_package() {
        let baseline = parse_payload(PRE_UPGRADE).expect("pre-upgrade fixture");
        let current = parse_payload(POST_UPGRADE).expect("post-upgrade fixture");
        assert!(baseline.clean);
        assert!(current.clean);
        assert!(!baseline.uses_sudo);
        assert!(!baseline.installs_packages);
        assert!(!baseline.opens_network);
        assert!(!current.uses_sudo);
        assert!(!current.installs_packages);
        assert!(!current.opens_network);

        let diff = diff_payloads(&baseline, &current);
        assert!(diff.removed.is_empty());
        let port = entry_named(&diff.added, "port:tcp:127.0.0.1:11434");
        assert_eq!(port.fact, "process=ollama");
        assert_eq!(port.severity, SeverityHint::Warning);
        assert_fact_is_separate(port);

        let kernel = entry_named(&diff.changed, "os:kernel_release");
        assert_eq!(kernel.fact, "6.8.0-45-generic -> 7.0.0-38-generic");
        assert_eq!(kernel.severity, SeverityHint::Warning);
        assert_fact_is_separate(kernel);

        let driver = entry_named(&diff.changed, "gpu:00000000:01:00.0:driver_version");
        assert_eq!(driver.fact, "550.90.07 -> 580.95.05");
        assert_eq!(driver.severity, SeverityHint::Warning);
        assert_fact_is_separate(driver);

        let package = entry_named(&diff.changed, "package:linux-image-generic:amd64");
        assert_eq!(package.fact, "6.8.0-45.45 -> 7.0.0-38.38");
        assert_eq!(package.severity, SeverityHint::Info);
        assert_fact_is_separate(package);
        assert!(diff
            .changed
            .iter()
            .all(|entry| entry.key != "package:bash:amd64"));

        let human = format_diff_human(
            "baseline-pre",
            "current-post",
            baseline.label.as_deref(),
            current.label.as_deref(),
            baseline.clean,
            current.clean,
            &diff,
        );
        assert!(human.contains("baseline clean: yes"));
        assert!(human.contains("current clean: yes"));
        assert!(human.contains("fact: 6.8.0-45-generic -> 7.0.0-38-generic"));
        assert!(human.contains("severity: warning"));
        assert!(!human.contains("fact: warning"));
    }

    #[test]
    fn partial_coverage_fixture_is_not_clean_and_diff_does_not_report_it_clean() {
        let stored: serde_json::Value =
            serde_json::from_str(PARTIAL_COVERAGE).expect("partial json");
        assert_eq!(stored["clean"], true);
        assert_eq!(stored["collectors"]["packages"]["report"]["clean"], false);
        assert_eq!(
            stored["collectors"]["packages"]["report"]["updates"]["status"],
            "unavailable"
        );

        let baseline = parse_payload(PRE_UPGRADE).expect("pre-upgrade fixture");
        let current = parse_payload(PARTIAL_COVERAGE).expect("partial fixture");
        assert!(baseline.clean);
        assert!(!current.clean);
        assert!(snapshot_warnings(&current)
            .iter()
            .any(|warning| warning == "packages coverage is partial"));

        let diff = diff_payloads(&baseline, &current);
        assert!(entry_named(&diff.changed, "os:kernel_release")
            .fact
            .contains("7.0.0-38-generic"));
        assert!(
            entry_named(&diff.changed, "gpu:00000000:01:00.0:driver_version")
                .fact
                .contains("580.95.05")
        );
        assert_eq!(
            entry_named(&diff.added, "port:tcp:127.0.0.1:11434").fact,
            "process=ollama"
        );
        assert!(
            entry_named(&diff.changed, "package:linux-image-generic:amd64")
                .fact
                .contains("7.0.0-38.38")
        );
        let updates = entry_named(&diff.changed, "packages:updates");
        assert_eq!(updates.fact, "available -> unavailable");
        assert_eq!(updates.severity, SeverityHint::Unknown);
        assert_fact_is_separate(updates);
        assert!(diff
            .changed
            .iter()
            .all(|entry| entry.key != "collector:packages"));

        let human = format_diff_human(
            "baseline-pre",
            "current-partial",
            baseline.label.as_deref(),
            current.label.as_deref(),
            baseline.clean,
            current.clean,
            &diff,
        );
        assert!(human.contains("baseline clean: yes"));
        assert!(human.contains("current clean: no"));
        assert!(!human.contains("current clean: yes"));
    }

    fn entry_named<'a>(entries: &'a [DiffEntry], key: &str) -> &'a DiffEntry {
        entries
            .iter()
            .find(|entry| entry.key == key)
            .unwrap_or_else(|| panic!("missing {key}"))
    }

    fn assert_fact_is_separate(entry: &DiffEntry) {
        assert_ne!(entry.fact, entry.severity.as_str());
        assert!(!matches!(
            entry.fact.as_str(),
            "info" | "warning" | "critical" | "unknown"
        ));
    }

    fn full_payload(label: &str) -> SnapshotPayload {
        assemble_snapshot(
            Some(label.into()),
            HostReports {
                os: os_report("6.8.0"),
                packages: packages_report(),
                units: units_report(false),
                ports: ports_report(),
                gpu_id: gpu_report("580.0"),
                dev_env: dev_env_report(),
                files: files_report("aa"),
                health: health_report(),
            },
        )
    }

    fn os_report(kernel: &str) -> OsIdentityReport {
        OsIdentityReport {
            uses_sudo: false,
            opens_port: false,
            collects_packages: false,
            clean: true,
            kernel_release: os_value(kernel),
            boot_id: os_value("boot-1"),
            uptime_seconds: OsReading {
                status: OsSource::Available,
                value: Some(10.0),
            },
            hostname_hash: os_value("hn-aaaaaaaaaaaaaaaa"),
        }
    }

    fn os_value(value: &str) -> OsReading<String> {
        OsReading {
            status: OsSource::Available,
            value: Some(value.into()),
        }
    }

    fn packages_report() -> PackagesReport {
        PackagesReport {
            uses_sudo: false,
            changes_packages: false,
            clean: true,
            status: PackageStatus::Available,
            installed: SourceCoverage {
                status: PackageStatus::Available,
                detail: "fixture".into(),
            },
            updates: SourceCoverage {
                status: PackageStatus::Available,
                detail: "fixture".into(),
            },
            packages: vec![
                InstalledPackage {
                    name: "bash".into(),
                    version: "1.0".into(),
                    architecture: "amd64".into(),
                },
                InstalledPackage {
                    name: "gone".into(),
                    version: "1".into(),
                    architecture: "amd64".into(),
                },
            ],
            pending: Vec::new(),
        }
    }

    fn units_report(failed: bool) -> UnitsReport {
        UnitsReport {
            uses_sudo: false,
            starts_units: false,
            stops_units: false,
            enables_units: false,
            disables_units: false,
            clean: true,
            status: UnitStatus::Available,
            systemctl: crate::units::SourceCoverage {
                status: UnitStatus::Available,
                detail: "fixture".into(),
            },
            units: vec![UnitRecord {
                name: "ssh.service".into(),
                enabled: "enabled".into(),
                active: "active".into(),
                failed,
            }],
        }
    }

    fn ports_report() -> PortsReport {
        PortsReport {
            opens_port: false,
            scans_remote: false,
            collects_arguments: false,
            clean: true,
            ss: crate::ports::SourceCoverage {
                status: PortStatus::Available,
                detail: "fixture".into(),
            },
            sockets: vec![ListenSocket {
                protocol: "tcp".into(),
                address: "127.0.0.1".into(),
                port: 22,
                process: Some("sshd".into()),
                attribution: Attribution::Present,
            }],
            unparsed_rows: 0,
        }
    }

    fn ports_unavailable() -> PortsReport {
        PortsReport {
            opens_port: false,
            scans_remote: false,
            collects_arguments: false,
            clean: false,
            ss: crate::ports::SourceCoverage {
                status: PortStatus::Unavailable,
                detail: "ss is not on PATH".into(),
            },
            sockets: Vec::new(),
            unparsed_rows: 0,
        }
    }

    fn gpu_report(driver: &str) -> GpuIdReport {
        GpuIdReport {
            uses_sudo: false,
            loads_modules: false,
            clean: true,
            nvidia_smi: ToolCoverage {
                status: GpuStatus::Available,
                detail: "fixture".into(),
            },
            gpus: vec![GpuIdentity {
                name: Field {
                    status: GpuStatus::Available,
                    value: Some("RTX 3060".into()),
                },
                driver_version: Field {
                    status: GpuStatus::Available,
                    value: Some(driver.into()),
                },
                pci_bus_id: Field {
                    status: GpuStatus::Available,
                    value: Some("00000000:01:00.0".into()),
                },
            }],
            row_warnings: Vec::new(),
        }
    }

    fn gpu_unavailable() -> GpuIdReport {
        GpuIdReport {
            uses_sudo: false,
            loads_modules: false,
            clean: false,
            nvidia_smi: ToolCoverage {
                status: GpuStatus::Unavailable,
                detail: "nvidia-smi is not on PATH".into(),
            },
            gpus: Vec::new(),
            row_warnings: Vec::new(),
        }
    }

    fn dev_env_report() -> DevEnvReport {
        let tools = ["rustc", "cargo", "python3", "node", "git", "gcc"]
            .into_iter()
            .map(|name| ToolVersion {
                name: name.into(),
                status: ToolStatus::Available,
                version_line: Some(format!("{name} 1")),
                detail: "fixture".into(),
            })
            .collect();
        DevEnvReport {
            installs_tools: false,
            uses_network: false,
            runs_package_audit: false,
            clean: true,
            tools,
        }
    }

    fn files_report(hash: &str) -> FilesReport {
        FilesReport {
            persists_contents: false,
            prints_contents: false,
            hash_algorithm: "sha256".into(),
            clean: true,
            files: vec![HashedFile {
                path: "/etc/example.conf".into(),
                status: FileCoverage::Available,
                size_bytes: Some(4),
                mtime_unix: Some(1),
                hash: Some(hash.into()),
                detail: "fixture".into(),
            }],
        }
    }

    fn health_report() -> HealthScanReport {
        HealthScanReport {
            uses_sudo: false,
            sends_signals: false,
            loads_modules: false,
            writes_bios: false,
            clean: true,
            cpu_count: health_u32_value(4),
            memory_used_bytes: health_u64_value(1),
            memory_total_bytes: health_u64_value(2),
            swap_used_bytes: health_u64_value(0),
            disk_free_bytes: health_u64_value(3),
            uptime_seconds: HealthReading {
                status: HealthSource::Available,
                value: Some(10.0),
            },
            processes: ProcessNames {
                status: HealthSource::Available,
                names: vec!["init".into()],
            },
        }
    }

    fn health_u32_value(value: u32) -> HealthReading<u32> {
        HealthReading {
            status: HealthSource::Available,
            value: Some(value),
        }
    }

    fn health_u64_value(value: u64) -> HealthReading<u64> {
        HealthReading {
            status: HealthSource::Available,
            value: Some(value),
        }
    }
}
