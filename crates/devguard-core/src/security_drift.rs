//! Port and failed-unit drift for `devguard security diff`.
//!
//! The command reads two snapshot payloads already stored by `devguard snapshot`.
//! It does not rescan the host, use sudo, or open a network connection.
//!
//! A listening port is identified by protocol, address, and port. A failed unit
//! is identified by unit name where `failed` is true. Each entry has a fact and
//! a separate severity. An unfamiliar process name is not malware proof and does
//! not change the severity.
//!
//! Default severities (`DriftRules::default`):
//! - added loopback listener (`127.*`, `::1`, `localhost`): `warning`
//! - added listener that is not loopback (`0.0.0.0`, `::`, `*`, other addresses): `critical`
//! - removed listener: `info`
//! - unit entered the failed set: `warning`
//! - unit left the failed set: `info`
//! - port or unit collector unavailable, or unparsed port rows: `unknown`
//!
//! An unavailable collector is not compared. An empty inventory on the other
//! side is not proof that nothing changed. `diff_stored_payloads_with_rules`
//! replaces a severity without rewriting the fact.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::exit::ExitCode;
use crate::ports::{Attribution, CoverageStatus as PortStatus, ListenSocket, PortsReport};
use crate::snapshot::{Collected, CollectorAvailability, SeverityHint};
use crate::units::{CoverageStatus as UnitStatus, UnitRecord, UnitsReport};

/// One added, removed, or coverage-gap entry.
///
/// `severity` is not encoded into `fact`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftFinding {
    pub key: String,
    pub fact: String,
    pub severity: SeverityHint,
}

/// Documented severities. The CLI uses [`DriftRules::default`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftRules {
    pub added_loopback_port: SeverityHint,
    pub added_exposed_port: SeverityHint,
    pub removed_port: SeverityHint,
    pub added_failed_unit: SeverityHint,
    pub removed_failed_unit: SeverityHint,
    pub collector_gap: SeverityHint,
}

impl Default for DriftRules {
    fn default() -> Self {
        Self {
            added_loopback_port: SeverityHint::Warning,
            added_exposed_port: SeverityHint::Critical,
            removed_port: SeverityHint::Info,
            added_failed_unit: SeverityHint::Warning,
            removed_failed_unit: SeverityHint::Info,
            collector_gap: SeverityHint::Unknown,
        }
    }
}

/// Human and JSON body for `devguard security diff`.
///
/// `clean` is false when a port or unit collector is unavailable or a port
/// listing has unparsed rows. That is coverage, not "no findings".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityDriftReport {
    /// False when either snapshot is missing a usable port or unit collector,
    /// or when a usable port listing left rows unparsed.
    pub clean: bool,
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never opens a network connection.
    pub opens_network: bool,
    /// Always false. This command reads stored snapshots only.
    pub rescans_host: bool,
    pub added_ports: Vec<DriftFinding>,
    pub removed_ports: Vec<DriftFinding>,
    pub added_failed_units: Vec<DriftFinding>,
    pub removed_failed_units: Vec<DriftFinding>,
    /// Unavailable collectors and unparsed port rows. Severity is `unknown`
    /// under the default rules.
    pub gaps: Vec<DriftFinding>,
}

impl SecurityDriftReport {
    pub fn exit_code(&self) -> ExitCode {
        if !self.clean {
            ExitCode::Partial
        } else if self.has_policy_findings() {
            ExitCode::Findings
        } else {
            ExitCode::Success
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.gaps
            .iter()
            .map(|finding| finding.fact.clone())
            .collect()
    }

    fn has_policy_findings(&self) -> bool {
        self.added_ports
            .iter()
            .chain(self.removed_ports.iter())
            .chain(self.added_failed_units.iter())
            .chain(self.removed_failed_units.iter())
            .any(|finding| {
                matches!(
                    finding.severity,
                    SeverityHint::Warning | SeverityHint::Critical
                )
            })
    }
}

/// Diff two stored snapshot payloads with the default severity rules.
pub fn diff_stored_payloads(
    baseline_payload: &str,
    current_payload: &str,
) -> Result<SecurityDriftReport, serde_json::Error> {
    diff_stored_payloads_with_rules(baseline_payload, current_payload, &DriftRules::default())
}

/// Diff two stored snapshot payloads. `rules` selects severities only.
pub fn diff_stored_payloads_with_rules(
    baseline_payload: &str,
    current_payload: &str,
    rules: &DriftRules,
) -> Result<SecurityDriftReport, serde_json::Error> {
    let baseline: StoredPayload = serde_json::from_str(baseline_payload)?;
    let current: StoredPayload = serde_json::from_str(current_payload)?;
    Ok(diff_views(&baseline, &current, rules))
}

pub fn format_security_drift_human(
    baseline_id: &str,
    current_id: &str,
    baseline_label: Option<&str>,
    current_label: Option<&str>,
    report: &SecurityDriftReport,
) -> String {
    let mut out = format!(
        "\
DevGuard security diff
  baseline: {baseline_id} ({baseline_label})
  current: {current_id} ({current_label})
  clean: {clean}
  uses sudo: no
  opens a network connection: no
  rescans the host: no
",
        baseline_label = baseline_label.unwrap_or("(none)"),
        current_label = current_label.unwrap_or("(none)"),
        clean = if report.clean { "yes" } else { "no" },
    );
    push_section(&mut out, "Added listening ports", &report.added_ports);
    push_section(&mut out, "Removed listening ports", &report.removed_ports);
    push_section(&mut out, "Added failed units", &report.added_failed_units);
    push_section(
        &mut out,
        "Removed failed units",
        &report.removed_failed_units,
    );
    push_section(&mut out, "Coverage gaps", &report.gaps);
    out
}

#[derive(Debug, Deserialize)]
struct StoredPayload {
    #[serde(default)]
    collectors: StoredCollectors,
}

#[derive(Debug, Default, Deserialize)]
struct StoredCollectors {
    #[serde(default)]
    ports: Option<Collected<PortsReport>>,
    #[serde(default)]
    units: Option<Collected<UnitsReport>>,
}

struct PortFact {
    fact: String,
    loopback: bool,
}

enum PortsInv {
    Gap,
    Ready {
        sockets: BTreeMap<String, PortFact>,
        unparsed: u32,
    },
}

enum UnitsInv {
    Gap,
    Ready(BTreeMap<String, String>),
}

enum GapSide {
    Baseline,
    Current,
    Both,
}

fn diff_views(
    baseline: &StoredPayload,
    current: &StoredPayload,
    rules: &DriftRules,
) -> SecurityDriftReport {
    let mut added_ports = Vec::new();
    let mut removed_ports = Vec::new();
    let mut added_failed_units = Vec::new();
    let mut removed_failed_units = Vec::new();
    let mut gaps = Vec::new();

    match (
        ports_inventory(baseline.collectors.ports.as_ref()),
        ports_inventory(current.collectors.ports.as_ref()),
    ) {
        (PortsInv::Gap, PortsInv::Gap) => {
            gaps.push(collector_gap("ports", GapSide::Both, rules));
        }
        (PortsInv::Gap, PortsInv::Ready { .. }) => {
            gaps.push(collector_gap("ports", GapSide::Baseline, rules));
        }
        (PortsInv::Ready { .. }, PortsInv::Gap) => {
            gaps.push(collector_gap("ports", GapSide::Current, rules));
        }
        (
            PortsInv::Ready {
                sockets: left,
                unparsed: left_unparsed,
            },
            PortsInv::Ready {
                sockets: right,
                unparsed: right_unparsed,
            },
        ) => {
            for key in left.keys().filter(|key| !right.contains_key(*key)) {
                let fact = left[key].fact.clone();
                removed_ports.push(finding(key.clone(), fact, rules.removed_port));
            }
            for key in right.keys().filter(|key| !left.contains_key(*key)) {
                let port = &right[key];
                let severity = if port.loopback {
                    rules.added_loopback_port
                } else {
                    rules.added_exposed_port
                };
                added_ports.push(finding(key.clone(), port.fact.clone(), severity));
            }
            if left_unparsed > 0 {
                gaps.push(unparsed_gap("baseline", left_unparsed, rules));
            }
            if right_unparsed > 0 {
                gaps.push(unparsed_gap("current", right_unparsed, rules));
            }
        }
    }

    match (
        units_inventory(baseline.collectors.units.as_ref()),
        units_inventory(current.collectors.units.as_ref()),
    ) {
        (UnitsInv::Gap, UnitsInv::Gap) => {
            gaps.push(collector_gap("units", GapSide::Both, rules));
        }
        (UnitsInv::Gap, UnitsInv::Ready(_)) => {
            gaps.push(collector_gap("units", GapSide::Baseline, rules));
        }
        (UnitsInv::Ready(_), UnitsInv::Gap) => {
            gaps.push(collector_gap("units", GapSide::Current, rules));
        }
        (UnitsInv::Ready(left), UnitsInv::Ready(right)) => {
            for key in left.keys().filter(|key| !right.contains_key(*key)) {
                removed_failed_units.push(finding(
                    key.clone(),
                    left[key].clone(),
                    rules.removed_failed_unit,
                ));
            }
            for key in right.keys().filter(|key| !left.contains_key(*key)) {
                added_failed_units.push(finding(
                    key.clone(),
                    right[key].clone(),
                    rules.added_failed_unit,
                ));
            }
        }
    }

    sort_findings(&mut added_ports);
    sort_findings(&mut removed_ports);
    sort_findings(&mut added_failed_units);
    sort_findings(&mut removed_failed_units);
    sort_findings(&mut gaps);

    SecurityDriftReport {
        clean: gaps.is_empty(),
        uses_sudo: false,
        opens_network: false,
        rescans_host: false,
        added_ports,
        removed_ports,
        added_failed_units,
        removed_failed_units,
        gaps,
    }
}

fn ports_inventory(collected: Option<&Collected<PortsReport>>) -> PortsInv {
    let Some(collected) = collected else {
        return PortsInv::Gap;
    };
    if collected.status != CollectorAvailability::Available
        || collected.report.ss.status != PortStatus::Available
    {
        return PortsInv::Gap;
    }
    PortsInv::Ready {
        sockets: port_map(&collected.report),
        unparsed: collected.report.unparsed_rows,
    }
}

fn units_inventory(collected: Option<&Collected<UnitsReport>>) -> UnitsInv {
    let Some(collected) = collected else {
        return UnitsInv::Gap;
    };
    if collected.status != CollectorAvailability::Available
        || collected.report.status != UnitStatus::Available
    {
        return UnitsInv::Gap;
    }
    UnitsInv::Ready(failed_unit_map(&collected.report))
}

fn port_map(report: &PortsReport) -> BTreeMap<String, PortFact> {
    let mut sockets = report.sockets.clone();
    sockets.sort_by(|left, right| {
        (
            &left.protocol,
            &left.address,
            left.port,
            left.process.as_deref().unwrap_or(""),
        )
            .cmp(&(
                &right.protocol,
                &right.address,
                right.port,
                right.process.as_deref().unwrap_or(""),
            ))
    });
    let mut map = BTreeMap::new();
    for socket in sockets {
        map.insert(port_key(&socket), port_fact(&socket));
    }
    map
}

fn failed_unit_map(report: &UnitsReport) -> BTreeMap<String, String> {
    let mut units: Vec<&UnitRecord> = report.units.iter().filter(|unit| unit.failed).collect();
    units.sort_by(|left, right| left.name.cmp(&right.name));
    let mut map = BTreeMap::new();
    for unit in units {
        map.insert(format!("unit:{}", unit.name), unit_fact(unit));
    }
    map
}

fn port_key(socket: &ListenSocket) -> String {
    format!(
        "port:{}:{}:{}",
        socket.protocol, socket.address, socket.port
    )
}

fn port_fact(socket: &ListenSocket) -> PortFact {
    let who = match socket.attribution {
        Attribution::Present => format!(
            "process={}",
            socket.process.as_deref().unwrap_or("unavailable")
        ),
        Attribution::Missing => "attribution missing".into(),
    };
    PortFact {
        fact: format!(
            "listening {} {}:{} {who}",
            socket.protocol, socket.address, socket.port
        ),
        loopback: is_loopback(&socket.address),
    }
}

fn unit_fact(unit: &UnitRecord) -> String {
    format!(
        "failed unit {} enabled={} active={}",
        unit.name, unit.enabled, unit.active
    )
}

fn is_loopback(address: &str) -> bool {
    let address = address.trim();
    if address.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = address
        .split_once('%')
        .map(|(host, _zone)| host)
        .unwrap_or(address);
    bare == "::1" || bare.starts_with("127.")
}

fn collector_gap(collector: &str, side: GapSide, rules: &DriftRules) -> DriftFinding {
    let where_missing = match side {
        GapSide::Baseline => "the baseline snapshot",
        GapSide::Current => "the current snapshot",
        GapSide::Both => "both snapshots",
    };
    finding(
        format!("collector:{collector}"),
        format!("{collector} collector is unavailable on {where_missing}"),
        rules.collector_gap,
    )
}

fn unparsed_gap(side: &str, rows: u32, rules: &DriftRules) -> DriftFinding {
    finding(
        format!("ports:unparsed:{side}"),
        format!("ports listing had {rows} unparsed row(s) on the {side} snapshot"),
        rules.collector_gap,
    )
}

fn finding(key: String, fact: String, severity: SeverityHint) -> DriftFinding {
    DriftFinding {
        key,
        fact,
        severity,
    }
}

fn sort_findings(findings: &mut [DriftFinding]) {
    findings.sort_by(|left, right| left.key.cmp(&right.key));
}

fn push_section(out: &mut String, title: &str, entries: &[DriftFinding]) {
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
    use crate::ports::{CoverageStatus as PortStatus, SourceCoverage as PortSource};
    use crate::units::{CoverageStatus as UnitStatus, SourceCoverage as UnitSource};

    #[test]
    fn added_and_removed_ports_and_failed_units_keep_severity_off_the_fact() {
        let baseline = payload(
            vec![
                socket("tcp", "127.0.0.1", 22, Some("sshd"), Attribution::Present),
                socket("tcp", "0.0.0.0", 80, Some("nginx"), Attribution::Present),
            ],
            0,
            true,
            vec![unit("ssh.service", false), unit("broken.service", true)],
            true,
        );
        let current = payload(
            vec![
                socket("tcp", "127.0.0.1", 22, Some("sshd"), Attribution::Present),
                socket(
                    "tcp",
                    "127.0.0.1",
                    9,
                    Some("mystery-bin"),
                    Attribution::Present,
                ),
                socket(
                    "tcp",
                    "0.0.0.0",
                    9,
                    Some("mystery-bin"),
                    Attribution::Present,
                ),
                socket("tcp", "::", 443, None, Attribution::Missing),
                socket(
                    "tcp",
                    "127.0.0.53%lo",
                    53,
                    Some("resolved"),
                    Attribution::Present,
                ),
            ],
            0,
            true,
            vec![unit("ssh.service", false), unit("fresh.service", true)],
            true,
        );
        let report = diff_stored_payloads(&baseline, &current).expect("diff");
        assert!(report.clean);
        assert!(!report.uses_sudo);
        assert!(!report.opens_network);
        assert!(!report.rescans_host);
        assert!(report.gaps.is_empty());
        assert_eq!(
            report
                .added_ports
                .iter()
                .map(|entry| (entry.key.as_str(), entry.severity))
                .collect::<Vec<_>>(),
            vec![
                ("port:tcp:0.0.0.0:9", SeverityHint::Critical),
                ("port:tcp:127.0.0.1:9", SeverityHint::Warning),
                ("port:tcp:127.0.0.53%lo:53", SeverityHint::Warning),
                ("port:tcp::::443", SeverityHint::Critical),
            ]
        );
        let exposed = report
            .added_ports
            .iter()
            .find(|entry| entry.key == "port:tcp:0.0.0.0:9")
            .expect("exposed");
        assert!(exposed.fact.contains("mystery-bin"));
        assert!(!exposed.fact.contains("critical"));
        assert!(!exposed.fact.contains("malware"));
        let loopback = report
            .added_ports
            .iter()
            .find(|entry| entry.key == "port:tcp:127.0.0.1:9")
            .expect("loopback");
        assert!(loopback.fact.contains("mystery-bin"));
        assert_eq!(loopback.severity, SeverityHint::Warning);
        let missing = report
            .added_ports
            .iter()
            .find(|entry| entry.key == "port:tcp::::443")
            .expect("missing attribution");
        assert!(missing.fact.contains("attribution missing"));
        assert_eq!(missing.severity, SeverityHint::Critical);
        assert_eq!(report.removed_ports.len(), 1);
        assert_eq!(report.removed_ports[0].key, "port:tcp:0.0.0.0:80");
        assert_eq!(report.removed_ports[0].severity, SeverityHint::Info);
        assert!(!report.removed_ports[0].fact.contains("info"));
        assert_eq!(report.added_failed_units.len(), 1);
        assert_eq!(report.added_failed_units[0].key, "unit:fresh.service");
        assert_eq!(report.added_failed_units[0].severity, SeverityHint::Warning);
        assert!(report.added_failed_units[0].fact.contains("failed unit"));
        assert!(!report.added_failed_units[0].fact.contains("warning"));
        assert_eq!(report.removed_failed_units.len(), 1);
        assert_eq!(report.removed_failed_units[0].key, "unit:broken.service");
        assert_eq!(report.removed_failed_units[0].severity, SeverityHint::Info);
        assert_eq!(report.exit_code(), ExitCode::Findings);
    }

    #[test]
    fn unchanged_process_name_is_not_an_added_port() {
        let baseline = payload(
            vec![socket(
                "tcp",
                "127.0.0.1",
                22,
                Some("sshd"),
                Attribution::Present,
            )],
            0,
            true,
            vec![unit("ssh.service", false)],
            true,
        );
        let current = payload(
            vec![socket(
                "tcp",
                "127.0.0.1",
                22,
                Some("other"),
                Attribution::Present,
            )],
            0,
            true,
            vec![unit("ssh.service", false)],
            true,
        );
        let report = diff_stored_payloads(&baseline, &current).expect("diff");
        assert!(report.added_ports.is_empty());
        assert!(report.removed_ports.is_empty());
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
    }

    #[test]
    fn unavailable_collector_is_unknown_and_not_an_empty_diff() {
        let baseline = payload(Vec::new(), 0, false, Vec::new(), true);
        let current = payload(
            vec![socket(
                "tcp",
                "0.0.0.0",
                9,
                Some("mystery-bin"),
                Attribution::Present,
            )],
            0,
            true,
            vec![unit("fresh.service", true)],
            false,
        );
        let report = diff_stored_payloads(&baseline, &current).expect("diff");
        assert!(!report.clean);
        assert!(report.added_ports.is_empty());
        assert!(report.removed_ports.is_empty());
        assert!(report.added_failed_units.is_empty());
        assert_eq!(report.gaps.len(), 2);
        assert_eq!(report.gaps[0].key, "collector:ports");
        assert_eq!(report.gaps[0].severity, SeverityHint::Unknown);
        assert!(report.gaps[0].fact.contains("baseline"));
        assert!(!report.gaps[0].fact.contains("unknown"));
        assert_eq!(report.gaps[1].key, "collector:units");
        assert!(report.gaps[1].fact.contains("current"));
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn missing_collector_keys_are_unknown_on_both_sides() {
        let report = diff_stored_payloads("{}", "{}").expect("diff");
        assert!(!report.clean);
        assert!(report.added_ports.is_empty());
        assert_eq!(
            report
                .gaps
                .iter()
                .map(|gap| gap.key.as_str())
                .collect::<Vec<_>>(),
            vec!["collector:ports", "collector:units"]
        );
        assert!(report.gaps.iter().all(|gap| gap.fact.contains("both")));
        assert!(report
            .gaps
            .iter()
            .all(|gap| gap.severity == SeverityHint::Unknown));
    }

    #[test]
    fn unparsed_rows_are_a_gap_and_parsed_sockets_still_diff() {
        let baseline = payload(
            vec![socket(
                "tcp",
                "127.0.0.1",
                22,
                Some("sshd"),
                Attribution::Present,
            )],
            2,
            true,
            vec![unit("ssh.service", false)],
            true,
        );
        let current = payload(
            vec![
                socket("tcp", "127.0.0.1", 22, Some("sshd"), Attribution::Present),
                socket("tcp", "*", 9, Some("mystery-bin"), Attribution::Present),
            ],
            0,
            true,
            vec![unit("ssh.service", false)],
            true,
        );
        let report = diff_stored_payloads(&baseline, &current).expect("diff");
        assert!(!report.clean);
        assert_eq!(report.added_ports.len(), 1);
        assert_eq!(report.added_ports[0].key, "port:tcp:*:9");
        assert_eq!(report.added_ports[0].severity, SeverityHint::Critical);
        assert_eq!(report.gaps.len(), 1);
        assert_eq!(report.gaps[0].key, "ports:unparsed:baseline");
        assert_eq!(report.gaps[0].severity, SeverityHint::Unknown);
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn rules_replace_severity_without_changing_the_fact() {
        let baseline = payload(Vec::new(), 0, true, Vec::new(), true);
        let current = payload(
            vec![socket(
                "tcp",
                "10.0.0.5",
                9,
                Some("mystery-bin"),
                Attribution::Present,
            )],
            0,
            true,
            Vec::new(),
            true,
        );
        let rules = DriftRules {
            added_exposed_port: SeverityHint::Info,
            ..DriftRules::default()
        };
        let report = diff_stored_payloads_with_rules(&baseline, &current, &rules).expect("diff");
        assert_eq!(report.added_ports.len(), 1);
        assert_eq!(report.added_ports[0].severity, SeverityHint::Info);
        assert!(report.added_ports[0].fact.contains("10.0.0.5:9"));
        assert!(report.added_ports[0].fact.contains("mystery-bin"));
        assert_eq!(report.exit_code(), ExitCode::Success);
    }

    #[test]
    fn extra_collectors_in_a_stored_snapshot_are_ignored() {
        let mut baseline: serde_json::Value =
            serde_json::from_str(&payload(Vec::new(), 0, true, Vec::new(), true)).expect("json");
        baseline["label"] = serde_json::json!("pre-upgrade");
        baseline["collectors"]["os"] =
            serde_json::json!({"status": "available", "report": {"kernel": "nope"}});
        let current = payload(Vec::new(), 0, true, vec![unit("kept.service", true)], true);
        let baseline_text = serde_json::to_string(&baseline).expect("baseline");
        let report = diff_stored_payloads(&baseline_text, &current).expect("diff");
        assert_eq!(report.added_failed_units.len(), 1);
        assert!(report.clean);
    }

    #[test]
    fn invalid_payload_is_an_error() {
        let err = diff_stored_payloads("not-json", "{}").expect_err("parse");
        assert!(err.is_syntax() || err.is_data());
    }

    #[test]
    fn human_output_separates_fact_and_severity() {
        let baseline = payload(Vec::new(), 0, true, Vec::new(), true);
        let current = payload(
            vec![socket(
                "tcp",
                "127.0.0.1",
                9,
                Some("discard"),
                Attribution::Present,
            )],
            0,
            true,
            Vec::new(),
            true,
        );
        let report = diff_stored_payloads(&baseline, &current).expect("diff");
        let text = format_security_drift_human("base", "now", Some("pre-upgrade"), None, &report);
        assert!(text.contains("DevGuard security diff"));
        assert!(text.contains("uses sudo: no"));
        assert!(text.contains("opens a network connection: no"));
        assert!(text.contains("rescans the host: no"));
        assert!(text.contains("baseline: base (pre-upgrade)"));
        assert!(text.contains("current: now ((none))"));
        assert!(text.contains("fact: listening tcp 127.0.0.1:9 process=discard"));
        assert!(text.contains("severity: warning"));
        assert!(text.contains("Added failed units\n  (none)"));
    }

    fn payload(
        sockets: Vec<ListenSocket>,
        unparsed_rows: u32,
        ports_available: bool,
        units: Vec<UnitRecord>,
        units_available: bool,
    ) -> String {
        let ports_status = if ports_available {
            CollectorAvailability::Available
        } else {
            CollectorAvailability::Unavailable
        };
        let port_source = if ports_available {
            PortStatus::Available
        } else {
            PortStatus::Unavailable
        };
        let units_status = if units_available {
            CollectorAvailability::Available
        } else {
            CollectorAvailability::Unavailable
        };
        let unit_source = if units_available {
            UnitStatus::Available
        } else {
            UnitStatus::Unavailable
        };
        let body = serde_json::json!({
            "collectors": {
                "ports": {
                    "status": ports_status,
                    "report": PortsReport {
                        opens_port: false,
                        scans_remote: false,
                        collects_arguments: false,
                        clean: ports_available && unparsed_rows == 0,
                        ss: PortSource {
                            status: port_source,
                            detail: "fixture".into(),
                        },
                        sockets,
                        unparsed_rows,
                    }
                },
                "units": {
                    "status": units_status,
                    "report": UnitsReport {
                        uses_sudo: false,
                        starts_units: false,
                        stops_units: false,
                        enables_units: false,
                        disables_units: false,
                        clean: units_available,
                        status: unit_source,
                        systemctl: UnitSource {
                            status: unit_source,
                            detail: "fixture".into(),
                        },
                        units,
                    }
                }
            }
        });
        serde_json::to_string(&body).expect("payload")
    }

    fn socket(
        protocol: &str,
        address: &str,
        port: u16,
        process: Option<&str>,
        attribution: Attribution,
    ) -> ListenSocket {
        ListenSocket {
            protocol: protocol.into(),
            address: address.into(),
            port,
            process: process.map(str::to_string),
            attribution,
        }
    }

    fn unit(name: &str, failed: bool) -> UnitRecord {
        UnitRecord {
            name: name.into(),
            enabled: "enabled".into(),
            active: if failed { "failed" } else { "active" }.into(),
            failed,
        }
    }
}
