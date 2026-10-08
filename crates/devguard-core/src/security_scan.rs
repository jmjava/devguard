//! Findings for `devguard security scan`.
//!
//! The command calls `scan_firewall`, `scan_path_permissions`, and
//! `scan_security_updates`. It does not re-read firewall output, walk the
//! disk, or parse APT lists itself. Each finding keeps the observed fact
//! separate from a severity of `info`, `warning`, `critical`, or `unknown`.
//!
//! An unavailable source is `unknown`, and the scan is not clean. An
//! unfamiliar nftables name or sshd setting is not proof of malware.
//!
//! Severity rules, applied only after the source answered:
//! - `ufw` inactive, or an active `ufw` whose default incoming policy is
//!   `allow` or `accept`: `warning`. Otherwise `info`.
//! - Each nftables table name: `info`. The listing is detection, not an audit.
//! - sshd listening beyond localhost: `warning`. A localhost listen is `info`.
//! - `PermitRootLogin yes` and `PermitEmptyPasswords yes`: `critical`.
//! - `PasswordAuthentication yes`: `warning`.
//! - Known restrictive sshd values (`no`, `prohibit-password`,
//!   `forced-commands-only`, `without-password`) and an unset directive:
//!   `info`. Any other value is `warning`.
//! - An allowlisted path with setuid, setgid, or other-write mode bits:
//!   `warning`. Any other readable mode is `info`. The mode is a fact, not a
//!   claim that the mode is tight.
//! - A security-update count above zero, or a pending security package:
//!   `warning`. A zero count is `info`.
//!
//! The command does not use sudo, recurse, read file contents, change
//! firewall rules, or run apt.

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::firewall::{
    scan_firewall, CoverageStatus as FirewallCoverage, FirewallReport, NftTable, SshSnapshot,
    UfwSnapshot,
};
use crate::path_perms::{scan_path_permissions, PathCoverage, PathPermission, PathPermsReport};
use crate::security_updates::{
    scan_security_updates, CoverageStatus as UpdatesCoverage, NotifierSummary, SecurityUpdate,
    SecurityUpdatesReport,
};

/// Severity for one finding. This is not the fact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Critical,
    Unknown,
}

impl FindingSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

/// One observed fact and the severity assigned to it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    /// `firewall`, `paths`, or `updates`.
    pub source: String,
    pub fact: String,
    pub severity: FindingSeverity,
}

/// Human and JSON body for `devguard security scan`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityScanReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command does not open file bytes.
    pub reads_contents: bool,
    /// Always false. This command does not print file bytes.
    pub prints_contents: bool,
    /// Always false. Directories are not walked.
    pub recursive: bool,
    /// Always false. This command never runs `ufw enable`.
    pub enables_firewall: bool,
    /// Always false. This command never runs `ufw disable`.
    pub disables_firewall: bool,
    /// Always false. This command never changes nftables rules.
    pub changes_nftables: bool,
    /// Always false. This command never runs apt.
    pub runs_apt: bool,
    /// Always false. This command never installs or upgrades packages.
    pub changes_packages: bool,
    /// Always false. An unfamiliar name is not proof of malware.
    pub unfamiliar_name_is_malware: bool,
    /// False when any source is `unknown`.
    pub clean: bool,
    pub findings: Vec<Finding>,
}

impl SecurityScanReport {
    pub fn exit_code(&self) -> ExitCode {
        if !self.clean {
            return ExitCode::Partial;
        }
        if self.findings.iter().any(|finding| {
            matches!(
                finding.severity,
                FindingSeverity::Warning | FindingSeverity::Critical
            )
        }) {
            ExitCode::Findings
        } else {
            ExitCode::Success
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Unknown)
            .map(|finding| format!("{} unavailable: {}", finding.source, finding.fact))
            .collect()
    }
}

/// Read firewall, allowlisted paths, and security updates, then assign findings.
///
/// `allowlist` is `security.sensitive_path_allowlist`. An empty allowlist
/// checks no paths and is not a clean scan.
pub fn scan_security(allowlist: &[String]) -> SecurityScanReport {
    findings_from(
        &scan_firewall(),
        &scan_path_permissions(allowlist),
        &scan_security_updates(),
    )
}

/// Map three completed checks into findings. Does not collect them again.
pub fn findings_from(
    firewall: &FirewallReport,
    paths: &PathPermsReport,
    updates: &SecurityUpdatesReport,
) -> SecurityScanReport {
    let mut findings = Vec::new();
    push_firewall(&mut findings, firewall);
    push_paths(&mut findings, paths);
    push_updates(&mut findings, updates);
    let clean = findings
        .iter()
        .all(|finding| finding.severity != FindingSeverity::Unknown);
    SecurityScanReport {
        uses_sudo: false,
        reads_contents: false,
        prints_contents: false,
        recursive: false,
        enables_firewall: false,
        disables_firewall: false,
        changes_nftables: false,
        runs_apt: false,
        changes_packages: false,
        unfamiliar_name_is_malware: false,
        clean,
        findings,
    }
}

/// Human report. Severity is printed beside the fact, not inside it.
pub fn format_security_scan_human(report: &SecurityScanReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard security scan\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  reads file contents: no\n");
    out.push_str("  prints file contents: no\n");
    out.push_str("  recursive scan: no\n");
    out.push_str("  enables firewall: no\n");
    out.push_str("  disables firewall: no\n");
    out.push_str("  changes nftables: no\n");
    out.push_str("  runs apt: no\n");
    out.push_str("  changes packages: no\n");
    out.push_str("  unfamiliar name is malware: no\n");
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    out.push_str("\nFindings\n");
    if report.findings.is_empty() {
        out.push_str("  none\n");
        return out;
    }
    for finding in &report.findings {
        out.push_str(&format!(
            "- [{}] {}: {}\n",
            finding.severity.as_str(),
            finding.source,
            finding.fact
        ));
    }
    out
}

fn push_firewall(findings: &mut Vec<Finding>, report: &FirewallReport) {
    match report.ufw.status {
        FirewallCoverage::Unavailable => findings.push(unknown("firewall", &report.ufw.detail)),
        FirewallCoverage::Available => match &report.ufw_status {
            Some(snapshot) => findings.push(ufw_finding(snapshot)),
            None => findings.push(unknown("firewall", &report.ufw.detail)),
        },
    }
    match report.nftables.status {
        FirewallCoverage::Unavailable => {
            findings.push(unknown("firewall", &report.nftables.detail));
        }
        FirewallCoverage::Available if report.nft_tables.is_empty() => {
            findings.push(Finding {
                source: "firewall".into(),
                fact: "nftables listed 0 table(s); detection, not a full audit".into(),
                severity: FindingSeverity::Info,
            });
        }
        FirewallCoverage::Available => {
            for table in &report.nft_tables {
                findings.push(nft_finding(table));
            }
        }
    }
    match report.ssh.status {
        FirewallCoverage::Unavailable => findings.push(unknown("firewall", &report.ssh.detail)),
        FirewallCoverage::Available => match &report.ssh_config {
            Some(snapshot) => push_ssh(findings, snapshot),
            None => findings.push(unknown("firewall", &report.ssh.detail)),
        },
    }
}

fn push_ssh(findings: &mut Vec<Finding>, ssh: &SshSnapshot) {
    let fact = if ssh.listen_default_all {
        "sshd has no ListenAddress directive, so it listens on all interfaces".to_string()
    } else if ssh.listen_addresses.is_empty() {
        "sshd listen address list is empty".to_string()
    } else {
        format!("sshd listens on {}", ssh.listen_addresses.join(", "))
    };
    let severity = if ssh.beyond_localhost {
        FindingSeverity::Warning
    } else {
        FindingSeverity::Info
    };
    findings.push(Finding {
        source: "firewall".into(),
        fact,
        severity,
    });
    findings.push(auth_finding(
        "PermitRootLogin",
        &ssh.permit_root_login,
        FindingSeverity::Critical,
    ));
    findings.push(auth_finding(
        "PasswordAuthentication",
        &ssh.password_authentication,
        FindingSeverity::Warning,
    ));
    findings.push(auth_finding(
        "PermitEmptyPasswords",
        &ssh.permit_empty_passwords,
        FindingSeverity::Critical,
    ));
}

fn push_paths(findings: &mut Vec<Finding>, report: &PathPermsReport) {
    if report.paths.is_empty() {
        findings.push(unknown("paths", "no paths were configured"));
        return;
    }
    for entry in &report.paths {
        findings.push(path_finding(entry));
    }
}

fn push_updates(findings: &mut Vec<Finding>, report: &SecurityUpdatesReport) {
    if report.status == UpdatesCoverage::Unavailable {
        findings.push(unknown(
            "updates",
            &format!(
                "{}; {}",
                report.update_notifier.detail, report.security_lists.detail
            ),
        ));
        return;
    }
    if report.update_notifier.status == UpdatesCoverage::Available {
        let severity = report
            .notifier
            .as_ref()
            .map(notifier_severity)
            .unwrap_or(FindingSeverity::Info);
        findings.push(Finding {
            source: "updates".into(),
            fact: report.update_notifier.detail.clone(),
            severity,
        });
    }
    if report.security_lists.status == UpdatesCoverage::Available {
        if report.pending.is_empty() {
            findings.push(Finding {
                source: "updates".into(),
                fact: "no security package updates are listed".into(),
                severity: FindingSeverity::Info,
            });
        } else {
            for update in &report.pending {
                findings.push(package_finding(update));
            }
        }
    }
}

fn ufw_finding(snapshot: &UfwSnapshot) -> Finding {
    let policy = if snapshot.default_incoming.is_empty() {
        "unset"
    } else {
        snapshot.default_incoming.as_str()
    };
    let fact = format!(
        "ufw status is {}; default incoming {policy}; {} rule(s)",
        snapshot.state,
        snapshot.rules.len()
    );
    let incoming = snapshot.default_incoming.to_ascii_lowercase();
    let open_incoming = incoming == "allow" || incoming == "accept";
    let severity = if snapshot.state == "inactive" || open_incoming {
        FindingSeverity::Warning
    } else {
        FindingSeverity::Info
    };
    Finding {
        source: "firewall".into(),
        fact,
        severity,
    }
}

fn nft_finding(table: &NftTable) -> Finding {
    Finding {
        source: "firewall".into(),
        fact: format!(
            "nftables {} {} has {} chain(s); detection, not a full audit",
            table.family,
            table.name,
            table.chains.len()
        ),
        severity: FindingSeverity::Info,
    }
}

fn auth_finding(name: &str, value: &str, yes: FindingSeverity) -> Finding {
    if value.is_empty() {
        return Finding {
            source: "firewall".into(),
            fact: format!("{name} is unset in the global sshd section"),
            severity: FindingSeverity::Info,
        };
    }
    let severity = match value {
        "yes" => yes,
        "no" | "prohibit-password" | "forced-commands-only" | "without-password" => {
            FindingSeverity::Info
        }
        _ => FindingSeverity::Warning,
    };
    Finding {
        source: "firewall".into(),
        fact: format!("{name} is {value}"),
        severity,
    }
}

fn path_finding(entry: &PathPermission) -> Finding {
    match entry.status {
        PathCoverage::Unavailable => Finding {
            source: "paths".into(),
            fact: format!("{} unavailable ({})", entry.path, entry.detail),
            severity: FindingSeverity::Unknown,
        },
        PathCoverage::Available => {
            let mode = entry.mode.as_deref().unwrap_or("unavailable");
            let owner = entry.owner.as_deref().unwrap_or("unavailable");
            let group = entry.group.as_deref().unwrap_or("unavailable");
            Finding {
                source: "paths".into(),
                fact: format!(
                    "{} mode={mode} owner={owner} group={group} ({})",
                    entry.path, entry.detail
                ),
                severity: mode_severity(entry.mode.as_deref()),
            }
        }
    }
}

fn mode_severity(mode: Option<&str>) -> FindingSeverity {
    let Some(mode) = mode else {
        return FindingSeverity::Info;
    };
    let bytes = mode.as_bytes();
    if bytes.len() != 4 || !bytes.iter().all(u8::is_ascii_digit) {
        return FindingSeverity::Info;
    }
    let special = bytes[0] - b'0';
    let other = bytes[3] - b'0';
    let setuid_or_setgid = special & 0b110 != 0;
    let other_write = other & 0b010 != 0;
    if setuid_or_setgid || other_write {
        FindingSeverity::Warning
    } else {
        FindingSeverity::Info
    }
}

fn notifier_severity(summary: &NotifierSummary) -> FindingSeverity {
    let pending = summary
        .immediate_updates
        .saturating_add(summary.standard_security_updates)
        .saturating_add(summary.esm_apps_security_updates)
        .saturating_add(summary.esm_infra_security_updates);
    if pending > 0 {
        FindingSeverity::Warning
    } else {
        FindingSeverity::Info
    }
}

fn package_finding(update: &SecurityUpdate) -> Finding {
    Finding {
        source: "updates".into(),
        fact: format!(
            "{} {} -> {} {} {}",
            update.name, update.installed, update.available, update.architecture, update.pocket
        ),
        severity: FindingSeverity::Warning,
    }
}

fn unknown(source: &str, fact: &str) -> Finding {
    Finding {
        source: source.to_string(),
        fact: fact.to_string(),
        severity: FindingSeverity::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{parse_nft_ruleset, parse_ufw_status, read_ssh_config, SourceCoverage};
    use crate::security_updates::read_security_updates;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    fn covered(detail: &str) -> SourceCoverage {
        SourceCoverage {
            status: FirewallCoverage::Available,
            detail: detail.to_string(),
        }
    }

    fn missing(detail: &str) -> SourceCoverage {
        SourceCoverage {
            status: FirewallCoverage::Unavailable,
            detail: detail.to_string(),
        }
    }

    fn firewall_report(
        ufw: SourceCoverage,
        ufw_status: Option<UfwSnapshot>,
        nftables: SourceCoverage,
        nft_tables: Vec<NftTable>,
        ssh: SourceCoverage,
        ssh_config: Option<SshSnapshot>,
    ) -> FirewallReport {
        let clean = ufw.status == FirewallCoverage::Available
            && nftables.status == FirewallCoverage::Available
            && ssh.status == FirewallCoverage::Available;
        FirewallReport {
            uses_sudo: false,
            enables_firewall: false,
            disables_firewall: false,
            changes_nftables: false,
            claims_full_audit: false,
            clean,
            status: if clean {
                FirewallCoverage::Available
            } else {
                FirewallCoverage::Unavailable
            },
            ufw,
            nftables,
            ssh,
            ufw_status,
            nft_tables,
            ssh_config,
        }
    }

    fn quiet_firewall() -> FirewallReport {
        let ufw = parse_ufw_status(
            &fs::read_to_string(fixtures().join("ufw-status-verbose.txt")).unwrap(),
        )
        .expect("ufw fixture");
        let nft =
            parse_nft_ruleset(&fs::read_to_string(fixtures().join("nft-ruleset.txt")).unwrap())
                .expect("nft fixture");
        let root = fixtures().join("sshd");
        let ssh = read_ssh_config(&root.join("sshd_config"), &root).expect("sshd fixture");
        firewall_report(
            covered("ufw"),
            Some(ufw),
            covered("nft"),
            nft,
            covered("ssh"),
            Some(ssh),
        )
    }

    fn quiet_updates(dir: &Path) -> SecurityUpdatesReport {
        let notifier = dir.join("updates-available");
        let status = dir.join("status");
        let lists = dir.join("lists");
        fs::write(&notifier, "0 updates can be applied immediately.\n").unwrap();
        fs::write(
            &status,
            "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n",
        )
        .unwrap();
        fs::create_dir_all(&lists).unwrap();
        fs::write(
            lists.join(
                "security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages",
            ),
            "Package: bash\nArchitecture: amd64\nVersion: 1.0\n",
        )
        .unwrap();
        read_security_updates(&notifier, &status, &lists)
    }

    fn token_path(dir: &Path, mode: u32) -> String {
        let path = dir.join("plain.toml");
        fs::write(&path, b"token=ghp_SuperSecretTokenValue").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(mode);
        fs::set_permissions(&path, perms).unwrap();
        path.display().to_string()
    }

    fn finding<'a>(report: &'a SecurityScanReport, source: &str, fact_part: &str) -> &'a Finding {
        report
            .findings
            .iter()
            .find(|finding| finding.source == source && finding.fact.contains(fact_part))
            .unwrap_or_else(|| panic!("missing {source} finding containing {fact_part}"))
    }

    #[test]
    fn fixture_sources_keep_facts_separate_from_info_severity() {
        let dir = tempfile::tempdir().unwrap();
        let path = token_path(dir.path(), 0o640);
        let report = findings_from(
            &quiet_firewall(),
            &scan_path_permissions(&[path.clone()]),
            &quiet_updates(dir.path()),
        );
        assert!(report.clean);
        assert!(!report.uses_sudo);
        assert!(!report.reads_contents);
        assert!(!report.prints_contents);
        assert!(!report.recursive);
        assert!(!report.enables_firewall);
        assert!(!report.disables_firewall);
        assert!(!report.changes_nftables);
        assert!(!report.runs_apt);
        assert!(!report.changes_packages);
        assert!(!report.unfamiliar_name_is_malware);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());

        let ufw = finding(&report, "firewall", "ufw status is active");
        assert_eq!(ufw.severity, FindingSeverity::Info);
        assert!(ufw.fact.contains("default incoming deny"));
        assert_ne!(ufw.fact, ufw.severity.as_str());

        let nft = finding(&report, "firewall", "nftables inet filter");
        assert_eq!(nft.severity, FindingSeverity::Info);
        assert!(!nft.fact.to_ascii_lowercase().contains("malware"));
        let nat = finding(&report, "firewall", "nftables ip nat");
        assert_eq!(nat.severity, FindingSeverity::Info);

        let listen = finding(&report, "firewall", "sshd listens on 127.0.0.1");
        assert_eq!(listen.severity, FindingSeverity::Info);
        assert_eq!(
            finding(&report, "firewall", "PermitRootLogin is prohibit-password").severity,
            FindingSeverity::Info
        );

        let mode = finding(&report, "paths", &path);
        assert_eq!(mode.severity, FindingSeverity::Info);
        assert!(mode.fact.contains("mode=0640"));
        assert!(!mode.fact.contains("ghp_SuperSecretTokenValue"));

        assert_eq!(
            finding(&report, "updates", "0 standard security update(s)").severity,
            FindingSeverity::Info
        );
        assert_eq!(
            finding(&report, "updates", "no security package updates are listed").severity,
            FindingSeverity::Info
        );

        let human = format_security_scan_human(&report);
        assert!(human.contains("DevGuard security scan"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("unfamiliar name is malware: no"));
        assert!(human.contains("clean: yes"));
        assert!(human.contains("[info] firewall: ufw status is active"));
        assert!(!human.contains("ghp_SuperSecretTokenValue"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn missing_path_is_unknown_and_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.toml");
        let report = findings_from(
            &quiet_firewall(),
            &scan_path_permissions(&[missing.display().to_string()]),
            &quiet_updates(dir.path()),
        );
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let path = finding(&report, "paths", "unavailable (missing)");
        assert_eq!(path.severity, FindingSeverity::Unknown);
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("paths unavailable")));
        let human = format_security_scan_human(&report);
        assert!(human.contains("clean: no"));
        assert!(human.contains("[unknown] paths:"));
    }

    #[test]
    fn empty_allowlist_is_unknown_and_not_a_clean_disk_scan() {
        let dir = tempfile::tempdir().unwrap();
        let report = findings_from(
            &quiet_firewall(),
            &scan_path_permissions(&[]),
            &quiet_updates(dir.path()),
        );
        assert!(!report.clean);
        let empty = finding(&report, "paths", "no paths were configured");
        assert_eq!(empty.severity, FindingSeverity::Unknown);
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn unavailable_firewall_and_updates_sources_are_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let path = token_path(dir.path(), 0o640);
        let firewall = firewall_report(
            missing("`ufw` is not on PATH"),
            None,
            covered("nft"),
            parse_nft_ruleset(&fs::read_to_string(fixtures().join("nft-ruleset.txt")).unwrap())
                .unwrap(),
            missing("sshd config is missing or unreadable"),
            None,
        );
        let updates = read_security_updates(
            &dir.path().join("missing-notifier"),
            &dir.path().join("missing-status"),
            &dir.path().join("missing-lists"),
        );
        let report = findings_from(&firewall, &scan_path_permissions(&[path]), &updates);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(
            finding(&report, "firewall", "`ufw` is not on PATH").severity,
            FindingSeverity::Unknown
        );
        assert_eq!(
            finding(&report, "firewall", "sshd config is missing or unreadable").severity,
            FindingSeverity::Unknown
        );
        assert_eq!(
            finding(&report, "updates", "update-notifier status is missing").severity,
            FindingSeverity::Unknown
        );
        assert!(report
            .findings
            .iter()
            .all(|finding| !finding.fact.to_ascii_lowercase().contains("malware")));
    }

    #[test]
    fn pending_update_and_loose_mode_are_warnings() {
        let dir = tempfile::tempdir().unwrap();
        let path = token_path(dir.path(), 0o666);
        let notifier = dir.path().join("updates-available");
        let status = dir.path().join("status");
        let lists = dir.path().join("lists");
        fs::write(&notifier, "1 update can be applied immediately.\n").unwrap();
        fs::write(
            &status,
            "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n",
        )
        .unwrap();
        fs::create_dir_all(&lists).unwrap();
        fs::write(
            lists.join(
                "security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages",
            ),
            "Package: bash\nArchitecture: amd64\nVersion: 1.1\n",
        )
        .unwrap();
        let report = findings_from(
            &quiet_firewall(),
            &scan_path_permissions(&[path]),
            &read_security_updates(&notifier, &status, &lists),
        );
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Findings);
        let mode = report
            .findings
            .iter()
            .find(|finding| finding.source == "paths")
            .expect("path");
        assert_eq!(mode.severity, FindingSeverity::Warning);
        assert!(mode.fact.contains("mode=0666"));
        let package = finding(&report, "updates", "bash 1.0 -> 1.1 amd64 standard");
        assert_eq!(package.severity, FindingSeverity::Warning);
        assert!(!package.fact.contains("warning"));
    }

    #[test]
    fn root_login_and_empty_passwords_are_critical_facts() {
        let dir = tempfile::tempdir().unwrap();
        let path = token_path(dir.path(), 0o640);
        let mut firewall = quiet_firewall();
        let ssh = firewall.ssh_config.as_mut().expect("ssh");
        ssh.permit_root_login = "yes".into();
        ssh.permit_empty_passwords = "yes".into();
        let report = findings_from(
            &firewall,
            &scan_path_permissions(&[path]),
            &quiet_updates(dir.path()),
        );
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Findings);
        assert_eq!(
            finding(&report, "firewall", "PermitRootLogin is yes").severity,
            FindingSeverity::Critical
        );
        assert_eq!(
            finding(&report, "firewall", "PermitEmptyPasswords is yes").severity,
            FindingSeverity::Critical
        );
        let human = format_security_scan_human(&report);
        assert!(human.contains("[critical] firewall: PermitRootLogin is yes"));
        assert!(human.contains("unfamiliar name is malware: no"));
        assert!(!human.contains("[critical] firewall: malware"));
    }

    #[test]
    fn inactive_ufw_and_open_incoming_are_warnings() {
        let inactive = parse_ufw_status("Status: inactive\n").expect("inactive");
        assert_eq!(ufw_finding(&inactive).severity, FindingSeverity::Warning);
        let mut open = parse_ufw_status(
            &fs::read_to_string(fixtures().join("ufw-status-verbose.txt")).unwrap(),
        )
        .unwrap();
        open.default_incoming = "allow".into();
        let finding = ufw_finding(&open);
        assert_eq!(finding.severity, FindingSeverity::Warning);
        assert!(finding.fact.contains("default incoming allow"));
    }

    #[test]
    fn unfamiliar_nft_name_stays_info() {
        let tables = parse_nft_ruleset(
            "table inet not-a-virus-widget {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n",
        )
        .expect("ruleset");
        let finding = nft_finding(&tables[0]);
        assert_eq!(finding.severity, FindingSeverity::Info);
        assert!(finding.fact.contains("not-a-virus-widget"));
        assert!(!finding.fact.to_ascii_lowercase().contains("malware"));
    }

    #[test]
    fn unfamiliar_sshd_value_is_a_warning_fact() {
        let finding = auth_finding("PermitRootLogin", "sometimes", FindingSeverity::Critical);
        assert_eq!(finding.severity, FindingSeverity::Warning);
        assert_eq!(finding.fact, "PermitRootLogin is sometimes");
        assert!(!finding.fact.to_ascii_lowercase().contains("malware"));
    }

    #[test]
    fn setuid_mode_is_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let path = token_path(dir.path(), 0o4755);
        let report = scan_path_permissions(&[path]);
        let finding = path_finding(&report.paths[0]);
        assert_eq!(finding.severity, FindingSeverity::Warning);
        assert!(finding.fact.contains("mode=4755"));
    }

    #[test]
    fn beyond_localhost_is_a_warning_fact() {
        let mut firewall = quiet_firewall();
        let ssh = firewall.ssh_config.as_mut().expect("ssh");
        ssh.beyond_localhost = true;
        ssh.listen_addresses = vec!["0.0.0.0".into()];
        let dir = tempfile::tempdir().unwrap();
        let path = token_path(dir.path(), 0o640);
        let report = findings_from(
            &firewall,
            &scan_path_permissions(&[path]),
            &quiet_updates(dir.path()),
        );
        let listen = finding(&report, "firewall", "sshd listens on 0.0.0.0");
        assert_eq!(listen.severity, FindingSeverity::Warning);
        assert_eq!(report.exit_code(), ExitCode::Findings);
    }
}
