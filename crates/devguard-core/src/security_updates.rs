//! Read-only OS security-update status for `devguard security updates`.
//!
//! The command reads an update-notifier status file or security-pocket APT
//! package lists that are already on disk. It reports security updates only.
//! It does not inventory every installed package, and it does not run
//! `apt install`, `apt upgrade`, `apt full-upgrade`, or `apt update`.
//! It does not use sudo. If neither security-update source is readable, the
//! result is unavailable and not clean.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::packages::debian_version_cmp;

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

/// Counts parsed from Ubuntu's update-notifier `updates-available` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotifierSummary {
    pub immediate_updates: u64,
    pub standard_security_updates: u64,
    pub esm_apps_enabled: Option<bool>,
    pub esm_infra_enabled: Option<bool>,
    pub esm_apps_security_updates: u64,
    pub esm_infra_security_updates: u64,
}

/// An installed package whose security-pocket candidate is strictly newer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityUpdate {
    pub name: String,
    pub architecture: String,
    pub installed: String,
    pub available: String,
    /// `standard`, `esm-apps`, or `esm-infra`.
    pub pocket: String,
}

/// Human and JSON body for `devguard security updates`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityUpdatesReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never runs apt.
    pub runs_apt: bool,
    /// Always false. This command never installs or upgrades packages.
    pub changes_packages: bool,
    /// False when neither update-notifier nor security-pocket lists could be read.
    pub clean: bool,
    /// `unavailable` when neither security-update source could be read.
    pub status: CoverageStatus,
    pub update_notifier: SourceCoverage,
    pub security_lists: SourceCoverage,
    pub notifier: Option<NotifierSummary>,
    pub pending: Vec<SecurityUpdate>,
}

impl SecurityUpdatesReport {
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
        vec![format!(
            "security updates unavailable: {}; {}",
            self.update_notifier.detail, self.security_lists.detail
        )]
    }
}

const NOTIFIER_UNREADABLE: &str = "update-notifier status is missing or unreadable";
const LISTS_UNREADABLE: &str = "security APT lists are missing or unreadable";
const STATUS_UNREADABLE: &str = "dpkg status is missing or unreadable";

struct Candidate {
    version: String,
    pocket: String,
}

type CandidateMap = BTreeMap<(String, String), Candidate>;

/// Read this host once. `DEVGUARD_UPDATE_NOTIFIER` selects the notifier file.
/// `DEVGUARD_DPKG_STATUS` selects the status file. `DEVGUARD_APT_LISTS`
/// selects the APT lists directory. None of these paths is passed to apt,
/// and this function never changes packages.
pub fn scan_security_updates() -> SecurityUpdatesReport {
    read_security_updates(&notifier_path(), &status_path(), &lists_path())
}

/// Parse security-update status from fixture or host files.
///
/// Either a readable update-notifier summary or readable security-pocket
/// package lists (compared with the dpkg status file) makes the result
/// available. A missing or unreadable security-update source leaves the
/// result unavailable and not clean.
pub fn read_security_updates(
    notifier: &Path,
    status: &Path,
    lists: &Path,
) -> SecurityUpdatesReport {
    let parsed_notifier = read_text(notifier).and_then(|text| parse_notifier(&text));
    let update_notifier = match &parsed_notifier {
        Some(summary) => SourceCoverage {
            status: CoverageStatus::Available,
            detail: notifier_detail(summary),
        },
        None => SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: NOTIFIER_UNREADABLE.to_string(),
        },
    };

    let (security_lists, pending) = match read_security_lists(status, lists) {
        SecurityListsRead::Ready {
            list_count,
            pending,
        } => (
            SourceCoverage {
                status: CoverageStatus::Available,
                detail: format!("{list_count} security package list(s)"),
            },
            pending,
        ),
        SecurityListsRead::StatusUnreadable => (
            SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: STATUS_UNREADABLE.to_string(),
            },
            Vec::new(),
        ),
        SecurityListsRead::ListsUnreadable => (
            SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: LISTS_UNREADABLE.to_string(),
            },
            Vec::new(),
        ),
    };

    let clean = update_notifier.status == CoverageStatus::Available
        || security_lists.status == CoverageStatus::Available;
    let status = if clean {
        CoverageStatus::Available
    } else {
        CoverageStatus::Unavailable
    };
    SecurityUpdatesReport {
        uses_sudo: false,
        runs_apt: false,
        changes_packages: false,
        clean,
        status,
        update_notifier,
        security_lists,
        notifier: parsed_notifier,
        pending,
    }
}

/// Human report. Does not describe a missing reading as healthy.
pub fn format_security_updates_human(report: &SecurityUpdatesReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard security updates\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  runs apt: no\n");
    out.push_str("  changes packages: no\n");
    out.push_str(&format!(
        "  update-notifier: {} — {}\n",
        status_word(report.update_notifier.status),
        report.update_notifier.detail
    ));
    out.push_str(&format!(
        "  security lists: {} — {}\n",
        status_word(report.security_lists.status),
        report.security_lists.detail
    ));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    out.push_str("\nSecurity package updates\n");
    if report.security_lists.status == CoverageStatus::Unavailable {
        out.push_str("  unavailable\n");
    } else if report.pending.is_empty() {
        out.push_str("  none\n");
    } else {
        for update in &report.pending {
            out.push_str(&format!(
                "- {} {} -> {} {} {}\n",
                update.name, update.installed, update.available, update.architecture, update.pocket
            ));
        }
    }
    out
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn notifier_detail(summary: &NotifierSummary) -> String {
    let mut parts = vec![format!(
        "{} standard security update(s)",
        summary.standard_security_updates
    )];
    push_esm(
        &mut parts,
        "ESM Apps",
        summary.esm_apps_enabled,
        summary.esm_apps_security_updates,
    );
    push_esm(
        &mut parts,
        "ESM Infra",
        summary.esm_infra_enabled,
        summary.esm_infra_security_updates,
    );
    parts.join("; ")
}

fn push_esm(parts: &mut Vec<String>, label: &str, enabled: Option<bool>, count: u64) {
    match enabled {
        Some(true) => parts.push(format!(
            "{label} enabled; {count} {label} security update(s)"
        )),
        Some(false) => parts.push(format!(
            "{label} not enabled; {count} additional {label} security update(s)"
        )),
        None if count > 0 => parts.push(format!("{count} {label} security update(s)")),
        None => {}
    }
}

fn notifier_path() -> PathBuf {
    env_path(
        "DEVGUARD_UPDATE_NOTIFIER",
        "/var/lib/update-notifier/updates-available",
    )
}

fn status_path() -> PathBuf {
    env_path("DEVGUARD_DPKG_STATUS", "/var/lib/dpkg/status")
}

fn lists_path() -> PathBuf {
    env_path("DEVGUARD_APT_LISTS", "/var/lib/apt/lists")
}

fn env_path(key: &str, default: &str) -> PathBuf {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(default),
    }
}

fn read_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A notifier file is readable only when it contains Ubuntu's immediate-update
/// sentence. Other lines are optional.
fn parse_notifier(text: &str) -> Option<NotifierSummary> {
    let mut summary = NotifierSummary {
        immediate_updates: 0,
        standard_security_updates: 0,
        esm_apps_enabled: None,
        esm_infra_enabled: None,
        esm_apps_security_updates: 0,
        esm_infra_security_updates: 0,
    };
    let mut saw_immediate = false;
    for raw in text.split('\n') {
        let line = raw.trim().trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some(enabled) = esm_enabled(line, "Applications") {
            summary.esm_apps_enabled = Some(enabled);
            continue;
        }
        if let Some(enabled) = esm_enabled(line, "Infrastructure") {
            summary.esm_infra_enabled = Some(enabled);
            continue;
        }
        let Some(sentence) = line.split('.').next() else {
            continue;
        };
        let sentence = sentence.trim();
        let Some((count, rest)) = split_count(sentence) else {
            continue;
        };
        if rest == "update can be applied immediately"
            || rest == "updates can be applied immediately"
        {
            summary.immediate_updates = count;
            saw_immediate = true;
        } else if rest == "of these updates is a standard security update"
            || rest == "of these updates are standard security updates"
        {
            summary.standard_security_updates = count;
        } else if rest == "of these updates is an ESM Apps security update"
            || rest == "of these updates are ESM Apps security updates"
            || rest == "additional security update can be applied with ESM Apps"
            || rest == "additional security updates can be applied with ESM Apps"
        {
            summary.esm_apps_security_updates = count;
        } else if rest == "of these updates is an ESM Infra security update"
            || rest == "of these updates are ESM Infra security updates"
            || rest == "additional security update can be applied with ESM Infra"
            || rest == "additional security updates can be applied with ESM Infra"
        {
            summary.esm_infra_security_updates = count;
        }
    }
    if saw_immediate {
        Some(summary)
    } else {
        None
    }
}

fn esm_enabled(line: &str, service: &str) -> Option<bool> {
    let prefix = format!("Expanded Security Maintenance for {service} ");
    let rest = line.strip_prefix(&prefix)?;
    if rest.starts_with("is not enabled") {
        Some(false)
    } else if rest.starts_with("is enabled") {
        Some(true)
    } else {
        None
    }
}

fn split_count(sentence: &str) -> Option<(u64, &str)> {
    let (count, rest) = sentence.split_once(' ')?;
    let count = count.parse().ok()?;
    Some((count, rest.trim()))
}

enum SecurityListsRead {
    Ready {
        list_count: usize,
        pending: Vec<SecurityUpdate>,
    },
    StatusUnreadable,
    ListsUnreadable,
}

fn read_security_lists(status: &Path, lists: &Path) -> SecurityListsRead {
    let Some((list_count, candidates)) = read_security_package_lists(lists) else {
        return SecurityListsRead::ListsUnreadable;
    };
    let Some(text) = read_text(status) else {
        return SecurityListsRead::StatusUnreadable;
    };
    let mut installed = installed_packages(&text);
    installed.sort_by(|left, right| {
        (&left.name, &left.architecture).cmp(&(&right.name, &right.architecture))
    });
    SecurityListsRead::Ready {
        list_count,
        pending: pending_security_updates(&installed, &candidates),
    }
}

fn read_security_package_lists(dir: &Path) -> Option<(usize, CandidateMap)> {
    let entries = fs::read_dir(dir).ok()?;
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if entry.path().is_file() && is_security_package_list(name) {
            files.push(entry.path());
        }
    }
    if files.is_empty() {
        return None;
    }
    files.sort();
    let mut readable = 0usize;
    let mut candidates = BTreeMap::new();
    for path in files {
        let Some(text) = read_text(&path) else {
            continue;
        };
        let pocket = pocket_for_name(&path);
        readable = readable.saturating_add(1);
        for package in parse_stanzas(&text) {
            consider_candidate(&mut candidates, package, pocket);
        }
    }
    if readable == 0 {
        None
    } else {
        Some((readable, candidates))
    }
}

fn is_security_package_list(name: &str) -> bool {
    if !(name == "Packages" || name.ends_with("_Packages")) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    lower.contains("-security") || lower.contains("security.ubuntu.com")
}

fn pocket_for_name(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.contains("apps-security") {
        "esm-apps"
    } else if name.contains("infra-security") {
        "esm-infra"
    } else {
        "standard"
    }
}

fn consider_candidate(candidates: &mut CandidateMap, package: RawPackage, pocket: &str) {
    let key = (package.name, package.architecture);
    if let Some(existing) = candidates.get(&key) {
        if debian_version_cmp(&package.version, &existing.version) != Ordering::Greater {
            return;
        }
    }
    candidates.insert(
        key,
        Candidate {
            version: package.version,
            pocket: pocket.to_string(),
        },
    );
}

fn pending_security_updates(
    installed: &[RawPackage],
    candidates: &CandidateMap,
) -> Vec<SecurityUpdate> {
    let mut pending = Vec::new();
    for package in installed {
        let Some(candidate) = best_candidate(candidates, &package.name, &package.architecture)
        else {
            continue;
        };
        if debian_version_cmp(&candidate.version, &package.version) == Ordering::Greater {
            pending.push(SecurityUpdate {
                name: package.name.clone(),
                architecture: package.architecture.clone(),
                installed: package.version.clone(),
                available: candidate.version.clone(),
                pocket: candidate.pocket.clone(),
            });
        }
    }
    pending.sort_by(|left, right| {
        (&left.name, &left.architecture).cmp(&(&right.name, &right.architecture))
    });
    pending
}

fn best_candidate<'a>(
    candidates: &'a CandidateMap,
    name: &str,
    architecture: &str,
) -> Option<&'a Candidate> {
    let mut best: Option<&Candidate> = None;
    for arch in [architecture, "all"] {
        let Some(candidate) = candidates.get(&(name.to_string(), arch.to_string())) else {
            continue;
        };
        best = Some(match best {
            Some(current)
                if debian_version_cmp(&candidate.version, &current.version)
                    != Ordering::Greater =>
            {
                current
            }
            _ => candidate,
        });
    }
    best
}

struct RawPackage {
    name: String,
    version: String,
    architecture: String,
    installed: bool,
}

fn installed_packages(text: &str) -> Vec<RawPackage> {
    parse_stanzas(text)
        .into_iter()
        .filter(|package| package.installed)
        .collect()
}

fn parse_stanzas(text: &str) -> Vec<RawPackage> {
    let mut packages = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut last_key: Option<String> = None;
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            if let Some(package) = package_from_fields(&fields) {
                packages.push(package);
            }
            fields.clear();
            last_key = None;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(key) = &last_key {
                if let Some(value) = fields.get_mut(key) {
                    value.push(' ');
                    value.push_str(line.trim());
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_string();
        if key.is_empty() {
            continue;
        }
        last_key = Some(key.clone());
        fields.insert(key, value.trim().to_string());
    }
    if let Some(package) = package_from_fields(&fields) {
        packages.push(package);
    }
    packages
}

fn package_from_fields(fields: &BTreeMap<String, String>) -> Option<RawPackage> {
    let name = fields.get("Package")?.trim();
    let version = fields.get("Version")?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    let architecture = fields
        .get("Architecture")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let installed = fields
        .get("Status")
        .map(|status| is_installed_status(status))
        .unwrap_or(false);
    Some(RawPackage {
        name: name.to_string(),
        version: version.to_string(),
        architecture: architecture.to_string(),
        installed,
    })
}

fn is_installed_status(status: &str) -> bool {
    let mut parts = status.split_whitespace();
    let want = parts.next();
    let _flag = parts.next();
    let state = parts.next();
    matches!(want, Some("install" | "hold")) && state == Some("installed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const NOTIFIER: &str = "\
Expanded Security Maintenance for Applications is not enabled.

3 updates can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

24 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm
";

    const STATUS: &str = "\
Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.21-2ubuntu4

Package: oldlib
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.39-0ubuntu8

Package: held
Status: hold ok installed
Architecture: all
Version: 2.0-1
";

    const LISTS_MAIN: &str = "\
Package: libc6
Architecture: amd64
Version: 2.39-0ubuntu9

Package: bash
Architecture: amd64
Version: 5.2.21-2ubuntu4
";

    const LISTS_SECURITY: &str = "\
Package: bash
Architecture: amd64
Version: 5.2.21-2ubuntu5

Package: bash
Architecture: i386
Version: 99.0

Package: libc6
Architecture: amd64
Version: 2.39-0ubuntu8

Package: held
Architecture: all
Version: 2.0-2
";

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn fixture_paths(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let notifier = dir.join("updates-available");
        let status = dir.join("status");
        let lists = dir.join("lists");
        write(&notifier, NOTIFIER);
        write(&status, STATUS);
        write(
            &lists.join("archive.ubuntu.com_ubuntu_dists_resolute_main_binary-amd64_Packages"),
            LISTS_MAIN,
        );
        write(
            &lists.join(
                "security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages",
            ),
            LISTS_SECURITY,
        );
        write(&lists.join("lock"), "locked\n");
        write(
            &lists.join("security.ubuntu.com_ubuntu_dists_resolute-security_InRelease"),
            "Origin: Ubuntu\n",
        );
        (notifier, status, lists)
    }

    #[test]
    fn fixture_reports_security_updates_and_ignores_the_main_pocket() {
        let dir = tempdir().unwrap();
        let (notifier, status, lists) = fixture_paths(dir.path());
        let report = read_security_updates(&notifier, &status, &lists);
        assert!(report.clean);
        assert_eq!(report.status, CoverageStatus::Available);
        assert!(!report.uses_sudo);
        assert!(!report.runs_apt);
        assert!(!report.changes_packages);
        assert_eq!(report.update_notifier.status, CoverageStatus::Available);
        assert_eq!(report.security_lists.status, CoverageStatus::Available);
        assert_eq!(report.security_lists.detail, "1 security package list(s)");
        let summary = report.notifier.as_ref().expect("notifier");
        assert_eq!(summary.immediate_updates, 3);
        assert_eq!(summary.standard_security_updates, 1);
        assert_eq!(summary.esm_apps_enabled, Some(false));
        assert_eq!(summary.esm_apps_security_updates, 24);
        assert_eq!(summary.esm_infra_enabled, None);
        assert_eq!(
            report.pending,
            vec![
                SecurityUpdate {
                    name: "bash".into(),
                    architecture: "amd64".into(),
                    installed: "5.2.21-2ubuntu4".into(),
                    available: "5.2.21-2ubuntu5".into(),
                    pocket: "standard".into(),
                },
                SecurityUpdate {
                    name: "held".into(),
                    architecture: "all".into(),
                    installed: "2.0-1".into(),
                    available: "2.0-2".into(),
                    pocket: "standard".into(),
                },
            ]
        );
        let human = format_security_updates_human(&report);
        assert!(human.contains("DevGuard security updates"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("runs apt: no"));
        assert!(human.contains("changes packages: no"));
        assert!(human.contains("- bash 5.2.21-2ubuntu4 -> 5.2.21-2ubuntu5 amd64 standard"));
        assert!(!human.contains("libc6"));
        assert!(!human.contains("oldlib"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
        assert!(report.warnings().is_empty());
        assert_eq!(report.exit_code(), ExitCode::Success);
    }

    #[test]
    fn missing_sources_are_unavailable() {
        let dir = tempdir().unwrap();
        let report = read_security_updates(
            &dir.path().join("missing-notifier"),
            &dir.path().join("missing-status"),
            &dir.path().join("missing-lists"),
        );
        assert!(!report.clean);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert_eq!(report.update_notifier.status, CoverageStatus::Unavailable);
        assert_eq!(report.update_notifier.detail, NOTIFIER_UNREADABLE);
        assert_eq!(report.security_lists.status, CoverageStatus::Unavailable);
        assert_eq!(report.security_lists.detail, LISTS_UNREADABLE);
        assert!(report.notifier.is_none());
        assert!(report.pending.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let human = format_security_updates_human(&report);
        assert!(human.contains("clean: no"));
        assert!(human.contains("Security package updates\n  unavailable\n"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
        let warnings = report.warnings();
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("security updates")));
    }

    #[test]
    fn main_pocket_lists_are_not_a_security_source() {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        let lists = dir.path().join("lists");
        write(&status, STATUS);
        write(
            &lists.join("archive.ubuntu.com_ubuntu_dists_resolute_main_binary-amd64_Packages"),
            LISTS_MAIN,
        );
        let report = read_security_updates(&dir.path().join("missing-notifier"), &status, &lists);
        assert!(!report.clean);
        assert_eq!(report.security_lists.status, CoverageStatus::Unavailable);
        assert_eq!(report.security_lists.detail, LISTS_UNREADABLE);
        assert!(report.pending.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn notifier_alone_is_available_without_package_names() {
        let dir = tempdir().unwrap();
        let notifier = dir.path().join("updates-available");
        write(&notifier, "0 updates can be applied immediately.\n");
        let report = read_security_updates(
            &notifier,
            &dir.path().join("missing-status"),
            &dir.path().join("missing-lists"),
        );
        assert!(report.clean);
        assert_eq!(report.status, CoverageStatus::Available);
        assert_eq!(report.update_notifier.status, CoverageStatus::Available);
        assert_eq!(
            report.update_notifier.detail,
            "0 standard security update(s)"
        );
        assert_eq!(report.security_lists.status, CoverageStatus::Unavailable);
        assert!(report.pending.is_empty());
        let human = format_security_updates_human(&report);
        assert!(human.contains("Security package updates\n  unavailable\n"));
        assert!(human.contains("clean: yes"));
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
    }

    #[test]
    fn security_lists_alone_are_available() {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        let lists = dir.path().join("lists");
        write(&status, STATUS);
        write(
            &lists.join(
                "security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages",
            ),
            LISTS_SECURITY,
        );
        let report = read_security_updates(&dir.path().join("missing-notifier"), &status, &lists);
        assert!(report.clean);
        assert_eq!(report.update_notifier.status, CoverageStatus::Unavailable);
        assert_eq!(report.security_lists.status, CoverageStatus::Available);
        assert_eq!(report.pending.len(), 2);
        assert_eq!(report.exit_code(), ExitCode::Success);
        let human = format_security_updates_human(&report);
        assert!(human.contains("Security package updates\n- bash"));
        assert!(!human.contains("  none\n"));
    }

    #[test]
    fn security_lists_without_dpkg_status_are_unavailable() {
        let dir = tempdir().unwrap();
        let lists = dir.path().join("lists");
        write(
            &lists.join(
                "security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages",
            ),
            LISTS_SECURITY,
        );
        let report = read_security_updates(
            &dir.path().join("missing-notifier"),
            &dir.path().join("missing-status"),
            &lists,
        );
        assert!(!report.clean);
        assert_eq!(report.security_lists.detail, STATUS_UNREADABLE);
        assert!(report.pending.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn empty_notifier_file_is_unreadable() {
        let dir = tempdir().unwrap();
        let notifier = dir.path().join("updates-available");
        write(&notifier, "\n");
        let report = read_security_updates(
            &notifier,
            &dir.path().join("missing-status"),
            &dir.path().join("missing-lists"),
        );
        assert!(!report.clean);
        assert!(report.notifier.is_none());
        assert_eq!(report.update_notifier.detail, NOTIFIER_UNREADABLE);
    }

    #[test]
    fn singular_notifier_sentences_parse() {
        let text = "\
Expanded Security Maintenance for Infrastructure is enabled.

1 update can be applied immediately.
1 of these updates is a standard security update.
1 of these updates is an ESM Infra security update.
";
        let summary = parse_notifier(text).expect("summary");
        assert_eq!(summary.immediate_updates, 1);
        assert_eq!(summary.standard_security_updates, 1);
        assert_eq!(summary.esm_infra_enabled, Some(true));
        assert_eq!(summary.esm_infra_security_updates, 1);
        assert_eq!(summary.esm_apps_enabled, None);
    }

    #[test]
    fn esm_apps_pocket_is_labeled() {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        let lists = dir.path().join("lists");
        write(
            &status,
            "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.0\n",
        );
        write(
            &lists.join(
                "esm.ubuntu.com_ubuntu_dists_resolute-apps-security_main_binary-amd64_Packages",
            ),
            "Package: openssl\nArchitecture: amd64\nVersion: 3.0.1\n",
        );
        let report = read_security_updates(&dir.path().join("missing-notifier"), &status, &lists);
        assert_eq!(report.pending.len(), 1);
        assert_eq!(report.pending[0].pocket, "esm-apps");
        assert_eq!(report.pending[0].available, "3.0.1");
    }
}
