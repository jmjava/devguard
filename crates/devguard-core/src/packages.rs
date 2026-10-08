//! Read-only APT inventory for `devguard health packages`.
//!
//! The command reports installed package names and versions from a dpkg status
//! file, and pending updates when local APT package list files are readable.
//! It does not run `apt install`, `apt upgrade`, or any command that changes
//! packages, and it does not use sudo. If the lists are missing or unreadable,
//! pending updates are unavailable and the result is not clean.

use std::cmp::Ordering;
use std::collections::BTreeMap;
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

/// One installed package from the dpkg status file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

/// An installed package whose APT list candidate is strictly newer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingUpdate {
    pub name: String,
    pub architecture: String,
    pub installed: String,
    pub available: String,
}

/// Human and JSON body for `devguard health packages`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackagesReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never installs or upgrades packages.
    pub changes_packages: bool,
    /// False when installed packages or APT lists could not be read.
    pub clean: bool,
    /// `unavailable` when installed packages or APT lists could not be read.
    pub status: CoverageStatus,
    pub installed: SourceCoverage,
    pub updates: SourceCoverage,
    pub packages: Vec<InstalledPackage>,
    pub pending: Vec<PendingUpdate>,
}

impl PackagesReport {
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
        if self.installed.status == CoverageStatus::Unavailable {
            warnings.push(format!("installed unavailable: {}", self.installed.detail));
        }
        if self.updates.status == CoverageStatus::Unavailable {
            warnings.push(format!("updates unavailable: {}", self.updates.detail));
        }
        warnings
    }
}

const STATUS_UNREADABLE: &str = "dpkg status is missing or unreadable";
const LISTS_UNREADABLE: &str = "APT lists are missing or unreadable";

type CandidateMap = BTreeMap<(String, String), String>;

/// Read this host once. `DEVGUARD_DPKG_STATUS` selects the status file.
/// `DEVGUARD_APT_LISTS` selects the APT lists directory. Neither path is
/// passed to apt or dpkg, and this function never changes packages.
pub fn scan_packages() -> PackagesReport {
    read_package_inventory(&status_path(), &lists_path())
}

/// Parse installed packages and pending updates from fixture or host files.
///
/// Pending updates are reported only when `lists` is a directory of readable
/// APT `*_Packages` files. A missing or unreadable lists directory leaves
/// that part unavailable and the result not clean.
pub fn read_package_inventory(status: &Path, lists: &Path) -> PackagesReport {
    let installed = match read_text(status) {
        Some(text) => {
            let mut packages = installed_packages(&text);
            packages.sort_by(|a, b| (&a.name, &a.architecture).cmp(&(&b.name, &b.architecture)));
            (true, packages)
        }
        None => (false, Vec::new()),
    };
    let lists_read = read_package_lists(lists);
    let (updates_available, list_count, candidates) = match lists_read {
        Some((count, candidates)) => (true, count, candidates),
        None => (false, 0, BTreeMap::new()),
    };
    let pending = if installed.0 && updates_available {
        pending_updates(&installed.1, &candidates)
    } else {
        Vec::new()
    };
    let installed_coverage = if installed.0 {
        SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("{} installed package(s)", installed.1.len()),
        }
    } else {
        SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: STATUS_UNREADABLE.to_string(),
        }
    };
    let updates_coverage = if updates_available {
        SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("{list_count} APT package list(s)"),
        }
    } else {
        SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: LISTS_UNREADABLE.to_string(),
        }
    };
    let clean = installed_coverage.status == CoverageStatus::Available
        && updates_coverage.status == CoverageStatus::Available;
    let status = if clean {
        CoverageStatus::Available
    } else {
        CoverageStatus::Unavailable
    };
    PackagesReport {
        uses_sudo: false,
        changes_packages: false,
        clean,
        status,
        installed: installed_coverage,
        updates: updates_coverage,
        packages: installed.1,
        pending,
    }
}

/// Human report. Does not describe a missing reading as healthy.
pub fn format_packages_human(report: &PackagesReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard health packages\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  changes packages: no\n");
    out.push_str(&format!(
        "  installed: {} — {}\n",
        status_word(report.installed.status),
        report.installed.detail
    ));
    out.push_str(&format!(
        "  updates: {} — {}\n",
        status_word(report.updates.status),
        report.updates.detail
    ));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    out.push_str("\nInstalled\n");
    if report.installed.status == CoverageStatus::Unavailable {
        out.push_str("  unavailable\n");
    } else if report.packages.is_empty() {
        out.push_str("  none\n");
    } else {
        for package in &report.packages {
            out.push_str(&format!(
                "- {} {} {}\n",
                package.name, package.version, package.architecture
            ));
        }
    }
    out.push_str("\nPending updates\n");
    if report.updates.status == CoverageStatus::Unavailable {
        out.push_str("  unavailable\n");
    } else if report.pending.is_empty() {
        out.push_str("  none\n");
    } else {
        for update in &report.pending {
            out.push_str(&format!(
                "- {} {} -> {} {}\n",
                update.name, update.installed, update.available, update.architecture
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

fn status_path() -> PathBuf {
    match std::env::var("DEVGUARD_DPKG_STATUS") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from("/var/lib/dpkg/status"),
    }
}

fn lists_path() -> PathBuf {
    match std::env::var("DEVGUARD_APT_LISTS") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from("/var/lib/apt/lists"),
    }
}

fn read_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_package_lists(dir: &Path) -> Option<(usize, CandidateMap)> {
    let entries = fs::read_dir(dir).ok()?;
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if entry.path().is_file() && is_package_list(name) {
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
        readable = readable.saturating_add(1);
        for package in parse_stanzas(&text) {
            consider_candidate(&mut candidates, package);
        }
    }
    if readable == 0 {
        return None;
    }
    Some((readable, candidates))
}

fn is_package_list(name: &str) -> bool {
    name == "Packages" || name.ends_with("_Packages")
}

fn consider_candidate(candidates: &mut CandidateMap, package: RawPackage) {
    let key = (package.name, package.architecture);
    match candidates.get(&key) {
        Some(existing) if debian_version_cmp(&package.version, existing) != Ordering::Greater => {}
        _ => {
            candidates.insert(key, package.version);
        }
    }
}

fn pending_updates(
    installed: &[InstalledPackage],
    candidates: &CandidateMap,
) -> Vec<PendingUpdate> {
    let mut pending = Vec::new();
    for package in installed {
        let Some(available) = best_candidate(candidates, &package.name, &package.architecture)
        else {
            continue;
        };
        if debian_version_cmp(available, &package.version) == Ordering::Greater {
            pending.push(PendingUpdate {
                name: package.name.clone(),
                architecture: package.architecture.clone(),
                installed: package.version.clone(),
                available: available.to_string(),
            });
        }
    }
    pending.sort_by(|a, b| (&a.name, &a.architecture).cmp(&(&b.name, &b.architecture)));
    pending
}

fn best_candidate<'a>(
    candidates: &'a CandidateMap,
    name: &str,
    architecture: &str,
) -> Option<&'a str> {
    let mut best: Option<&str> = None;
    for arch in [architecture, "all"] {
        let Some(version) = candidates.get(&(name.to_string(), arch.to_string())) else {
            continue;
        };
        best = Some(match best {
            Some(current) if debian_version_cmp(version, current) != Ordering::Greater => current,
            _ => version.as_str(),
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

fn installed_packages(text: &str) -> Vec<InstalledPackage> {
    parse_stanzas(text)
        .into_iter()
        .filter(|package| package.installed)
        .map(|package| InstalledPackage {
            name: package.name,
            version: package.version,
            architecture: package.architecture,
        })
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

pub(crate) fn debian_version_cmp(left: &str, right: &str) -> Ordering {
    let (epoch_left, rest_left) = split_epoch(left);
    let (epoch_right, rest_right) = split_epoch(right);
    match epoch_left.cmp(&epoch_right) {
        Ordering::Equal => {}
        other => return other,
    }
    let (upstream_left, revision_left) = split_revision(rest_left);
    let (upstream_right, revision_right) = split_revision(rest_right);
    match verrevcmp(upstream_left.as_bytes(), upstream_right.as_bytes()) {
        Ordering::Equal => verrevcmp(revision_left.as_bytes(), revision_right.as_bytes()),
        other => other,
    }
}

fn split_epoch(raw: &str) -> (u64, &str) {
    let Some((epoch, rest)) = raw.split_once(':') else {
        return (0, raw);
    };
    if epoch.is_empty() || !epoch.bytes().all(|byte| byte.is_ascii_digit()) {
        return (0, raw);
    }
    (epoch.parse::<u64>().unwrap_or(u64::MAX), rest)
}

fn split_revision(raw: &str) -> (&str, &str) {
    match raw.rfind('-') {
        Some(index) => (&raw[..index], &raw[index + 1..]),
        None => (raw, ""),
    }
}

fn verrevcmp(left: &[u8], right: &[u8]) -> Ordering {
    let mut ia = 0;
    let mut ib = 0;
    while ia < left.len() || ib < right.len() {
        let mut first_diff = 0i32;
        while (ia < left.len() && !left[ia].is_ascii_digit())
            || (ib < right.len() && !right[ib].is_ascii_digit())
        {
            let ac = version_order(left.get(ia).copied());
            let bc = version_order(right.get(ib).copied());
            if ac != bc {
                return ac.cmp(&bc);
            }
            if ia < left.len() {
                ia += 1;
            }
            if ib < right.len() {
                ib += 1;
            }
        }
        while ia < left.len() && left[ia] == b'0' {
            ia += 1;
        }
        while ib < right.len() && right[ib] == b'0' {
            ib += 1;
        }
        while ia < left.len()
            && ib < right.len()
            && left[ia].is_ascii_digit()
            && right[ib].is_ascii_digit()
        {
            if first_diff == 0 {
                first_diff = i32::from(left[ia]) - i32::from(right[ib]);
            }
            ia += 1;
            ib += 1;
        }
        if ia < left.len() && left[ia].is_ascii_digit() {
            return Ordering::Greater;
        }
        if ib < right.len() && right[ib].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

fn version_order(byte: Option<u8>) -> i32 {
    match byte {
        None => 0,
        Some(b'~') => -1,
        Some(value) if value.is_ascii_digit() => 0,
        Some(value) if value.is_ascii_alphabetic() => i32::from(value),
        Some(value) => i32::from(value) + 256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const STATUS: &str = "\
Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.21-2ubuntu4
Description: GNU Bourne Again SHell
 A command language interpreter.

Package: oldlib
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: held
Status: hold ok installed
Architecture: all
Version: 2.0-1

Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.39-0ubuntu8
";

    const LISTS_MAIN: &str = "\
Package: bash
Architecture: amd64
Version: 5.2.21-2ubuntu4

Package: bash
Architecture: i386
Version: 99.0

Package: held
Architecture: all
Version: 2.0-1

Package: libc6
Architecture: amd64
Version: 2.39-0ubuntu8.1
";

    const LISTS_SECURITY: &str = "\
Package: bash
Architecture: amd64
Version: 5.2.21-2ubuntu5

Package: libc6
Architecture: amd64
Version: 2.39-0ubuntu8
";

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn fixture() -> (tempfile::TempDir, PackagesReport) {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        let lists = dir.path().join("lists");
        write(&status, STATUS);
        write(
            &lists.join("archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages"),
            LISTS_MAIN,
        );
        write(
            &lists
                .join("security.ubuntu.com_ubuntu_dists_noble-security_main_binary-amd64_Packages"),
            LISTS_SECURITY,
        );
        write(&lists.join("lock"), "locked\n");
        write(
            &lists.join("archive.ubuntu.com_ubuntu_dists_noble_InRelease"),
            "Origin: Ubuntu\n",
        );
        let report = read_package_inventory(&status, &lists);
        (dir, report)
    }

    #[test]
    fn fixture_lists_report_names_versions_and_newer_candidates() {
        let (_dir, report) = fixture();
        assert!(report.clean);
        assert_eq!(report.status, CoverageStatus::Available);
        assert!(!report.uses_sudo);
        assert!(!report.changes_packages);
        assert_eq!(report.installed.status, CoverageStatus::Available);
        assert_eq!(report.updates.status, CoverageStatus::Available);
        assert_eq!(report.updates.detail, "2 APT package list(s)");
        assert_eq!(
            report.packages,
            vec![
                InstalledPackage {
                    name: "bash".into(),
                    version: "5.2.21-2ubuntu4".into(),
                    architecture: "amd64".into(),
                },
                InstalledPackage {
                    name: "held".into(),
                    version: "2.0-1".into(),
                    architecture: "all".into(),
                },
                InstalledPackage {
                    name: "libc6".into(),
                    version: "2.39-0ubuntu8".into(),
                    architecture: "amd64".into(),
                },
            ]
        );
        assert_eq!(
            report.pending,
            vec![
                PendingUpdate {
                    name: "bash".into(),
                    architecture: "amd64".into(),
                    installed: "5.2.21-2ubuntu4".into(),
                    available: "5.2.21-2ubuntu5".into(),
                },
                PendingUpdate {
                    name: "libc6".into(),
                    architecture: "amd64".into(),
                    installed: "2.39-0ubuntu8".into(),
                    available: "2.39-0ubuntu8.1".into(),
                },
            ]
        );
        let human = format_packages_human(&report);
        assert!(human.contains("DevGuard health packages"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("changes packages: no"));
        assert!(human.contains("- bash 5.2.21-2ubuntu4 amd64"));
        assert!(human.contains("- bash 5.2.21-2ubuntu4 -> 5.2.21-2ubuntu5 amd64"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
        assert!(report.warnings().is_empty());
        assert_eq!(report.exit_code(), ExitCode::Success);
    }

    #[test]
    fn missing_lists_leave_updates_unavailable() {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        write(&status, STATUS);
        let report = read_package_inventory(&status, &dir.path().join("missing-lists"));
        assert!(!report.clean);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert_eq!(report.installed.status, CoverageStatus::Available);
        assert_eq!(report.packages.len(), 3);
        assert_eq!(report.updates.status, CoverageStatus::Unavailable);
        assert_eq!(report.updates.detail, LISTS_UNREADABLE);
        assert!(report.pending.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let warnings = report.warnings();
        assert!(warnings.iter().any(|warning| warning.contains("updates")));
        assert!(!warnings.iter().any(|warning| warning.contains("installed")));
        let human = format_packages_human(&report);
        assert!(human.contains("Pending updates\n  unavailable\n"));
        assert!(human.contains("- bash 5.2.21-2ubuntu4 amd64"));
        assert!(human.contains("clean: no"));
    }

    #[test]
    fn empty_lists_directory_is_unreadable() {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        let lists = dir.path().join("lists");
        write(&status, STATUS);
        fs::create_dir_all(&lists).unwrap();
        write(&lists.join("lock"), "");
        let report = read_package_inventory(&status, &lists);
        assert!(!report.clean);
        assert_eq!(report.updates.status, CoverageStatus::Unavailable);
        assert_eq!(report.updates.detail, LISTS_UNREADABLE);
    }

    #[test]
    fn lists_path_that_is_a_file_is_unreadable() {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        write(&status, STATUS);
        let report = read_package_inventory(&status, &status);
        assert_eq!(report.updates.status, CoverageStatus::Unavailable);
        assert!(!report.clean);
    }

    #[test]
    fn missing_status_is_not_clean() {
        let dir = tempdir().unwrap();
        let lists = dir.path().join("lists");
        write(&lists.join("dist_main_binary-amd64_Packages"), LISTS_MAIN);
        let report = read_package_inventory(&dir.path().join("missing-status"), &lists);
        assert!(!report.clean);
        assert!(report.packages.is_empty());
        assert!(report.pending.is_empty());
        assert_eq!(report.installed.status, CoverageStatus::Unavailable);
        assert_eq!(report.installed.detail, STATUS_UNREADABLE);
        assert_eq!(report.updates.status, CoverageStatus::Available);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let human = format_packages_human(&report);
        assert!(human.contains("Installed\n  unavailable\n"));
        assert!(human.contains("Pending updates\n  none\n"));
    }

    #[test]
    fn equal_and_older_candidates_are_not_pending() {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        let lists = dir.path().join("lists");
        write(
            &status,
            "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2:1.0\n\n",
        );
        write(
            &lists.join("dist_main_binary-amd64_Packages"),
            "Package: bash\nArchitecture: amd64\nVersion: 1:9.0\n\nPackage: bash\nArchitecture: amd64\nVersion: 2:1.0\n",
        );
        let report = read_package_inventory(&status, &lists);
        assert!(report.clean);
        assert!(report.pending.is_empty());
        let human = format_packages_human(&report);
        assert!(human.contains("Pending updates\n  none\n"));
    }

    #[test]
    fn tilde_and_numeric_versions_follow_debian_order() {
        assert_eq!(debian_version_cmp("1.0", "1.0"), Ordering::Equal);
        assert_eq!(debian_version_cmp("1.0", "1.1"), Ordering::Less);
        assert_eq!(debian_version_cmp("1.10", "1.9"), Ordering::Greater);
        assert_eq!(debian_version_cmp("1.01", "1.1"), Ordering::Equal);
        assert_eq!(debian_version_cmp("1.0-1", "1.0-2"), Ordering::Less);
        assert_eq!(debian_version_cmp("1:1.0", "2.0"), Ordering::Greater);
        assert_eq!(debian_version_cmp("0:1.0", "1.0"), Ordering::Equal);
        assert_eq!(debian_version_cmp("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(debian_version_cmp("1.0~rc1", "1.0~rc2"), Ordering::Less);
        assert_eq!(
            debian_version_cmp("1.0ubuntu1", "1.0ubuntu2"),
            Ordering::Less
        );
        assert_eq!(debian_version_cmp("2:1.0", "1:9.0"), Ordering::Greater);
    }

    #[test]
    fn prerelease_candidate_is_a_pending_update() {
        let dir = tempdir().unwrap();
        let status = dir.path().join("status");
        let lists = dir.path().join("lists");
        write(
            &status,
            "Package: widget\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0~rc1\n",
        );
        write(
            &lists.join("Packages"),
            "Package: widget\nArchitecture: amd64\nVersion: 1.0\n",
        );
        let report = read_package_inventory(&status, &lists);
        assert_eq!(report.pending.len(), 1);
        assert_eq!(report.pending[0].available, "1.0");
        assert_eq!(report.pending[0].installed, "1.0~rc1");
    }
}
