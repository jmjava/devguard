//! Dry-run plan for `devguard backup plan`.
//!
//! The plan lists configured include paths, exclude patterns, unreadable
//! paths, and huge-model warnings. It does not choose `restic` or `rustic`,
//! spawn either binary, create a repository, or write a snapshot. A missing
//! engine or repository is unavailable, and that result is not clean. An empty
//! include list is not a plan of the whole disk.
//!
//! File bytes are never opened. Names and metadata are enough to classify a
//! path. Symlinks are not followed. The filesystem root is refused.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{BackupConfig, Config};
use crate::exit::ExitCode;
use crate::redact::redact_text;

const MAX_WALK_ENTRIES: usize = 4_096;
const MAX_WALK_DEPTH: usize = 16;
const MAX_HUGE_WARNINGS: usize = 64;

/// `available` or `unavailable`. A missing engine, repository, or include is never clean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlanCoverage {
    Available,
    Unavailable,
}

/// One configured include path after `~` expansion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedInclude {
    pub configured: String,
    pub path: String,
    pub status: PlanCoverage,
    pub detail: String,
}

/// A path the plan could not read. File bytes are not included.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnreadablePath {
    pub path: String,
    pub detail: String,
}

/// Human and JSON body for `devguard backup plan`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupPlanReport {
    /// Always true. This command never writes a backup.
    pub dry_run: bool,
    /// Always false. This command does not write a snapshot.
    pub writes_snapshot: bool,
    /// Always false. This command does not create a repository.
    pub creates_repository: bool,
    /// Always false. This command does not spawn a backup engine.
    pub runs_engine: bool,
    /// Always false. This command does not choose restic or rustic.
    pub engine_selected: bool,
    /// Always false. This command does not call sudo.
    pub uses_sudo: bool,
    /// Always false. This command does not call systemctl.
    pub calls_systemctl: bool,
    /// Always false. An empty include list is not a plan of the whole disk.
    pub whole_disk: bool,
    /// False when the engine or repository is missing, the include list is
    /// empty, any include is unreadable, or the walk stopped early.
    /// Huge-model warnings are listed separately and do not by themselves
    /// clear this flag.
    pub clean: bool,
    /// True when the include walk hit its entry or depth bound.
    pub walk_limited: bool,
    pub engine: Option<String>,
    pub engine_status: PlanCoverage,
    pub repository: Option<String>,
    pub repository_status: PlanCoverage,
    /// Metadata check only. A missing directory is not created.
    pub repository_exists: bool,
    pub includes: Vec<PlannedInclude>,
    pub excludes: Vec<String>,
    pub unreadable: Vec<UnreadablePath>,
    pub huge_model_warnings: Vec<String>,
}

impl BackupPlanReport {
    pub fn exit_code(&self) -> ExitCode {
        if !self.clean {
            ExitCode::Partial
        } else if !self.huge_model_warnings.is_empty() {
            ExitCode::Findings
        } else {
            ExitCode::Success
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.engine_status == PlanCoverage::Unavailable {
            warnings.push("backup engine is not configured".to_string());
        }
        if self.repository_status == PlanCoverage::Unavailable {
            warnings.push("backup repository is not configured".to_string());
        }
        if self.includes.is_empty() {
            warnings.push(
                "no include paths were configured; this is not a plan of the whole disk"
                    .to_string(),
            );
        }
        for entry in &self.unreadable {
            warnings.push(format!("{} unreadable: {}", entry.path, entry.detail));
        }
        if self.walk_limited {
            warnings.push("include walk stopped before every path was listed".to_string());
        }
        warnings.extend(self.huge_model_warnings.iter().cloned());
        warnings
    }
}

/// Build a dry-run plan from backup settings. Does not spawn a process.
pub fn plan_backup(backup: &BackupConfig) -> BackupPlanReport {
    let engine_name = backup.engine.trim();
    let (engine, engine_status) = if engine_name.is_empty() {
        (None, PlanCoverage::Unavailable)
    } else {
        (Some(engine_name.to_string()), PlanCoverage::Available)
    };

    let repository_raw = backup
        .repository
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (repository, repository_status, repository_exists) = match repository_raw {
        Some(raw) => {
            let exists = Config::expand_user_path(raw)
                .map(|path| path.exists())
                .unwrap_or(false);
            (Some(redact_text(raw)), PlanCoverage::Available, exists)
        }
        None => (None, PlanCoverage::Unavailable, false),
    };

    let excludes: Vec<String> = backup
        .exclude
        .iter()
        .map(|pattern| redact_text(pattern.trim()))
        .filter(|pattern| !pattern.is_empty())
        .collect();

    let scanned = scan_includes(&backup.include, &excludes);
    let mut huge_model_warnings = pattern_warnings(&excludes);
    for warning in scanned.warnings {
        push_unique(&mut huge_model_warnings, warning);
    }

    let includes_readable = !scanned.includes.is_empty()
        && scanned.unreadable.is_empty()
        && scanned
            .includes
            .iter()
            .all(|entry| entry.status == PlanCoverage::Available)
        && !scanned.walk_limited;
    let clean = engine_status == PlanCoverage::Available
        && repository_status == PlanCoverage::Available
        && includes_readable;

    BackupPlanReport {
        dry_run: true,
        writes_snapshot: false,
        creates_repository: false,
        runs_engine: false,
        engine_selected: false,
        uses_sudo: false,
        calls_systemctl: false,
        whole_disk: false,
        clean,
        walk_limited: scanned.walk_limited,
        engine,
        engine_status,
        repository,
        repository_status,
        repository_exists,
        includes: scanned.includes,
        excludes,
        unreadable: scanned.unreadable,
        huge_model_warnings,
    }
}

pub fn format_backup_plan_human(report: &BackupPlanReport) -> String {
    let mut out = format!(
        "\
DevGuard backup plan
  dry run: yes
  writes snapshot: no
  creates repository: no
  runs engine: no
  engine selected: no
  uses sudo: no
  calls systemctl: no
  whole disk: no
  clean: {clean}
  walk limited: {limited}
  engine: {engine}
  repository: {repository}
  repository exists: {exists}
",
        clean = yes_no(report.clean),
        limited = yes_no(report.walk_limited),
        engine = coverage_label(report.engine.as_deref(), report.engine_status),
        repository = coverage_label(report.repository.as_deref(), report.repository_status),
        exists = yes_no(report.repository_exists),
    );

    if report.includes.is_empty() {
        out.push_str("\nNo include paths were configured. This is not a plan of the whole disk.\n");
    }

    out.push_str("\nIncludes\n");
    if report.includes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for entry in &report.includes {
            out.push_str(&format!(
                "- {path} ({status}: {detail})\n",
                path = entry.path,
                status = coverage_word(entry.status),
                detail = entry.detail,
            ));
        }
    }

    out.push_str("\nExcludes\n");
    if report.excludes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for pattern in &report.excludes {
            out.push_str(&format!("- {pattern}\n"));
        }
    }

    out.push_str("\nUnreadable\n");
    if report.unreadable.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for entry in &report.unreadable {
            out.push_str(&format!("- {} ({})\n", entry.path, entry.detail));
        }
    }

    out.push_str("\nHuge-model warnings\n");
    if report.huge_model_warnings.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for warning in &report.huge_model_warnings {
            out.push_str(&format!("- {warning}\n"));
        }
    }
    out
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn coverage_word(status: PlanCoverage) -> &'static str {
    match status {
        PlanCoverage::Available => "available",
        PlanCoverage::Unavailable => "unavailable",
    }
}

fn coverage_label(value: Option<&str>, status: PlanCoverage) -> String {
    match (status, value) {
        (PlanCoverage::Available, Some(value)) => value.to_string(),
        _ => "unavailable".to_string(),
    }
}

struct IncludeScan {
    includes: Vec<PlannedInclude>,
    unreadable: Vec<UnreadablePath>,
    warnings: Vec<String>,
    walk_limited: bool,
}

fn scan_includes(raw_includes: &[String], excludes: &[String]) -> IncludeScan {
    let mut scan = IncludeScan {
        includes: Vec::new(),
        unreadable: Vec::new(),
        warnings: Vec::new(),
        walk_limited: false,
    };
    let mut remaining = MAX_WALK_ENTRIES;
    for raw in raw_includes {
        let configured = redact_text(raw.trim());
        if configured.is_empty() {
            scan.includes.push(PlannedInclude {
                configured: configured.clone(),
                path: String::new(),
                status: PlanCoverage::Unavailable,
                detail: "path is empty".to_string(),
            });
            scan.unreadable.push(UnreadablePath {
                path: "(empty)".to_string(),
                detail: "path is empty".to_string(),
            });
            continue;
        }
        let expanded = match Config::expand_user_path(raw.trim()) {
            Ok(path) => path,
            Err(_) => {
                mark_unreadable(&mut scan, &configured, &configured, "unable to expand path");
                continue;
            }
        };
        let display = redact_text(&expanded.display().to_string());
        if is_filesystem_root(&expanded) {
            scan.includes.push(PlannedInclude {
                configured,
                path: display,
                status: PlanCoverage::Unavailable,
                detail: "filesystem root is not a backup include".to_string(),
            });
            continue;
        }
        inspect_include(
            &mut scan,
            &mut remaining,
            configured,
            expanded,
            display,
            excludes,
        );
    }
    scan
}

fn mark_unreadable(scan: &mut IncludeScan, configured: &str, path: &str, detail: &str) {
    scan.includes.push(PlannedInclude {
        configured: configured.to_string(),
        path: path.to_string(),
        status: PlanCoverage::Unavailable,
        detail: detail.to_string(),
    });
    scan.unreadable.push(UnreadablePath {
        path: path.to_string(),
        detail: detail.to_string(),
    });
}

fn inspect_include(
    scan: &mut IncludeScan,
    remaining: &mut usize,
    configured: String,
    expanded: PathBuf,
    display: String,
    excludes: &[String],
) {
    let meta = match fs::symlink_metadata(&expanded) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            mark_unreadable(scan, &configured, &display, "missing");
            return;
        }
        Err(_) => {
            mark_unreadable(scan, &configured, &display, "unreadable");
            return;
        }
    };
    if meta.file_type().is_symlink() {
        scan.includes.push(PlannedInclude {
            configured,
            path: display,
            status: PlanCoverage::Unavailable,
            detail: "symlink (not followed)".to_string(),
        });
        return;
    }

    let key = match_key(&expanded, &expanded);
    note_huge_model(scan, excludes, &key, &display);
    let root_excluded = is_excluded(excludes, &key);

    if meta.is_dir() {
        if let Err(err) = fs::read_dir(&expanded) {
            let detail = if err.kind() == std::io::ErrorKind::NotFound {
                "missing"
            } else {
                "unreadable"
            };
            mark_unreadable(scan, &configured, &display, detail);
            return;
        }
        scan.includes.push(PlannedInclude {
            configured,
            path: display,
            status: PlanCoverage::Available,
            detail: if root_excluded {
                "directory (excluded)".to_string()
            } else {
                "directory".to_string()
            },
        });
        if !root_excluded {
            walk_dir(scan, remaining, &expanded, &expanded, excludes, 1);
        }
        return;
    }

    scan.includes.push(PlannedInclude {
        configured,
        path: display,
        status: PlanCoverage::Available,
        detail: "regular file".to_string(),
    });
}

fn walk_dir(
    scan: &mut IncludeScan,
    remaining: &mut usize,
    include_root: &Path,
    dir: &Path,
    excludes: &[String],
    depth: usize,
) {
    if depth > MAX_WALK_DEPTH || *remaining == 0 {
        scan.walk_limited = true;
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => {
            scan.unreadable.push(UnreadablePath {
                path: redact_text(&dir.display().to_string()),
                detail: "unreadable".to_string(),
            });
            return;
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => paths.push(entry.path()),
            Err(_) => {
                scan.unreadable.push(UnreadablePath {
                    path: redact_text(&dir.display().to_string()),
                    detail: "unreadable directory entry".to_string(),
                });
            }
        }
    }
    paths.sort();
    for path in paths {
        if *remaining == 0 {
            scan.walk_limited = true;
            return;
        }
        *remaining -= 1;
        let display = redact_text(&path.display().to_string());
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                scan.unreadable.push(UnreadablePath {
                    path: display,
                    detail: "missing".to_string(),
                });
                continue;
            }
            Err(_) => {
                scan.unreadable.push(UnreadablePath {
                    path: display,
                    detail: "unreadable".to_string(),
                });
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let key = match_key(include_root, &path);
        let excluded = is_excluded(excludes, &key);
        note_huge_model(scan, excludes, &key, &display);
        if meta.is_dir() && !excluded {
            walk_dir(scan, remaining, include_root, &path, excludes, depth + 1);
        }
    }
}

fn note_huge_model(scan: &mut IncludeScan, excludes: &[String], key: &str, display: &str) {
    if !is_huge_model_key(key) {
        return;
    }
    if scan.warnings.len() >= MAX_HUGE_WARNINGS {
        scan.walk_limited = true;
        return;
    }
    let warning = if is_excluded(excludes, key) {
        format!("excluded huge model: {display}")
    } else {
        format!("huge model would be included: {display}")
    };
    push_unique(&mut scan.warnings, warning);
}

fn pattern_warnings(excludes: &[String]) -> Vec<String> {
    excludes
        .iter()
        .filter(|pattern| is_huge_model_exclude(pattern))
        .map(|pattern| format!("exclude pattern `{pattern}` omits huge models"))
        .collect()
}

fn is_huge_model_exclude(pattern: &str) -> bool {
    let lower = pattern.to_ascii_lowercase();
    lower.contains("gguf") || lower.contains(".bin") || lower.contains("models")
}

fn is_huge_model_key(key: &str) -> bool {
    let parts: Vec<&str> = key.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| *part == "models") {
        return true;
    }
    match parts.last() {
        Some(name) => {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".gguf") || lower.ends_with(".bin")
        }
        None => false,
    }
}

fn is_excluded(excludes: &[String], key: &str) -> bool {
    excludes.iter().any(|pattern| glob_match(pattern, key))
}

fn match_key(include_root: &Path, path: &Path) -> String {
    if path == include_root {
        return include_root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
    }
    path.strip_prefix(include_root)
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

fn is_filesystem_root(path: &Path) -> bool {
    lexical_normal(path) == Path::new("/")
}

fn lexical_normal(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir => out.push(component),
            Component::Normal(part) => out.push(part),
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
        }
    }
    out
}

fn push_unique(warnings: &mut Vec<String>, warning: String) {
    if !warnings.iter().any(|existing| existing == &warning) {
        warnings.push(warning);
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match_parts(&pat, &parts)
}

fn match_parts(pat: &[&str], parts: &[&str]) -> bool {
    if pat.is_empty() {
        return parts.is_empty();
    }
    if pat[0] == "**" {
        if match_parts(&pat[1..], parts) {
            return true;
        }
        return !parts.is_empty() && match_parts(pat, &parts[1..]);
    }
    if parts.is_empty() {
        return false;
    }
    component_match(pat[0], parts[0]) && match_parts(&pat[1..], &parts[1..])
}

fn component_match(pattern: &str, text: &str) -> bool {
    match_star(pattern.as_bytes(), text.as_bytes())
}

fn match_star(pattern: &[u8], text: &[u8]) -> bool {
    let mut pattern_index = 0;
    let mut text_index = 0;
    let mut star_at: Option<usize> = None;
    let mut star_text = 0;
    while text_index < text.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == text[text_index])
        {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_at = Some(pattern_index);
            star_text = text_index;
            pattern_index += 1;
        } else if let Some(star) = star_at {
            pattern_index = star + 1;
            star_text += 1;
            text_index = star_text;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn sample_config(include: &str, repository: Option<&str>, exclude: &[&str]) -> BackupConfig {
        BackupConfig {
            engine: "restic".into(),
            repository: repository.map(str::to_string),
            include: vec![include.to_string()],
            exclude: exclude
                .iter()
                .map(|pattern| (*pattern).to_string())
                .collect(),
            verify_mode: "sample".into(),
        }
    }

    #[test]
    fn empty_include_is_not_a_whole_disk_plan() {
        let report = plan_backup(&BackupConfig::default());
        assert!(!report.clean);
        assert!(!report.whole_disk);
        assert!(!report.runs_engine);
        assert!(!report.engine_selected);
        assert!(!report.writes_snapshot);
        assert!(!report.creates_repository);
        assert!(!report.uses_sudo);
        assert!(!report.calls_systemctl);
        assert!(report.dry_run);
        assert_eq!(report.engine_status, PlanCoverage::Available);
        assert_eq!(report.repository_status, PlanCoverage::Unavailable);
        assert!(report.includes.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let human = format_backup_plan_human(&report);
        assert!(human.contains("not a plan of the whole disk"));
        assert!(human.contains("whole disk: no"));
        assert!(human.contains("runs engine: no"));
        let warnings = report.huge_model_warnings.join("\n");
        assert!(warnings.contains("gguf"));
        assert!(warnings.contains(".bin"));
        assert!(warnings.contains("models"));
    }

    #[test]
    fn blank_engine_is_unavailable() {
        let backup = BackupConfig {
            engine: "  ".into(),
            repository: Some("/tmp/devguard-backup-plan-unused".into()),
            ..BackupConfig::default()
        };
        let report = plan_backup(&backup);
        assert_eq!(report.engine_status, PlanCoverage::Unavailable);
        assert!(report.engine.is_none());
        assert!(!report.clean);
        assert!(!report.engine_selected);
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn missing_repository_is_unavailable_and_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let include = dir.path().join("docs");
        fs::create_dir(&include).unwrap();
        let repo = dir.path().join("repo");
        let backup = sample_config(include.to_str().unwrap(), None, &[]);
        let report = plan_backup(&backup);
        assert_eq!(report.repository_status, PlanCoverage::Unavailable);
        assert!(!report.repository_exists);
        assert!(!report.clean);
        assert!(!repo.exists());
        assert!(!report.creates_repository);
    }

    #[test]
    fn readable_include_lists_paths_without_writing_a_repository() {
        let dir = tempfile::tempdir().unwrap();
        let include = dir.path().join("docs");
        fs::create_dir(&include).unwrap();
        fs::write(include.join("notes.txt"), "hello").unwrap();
        let repo = dir.path().join("repo");
        let backup = sample_config(include.to_str().unwrap(), Some(repo.to_str().unwrap()), &[]);
        let before = repo.exists();
        let report = plan_backup(&backup);
        assert!(!before);
        assert!(!repo.exists());
        assert!(report.clean);
        assert!(!report.whole_disk);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert_eq!(report.includes.len(), 1);
        assert_eq!(report.includes[0].status, PlanCoverage::Available);
        assert!(report.unreadable.is_empty());
        assert!(report.huge_model_warnings.is_empty());
        assert!(!report.repository_exists);
    }

    #[test]
    fn missing_include_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        let repo = dir.path().join("repo");
        let backup = sample_config(missing.to_str().unwrap(), Some(repo.to_str().unwrap()), &[]);
        let report = plan_backup(&backup);
        assert!(!report.clean);
        assert_eq!(report.unreadable.len(), 1);
        assert_eq!(report.unreadable[0].detail, "missing");
        assert!(report.unreadable[0].path.contains("absent"));
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn unreadable_directory_is_listed() {
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        let mut perms = fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&locked, perms).unwrap();
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let mut perms = fs::metadata(&self.0).unwrap().permissions();
                perms.set_mode(0o755);
                let _ = fs::set_permissions(&self.0, perms);
            }
        }
        let _restore = Restore(locked.clone());
        let repo = dir.path().join("repo");
        let backup = sample_config(locked.to_str().unwrap(), Some(repo.to_str().unwrap()), &[]);
        let report = plan_backup(&backup);
        if fs::read_dir(&locked).is_err() {
            assert!(!report.clean);
            assert!(report
                .unreadable
                .iter()
                .any(|entry| entry.detail == "unreadable"));
        } else {
            assert_eq!(report.includes[0].status, PlanCoverage::Available);
        }
    }

    #[test]
    fn excluded_huge_models_are_warned_and_file_bytes_stay_unread() {
        let dir = tempfile::tempdir().unwrap();
        let include = dir.path().join("proj");
        fs::create_dir_all(include.join("models")).unwrap();
        let secret = "password=hunter2-backup-plan";
        let mut file = fs::File::create(include.join("weights.gguf")).unwrap();
        writeln!(file, "{secret}").unwrap();
        fs::write(include.join("models").join("big.gguf"), secret).unwrap();
        fs::write(include.join("notes.txt"), "keep").unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let backup = sample_config(
            include.to_str().unwrap(),
            Some(repo.to_str().unwrap()),
            &["**/*.gguf", "**/models/**", "**/*.bin"],
        );
        let report = plan_backup(&backup);
        assert!(report.repository_exists);
        assert!(!report.creates_repository);
        assert_eq!(fs::read_dir(&repo).unwrap().count(), 0);
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Findings);
        let warnings = report.huge_model_warnings.join("\n");
        assert!(warnings.contains("weights.gguf"));
        assert!(warnings.contains("models"));
        assert!(warnings.contains("omits huge models"));
        let human = format_backup_plan_human(&report);
        assert!(human.contains("Includes"));
        assert!(human.contains("Excludes"));
        assert!(human.contains("Unreadable"));
        assert!(human.contains("Huge-model warnings"));
        assert!(!human.contains(secret), "{human}");
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(secret), "{json}");
    }

    #[test]
    fn included_gguf_warns_without_an_exclude() {
        let dir = tempfile::tempdir().unwrap();
        let include = dir.path().join("proj");
        fs::create_dir(&include).unwrap();
        fs::write(include.join("weights.gguf"), "bytes").unwrap();
        let repo = dir.path().join("repo");
        let backup = sample_config(include.to_str().unwrap(), Some(repo.to_str().unwrap()), &[]);
        let report = plan_backup(&backup);
        assert!(report.huge_model_warnings.iter().any(|warning| warning
            .contains("would be included")
            && warning.contains("weights.gguf")));
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Findings);
    }

    #[test]
    fn filesystem_root_is_not_a_whole_disk_plan() {
        let backup = BackupConfig {
            repository: Some("/tmp/devguard-not-created".into()),
            include: vec!["/".into()],
            exclude: Vec::new(),
            ..BackupConfig::default()
        };
        let report = plan_backup(&backup);
        assert!(!report.whole_disk);
        assert!(!report.clean);
        assert!(report.unreadable.is_empty());
        assert_eq!(
            report.includes[0].detail,
            "filesystem root is not a backup include"
        );
        assert!(report
            .includes
            .iter()
            .all(|entry| !entry.path.starts_with("/proc") && !entry.path.starts_with("/home")));
    }

    #[test]
    fn repository_password_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let include = dir.path().join("docs");
        fs::create_dir(&include).unwrap();
        let secret = "s3cret-password";
        let repository = format!("sftp://alice:{secret}@backup.example/repo");
        let backup = sample_config(include.to_str().unwrap(), Some(&repository), &[]);
        let report = plan_backup(&backup);
        let human = format_backup_plan_human(&report);
        assert!(!human.contains(secret), "{human}");
        assert!(human.contains("[REDACTED]"));
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(secret), "{json}");
        assert!(!report.runs_engine);
    }

    #[test]
    fn rustic_name_is_reported_and_not_selected() {
        let backup = BackupConfig {
            engine: "rustic".into(),
            ..BackupConfig::default()
        };
        let report = plan_backup(&backup);
        assert_eq!(report.engine.as_deref(), Some("rustic"));
        assert!(!report.engine_selected);
        assert!(!report.runs_engine);
        assert!(!report.clean);
    }

    #[test]
    fn glob_matches_huge_model_patterns() {
        assert!(glob_match("**/*.gguf", "weights.gguf"));
        assert!(glob_match("**/*.gguf", "dir/weights.gguf"));
        assert!(glob_match("**/models/**", "models"));
        assert!(glob_match("**/models/**", "models/big.gguf"));
        assert!(glob_match("**/models/**", "proj/models/big.gguf"));
        assert!(!glob_match("**/*.gguf", "notes.txt"));
        assert!(!glob_match("**/target", "target/debug/out"));
        assert!(glob_match("**/target", "crate/target"));
    }
}
