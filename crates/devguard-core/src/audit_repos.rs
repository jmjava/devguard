//! Backup-audit repo scanner for `devguard audit repos`.
//!
//! Scans common locations (`~/github`, `~/projects`, `~/src`, `~/code`)
//! plus any configured `dev.repo_roots` for git repositories. Reports
//! path, branch, dirty status, last commit date, remote URL, and flags
//! repos that are local-only, have stale uncommitted changes (>7 days),
//! or have unpushed commits.
//!
//! Read-only. Does not fetch, pull, push, or use sudo.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::exit::ExitCode;
use crate::redact::redact_text;

const GIT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_DETAIL_CHARS: usize = 256;
const MAX_DEPTH: usize = 6;
const MAX_VISITS: usize = 4_096;
const MAX_REPOS: usize = 256;
const STALE_UNCOMMITTED_DAYS: i64 = 7;

const DEFAULT_SCAN_DIRS: &[&str] = &["~/github", "~/projects", "~/src", "~/code"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Available,
    Unavailable,
}

/// One discovered git repository.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRepoEntry {
    pub path: String,
    pub branch: Option<String>,
    pub dirty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_commit_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    pub has_remote: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncommitted_age_days: Option<i64>,
    pub stale_uncommitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpushed_commits: Option<u32>,
}

/// Flagged repos grouped by risk category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReposFlags {
    pub local_only: Vec<String>,
    pub stale_uncommitted: Vec<String>,
    pub unpushed: Vec<String>,
}

/// Report for `devguard audit repos`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReposReport {
    pub uses_sudo: bool,
    pub uses_network: bool,
    pub scan_paths: Vec<String>,
    pub total: usize,
    pub dirty_count: usize,
    pub local_only_count: usize,
    pub unpushed_count: usize,
    pub repos: Vec<AuditRepoEntry>,
    pub flags: AuditReposFlags,
    pub clean: bool,
    pub status: CoverageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditReposReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.status == CoverageStatus::Unavailable {
            if let Some(detail) = &self.detail {
                warnings.push(format!("audit repos unavailable: {detail}"));
            }
        }
        for path in &self.flags.local_only {
            warnings.push(format!("local-only (no remote): {path}"));
        }
        for path in &self.flags.stale_uncommitted {
            warnings.push(format!("stale uncommitted changes (>7 days): {path}"));
        }
        for path in &self.flags.unpushed {
            warnings.push(format!("unpushed commits: {path}"));
        }
        warnings
    }
}

/// Scan for repos under the default locations and configured roots.
pub fn scan_audit_repos(git_bin: &Path, config_roots: &[String]) -> AuditReposReport {
    let scan_paths = build_scan_paths(config_roots);
    scan_audit_repos_inner(git_bin, &scan_paths)
}

/// Scan only the given explicit paths (no defaults). Useful for testing.
pub fn scan_audit_repos_explicit(git_bin: &Path, paths: &[PathBuf]) -> AuditReposReport {
    scan_audit_repos_inner(git_bin, paths)
}

fn scan_audit_repos_inner(git_bin: &Path, scan_paths: &[PathBuf]) -> AuditReposReport {
    if scan_paths.is_empty() {
        return AuditReposReport {
            uses_sudo: false,
            uses_network: false,
            scan_paths: Vec::new(),
            total: 0,
            dirty_count: 0,
            local_only_count: 0,
            unpushed_count: 0,
            repos: Vec::new(),
            flags: AuditReposFlags {
                local_only: Vec::new(),
                stale_uncommitted: Vec::new(),
                unpushed: Vec::new(),
            },
            clean: false,
            status: CoverageStatus::Unavailable,
            detail: Some(
                "no scan paths resolved (none of the default dirs or config roots exist)".into(),
            ),
        };
    }

    if !git_runs(git_bin) {
        return AuditReposReport {
            uses_sudo: false,
            uses_network: false,
            scan_paths: scan_paths.iter().map(|p| display_path(p)).collect(),
            total: 0,
            dirty_count: 0,
            local_only_count: 0,
            unpushed_count: 0,
            repos: Vec::new(),
            flags: AuditReposFlags {
                local_only: Vec::new(),
                stale_uncommitted: Vec::new(),
                unpushed: Vec::new(),
            },
            clean: false,
            status: CoverageStatus::Unavailable,
            detail: Some("`git` is not available".into()),
        };
    }

    let mut repos = Vec::new();
    let mut seen = HashSet::new();
    for root in scan_paths {
        discover_repos(root, &mut repos, &mut seen);
    }
    repos.sort();

    let now = Utc::now();
    let entries: Vec<AuditRepoEntry> = repos
        .iter()
        .map(|repo| inspect_repo(git_bin, repo, now))
        .collect();

    let dirty_count = entries.iter().filter(|e| e.dirty).count();
    let local_only_count = entries.iter().filter(|e| !e.has_remote).count();
    let unpushed_count = entries
        .iter()
        .filter(|e| e.unpushed_commits.is_some_and(|c| c > 0))
        .count();

    let flags = AuditReposFlags {
        local_only: entries
            .iter()
            .filter(|e| !e.has_remote)
            .map(|e| e.path.clone())
            .collect(),
        stale_uncommitted: entries
            .iter()
            .filter(|e| e.stale_uncommitted)
            .map(|e| e.path.clone())
            .collect(),
        unpushed: entries
            .iter()
            .filter(|e| e.unpushed_commits.is_some_and(|c| c > 0))
            .map(|e| e.path.clone())
            .collect(),
    };

    let total = entries.len();
    AuditReposReport {
        uses_sudo: false,
        uses_network: false,
        scan_paths: scan_paths.iter().map(|p| display_path(p)).collect(),
        total,
        dirty_count,
        local_only_count,
        unpushed_count,
        repos: entries,
        flags,
        clean: true,
        status: CoverageStatus::Available,
        detail: None,
    }
}

pub fn format_audit_repos_human(report: &AuditReposReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard audit repos\n");
    out.push_str(&format!("  total repos: {}\n", report.total));
    out.push_str(&format!("  dirty: {}\n", report.dirty_count));
    out.push_str(&format!(
        "  local-only (no remote): {}\n",
        report.local_only_count
    ));
    out.push_str(&format!("  unpushed: {}\n", report.unpushed_count));
    out.push_str(&format!(
        "  uses network: {}\n  uses sudo: {}\n",
        yn(report.uses_network),
        yn(report.uses_sudo),
    ));
    if let Some(detail) = &report.detail {
        out.push_str(&format!("  detail: {detail}\n"));
    }
    out.push('\n');

    if report.repos.is_empty() {
        out.push_str("  (no repos found)\n");
    }
    for repo in &report.repos {
        let dirty_mark = if repo.dirty { " [DIRTY]" } else { "" };
        let remote_mark = if !repo.has_remote { " [NO REMOTE]" } else { "" };
        let stale_mark = if repo.stale_uncommitted {
            " [STALE]"
        } else {
            ""
        };
        let unpushed_mark = match repo.unpushed_commits {
            Some(n) if n > 0 => format!(" [UNPUSHED: {n}]"),
            _ => String::new(),
        };
        out.push_str(&format!(
            "  {}{dirty_mark}{remote_mark}{stale_mark}{unpushed_mark}\n",
            repo.path
        ));
        out.push_str(&format!(
            "    branch: {}  remote: {}  last commit: {}\n",
            repo.branch.as_deref().unwrap_or("(none)"),
            repo.remote_url.as_deref().unwrap_or("(none)"),
            repo.last_commit_date.as_deref().unwrap_or("(unknown)"),
        ));
    }

    if !report.flags.local_only.is_empty() {
        out.push_str("\nAt-risk (no remote):\n");
        for p in &report.flags.local_only {
            out.push_str(&format!("  ⚠ {p}\n"));
        }
    }
    if !report.flags.stale_uncommitted.is_empty() {
        out.push_str("\nStale uncommitted (>7 days):\n");
        for p in &report.flags.stale_uncommitted {
            out.push_str(&format!("  ⚠ {p}\n"));
        }
    }
    if !report.flags.unpushed.is_empty() {
        out.push_str("\nUnpushed commits:\n");
        for p in &report.flags.unpushed {
            out.push_str(&format!("  ⚠ {p}\n"));
        }
    }
    out
}

fn build_scan_paths(config_roots: &[String]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();

    for raw in DEFAULT_SCAN_DIRS {
        if let Ok(expanded) = Config::expand_user_path(raw) {
            if expanded.is_dir() {
                if let Ok(canonical) = std::fs::canonicalize(&expanded) {
                    if seen.insert(canonical.clone()) {
                        paths.push(canonical);
                    }
                }
            }
        }
    }

    for raw in config_roots {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(expanded) = Config::expand_user_path(trimmed) {
            if expanded.is_dir() {
                if let Ok(canonical) = std::fs::canonicalize(&expanded) {
                    if seen.insert(canonical.clone()) {
                        paths.push(canonical);
                    }
                }
            }
        }
    }

    paths
}

fn discover_repos(root: &Path, repos: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>) {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visits = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        visits += 1;
        if visits > MAX_VISITS || repos.len() >= MAX_REPOS {
            return;
        }
        if dir.join(".git").symlink_metadata().is_ok() {
            if let Ok(canonical) = std::fs::canonicalize(&dir) {
                if seen.insert(canonical.clone()) {
                    repos.push(canonical);
                }
            }
            continue;
        }
        if depth >= MAX_DEPTH {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() || !ft.is_dir() {
                continue;
            }
            if entry.file_name() == ".git" {
                continue;
            }
            stack.push((entry.path(), depth + 1));
        }
    }
}

fn inspect_repo(git_bin: &Path, repo: &Path, now: DateTime<Utc>) -> AuditRepoEntry {
    let shown = display_path(repo);

    let branch = git_line(git_bin, repo, &["rev-parse", "--abbrev-ref", "HEAD"]).ok();

    let dirty = git_stdout(
        git_bin,
        repo,
        &["status", "--porcelain=v1", "--untracked-files=no", "-z"],
    )
    .map(|s| !s.is_empty())
    .unwrap_or(false);

    let last_commit_date = git_line(git_bin, repo, &["log", "-1", "--format=%aI"]).ok();

    let remote_url = git_line(git_bin, repo, &["remote", "get-url", "origin"]).ok();
    let has_remote = remote_url.is_some();

    let uncommitted_age_days = if dirty {
        compute_uncommitted_age(&last_commit_date, now)
    } else {
        None
    };
    let stale_uncommitted =
        dirty && uncommitted_age_days.is_some_and(|d| d > STALE_UNCOMMITTED_DAYS);

    let unpushed_commits = compute_unpushed(git_bin, repo);

    AuditRepoEntry {
        path: shown,
        branch,
        dirty,
        last_commit_date,
        remote_url,
        has_remote,
        uncommitted_age_days,
        stale_uncommitted,
        unpushed_commits,
    }
}

fn compute_uncommitted_age(last_commit_date: &Option<String>, now: DateTime<Utc>) -> Option<i64> {
    let date_str = last_commit_date.as_deref()?;
    let parsed = DateTime::parse_from_rfc3339(date_str).ok().or_else(|| {
        NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M:%S")
            .ok()
            .map(|ndt| ndt.and_utc().fixed_offset())
    })?;
    let age = now.signed_duration_since(parsed.with_timezone(&Utc));
    Some(age.num_days())
}

fn compute_unpushed(git_bin: &Path, repo: &Path) -> Option<u32> {
    let upstream = git_line(git_bin, repo, &["rev-parse", "--abbrev-ref", "@{upstream}"]).ok()?;
    let range = format!("{upstream}..HEAD");
    let count_str = git_line(git_bin, repo, &["rev-list", "--count", &range]).ok()?;
    count_str.parse::<u32>().ok()
}

fn git_runs(git_bin: &Path) -> bool {
    match run_git(git_bin, None, &["--version"]) {
        Ok(out) => out.success && !out.stdout.trim().is_empty(),
        Err(_) => false,
    }
}

fn git_line(git_bin: &Path, repo: &Path, args: &[&str]) -> Result<String, String> {
    let text = git_stdout(git_bin, repo, args)?;
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(bound_detail)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "git printed no line".to_string())
}

fn git_stdout(git_bin: &Path, repo: &Path, args: &[&str]) -> Result<String, String> {
    match run_git(git_bin, Some(repo), args) {
        Ok(out) if out.success => Ok(out.stdout),
        Ok(_) => Err("git exited non-zero".into()),
        Err(GitFail::TimedOut) => Err("git timed out".into()),
        Err(GitFail::Failed) => Err("`git` is not available".into()),
    }
}

enum GitFail {
    TimedOut,
    Failed,
}

struct GitOutput {
    success: bool,
    stdout: String,
}

fn run_git(git_bin: &Path, repo: Option<&Path>, args: &[&str]) -> Result<GitOutput, GitFail> {
    let forbidden = ["fetch", "pull", "push", "clone", "ls-remote"];
    if args.iter().any(|a| forbidden.contains(a)) {
        return Err(GitFail::Failed);
    }
    let mut cmd = Command::new(git_bin);
    cmd.arg("--no-optional-locks")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("-c")
        .arg("credential.helper=")
        .arg("-c")
        .arg("core.fsmonitor=")
        .arg("-c")
        .arg("status.submoduleSummary=false")
        .arg("-c")
        .arg("submodule.recurse=false")
        .arg("-c")
        .arg("fetch.recurseSubmodules=false");
    if let Some(repo) = repo {
        cmd.arg("-C").arg(repo);
    }
    cmd.args(args)
        .current_dir(std::env::temp_dir())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GCM_INTERACTIVE", "Never")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| GitFail::Failed)?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_handle = thread::spawn(move || read_capped(stdout));
    let stderr_handle = thread::spawn(move || read_capped(stderr));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle.join().unwrap_or_default();
                let _stderr = stderr_handle.join().unwrap_or_default();
                return Ok(GitOutput {
                    success: status.success(),
                    stdout,
                });
            }
            Ok(None) if started.elapsed() > GIT_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(GitFail::TimedOut);
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(GitFail::Failed);
            }
        }
    }
}

fn read_capped(pipe: Option<impl Read>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while buf.len() < MAX_CAPTURE_BYTES {
        let room = MAX_CAPTURE_BYTES - buf.len();
        let take = room.min(chunk.len());
        match pipe.read(&mut chunk[..take]) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn display_path(path: &Path) -> String {
    let text = redact_text(&path.to_string_lossy());
    let mut out: String = text.chars().take(512).collect();
    if text.chars().count() > 512 {
        out.push('…');
    }
    out
}

fn bound_detail(text: &str) -> String {
    let redacted = redact_text(text);
    let mut out: String = redacted.chars().take(MAX_DETAIL_CHARS).collect();
    if redacted.chars().count() > MAX_DETAIL_CHARS {
        out.push('…');
    }
    out
}

fn yn(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;

    fn git(dir: &Path, args: &[&str]) {
        let output = StdCommand::new("git")
            .current_dir(dir)
            .args([
                "-c",
                "user.name=DevGuard",
                "-c",
                "user.email=devguard@example.com",
            ])
            .args(args)
            .env("GIT_AUTHOR_NAME", "DevGuard")
            .env("GIT_AUTHOR_EMAIL", "devguard@example.com")
            .env("GIT_COMMITTER_NAME", "DevGuard")
            .env("GIT_COMMITTER_EMAIL", "devguard@example.com")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_repo(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-b", "main"]);
        std::fs::write(dir.join("README"), "hello\n").unwrap();
        git(dir, &["add", "README"]);
        git(dir, &["commit", "-m", "init"]);
    }

    #[test]
    fn missing_git_is_unavailable() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("scanroot");
        std::fs::create_dir_all(&root).unwrap();
        let report = scan_audit_repos_explicit(Path::new("/no/such/git"), &[root]);
        assert!(!report.clean);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert!(report.repos.is_empty());
    }

    #[test]
    fn no_scan_paths_is_unavailable() {
        let report = scan_audit_repos_explicit(Path::new("git"), &[]);
        assert!(!report.clean);
        assert_eq!(report.status, CoverageStatus::Unavailable);
    }

    #[test]
    fn clean_repo_detected() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("scanroot");
        let repo = root.join("myrepo");
        init_repo(&repo);
        let report = scan_audit_repos_explicit(Path::new("git"), &[root]);
        assert!(report.clean, "{report:?}");
        assert_eq!(report.total, 1);
        assert_eq!(report.dirty_count, 0);
        assert!(!report.repos[0].dirty);
        assert!(report.repos[0].branch.as_deref() == Some("main"));
        assert!(!report.repos[0].has_remote);
        assert_eq!(report.local_only_count, 1);
        assert_eq!(report.flags.local_only.len(), 1);
    }

    #[test]
    fn dirty_repo_flagged() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("scanroot");
        let repo = root.join("dirtyrepo");
        init_repo(&repo);
        std::fs::write(repo.join("README"), "modified\n").unwrap();
        let report = scan_audit_repos_explicit(Path::new("git"), &[root]);
        assert_eq!(report.dirty_count, 1);
        assert!(report.repos[0].dirty);
    }

    #[test]
    fn no_remote_flagged() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("scanroot");
        let repo = root.join("local");
        init_repo(&repo);
        let report = scan_audit_repos_explicit(Path::new("git"), &[root]);
        assert!(!report.repos[0].has_remote);
        assert_eq!(report.flags.local_only.len(), 1);
    }

    #[test]
    fn unpushed_commits_counted() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("scanroot");
        let repo = root.join("unpushed");
        init_repo(&repo);
        git(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        git(
            &repo,
            &["remote", "add", "origin", repo.to_str().expect("utf8")],
        );
        git(&repo, &["config", "branch.main.remote", "origin"]);
        git(&repo, &["config", "branch.main.merge", "refs/heads/main"]);
        std::fs::write(repo.join("new.txt"), "content\n").unwrap();
        git(&repo, &["add", "new.txt"]);
        git(&repo, &["commit", "-m", "second"]);
        let report = scan_audit_repos_explicit(Path::new("git"), &[root]);
        let unpushed_repo = report
            .repos
            .iter()
            .find(|r| r.path.contains("unpushed"))
            .unwrap();
        assert!(unpushed_repo.has_remote);
        assert_eq!(unpushed_repo.unpushed_commits, Some(1));
        assert_eq!(report.unpushed_count, 1);
        assert_eq!(report.flags.unpushed.len(), 1);
    }

    #[test]
    fn json_envelope_format() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("scanroot");
        let repo = root.join("jsontest");
        init_repo(&repo);
        let report = scan_audit_repos_explicit(Path::new("git"), &[root]);
        let envelope = crate::json::JsonEnvelope::success("audit repos", &report);
        let value = serde_json::to_value(&envelope).expect("serialize");
        assert_eq!(value["ok"], true);
        assert_eq!(value["command"], "audit repos");
        assert!(value["data"]["repos"].is_array());
        assert!(value["data"]["total"].is_number());
    }

    #[test]
    fn human_format_contains_key_fields() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("scanroot");
        let repo = root.join("humantest");
        init_repo(&repo);
        std::fs::write(repo.join("README"), "dirty\n").unwrap();
        let report = scan_audit_repos_explicit(Path::new("git"), &[root]);
        let human = format_audit_repos_human(&report);
        assert!(human.contains("DIRTY"));
        assert!(human.contains("NO REMOTE"));
        assert!(human.contains("total repos:"));
    }

    #[test]
    fn compute_age_works() {
        let now = Utc::now();
        let ten_days_ago = now - chrono::Duration::days(10);
        let date_str = ten_days_ago.to_rfc3339();
        let age = compute_uncommitted_age(&Some(date_str), now);
        assert!(age.is_some());
        assert!(age.unwrap() >= 9);
    }
}
