//! Opt-in git repository scan for `devguard dev repos scan`.
//!
//! The command reads only paths named on the command line or in
//! `dev.repo_roots`. It does not walk the home directory or the filesystem
//! root. Git is a subprocess with an argument list. The scan does not fetch,
//! pull, or push. Upstream and unpublished commits come from local refs.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::exit::ExitCode;
use crate::redact::redact_text;

const GIT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_DETAIL_CHARS: usize = 160;
const MAX_DEPTH: usize = 6;
const MAX_VISITS: usize = 4_096;
const MAX_REPOS: usize = 128;
const FORBIDDEN_GIT_ARGS: &[&str] = &["fetch", "pull", "push", "clone", "ls-remote"];

/// `available` or `unavailable`. Missing git or an unreadable path is never clean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Available,
    Unavailable,
}

/// One opt-in directory that was considered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootCoverage {
    pub path: String,
    pub status: CoverageStatus,
    pub detail: String,
}

/// One git work tree under an opt-in path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoReading {
    pub path: String,
    pub status: CoverageStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untracked: Option<bool>,
    /// Commits reachable from `HEAD` and not from the local upstream ref.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpublished: Option<u32>,
}

/// Human and JSON body for `devguard dev repos scan`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevReposReport {
    /// Always false. This command never runs `git fetch`.
    pub fetches: bool,
    /// Always false. This command never runs `git pull`.
    pub pulls: bool,
    /// Always false. This command never runs `git push`.
    pub pushes: bool,
    /// Always false. Upstream status is read from local refs.
    pub uses_network: bool,
    /// Always false. This command does not use sudo.
    pub uses_sudo: bool,
    /// False when git is missing, no path was named, or a path is unreadable.
    pub clean: bool,
    pub status: CoverageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub roots: Vec<RootCoverage>,
    pub repos: Vec<RepoReading>,
}

impl DevReposReport {
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
                warnings.push(format!("dev repos is unavailable: {detail}"));
            }
        }
        for root in &self.roots {
            if root.status == CoverageStatus::Unavailable {
                warnings.push(format!("{} is unavailable: {}", root.path, root.detail));
            }
        }
        for repo in &self.repos {
            if repo.status == CoverageStatus::Unavailable {
                warnings.push(format!("{} is unavailable: {}", repo.path, repo.detail));
            }
        }
        warnings
    }
}

/// Scan `explicit` paths and `config_roots` (`dev.repo_roots` strings).
///
/// An empty list of both is unavailable. `git_bin` is invoked with an argument
/// vector. Pass `Path::new("git")` to use `PATH`.
pub fn scan_dev_repos(
    git_bin: &Path,
    explicit: &[PathBuf],
    config_roots: &[String],
) -> DevReposReport {
    let planned = plan_roots(explicit, config_roots);
    if planned.is_empty() {
        return unavailable_report(
            "no opt-in path; pass a path or set dev.repo_roots",
            Vec::new(),
        );
    }
    if !git_runs(git_bin) {
        let roots = planned
            .iter()
            .map(|root| unavailable_root(&root.display, "`git` is not available"))
            .collect();
        return unavailable_report("`git` is not available", roots);
    }

    let mut report = available_shell();
    let mut seen = HashSet::new();
    for root in &planned {
        scan_root(&mut report, git_bin, root, &mut seen);
    }
    report
        .repos
        .sort_by(|left, right| left.path.cmp(&right.path));
    finalize(report)
}

pub fn format_dev_repos_human(report: &DevReposReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard dev repos\n");
    out.push_str(&format!("  fetches: {}\n", yes_no(report.fetches)));
    out.push_str(&format!("  pulls: {}\n", yes_no(report.pulls)));
    out.push_str(&format!("  pushes: {}\n", yes_no(report.pushes)));
    out.push_str(&format!(
        "  uses network: {}\n",
        yes_no(report.uses_network)
    ));
    out.push_str(&format!("  uses sudo: {}\n", yes_no(report.uses_sudo)));
    out.push_str(&format!("  clean: {}\n", yes_no(report.clean)));
    out.push_str(&format!("  status: {}\n", status_word(report.status)));
    if let Some(detail) = &report.detail {
        out.push_str(&format!("  detail: {detail}\n"));
    }
    out.push_str("\nRoots\n");
    if report.roots.is_empty() {
        out.push_str("  (none)\n");
    }
    for root in &report.roots {
        out.push_str(&format!(
            "  {path}: {status} — {detail}\n",
            path = root.path,
            status = status_word(root.status),
            detail = root.detail,
        ));
    }
    out.push_str("\nRepositories\n");
    if report.repos.is_empty() {
        out.push_str("  (none)\n");
    }
    for repo in &report.repos {
        if repo.status == CoverageStatus::Available {
            let unpublished = repo
                .unpublished
                .map(|count| count.to_string())
                .unwrap_or_else(|| "none".to_string());
            out.push_str(&format!(
                "  {path}: available — branch {branch}, upstream {upstream}, dirty {dirty}, untracked {untracked}, unpublished {unpublished}\n",
                path = repo.path,
                branch = repo.branch.as_deref().unwrap_or("none"),
                upstream = repo.upstream.as_deref().unwrap_or("none"),
                dirty = repo.dirty.map(yes_no).unwrap_or("none"),
                untracked = repo.untracked.map(yes_no).unwrap_or("none"),
            ));
        } else {
            out.push_str(&format!(
                "  {path}: unavailable — {detail}\n",
                path = repo.path,
                detail = repo.detail,
            ));
        }
    }
    out
}

struct PlannedRoot {
    display: String,
    path: Option<PathBuf>,
    error: Option<String>,
}

struct Discovery {
    repos: Vec<PathBuf>,
    detail: Option<String>,
}

enum GitFail {
    TimedOut,
    Failed,
}

struct GitOutput {
    success: bool,
    stdout: String,
}

fn plan_roots(explicit: &[PathBuf], config_roots: &[String]) -> Vec<PlannedRoot> {
    let mut planned = Vec::new();
    let mut seen_display = HashSet::new();
    for path in explicit {
        let display = display_path(path);
        if display.is_empty() || !seen_display.insert(display.clone()) {
            continue;
        }
        planned.push(PlannedRoot {
            display,
            path: Some(path.clone()),
            error: None,
        });
    }
    for raw in config_roots {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        match Config::expand_user_path(trimmed) {
            Ok(path) => {
                let display = display_path(&path);
                if display.is_empty() || !seen_display.insert(display.clone()) {
                    continue;
                }
                planned.push(PlannedRoot {
                    display,
                    path: Some(path),
                    error: None,
                });
            }
            Err(err) => {
                let display = bound_detail(trimmed);
                if display.is_empty() || !seen_display.insert(display.clone()) {
                    continue;
                }
                planned.push(PlannedRoot {
                    display,
                    path: None,
                    error: Some(bound_detail(&err.to_string())),
                });
            }
        }
    }
    planned
}

fn scan_root(
    report: &mut DevReposReport,
    git_bin: &Path,
    root: &PlannedRoot,
    seen: &mut HashSet<PathBuf>,
) {
    if let Some(detail) = &root.error {
        report.roots.push(unavailable_root(&root.display, detail));
        return;
    }
    let Some(path) = &root.path else {
        report
            .roots
            .push(unavailable_root(&root.display, "path is unreadable"));
        return;
    };
    let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => {
            report
                .roots
                .push(unavailable_root(&root.display, "path is unreadable"));
            return;
        }
    };
    if !seen.insert(canonical.clone()) {
        return;
    }
    let shown = display_path(&canonical);
    if let Some(reason) = refuse_reason(&canonical) {
        report.roots.push(unavailable_root(&shown, reason));
        return;
    }
    if !canonical.is_dir() {
        report
            .roots
            .push(unavailable_root(&shown, "path is unreadable"));
        return;
    }
    let found = discover(&canonical);
    for repo in &found.repos {
        report.repos.push(inspect_repo(git_bin, repo));
    }
    if let Some(detail) = found.detail {
        report.roots.push(unavailable_root(&shown, &detail));
    } else {
        report.roots.push(RootCoverage {
            path: shown,
            status: CoverageStatus::Available,
            detail: "scanned".into(),
        });
    }
}

fn discover(root: &Path) -> Discovery {
    let mut repos = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visits = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        visits += 1;
        if visits > MAX_VISITS || repos.len() >= MAX_REPOS {
            return Discovery {
                repos,
                detail: Some("stopped at the scan bound".into()),
            };
        }
        if has_git_metadata(&dir) {
            repos.push(dir);
            continue;
        }
        if depth >= MAX_DEPTH {
            return Discovery {
                repos,
                detail: Some("stopped at the depth bound".into()),
            };
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                return Discovery {
                    repos,
                    detail: Some("path is unreadable".into()),
                };
            }
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return Discovery {
                    repos,
                    detail: Some("path is unreadable".into()),
                };
            };
            let Ok(file_type) = entry.file_type() else {
                return Discovery {
                    repos,
                    detail: Some("path is unreadable".into()),
                };
            };
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            if entry.file_name() == ".git" {
                continue;
            }
            stack.push((entry.path(), depth + 1));
        }
    }
    Discovery {
        repos,
        detail: None,
    }
}

fn has_git_metadata(dir: &Path) -> bool {
    dir.join(".git").symlink_metadata().is_ok()
}

fn inspect_repo(git_bin: &Path, repo: &Path) -> RepoReading {
    let shown = display_path(repo);
    match git_line(git_bin, repo, &["rev-parse", "--is-inside-work-tree"]) {
        Ok(line) if line == "true" => {}
        Ok(_) => return unavailable_repo(&shown, "path is not a git work tree"),
        Err(detail) => return unavailable_repo(&shown, &detail),
    }
    let branch = match git_line(git_bin, repo, &["rev-parse", "--abbrev-ref", "HEAD"]) {
        Ok(line) => line,
        Err(detail) => return unavailable_repo(&shown, &detail),
    };
    let dirty = match git_stdout(
        git_bin,
        repo,
        &["status", "--porcelain=v1", "--untracked-files=no", "-z"],
    ) {
        Ok(text) => !text.is_empty(),
        Err(detail) => return unavailable_repo(&shown, &detail),
    };
    let untracked = match git_stdout(
        git_bin,
        repo,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    ) {
        Ok(text) => !text.is_empty(),
        Err(detail) => return unavailable_repo(&shown, &detail),
    };
    let upstream = match git_line(git_bin, repo, &["rev-parse", "--abbrev-ref", "@{upstream}"]) {
        Ok(line) if is_safe_ref(&line) => Some(line),
        Ok(_) => return unavailable_repo(&shown, "upstream ref name was rejected"),
        Err(_) => None,
    };
    let unpublished = if let Some(upstream) = &upstream {
        let range = format!("{upstream}..HEAD");
        match git_line(git_bin, repo, &["rev-list", "--count", &range]) {
            Ok(line) => match line.parse::<u32>() {
                Ok(count) => Some(count),
                Err(_) => {
                    return unavailable_repo(&shown, "unpublished commit count was unreadable");
                }
            },
            Err(_) => return unavailable_repo(&shown, "local upstream ref is missing"),
        }
    } else {
        None
    };
    RepoReading {
        path: shown,
        status: CoverageStatus::Available,
        detail: "read from local git refs".into(),
        branch: Some(branch),
        upstream,
        dirty: Some(dirty),
        untracked: Some(untracked),
        unpublished,
    }
}

fn is_safe_ref(name: &str) -> bool {
    if name.is_empty() || name.len() > 200 || name.starts_with('-') || name.contains("..") {
        return false;
    }
    name.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '.' | '-'))
}

fn refuse_reason(canonical: &Path) -> Option<&'static str> {
    if canonical == Path::new("/") {
        return Some("refusing to scan the filesystem root");
    }
    if canonical == Path::new("/home") {
        return Some("refusing to scan the home directory");
    }
    if let Some(base) = directories::BaseDirs::new() {
        let home = std::fs::canonicalize(base.home_dir())
            .unwrap_or_else(|_| base.home_dir().to_path_buf());
        if canonical == home {
            return Some("refusing to scan the home directory");
        }
    }
    None
}

fn git_runs(git_bin: &Path) -> bool {
    match run_git(git_bin, None, &["--version"]) {
        Ok(output) => output.success && !output.stdout.trim().is_empty(),
        Err(_) => false,
    }
}

fn git_line(git_bin: &Path, repo: &Path, args: &[&str]) -> Result<String, String> {
    let text = git_stdout(git_bin, repo, args)?;
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(bound_detail)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| "git printed no line".to_string())
}

fn git_stdout(git_bin: &Path, repo: &Path, args: &[&str]) -> Result<String, String> {
    match run_git(git_bin, Some(repo), args) {
        Ok(output) if output.success => Ok(output.stdout),
        Ok(_) => Err("git exited non-zero".into()),
        Err(GitFail::TimedOut) => Err("git timed out".into()),
        Err(GitFail::Failed) => Err("`git` is not available".into()),
    }
}

fn run_git(git_bin: &Path, repo: Option<&Path>, args: &[&str]) -> Result<GitOutput, GitFail> {
    if args.iter().any(|arg| FORBIDDEN_GIT_ARGS.contains(arg)) {
        return Err(GitFail::Failed);
    }
    let mut command = Command::new(git_bin);
    command
        .arg("--no-optional-locks")
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
        command.arg("-C").arg(repo);
    }
    command
        .args(args)
        .current_dir(std::env::temp_dir())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GCM_INTERACTIVE", "Never")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| GitFail::Failed)?;
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

fn available_shell() -> DevReposReport {
    DevReposReport {
        fetches: false,
        pulls: false,
        pushes: false,
        uses_network: false,
        uses_sudo: false,
        clean: true,
        status: CoverageStatus::Available,
        detail: None,
        roots: Vec::new(),
        repos: Vec::new(),
    }
}

fn unavailable_report(detail: &str, roots: Vec<RootCoverage>) -> DevReposReport {
    DevReposReport {
        fetches: false,
        pulls: false,
        pushes: false,
        uses_network: false,
        uses_sudo: false,
        clean: false,
        status: CoverageStatus::Unavailable,
        detail: Some(bound_detail(detail)),
        roots,
        repos: Vec::new(),
    }
}

fn unavailable_root(path: &str, detail: &str) -> RootCoverage {
    RootCoverage {
        path: path.to_string(),
        status: CoverageStatus::Unavailable,
        detail: bound_detail(detail),
    }
}

fn unavailable_repo(path: &str, detail: &str) -> RepoReading {
    RepoReading {
        path: path.to_string(),
        status: CoverageStatus::Unavailable,
        detail: bound_detail(detail),
        branch: None,
        upstream: None,
        dirty: None,
        untracked: None,
        unpublished: None,
    }
}

fn finalize(mut report: DevReposReport) -> DevReposReport {
    let roots_ok = report
        .roots
        .iter()
        .all(|root| root.status == CoverageStatus::Available);
    let repos_ok = report
        .repos
        .iter()
        .all(|repo| repo.status == CoverageStatus::Available);
    report.clean = report.status == CoverageStatus::Available && roots_ok && repos_ok;
    if !report.clean {
        report.status = CoverageStatus::Unavailable;
    }
    report.fetches = false;
    report.pulls = false;
    report.pushes = false;
    report.uses_network = false;
    report.uses_sudo = false;
    report
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let text = dir.to_string_lossy();
        assert!(
            !text.starts_with("/home/ubuntu"),
            "test path must stay off the home directory: {text}"
        );
        let output = Command::new("git")
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

    fn repo_named<'a>(report: &'a DevReposReport, name: &str) -> &'a RepoReading {
        report
            .repos
            .iter()
            .find(|repo| repo.path.ends_with(name))
            .unwrap_or_else(|| panic!("missing repo {name}: {report:?}"))
    }

    #[test]
    fn no_paths_is_unavailable_and_not_clean() {
        let report = scan_dev_repos(Path::new("git"), &[], &[]);
        assert!(!report.clean);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert!(report.repos.is_empty());
        assert!(report.roots.is_empty());
        assert!(!report.fetches && !report.pulls && !report.pushes);
        assert!(!report.uses_network && !report.uses_sudo);
        assert!(report.detail.as_deref().unwrap().contains("opt-in"));
        let human = format_dev_repos_human(&report);
        assert!(human.contains("clean: no"));
        assert!(human.contains("uses network: no"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("(none)"));
    }

    #[test]
    fn missing_git_is_unavailable_without_reading_repos() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        let report = scan_dev_repos(
            Path::new("/no/such/devguard-git"),
            &[root.path().to_path_buf()],
            &[],
        );
        assert!(!report.clean);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert!(report.repos.is_empty());
        assert!(report.detail.unwrap().contains("git"));
        assert!(report
            .roots
            .iter()
            .all(|root| root.status == CoverageStatus::Unavailable));
    }

    #[test]
    fn unreadable_path_is_unavailable_and_not_clean() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let report = scan_dev_repos(Path::new("git"), &[missing], &[]);
        assert!(!report.clean);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert!(report.repos.is_empty());
        assert_eq!(report.roots.len(), 1);
        assert_eq!(report.roots[0].status, CoverageStatus::Unavailable);
        assert!(report.roots[0].detail.contains("unreadable"));
    }

    #[test]
    fn filesystem_root_and_home_are_refused_without_a_walk() {
        assert!(refuse_reason(Path::new("/"))
            .unwrap()
            .contains("filesystem root"));
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();
        let home = std::fs::canonicalize(&home).unwrap_or(home);
        assert!(refuse_reason(&home).unwrap().contains("home"));
    }

    #[test]
    fn symlink_to_filesystem_root_is_not_walked() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("root-link");
        std::os::unix::fs::symlink("/", &link).unwrap();
        let report = scan_dev_repos(Path::new("git"), &[link], &[]);
        assert!(!report.clean);
        assert!(report.repos.is_empty());
        assert!(report.roots[0].detail.contains("filesystem root"));
    }

    #[test]
    fn temp_repos_report_dirty_untracked_branch_upstream_and_unpublished() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("scan");
        std::fs::create_dir(&root).unwrap();
        let dirty = root.join("dirty-repo");
        init_repo(&dirty);
        git(&dirty, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        std::fs::write(dirty.join("README"), "changed\n").unwrap();
        git(&dirty, &["add", "README"]);
        git(&dirty, &["commit", "-m", "edit"]);
        git(
            &dirty,
            &["remote", "add", "origin", dirty.to_str().expect("utf8")],
        );
        git(&dirty, &["config", "branch.main.remote", "origin"]);
        git(&dirty, &["config", "branch.main.merge", "refs/heads/main"]);
        std::fs::write(dirty.join("README"), "changed-again\n").unwrap();
        std::fs::write(dirty.join("extra.txt"), "new\n").unwrap();

        let clean = root.join("clean-repo");
        init_repo(&clean);
        init_repo(&dirty.join("nested-repo"));
        let outside = scratch.path().join("outside-repo");
        init_repo(&outside);
        std::os::unix::fs::symlink(&outside, root.join("linked-repo")).unwrap();

        let report = scan_dev_repos(Path::new("git"), &[root], &[]);
        assert!(report.clean, "{report:?}");
        assert_eq!(report.status, CoverageStatus::Available);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(!report.uses_network && !report.uses_sudo);
        assert_eq!(report.repos.len(), 2, "{report:?}");

        let dirty_row = repo_named(&report, "dirty-repo");
        assert_eq!(dirty_row.status, CoverageStatus::Available);
        assert_eq!(dirty_row.branch.as_deref(), Some("main"));
        assert_eq!(dirty_row.upstream.as_deref(), Some("origin/main"));
        assert_eq!(dirty_row.dirty, Some(true));
        assert_eq!(dirty_row.untracked, Some(true));
        assert_eq!(dirty_row.unpublished, Some(1));

        let clean_row = repo_named(&report, "clean-repo");
        assert_eq!(clean_row.branch.as_deref(), Some("main"));
        assert!(clean_row.upstream.is_none());
        assert_eq!(clean_row.dirty, Some(false));
        assert_eq!(clean_row.untracked, Some(false));
        assert!(clean_row.unpublished.is_none());

        let human = format_dev_repos_human(&report);
        assert!(human.contains("branch main"));
        assert!(human.contains("upstream origin/main"));
        assert!(human.contains("dirty yes"));
        assert!(human.contains("untracked yes"));
        assert!(human.contains("unpublished 1"));
        assert!(human.contains("fetches: no"));
        assert!(human.contains("pushes: no"));
    }

    #[test]
    fn config_roots_are_scanned_when_no_explicit_path_is_given() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("from-config");
        init_repo(&repo);
        let report = scan_dev_repos(
            Path::new("git"),
            &[],
            &[root.path().to_string_lossy().into_owned()],
        );
        assert!(report.clean, "{report:?}");
        assert_eq!(report.repos.len(), 1);
        assert!(report.repos[0].path.ends_with("from-config"));
        assert_eq!(report.repos[0].unpublished, None);
    }

    #[test]
    fn wrapper_records_an_argument_list_and_rejects_network_commands() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("wrapped");
        init_repo(&repo);
        let log = root.path().join("git-args.log");
        let wrapper = root.path().join("git-wrapper");
        let real = Command::new("which").arg("git").output().expect("which");
        assert!(real.status.success());
        let real_git = String::from_utf8_lossy(&real.stdout).trim().to_string();
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$0\" >> '{log}'\nfor arg in \"$@\"; do\n  printf '%s\\n' \"$arg\" >> '{log}'\n  case \"$arg\" in\n    fetch|pull|push|clone|ls-remote) echo forbidden >&2; exit 97 ;;\n  esac\ndone\nprintf '%s\\n' '---' >> '{log}'\nexec '{real}' \"$@\"\n",
            log = log.display(),
            real = real_git,
        );
        std::fs::write(&wrapper, script).unwrap();
        let mut perms = std::fs::metadata(&wrapper).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&wrapper, perms).unwrap();

        let report = scan_dev_repos(&wrapper, &[repo], &[]);
        assert!(report.clean, "{report:?}");
        let recorded = std::fs::read_to_string(&log).unwrap();
        assert!(recorded.contains("-C"));
        assert!(recorded.contains("status"));
        assert!(recorded.contains("rev-parse"));
        assert!(!recorded
            .lines()
            .any(|line| matches!(line, "fetch" | "pull" | "push" | "clone" | "ls-remote")));
    }
}
