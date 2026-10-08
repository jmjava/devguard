//! One work-tree reading for `devguard dev repos`.
//!
//! The command reports the branch name, the upstream name when one is
//! configured, and whether the tree is dirty, has untracked files, or has
//! commits that are not in the configured upstream. It does not fetch, push,
//! or use the network. A path that is not a git work tree is `unavailable`,
//! and that result is not clean.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::redact::redact_text;

const GIT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURE_BYTES: usize = 4 * 1024;
const MAX_NAME_CHARS: usize = 200;

/// `available` when the path is a git work tree and the local reading finished.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepoStatus {
    Available,
    Unavailable,
}

/// Human and JSON body for `devguard dev repos`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevReposReport {
    pub path: String,
    pub status: RepoStatus,
    /// Always false. This command never fetches.
    pub fetches: bool,
    /// Always false. This command never pushes.
    pub pushes: bool,
    /// Always false. This command never contacts the network.
    pub uses_network: bool,
    /// False when the path is not a git work tree or the local reading failed.
    pub clean: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untracked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpushed: Option<bool>,
    pub detail: String,
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
        if self.status == RepoStatus::Available {
            Vec::new()
        } else {
            vec![format!("repos is unavailable: {}", self.detail)]
        }
    }
}

/// Read one path using `git` from the process `PATH`.
pub fn scan_dev_repos(path: &Path) -> DevReposReport {
    let path_env = std::env::var_os("PATH").unwrap_or_default();
    scan_dev_repos_on_path(path, &path_env)
}

/// Read one path using `git` on `path_env`. Tests pass a fixture directory.
pub fn scan_dev_repos_on_path(path: &Path, path_env: &OsStr) -> DevReposReport {
    match find_on_path(path_env, "git") {
        Some(git) => inspect_repo(path, &git),
        None => unavailable(path, "`git` is not on PATH"),
    }
}

pub fn format_dev_repos_human(report: &DevReposReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard dev repos\n");
    out.push_str(&format!("  path: {}\n", report.path));
    out.push_str("  fetches: no\n");
    out.push_str("  pushes: no\n");
    out.push_str("  uses network: no\n");
    out.push_str(&format!("  clean: {}\n", yes_no(report.clean)));
    out.push_str(&format!(
        "  status: {status}",
        status = status_word(report.status)
    ));
    if report.status == RepoStatus::Unavailable {
        out.push_str(" — ");
        out.push_str(&report.detail);
    }
    out.push('\n');
    if report.status == RepoStatus::Available {
        out.push_str(&format!(
            "  branch: {}\n",
            report.branch.as_deref().unwrap_or("none")
        ));
        out.push_str(&format!(
            "  upstream: {}\n",
            report.upstream.as_deref().unwrap_or("none")
        ));
        out.push_str(&format!(
            "  dirty: {}\n",
            yes_no(report.dirty.unwrap_or(false))
        ));
        out.push_str(&format!(
            "  untracked: {}\n",
            yes_no(report.untracked.unwrap_or(false))
        ));
        out.push_str(&format!(
            "  unpushed: {}\n",
            yes_no(report.unpushed.unwrap_or(false))
        ));
    }
    out
}

/// Classify `git status --porcelain=v1 -z` bytes.
#[cfg(test)]
///
/// Rename and copy records consume the following path so a filename is not
/// read as a second status code.
fn classify_porcelain_z(text: &str) -> (bool, bool) {
    let mut dirty = false;
    let mut untracked = false;
    let mut entries = text.split('\0').filter(|entry| !entry.is_empty());
    while let Some(entry) = entries.next() {
        let bytes = entry.as_bytes();
        if bytes.len() < 2 {
            continue;
        }
        if bytes[0] == b'?' && bytes[1] == b'?' {
            untracked = true;
        } else if bytes[0] == b'!' && bytes[1] == b'!' {
            // Ignored files are not untracked files.
        } else {
            dirty = true;
        }
        if bytes[0] == b'R' || bytes[0] == b'C' || bytes[1] == b'R' || bytes[1] == b'C' {
            let _old_path = entries.next();
        }
    }
    (dirty, untracked)
}

fn inspect_repo(path: &Path, git: &Path) -> DevReposReport {
    if !path.exists() {
        return unavailable(path, "path does not exist");
    }
    match git_output(git, path, &["rev-parse", "--is-inside-work-tree"]) {
        Ok(output) if output.success && output.stdout.trim() == "true" => {}
        Ok(_) => return unavailable(path, "path is not a git work tree"),
        Err(GitFail::TimedOut) => return unavailable(path, "`git` timed out"),
        Err(GitFail::Failed) => return unavailable(path, "path is not a git work tree"),
    }

    let branch = match git_output(git, path, &["branch", "--show-current"]) {
        Ok(output) if output.success => first_name(&output.stdout),
        Ok(_) => return unavailable(path, "branch could not be read"),
        Err(GitFail::TimedOut) => return unavailable(path, "`git` timed out"),
        Err(GitFail::Failed) => return unavailable(path, "branch could not be read"),
    };

    let upstream = match git_output(git, path, &["rev-parse", "--abbrev-ref", "@{upstream}"]) {
        Ok(output) if output.success => match safe_ref_name(&output.stdout) {
            Some(name) => Some(name),
            None => return unavailable(path, "upstream name could not be read"),
        },
        Ok(_) => None,
        Err(GitFail::TimedOut) => return unavailable(path, "`git` timed out"),
        Err(GitFail::Failed) => return unavailable(path, "upstream could not be read"),
    };

    let dirty = match worktree_dirty(git, path) {
        Ok(dirty) => dirty,
        Err(detail) => return unavailable(path, detail),
    };
    let untracked = match worktree_untracked(git, path) {
        Ok(untracked) => untracked,
        Err(detail) => return unavailable(path, detail),
    };
    let unpushed = match commits_unpushed(git, path, upstream.as_deref()) {
        Ok(unpushed) => unpushed,
        Err(detail) => return unavailable(path, detail),
    };

    DevReposReport {
        path: path_text(path),
        status: RepoStatus::Available,
        fetches: false,
        pushes: false,
        uses_network: false,
        clean: true,
        branch,
        upstream,
        dirty: Some(dirty),
        untracked: Some(untracked),
        unpushed: Some(unpushed),
        detail: "git work tree".to_string(),
    }
}

fn worktree_dirty(git: &Path, path: &Path) -> Result<bool, &'static str> {
    match git_output(
        git,
        path,
        &["status", "--porcelain=v1", "--untracked-files=no", "-z"],
    ) {
        Ok(output) if output.success => Ok(!output.stdout.is_empty()),
        Ok(_) => Err("work tree status could not be read"),
        Err(GitFail::TimedOut) => Err("`git` timed out"),
        Err(GitFail::Failed) => Err("work tree status could not be read"),
    }
}

fn worktree_untracked(git: &Path, path: &Path) -> Result<bool, &'static str> {
    match git_output(
        git,
        path,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    ) {
        Ok(output) if output.success => Ok(!output.stdout.is_empty()),
        Ok(_) => Err("untracked files could not be read"),
        Err(GitFail::TimedOut) => Err("`git` timed out"),
        Err(GitFail::Failed) => Err("untracked files could not be read"),
    }
}

fn commits_unpushed(git: &Path, path: &Path, upstream: Option<&str>) -> Result<bool, &'static str> {
    let Some(upstream) = upstream else {
        return Ok(false);
    };
    let revspec = format!("{upstream}..HEAD");
    match git_output(git, path, &["rev-list", "--count", &revspec]) {
        Ok(output) if output.success => match output.stdout.trim().parse::<u64>() {
            Ok(count) => Ok(count > 0),
            Err(_) => Err("unpushed commits could not be read locally"),
        },
        Ok(_) => Err("unpushed commits could not be read locally"),
        Err(GitFail::TimedOut) => Err("`git` timed out"),
        Err(GitFail::Failed) => Err("unpushed commits could not be read locally"),
    }
}

fn unavailable(path: &Path, detail: &str) -> DevReposReport {
    DevReposReport {
        path: path_text(path),
        status: RepoStatus::Unavailable,
        fetches: false,
        pushes: false,
        uses_network: false,
        clean: false,
        branch: None,
        upstream: None,
        dirty: None,
        untracked: None,
        unpushed: None,
        detail: bound_detail(detail),
    }
}

fn path_text(path: &Path) -> String {
    bound_detail(&path.display().to_string())
}

fn bound_detail(text: &str) -> String {
    let redacted = redact_text(text);
    let mut out: String = redacted.chars().take(MAX_NAME_CHARS).collect();
    if redacted.chars().count() > MAX_NAME_CHARS {
        out.push('…');
    }
    out
}

fn first_name(text: &str) -> Option<String> {
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(bound_detail(line))
    }
}

fn safe_ref_name(text: &str) -> Option<String> {
    let line = text.lines().next()?.trim();
    if line.is_empty()
        || line.len() > MAX_NAME_CHARS
        || line.starts_with('-')
        || !line
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '.' | '-' | '@'))
    {
        return None;
    }
    Some(line.to_string())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn status_word(status: RepoStatus) -> &'static str {
    match status {
        RepoStatus::Available => "available",
        RepoStatus::Unavailable => "unavailable",
    }
}

fn find_on_path(path: &OsStr, name: &str) -> Option<PathBuf> {
    for dir in std::env::split_paths(path) {
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

enum GitFail {
    TimedOut,
    Failed,
}

struct GitOutput {
    success: bool,
    stdout: String,
}

fn git_output(git: &Path, repo: &Path, args: &[&str]) -> Result<GitOutput, GitFail> {
    let mut command = Command::new(git);
    command
        .arg("--no-optional-locks")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("-c")
        .arg("credential.helper=")
        .arg("-c")
        .arg("core.fsmonitor=")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    fn assert_outside_devguard_checkout(path: &Path) {
        let text = path.to_string_lossy();
        assert!(
            !text.starts_with("/home/ubuntu/github/jmjava/devguard"),
            "test path must stay off the devguard checkout: {text}"
        );
    }

    fn git(dir: &Path, args: &[&str]) {
        assert_outside_devguard_checkout(dir);
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
            "git {args:?} in {}: {}",
            dir.display(),
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

    fn clone_local(origin: &Path, dest: &Path) {
        assert_outside_devguard_checkout(origin);
        assert_outside_devguard_checkout(dest);
        let output = Command::new("git")
            .args([
                "clone",
                "--local",
                origin.to_str().expect("origin"),
                dest.to_str().expect("dest"),
            ])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("clone");
        assert!(
            output.status.success(),
            "clone: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn real_git() -> PathBuf {
        let path = std::env::var_os("PATH").unwrap_or_default();
        find_on_path(&path, "git").expect("git on PATH for tests")
    }

    #[test]
    fn porcelain_marks_dirty_untracked_and_skips_rename_paths() {
        let (dirty, untracked) = classify_porcelain_z(" M README\0?? extra.txt\0");
        assert!(dirty);
        assert!(untracked);
        let (dirty, untracked) = classify_porcelain_z("R  new.txt\0?? not-a-status\0");
        assert!(dirty);
        assert!(!untracked);
        let (dirty, untracked) = classify_porcelain_z("!! ignored.bin\0");
        assert!(!dirty);
        assert!(!untracked);
    }

    #[test]
    fn clean_repo_without_upstream_reports_the_branch() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        let report = scan_dev_repos(&repo);
        assert_eq!(report.status, RepoStatus::Available);
        assert!(report.clean);
        assert!(!report.fetches);
        assert!(!report.pushes);
        assert!(!report.uses_network);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert_eq!(report.branch.as_deref(), Some("main"));
        assert!(report.upstream.is_none());
        assert_eq!(report.dirty, Some(false));
        assert_eq!(report.untracked, Some(false));
        assert_eq!(report.unpushed, Some(false));
        let human = format_dev_repos_human(&report);
        assert!(human.contains("DevGuard dev repos"));
        assert!(human.contains("clean: yes"));
        assert!(human.contains("fetches: no"));
        assert!(human.contains("pushes: no"));
        assert!(human.contains("uses network: no"));
        assert!(human.contains("branch: main"));
        assert!(human.contains("upstream: none"));
        assert!(human.contains("unpushed: no"));
    }

    #[test]
    fn dirty_and_untracked_files_stay_separate() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join("README"), "changed\n").unwrap();
        std::fs::write(repo.join("notes.txt"), "local\n").unwrap();
        let report = scan_dev_repos(&repo);
        assert!(report.clean);
        assert_eq!(report.dirty, Some(true));
        assert_eq!(report.untracked, Some(true));
        assert_eq!(report.unpushed, Some(false));
        let human = format_dev_repos_human(&report);
        assert!(human.contains("dirty: yes"));
        assert!(human.contains("untracked: yes"));
    }

    #[test]
    fn ignored_files_are_not_untracked() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        std::fs::write(repo.join(".gitignore"), "secret.log\n").unwrap();
        git(&repo, &["add", ".gitignore"]);
        git(&repo, &["commit", "-m", "ignore"]);
        std::fs::write(repo.join("secret.log"), "nope\n").unwrap();
        let report = scan_dev_repos(&repo);
        assert_eq!(report.dirty, Some(false));
        assert_eq!(report.untracked, Some(false));
    }

    #[test]
    fn commits_ahead_of_a_local_upstream_are_unpushed() {
        let root = tempfile::tempdir().unwrap();
        let origin = root.path().join("origin");
        let wt = root.path().join("wt");
        init_repo(&origin);
        clone_local(&origin, &wt);
        let even = scan_dev_repos(&wt);
        assert_eq!(even.branch.as_deref(), Some("main"));
        assert_eq!(even.upstream.as_deref(), Some("origin/main"));
        assert_eq!(even.unpushed, Some(false));
        assert_eq!(even.dirty, Some(false));
        std::fs::write(wt.join("README"), "ahead\n").unwrap();
        git(&wt, &["add", "README"]);
        git(&wt, &["commit", "-m", "ahead"]);
        let ahead = scan_dev_repos(&wt);
        assert!(ahead.clean);
        assert_eq!(ahead.upstream.as_deref(), Some("origin/main"));
        assert_eq!(ahead.dirty, Some(false));
        assert_eq!(ahead.untracked, Some(false));
        assert_eq!(ahead.unpushed, Some(true));
        assert!(!ahead.fetches);
        assert!(!ahead.pushes);
        assert!(!ahead.uses_network);
        let human = format_dev_repos_human(&ahead);
        assert!(human.contains("upstream: origin/main"));
        assert!(human.contains("unpushed: yes"));
    }

    #[test]
    fn missing_path_and_non_repo_are_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let missing_report = scan_dev_repos(&missing);
        assert_eq!(missing_report.status, RepoStatus::Unavailable);
        assert!(!missing_report.clean);
        assert_eq!(missing_report.exit_code(), ExitCode::Partial);
        assert!(missing_report.branch.is_none());
        assert!(missing_report.dirty.is_none());
        assert!(missing_report.detail.contains("does not exist"));
        assert!(missing_report
            .warnings()
            .iter()
            .any(|w| w.contains("unavailable")));

        let plain = root.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        let plain_report = scan_dev_repos(&plain);
        assert_eq!(plain_report.status, RepoStatus::Unavailable);
        assert!(!plain_report.clean);
        assert!(plain_report.detail.contains("not a git work tree"));
        assert!(plain_report.unpushed.is_none());
        let human = format_dev_repos_human(&plain_report);
        assert!(human.contains("clean: no"));
        assert!(human.contains("fetches: no"));
        assert!(human.contains("uses network: no"));
        assert!(!human.contains("dirty:"));

        let bare = root.path().join("bare.git");
        std::fs::create_dir(&bare).unwrap();
        git(&bare, &["init", "--bare"]);
        let bare_report = scan_dev_repos(&bare);
        assert_eq!(bare_report.status, RepoStatus::Unavailable);
        assert!(!bare_report.clean);
    }

    #[test]
    fn git_missing_from_path_is_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        init_repo(&repo);
        let empty = root.path().join("empty-path");
        std::fs::create_dir(&empty).unwrap();
        let report = scan_dev_repos_on_path(&repo, empty.as_os_str());
        assert_eq!(report.status, RepoStatus::Unavailable);
        assert!(!report.clean);
        assert!(report.detail.contains("not on PATH"));
        assert!(!report.uses_network);
    }

    #[test]
    fn wrapper_git_is_not_asked_to_fetch_or_push() {
        let root = tempfile::tempdir().unwrap();
        let origin = root.path().join("origin");
        let wt = root.path().join("wt");
        init_repo(&origin);
        clone_local(&origin, &wt);
        let log = root.path().join("git.log");
        let wrapper = root.path().join("git");
        let real = real_git();
        let script = format!(
            "#!/bin/sh\nlog={log}\nreal={real}\nprev=\nsub=\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-C\" ] || [ \"$prev\" = \"-c\" ]; then\n    prev=$arg\n    continue\n  fi\n  case \"$arg\" in\n    -*) prev=$arg; continue ;;\n  esac\n  sub=$arg\n  break\ndone\nprintf '%s\\n' \"$sub\" >> \"$log\"\ncase \"$sub\" in\n  fetch|pull|push|ls-remote|clone)\n    printf '%s\\n' forbidden >> \"$log\"\n    exit 97\n    ;;\nesac\nexec \"$real\" \"$@\"\n",
            log = sh_quote(&log),
            real = sh_quote(&real),
        );
        std::fs::write(&wrapper, script).unwrap();
        let mut perms = std::fs::metadata(&wrapper).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&wrapper, perms.clone()).unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::copy(&wrapper, bin.join("git")).unwrap();
        std::fs::set_permissions(bin.join("git"), perms).unwrap();
        let report = scan_dev_repos_on_path(&wt, bin.as_os_str());
        assert!(report.clean, "{}", report.detail);
        assert_eq!(report.upstream.as_deref(), Some("origin/main"));
        assert!(!report.fetches);
        assert!(!report.pushes);
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(!logged.contains("forbidden"), "{logged}");
        for forbidden in ["fetch", "pull", "push", "ls-remote", "clone"] {
            assert!(!logged.lines().any(|line| line == forbidden), "{logged}");
        }
    }

    fn sh_quote(path: &Path) -> String {
        let text = path.to_str().expect("utf8 path");
        assert!(!text.contains('\''), "{text}");
        format!("'{text}'")
    }
}
