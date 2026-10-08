//! Toolchain version lines for `devguard dev env`.
//!
//! The command reads one version line from each tool that is on `PATH`.
//! A missing tool is `unavailable`, and that report is not clean. It does not
//! install tools, use the network, or run a package audit.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::redact::redact_text;

const TOOL_NAMES: &[&str] = &["rustc", "cargo", "python3", "node", "git", "gcc"];
const VERSION_ARGS: &[&str] = &["--version"];
const TOOL_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURE_BYTES: usize = 8 * 1024;
const MAX_LINE_CHARS: usize = 200;

/// `available` or `unavailable`. A tool that is not on `PATH` is never clean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Available,
    Unavailable,
}

/// One compiler or tool. `version_line` is set only when the tool answered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolVersion {
    pub name: String,
    pub status: CoverageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_line: Option<String>,
    pub detail: String,
}

/// Human and JSON body for `devguard dev env`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevEnvReport {
    /// Always false. This command never installs a tool.
    pub installs_tools: bool,
    /// Always false. This command never contacts the network.
    pub uses_network: bool,
    /// Always false. This command never runs a package audit.
    pub runs_package_audit: bool,
    /// False when any tool is missing or prints no version line.
    pub clean: bool,
    pub tools: Vec<ToolVersion>,
}

impl DevEnvReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.tools
            .iter()
            .filter(|tool| tool.status == CoverageStatus::Unavailable)
            .map(|tool| format!("{} is unavailable: {}", tool.name, tool.detail))
            .collect()
    }
}

/// First non-empty line of fixture or tool text, with secret-like values redacted.
pub fn version_line(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|line| !line.is_empty())?;
    let redacted = redact_text(line);
    let mut out: String = redacted.chars().take(MAX_LINE_CHARS).collect();
    if redacted.chars().count() > MAX_LINE_CHARS {
        out.push('…');
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Read version lines from the tools on the process `PATH`.
pub fn scan_dev_env() -> DevEnvReport {
    let path = std::env::var_os("PATH").unwrap_or_default();
    scan_dev_env_on_path(&path)
}

/// Read version lines from the tools on `path`. Tests pass a fixture directory.
pub fn scan_dev_env_on_path(path: &OsStr) -> DevEnvReport {
    let tools: Vec<ToolVersion> = TOOL_NAMES
        .iter()
        .map(|name| probe_tool(path, name))
        .collect();
    let clean = tools
        .iter()
        .all(|tool| tool.status == CoverageStatus::Available);
    DevEnvReport {
        installs_tools: false,
        uses_network: false,
        runs_package_audit: false,
        clean,
        tools,
    }
}

pub fn format_dev_env_human(report: &DevEnvReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard dev env\n");
    out.push_str("  installs tools: no\n");
    out.push_str("  uses network: no\n");
    out.push_str("  runs package audit: no\n");
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    out.push_str("\nTools\n");
    for tool in &report.tools {
        let shown = tool.version_line.as_deref().unwrap_or(tool.detail.as_str());
        out.push_str(&format!(
            "  {name}: {status} — {shown}\n",
            name = tool.name,
            status = status_word(tool.status),
        ));
    }
    out
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn probe_tool(path: &OsStr, name: &str) -> ToolVersion {
    let Some(program) = find_on_path(path, name) else {
        return unavailable(name, format!("`{name}` is not on PATH"));
    };
    match run_version(&program) {
        Ok(output) => match version_line(&output.stdout).or_else(|| version_line(&output.stderr)) {
            Some(line) => available(name, line),
            None if output.success => {
                unavailable(name, format!("`{name}` printed no version line"))
            }
            None => unavailable(name, format!("`{name}` exited non-zero")),
        },
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
            unavailable(name, format!("`{name}` timed out"))
        }
        Err(err) => unavailable(name, format!("`{name}` failed: {err}")),
    }
}

fn available(name: &str, version_line: String) -> ToolVersion {
    ToolVersion {
        name: name.to_string(),
        status: CoverageStatus::Available,
        detail: version_line.clone(),
        version_line: Some(version_line),
    }
}

fn unavailable(name: &str, detail: String) -> ToolVersion {
    ToolVersion {
        name: name.to_string(),
        status: CoverageStatus::Unavailable,
        version_line: None,
        detail: bound_detail(&detail),
    }
}

fn bound_detail(text: &str) -> String {
    let redacted = redact_text(text);
    let mut out: String = redacted.chars().take(160).collect();
    if redacted.chars().count() > 160 {
        out.push('…');
    }
    out
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

struct ToolOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_version(program: &Path) -> std::io::Result<ToolOutput> {
    let mut child = Command::new(program)
        .args(VERSION_ARGS)
        .env("CARGO_NET_OFFLINE", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_handle = thread::spawn(move || read_capped(stdout));
    let stderr_handle = thread::spawn(move || read_capped(stderr));
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_handle.join().unwrap_or_default();
            let stderr = stderr_handle.join().unwrap_or_default();
            return Ok(ToolOutput {
                success: status.success(),
                stdout,
                stderr,
            });
        }
        if started.elapsed() > TOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{} timed out", program.display()),
            ));
        }
        thread::sleep(Duration::from_millis(20));
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

    fn write_tool(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }

    fn version_script(line: &str) -> String {
        format!("#!/bin/sh\nprintf '%s\\n' '{line}'\n")
    }

    fn fill_tools(dir: &Path, line_for: impl Fn(&str) -> String) {
        for name in TOOL_NAMES {
            write_tool(dir, name, &line_for(name));
        }
    }

    #[test]
    fn parses_fixture_version_text() {
        assert_eq!(
            version_line("rustc 1.85.0 (fixture)\ncommit-hash\n").as_deref(),
            Some("rustc 1.85.0 (fixture)")
        );
        assert_eq!(
            version_line("\n\ngcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0\nCopyright\n").as_deref(),
            Some("gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0")
        );
        assert_eq!(version_line("   \n\n"), None);
        assert_eq!(
            version_line("node v20.18.0 token=supersecret\n").as_deref(),
            Some("node v20.18.0 token=[REDACTED]")
        );
    }

    #[test]
    fn fixture_path_reports_every_version_line() {
        let dir = tempfile::tempdir().unwrap();
        let lines = [
            ("rustc", "rustc 1.85.0 (fixture)"),
            ("cargo", "cargo 1.85.0 (fixture)"),
            ("python3", "Python 3.12.3"),
            ("node", "v20.18.0"),
            ("git", "git version 2.43.0"),
            ("gcc", "gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0"),
        ];
        for (name, line) in lines {
            write_tool(dir.path(), name, &version_script(line));
        }
        let report = scan_dev_env_on_path(dir.path().as_os_str());
        assert!(report.clean);
        assert!(!report.installs_tools);
        assert!(!report.uses_network);
        assert!(!report.runs_package_audit);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert_eq!(report.tools.len(), lines.len());
        for (tool, (name, line)) in report.tools.iter().zip(lines) {
            assert_eq!(tool.name, name);
            assert_eq!(tool.status, CoverageStatus::Available);
            assert_eq!(tool.version_line.as_deref(), Some(line));
        }
        let human = format_dev_env_human(&report);
        assert!(human.contains("clean: yes"));
        assert!(human.contains("rustc 1.85.0 (fixture)"));
        assert!(human.contains("runs package audit: no"));
    }

    #[test]
    fn missing_tool_is_unavailable_and_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        write_tool(dir.path(), "git", &version_script("git version 2.43.0"));
        std::fs::create_dir(dir.path().join("gcc")).unwrap();
        let report = scan_dev_env_on_path(dir.path().as_os_str());
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let gcc = report
            .tools
            .iter()
            .find(|tool| tool.name == "gcc")
            .expect("gcc");
        assert_eq!(gcc.status, CoverageStatus::Unavailable);
        assert!(gcc.version_line.is_none());
        assert!(gcc.detail.contains("not on PATH"));
        let git = report
            .tools
            .iter()
            .find(|tool| tool.name == "git")
            .expect("git");
        assert_eq!(git.version_line.as_deref(), Some("git version 2.43.0"));
        let human = format_dev_env_human(&report);
        assert!(human.contains("clean: no"));
        assert!(human.contains("uses network: no"));
        assert!(human.contains("installs tools: no"));
        assert!(human.contains("`gcc` is not on PATH"));
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("gcc")));
    }

    #[test]
    fn empty_version_text_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        fill_tools(dir.path(), |_| "#!/bin/sh\nexit 0\n".to_string());
        let report = scan_dev_env_on_path(dir.path().as_os_str());
        assert!(!report.clean);
        assert!(report
            .tools
            .iter()
            .all(|tool| tool.status == CoverageStatus::Unavailable));
        assert!(report
            .tools
            .iter()
            .all(|tool| tool.detail.contains("no version line")));
    }

    #[test]
    fn version_on_stderr_counts() {
        let dir = tempfile::tempdir().unwrap();
        fill_tools(dir.path(), |name| {
            if name == "python3" {
                "#!/bin/sh\nprintf '%s\\n' 'Python 3.11.0' >&2\n".to_string()
            } else {
                version_script("ok")
            }
        });
        let report = scan_dev_env_on_path(dir.path().as_os_str());
        let python = report
            .tools
            .iter()
            .find(|tool| tool.name == "python3")
            .expect("python3");
        assert_eq!(python.version_line.as_deref(), Some("Python 3.11.0"));
        assert!(report.clean);
    }

    #[test]
    fn first_path_entry_wins() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        fill_tools(&first, |_| version_script("from-first"));
        fill_tools(&second, |_| version_script("from-second"));
        let path = std::env::join_paths([&first, &second]).unwrap();
        let report = scan_dev_env_on_path(&path);
        assert!(report
            .tools
            .iter()
            .all(|tool| tool.version_line.as_deref() == Some("from-first")));
    }
}
