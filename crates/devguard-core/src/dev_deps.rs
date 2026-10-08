//! Opt-in dependency audit for `devguard dev deps audit`.
//!
//! The default scan looks for local adapter binaries and does not run them.
//! It does not contact the network and does not transmit a private manifest.
//! `--online` is the only path that runs a networked tool. A missing local
//! tool is `unavailable`, and that report is not clean. This module does not
//! install tools and does not use sudo.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::redact::redact_text;

const AUDIT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CAPTURE_BYTES: usize = 16 * 1024;
const MAX_LINE_CHARS: usize = 200;
const NOT_REQUESTED: &str = "network audit was not requested";

const TOKEN_PREFIXES: &[&str] = &["ghp_", "github_pat_", "npm_", "glpat-", "sk-", "AKIA"];

/// `available` or `unavailable`. A missing local tool is never clean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Available,
    Unavailable,
}

/// Whether a network audit ran.
///
/// The default is [`NetworkAudit::NotRequested`]. No networked tool runs in
/// that state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAudit {
    NotRequested,
    NotRun,
    Ran,
}

/// One local audit adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditAdapter {
    pub name: String,
    pub status: CoverageStatus,
    /// Binary that was found, when one was on `PATH`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub detail: String,
    /// First redacted line from the tool. Set only after an `--online` run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// Human and JSON body for `devguard dev deps audit`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepsAuditReport {
    /// Always false. This command never installs an audit tool.
    pub installs_tools: bool,
    /// Always false. This command never uses sudo.
    pub uses_sudo: bool,
    /// True only when the operator passed `--online`.
    pub online: bool,
    /// True only when an `--online` scan actually started a tool.
    pub uses_network: bool,
    /// True only when an `--online` scan started a tool that may send
    /// dependency names. The default scan never transmits a manifest.
    pub transmits_manifest: bool,
    pub network_audit: NetworkAudit,
    /// False when any adapter tool is missing or, with `--online`, did not answer.
    /// This is coverage. It is not a claim that the tree has no advisories.
    pub clean: bool,
    pub adapters: Vec<AuditAdapter>,
}

struct Candidate {
    binary: &'static str,
    args: &'static [&'static str],
}

struct AdapterSpec {
    name: &'static str,
    candidates: &'static [Candidate],
    missing: &'static str,
}

const ADAPTERS: &[AdapterSpec] = &[
    AdapterSpec {
        name: "cargo-audit",
        candidates: &[Candidate {
            binary: "cargo-audit",
            args: &[],
        }],
        missing: "`cargo-audit` is not on PATH",
    },
    AdapterSpec {
        name: "python",
        candidates: &[
            Candidate {
                binary: "pip-audit",
                args: &[],
            },
            Candidate {
                binary: "safety",
                args: &["check"],
            },
        ],
        missing: "`pip-audit` and `safety` are not on PATH",
    },
    AdapterSpec {
        name: "npm",
        candidates: &[Candidate {
            binary: "npm",
            args: &["audit"],
        }],
        missing: "`npm` is not on PATH",
    },
    AdapterSpec {
        name: "maven-gradle",
        candidates: &[
            Candidate {
                binary: "mvn",
                args: &["-q", "org.owasp:dependency-check-maven:check"],
            },
            Candidate {
                binary: "gradle",
                args: &["dependencyCheckAnalyze", "--no-daemon"],
            },
        ],
        missing: "`mvn` and `gradle` are not on PATH",
    },
];

impl DepsAuditReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.adapters
            .iter()
            .filter(|adapter| adapter.status == CoverageStatus::Unavailable)
            .map(|adapter| format!("{} is unavailable: {}", adapter.name, adapter.detail))
            .collect()
    }
}

/// Look up local audit tools on `path`.
///
/// When `online` is false, this function does not spawn those tools. `workdir`
/// is the directory an `--online` tool would scan. The offline path does not
/// read it.
pub fn scan_deps_audit(path: &OsStr, online: bool, workdir: &Path) -> DepsAuditReport {
    let mut ran_any = false;
    let adapters = ADAPTERS
        .iter()
        .map(|spec| {
            let (adapter, ran) = probe_adapter(spec, path, online, workdir);
            ran_any |= ran;
            adapter
        })
        .collect();
    finish(online, ran_any, adapters)
}

pub fn format_deps_audit_human(report: &DepsAuditReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard dev deps\n");
    out.push_str(&format!(
        "  installs tools: {}\n",
        yes_no(report.installs_tools)
    ));
    out.push_str(&format!("  uses sudo: {}\n", yes_no(report.uses_sudo)));
    out.push_str(&format!(
        "  uses network: {}\n",
        yes_no(report.uses_network)
    ));
    out.push_str(&format!(
        "  transmits manifest: {}\n",
        yes_no(report.transmits_manifest)
    ));
    out.push_str(&format!(
        "  network audit: {}\n",
        network_audit_word(report.network_audit)
    ));
    out.push_str(&format!("  clean: {}\n", yes_no(report.clean)));
    out.push_str("\nAdapters\n");
    for adapter in &report.adapters {
        let shown = adapter
            .summary
            .as_deref()
            .unwrap_or(adapter.detail.as_str());
        out.push_str(&format!(
            "  {name}: {status} — {shown}\n",
            name = adapter.name,
            status = status_word(adapter.status),
        ));
    }
    out
}

fn finish(online: bool, ran_any: bool, adapters: Vec<AuditAdapter>) -> DepsAuditReport {
    let (uses_network, transmits_manifest, network_audit) = if !online {
        (false, false, NetworkAudit::NotRequested)
    } else if ran_any {
        (true, true, NetworkAudit::Ran)
    } else {
        (false, false, NetworkAudit::NotRun)
    };
    let clean = adapters
        .iter()
        .all(|adapter| adapter.status == CoverageStatus::Available);
    DepsAuditReport {
        installs_tools: false,
        uses_sudo: false,
        online,
        uses_network,
        transmits_manifest,
        network_audit,
        clean,
        adapters,
    }
}

fn probe_adapter(
    spec: &AdapterSpec,
    path: &OsStr,
    online: bool,
    workdir: &Path,
) -> (AuditAdapter, bool) {
    let Some(found) = find_candidate(path, spec) else {
        return (
            AuditAdapter {
                name: spec.name.to_string(),
                status: CoverageStatus::Unavailable,
                tool: None,
                detail: spec.missing.to_string(),
                summary: None,
            },
            false,
        );
    };
    if !online {
        return (
            AuditAdapter {
                name: spec.name.to_string(),
                status: CoverageStatus::Available,
                tool: Some(found.binary.to_string()),
                detail: NOT_REQUESTED.to_string(),
                summary: None,
            },
            false,
        );
    }
    match run_audit(&found.program, found.args, path, workdir) {
        Ok(output) => {
            let line = audit_line(&output.stdout).or_else(|| audit_line(&output.stderr));
            match line {
                Some(summary) => (
                    AuditAdapter {
                        name: spec.name.to_string(),
                        status: CoverageStatus::Available,
                        tool: Some(found.binary.to_string()),
                        detail: summary.clone(),
                        summary: Some(summary),
                    },
                    true,
                ),
                None => (
                    AuditAdapter {
                        name: spec.name.to_string(),
                        status: CoverageStatus::Unavailable,
                        tool: Some(found.binary.to_string()),
                        detail: format!("`{}` printed no audit line", found.binary),
                        summary: None,
                    },
                    true,
                ),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => (
            AuditAdapter {
                name: spec.name.to_string(),
                status: CoverageStatus::Unavailable,
                tool: Some(found.binary.to_string()),
                detail: format!("`{}` timed out", found.binary),
                summary: None,
            },
            true,
        ),
        Err(err) => (
            AuditAdapter {
                name: spec.name.to_string(),
                status: CoverageStatus::Unavailable,
                tool: Some(found.binary.to_string()),
                detail: bound_detail(&format!("`{}` failed: {err}", found.binary)),
                summary: None,
            },
            true,
        ),
    }
}

struct FoundTool {
    binary: &'static str,
    args: &'static [&'static str],
    program: PathBuf,
}

fn find_candidate(path: &OsStr, spec: &AdapterSpec) -> Option<FoundTool> {
    for candidate in spec.candidates {
        if let Some(program) = find_on_path(path, candidate.binary) {
            return Some(FoundTool {
                binary: candidate.binary,
                args: candidate.args,
                program,
            });
        }
    }
    None
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
    stdout: String,
    stderr: String,
}

fn run_audit(
    program: &Path,
    args: &[&str],
    path: &OsStr,
    workdir: &Path,
) -> std::io::Result<ToolOutput> {
    debug_assert!(
        !args.iter().any(|arg| {
            let lower = arg.to_ascii_lowercase();
            lower == "sudo" || lower == "install" || lower.contains("token")
        }),
        "audit args must not install, use sudo, or carry a token"
    );
    let mut child = Command::new(program)
        .args(args)
        .current_dir(workdir)
        .env("PATH", path)
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
        if let Some(_status) = child.try_wait()? {
            let stdout = stdout_handle.join().unwrap_or_default();
            let stderr = stderr_handle.join().unwrap_or_default();
            return Ok(ToolOutput { stdout, stderr });
        }
        if started.elapsed() > AUDIT_TIMEOUT {
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

fn audit_line(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|line| !line.is_empty())?;
    let redacted = redact_audit_text(line);
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

fn redact_audit_text(input: &str) -> String {
    scrub_token_prefixes(&redact_text(input))
}

fn scrub_token_prefixes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while !rest.is_empty() {
        if let Some((prefix, skip)) = token_at(rest) {
            out.push_str("[REDACTED]");
            rest = &rest[prefix.len() + skip..];
            continue;
        }
        let ch = rest.chars().next().expect("rest is non-empty");
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    out
}

fn token_at(input: &str) -> Option<(&'static str, usize)> {
    for prefix in TOKEN_PREFIXES {
        if let Some(body) = input.strip_prefix(prefix) {
            let skip = token_body_len(body);
            if skip >= 8 {
                return Some((prefix, skip));
            }
        }
    }
    None
}

fn token_body_len(body: &str) -> usize {
    body.chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .map(char::len_utf8)
        .sum()
}

fn bound_detail(text: &str) -> String {
    let redacted = redact_audit_text(text);
    let mut out: String = redacted.chars().take(160).collect();
    if redacted.chars().count() > 160 {
        out.push('…');
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

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn network_audit_word(audit: NetworkAudit) -> &'static str {
    match audit {
        NetworkAudit::NotRequested => "not requested",
        NetworkAudit::NotRun => "not run",
        NetworkAudit::Ran => "ran",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const SECRET: &str = "token=ghp_SuperSecretTokenValue ghp_BareTokenValue99";

    fn write_tool(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }

    fn marker_script() -> String {
        // Redirection stays inside the shell so a short PATH cannot launch a
        // real audit tool or another program.
        format!("#!/bin/sh\n: > ran-marker\nprintf '%s\\n' '{SECRET}'\n")
    }

    fn fill_primary(dir: &Path) {
        for name in ["cargo-audit", "pip-audit", "npm", "mvn"] {
            write_tool(dir, name, &marker_script());
        }
    }

    fn assert_secret_hidden(text: &str) {
        assert!(!text.contains("SuperSecret"), "{text}");
        assert!(!text.contains("BareToken"), "{text}");
        assert!(!text.contains("ghp_"), "{text}");
    }

    #[test]
    fn offline_missing_tools_are_unavailable_and_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        let report = scan_deps_audit(dir.path().as_os_str(), false, dir.path());
        assert!(!report.clean);
        assert!(!report.online);
        assert!(!report.uses_network);
        assert!(!report.transmits_manifest);
        assert!(!report.installs_tools);
        assert!(!report.uses_sudo);
        assert_eq!(report.network_audit, NetworkAudit::NotRequested);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.adapters.len(), 4);
        assert!(report
            .adapters
            .iter()
            .all(|adapter| adapter.status == CoverageStatus::Unavailable));
        assert!(report
            .adapters
            .iter()
            .all(|adapter| adapter.summary.is_none()));
        assert!(report
            .adapters
            .iter()
            .any(|adapter| adapter.detail.contains("not on PATH")));
        let human = format_deps_audit_human(&report);
        assert!(human.contains("network audit: not requested"));
        assert!(human.contains("uses network: no"));
        assert!(human.contains("transmits manifest: no"));
        assert!(human.contains("clean: no"));
        assert!(human.contains("installs tools: no"));
        assert!(human.contains("uses sudo: no"));
        assert!(!dir.path().join("ran-marker").exists());
    }

    #[test]
    fn offline_present_tools_do_not_run_and_are_clean() {
        let dir = tempfile::tempdir().unwrap();
        fill_primary(dir.path());
        std::fs::write(dir.path().join("Cargo.toml"), SECRET).unwrap();
        std::fs::write(dir.path().join("package.json"), SECRET).unwrap();
        let report = scan_deps_audit(dir.path().as_os_str(), false, dir.path());
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert_eq!(report.network_audit, NetworkAudit::NotRequested);
        assert!(!report.uses_network);
        assert!(!report.transmits_manifest);
        assert!(report.warnings().is_empty());
        for adapter in &report.adapters {
            assert_eq!(adapter.status, CoverageStatus::Available);
            assert_eq!(adapter.detail, NOT_REQUESTED);
            assert!(adapter.summary.is_none());
        }
        assert_eq!(
            report
                .adapters
                .iter()
                .find(|adapter| adapter.name == "python")
                .unwrap()
                .tool
                .as_deref(),
            Some("pip-audit")
        );
        assert!(!dir.path().join("ran-marker").exists());
        let human = format_deps_audit_human(&report);
        assert!(human.contains(NOT_REQUESTED));
        assert_secret_hidden(&human);
        assert_secret_hidden(&serde_json::to_string(&report).unwrap());
    }

    #[test]
    fn a_missing_adapter_is_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        fill_primary(dir.path());
        std::fs::remove_file(dir.path().join("cargo-audit")).unwrap();
        std::fs::remove_file(dir.path().join("npm")).unwrap();
        std::fs::create_dir(dir.path().join("npm")).unwrap();
        let report = scan_deps_audit(dir.path().as_os_str(), false, dir.path());
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let cargo = report
            .adapters
            .iter()
            .find(|adapter| adapter.name == "cargo-audit")
            .unwrap();
        assert_eq!(cargo.status, CoverageStatus::Unavailable);
        assert!(cargo.tool.is_none());
        let npm = report
            .adapters
            .iter()
            .find(|adapter| adapter.name == "npm")
            .unwrap();
        assert_eq!(npm.status, CoverageStatus::Unavailable);
        assert!(report.warnings().len() >= 2);
        assert!(!dir.path().join("ran-marker").exists());
    }

    #[test]
    fn python_and_maven_fall_back_to_the_second_tool() {
        let dir = tempfile::tempdir().unwrap();
        write_tool(dir.path(), "cargo-audit", &marker_script());
        write_tool(dir.path(), "safety", &marker_script());
        write_tool(dir.path(), "npm", &marker_script());
        write_tool(dir.path(), "gradle", &marker_script());
        let report = scan_deps_audit(dir.path().as_os_str(), false, dir.path());
        assert!(report.clean);
        assert_eq!(
            report
                .adapters
                .iter()
                .find(|adapter| adapter.name == "python")
                .unwrap()
                .tool
                .as_deref(),
            Some("safety")
        );
        assert_eq!(
            report
                .adapters
                .iter()
                .find(|adapter| adapter.name == "maven-gradle")
                .unwrap()
                .tool
                .as_deref(),
            Some("gradle")
        );
        assert!(!dir.path().join("ran-marker").exists());
    }

    #[test]
    fn online_runs_fixtures_and_hides_tokens() {
        let dir = tempfile::tempdir().unwrap();
        fill_primary(dir.path());
        std::fs::write(dir.path().join("package.json"), SECRET).unwrap();
        let report = scan_deps_audit(dir.path().as_os_str(), true, dir.path());
        assert!(report.clean, "{report:?}");
        assert!(report.online);
        assert!(report.uses_network);
        assert!(report.transmits_manifest);
        assert_eq!(report.network_audit, NetworkAudit::Ran);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(dir.path().join("ran-marker").exists());
        for adapter in &report.adapters {
            assert_eq!(adapter.status, CoverageStatus::Available);
            let summary = adapter.summary.as_deref().unwrap();
            assert!(summary.contains("[REDACTED]"), "{summary}");
            assert_secret_hidden(summary);
        }
        let human = format_deps_audit_human(&report);
        assert!(human.contains("network audit: ran"));
        assert!(human.contains("transmits manifest: yes"));
        assert_secret_hidden(&human);
        assert_secret_hidden(&serde_json::to_string(&report).unwrap());
    }

    #[test]
    fn online_with_no_tools_does_not_claim_a_network_run() {
        let dir = tempfile::tempdir().unwrap();
        let report = scan_deps_audit(dir.path().as_os_str(), true, dir.path());
        assert!(!report.clean);
        assert!(report.online);
        assert!(!report.uses_network);
        assert!(!report.transmits_manifest);
        assert_eq!(report.network_audit, NetworkAudit::NotRun);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert!(!dir.path().join("ran-marker").exists());
    }

    #[test]
    fn static_args_do_not_install_or_carry_a_token() {
        for spec in ADAPTERS {
            for candidate in spec.candidates {
                for arg in candidate.args {
                    let lower = arg.to_ascii_lowercase();
                    assert_ne!(lower, "sudo");
                    assert_ne!(lower, "install");
                    assert!(!lower.contains("token"));
                    assert!(!arg.contains("ghp_"));
                }
            }
        }
    }
}
