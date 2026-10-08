//! SSH login history and failed auth attempts for `devguard security ssh-auth`.
//!
//! Login rows come from `last`. Failed auth rows come from `journalctl -t sshd`
//! and the auth log, where each source is readable. The report keeps counts,
//! timestamps, and source addresses only. It does not copy credentials,
//! passwords, private keys, usernames, or the log line itself.
//!
//! A missing `last`, a missing journal, or an unreadable auth log is
//! `unavailable`, and that result is not clean. The command does not use sudo,
//! start or stop sshd, or change sshd config.
//!
//! Tests parse fixtures through [`report_from_texts`] and [`report_from_files`].
//! They do not read the host journal.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::redact::redact_text;

const TOOL_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_LIMIT: usize = 256 * 1024;
const MAX_EVENTS: usize = 200;
const DEFAULT_AUTH_LOG: &str = "/var/log/auth.log";

/// `last -F -i -n 200`. Read-only. No sudo.
const LAST_ARGS: &[&str] = &["-F", "-i", "-n", "200"];
/// One bounded `journalctl` read of the sshd identifier. No follow, no sudo.
const JOURNAL_ARGS: &[&str] = &["--no-pager", "-n", "200", "-o", "short-iso", "-t", "sshd"];

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `available` or `unavailable`. A missing source is never a clean result.
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

/// One login or failed-auth row. A field is present only when the source line
/// already had that value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshAuthEvent {
    pub timestamp: Option<String>,
    pub source_address: Option<String>,
}

/// Human and JSON body for `devguard security ssh-auth`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshAuthReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never starts sshd.
    pub starts_sshd: bool,
    /// Always false. This command never stops sshd.
    pub stops_sshd: bool,
    /// Always false. This command never writes sshd config.
    pub changes_sshd_config: bool,
    /// Always false. Credentials, passwords, and private keys are not copied.
    pub copies_credentials: bool,
    /// Always false. Full journal and log lines are not copied.
    pub copies_journal: bool,
    /// False when `last`, the journal, or the auth log is unavailable.
    pub clean: bool,
    pub last: SourceCoverage,
    pub journal: SourceCoverage,
    pub auth_log: SourceCoverage,
    pub login_count: u32,
    pub failure_count: u32,
    pub logins: Vec<SshAuthEvent>,
    pub failures: Vec<SshAuthEvent>,
}

impl SshAuthReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.last.status == CoverageStatus::Unavailable {
            warnings.push(format!("last unavailable: {}", self.last.detail));
        }
        if self.journal.status == CoverageStatus::Unavailable {
            warnings.push(format!("journal unavailable: {}", self.journal.detail));
        }
        if self.auth_log.status == CoverageStatus::Unavailable {
            warnings.push(format!("auth log unavailable: {}", self.auth_log.detail));
        }
        warnings
    }
}

/// Read this host once.
///
/// `DEVGUARD_LAST_FILE` reads a fixture instead of `last`.
/// `DEVGUARD_JOURNAL_FILE` reads a fixture instead of `journalctl`.
/// `DEVGUARD_AUTH_LOG` selects the auth log path.
/// `DEVGUARD_LAST_BIN` and `DEVGUARD_JOURNALCTL_BIN`, when set, must be
/// absolute paths. An empty override is unavailable and does not fall through
/// to the host.
pub fn scan_ssh_auth() -> SshAuthReport {
    let last = load_last();
    let journal = load_journal();
    let auth_log = load_auth_log();
    assemble(last, journal, auth_log)
}

/// Parse fixture texts. `None` is an unavailable source and is not clean.
///
/// This function does not open the host journal, run `last`, or run `journalctl`.
pub fn report_from_texts(
    last: Option<&str>,
    journal: Option<&str>,
    auth_log: Option<&str>,
) -> SshAuthReport {
    assemble(
        loaded_text(last, "last is not available"),
        loaded_text(journal, "journal is not available"),
        loaded_text(auth_log, "auth log is unreadable"),
    )
}

/// Read only the three given paths. A missing or unreadable path is unavailable.
///
/// This function does not run `last` or `journalctl` and does not open the host
/// journal unless that journal path was passed in.
pub fn report_from_files(last: &Path, journal: &Path, auth_log: &Path) -> SshAuthReport {
    assemble(
        read_path(last, "last is not available"),
        read_path(journal, "journal is not available"),
        read_path(auth_log, "auth log is unreadable"),
    )
}

pub fn format_ssh_auth_human(report: &SshAuthReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard security ssh-auth\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  starts sshd: no\n");
    out.push_str("  stops sshd: no\n");
    out.push_str("  changes sshd config: no\n");
    out.push_str("  copies credentials: no\n");
    out.push_str("  copies journal payloads: no\n");
    push_source(&mut out, "last", &report.last);
    push_source(&mut out, "journal", &report.journal);
    push_source(&mut out, "auth log", &report.auth_log);
    out.push_str(&format!("  login count: {}\n", report.login_count));
    out.push_str(&format!("  failure count: {}\n", report.failure_count));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    out.push_str("\nLogins\n");
    push_events(
        &mut out,
        &report.logins,
        report.last.status == CoverageStatus::Available,
    );
    out.push_str("\nFailed auth\n");
    let failures_known = report.journal.status == CoverageStatus::Available
        || report.auth_log.status == CoverageStatus::Available;
    push_events(&mut out, &report.failures, failures_known);
    out
}

fn push_source(out: &mut String, label: &str, source: &SourceCoverage) {
    out.push_str(&format!(
        "  {label}: {} — {}\n",
        status_word(source.status),
        source.detail
    ));
}

fn push_events(out: &mut String, events: &[SshAuthEvent], known: bool) {
    if !known {
        out.push_str("  unavailable\n");
        return;
    }
    if events.is_empty() {
        out.push_str("  none\n");
        return;
    }
    for event in events {
        match (&event.timestamp, &event.source_address) {
            (Some(timestamp), Some(address)) => {
                out.push_str(&format!("- {timestamp}  {address}\n"));
            }
            (Some(timestamp), None) => out.push_str(&format!("- {timestamp}\n")),
            (None, Some(address)) => out.push_str(&format!("- {address}\n")),
            (None, None) => {}
        }
    }
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

struct Loaded {
    text: Option<String>,
    unavailable_detail: &'static str,
}

fn loaded_text(text: Option<&str>, unavailable_detail: &'static str) -> Loaded {
    Loaded {
        text: text.map(str::to_string),
        unavailable_detail,
    }
}

fn assemble(last: Loaded, journal: Loaded, auth_log: Loaded) -> SshAuthReport {
    let (last_coverage, logins, login_count) = login_source(&last);
    let (journal_coverage, journal_failures) = failure_source(&journal, "journal");
    let (auth_coverage, auth_failures) = failure_source(&auth_log, "auth log");
    let failures = merge_failures(journal_failures, auth_failures);
    let failure_count = u32::try_from(failures.len()).unwrap_or(u32::MAX);
    let mut failures = failures;
    if failures.len() > MAX_EVENTS {
        failures.truncate(MAX_EVENTS);
    }
    let mut logins = logins;
    if logins.len() > MAX_EVENTS {
        logins.truncate(MAX_EVENTS);
    }
    let clean = last_coverage.status == CoverageStatus::Available
        && journal_coverage.status == CoverageStatus::Available
        && auth_coverage.status == CoverageStatus::Available;
    SshAuthReport {
        uses_sudo: false,
        starts_sshd: false,
        stops_sshd: false,
        changes_sshd_config: false,
        copies_credentials: false,
        copies_journal: false,
        clean,
        last: last_coverage,
        journal: journal_coverage,
        auth_log: auth_coverage,
        login_count,
        failure_count,
        logins,
        failures,
    }
}

fn login_source(loaded: &Loaded) -> (SourceCoverage, Vec<SshAuthEvent>, u32) {
    let Some(text) = loaded.text.as_deref() else {
        return (unavailable(loaded.unavailable_detail), Vec::new(), 0);
    };
    let logins = parse_last(text);
    let count = u32::try_from(logins.len()).unwrap_or(u32::MAX);
    (
        SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("last returned {count} login(s)"),
        },
        logins,
        count,
    )
}

fn failure_source(loaded: &Loaded, label: &str) -> (SourceCoverage, Vec<SshAuthEvent>) {
    let Some(text) = loaded.text.as_deref() else {
        return (unavailable(loaded.unavailable_detail), Vec::new());
    };
    let events = parse_failures(text);
    let count = events.len();
    (
        SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("{label} returned {count} failed auth event(s)"),
        },
        events,
    )
}

fn unavailable(detail: &str) -> SourceCoverage {
    SourceCoverage {
        status: CoverageStatus::Unavailable,
        detail: detail.to_string(),
    }
}

fn merge_failures(journal: Vec<SshAuthEvent>, auth_log: Vec<SshAuthEvent>) -> Vec<SshAuthEvent> {
    let mut seen = BTreeSet::new();
    let mut merged = Vec::with_capacity(journal.len() + auth_log.len());
    for event in journal {
        if let Some(key) = dedupe_key(&event) {
            seen.insert(key);
        }
        merged.push(event);
    }
    for event in auth_log {
        if let Some(key) = dedupe_key(&event) {
            if !seen.insert(key) {
                continue;
            }
        }
        merged.push(event);
    }
    merged
}

fn dedupe_key(event: &SshAuthEvent) -> Option<(String, String)> {
    let address = event.source_address.clone().unwrap_or_default();
    let clock = event.timestamp.as_deref().map(clock_of).unwrap_or_default();
    if address.is_empty() && clock.is_empty() {
        None
    } else {
        Some((address, clock))
    }
}

fn parse_last(text: &str) -> Vec<SshAuthEvent> {
    let mut events = Vec::new();
    for line in text.lines() {
        if !is_last_login(line) {
            continue;
        }
        events.push(event_from_line(line));
    }
    events
}

fn parse_failures(text: &str) -> Vec<SshAuthEvent> {
    let mut events = Vec::new();
    for line in text.lines() {
        if is_ssh_failure(line) {
            events.push(event_from_line(line));
        }
    }
    events
}

fn is_last_login(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.contains("system boot") || line.contains(" begins") {
        return false;
    }
    let mut tokens = line.split_whitespace();
    let Some(first) = tokens.next() else {
        return false;
    };
    if matches!(first, "reboot" | "shutdown" | "wtmp" | "btmp") {
        return false;
    }
    let Some(tty) = tokens.next() else {
        return false;
    };
    tty.starts_with("pts/")
}

fn is_ssh_failure(line: &str) -> bool {
    if !line.contains("sshd") {
        return false;
    }
    let lower = line.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "failed password",
        "failed publickey",
        "failed keyboard-interactive",
        "invalid user",
        "authentication failure",
        "maximum authentication attempts exceeded",
        "connection closed by authenticating user",
        "disconnected from authenticating user",
    ];
    MARKERS.iter().any(|marker| lower.contains(marker))
}

fn event_from_line(line: &str) -> SshAuthEvent {
    SshAuthEvent {
        timestamp: keep_field(timestamp_in(line)),
        source_address: keep_field(source_address(line)),
    }
}

fn keep_field(value: Option<String>) -> Option<String> {
    let value = value?;
    let redacted = redact_text(&value);
    if redacted.contains("[REDACTED]") || looks_like_secret(&redacted) {
        return Some("[REDACTED]".to_string());
    }
    Some(redacted)
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("private key")
        || lower.contains("begin openssh")
        || lower.contains("begin rsa")
        || lower.contains("password=")
        || lower.contains("token=")
        || lower.contains("secret=")
}

fn timestamp_in(line: &str) -> Option<String> {
    if let Some(value) = iso_timestamp(line) {
        return Some(value);
    }
    if let Some(value) = weekday_timestamp(line) {
        return Some(value);
    }
    syslog_timestamp(line)
}

fn iso_timestamp(line: &str) -> Option<String> {
    let token = line.split_whitespace().next()?;
    let bytes = token.as_bytes();
    if bytes.len() < 19 || !is_iso_head(&token[..19]) {
        return None;
    }
    let tail_ok = token[19..]
        .chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, '-' | '+' | ':' | 'Z' | 'z'));
    if tail_ok {
        Some(token.to_string())
    } else {
        Some(token[..19].to_string())
    }
}

fn is_iso_head(head: &str) -> bool {
    let bytes = head.as_bytes();
    bytes.len() == 19
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && head[..4].chars().all(|ch| ch.is_ascii_digit())
        && head[5..7].chars().all(|ch| ch.is_ascii_digit())
        && head[8..10].chars().all(|ch| ch.is_ascii_digit())
        && is_clock(&head[11..])
}

fn weekday_timestamp(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    for window in tokens.windows(5) {
        if WEEKDAYS.contains(&window[0])
            && MONTHS.contains(&window[1])
            && is_day_number(window[2])
            && is_clock(window[3])
            && is_year(window[4])
        {
            return Some(format!(
                "{} {} {} {} {}",
                window[0], window[1], window[2], window[3], window[4]
            ));
        }
    }
    None
}

fn syslog_timestamp(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() >= 3
        && MONTHS.contains(&tokens[0])
        && is_day_number(tokens[1])
        && is_clock(tokens[2])
    {
        return Some(format!("{} {} {}", tokens[0], tokens[1], tokens[2]));
    }
    None
}

fn source_address(line: &str) -> Option<String> {
    for token in line.split_whitespace() {
        if let Some(address) = address_token(token) {
            return Some(address);
        }
    }
    None
}

fn address_token(token: &str) -> Option<String> {
    let trimmed =
        token.trim_matches(|ch: char| matches!(ch, ',' | ';' | '"' | '\'' | '[' | ']' | '(' | ')'));
    let trimmed = trimmed.strip_prefix("rhost=").unwrap_or(trimmed);
    if is_ipv4(trimmed) {
        return Some(trimmed.to_string());
    }
    if trimmed.parse::<Ipv6Addr>().is_ok() && !is_clock(trimmed) {
        return Some(trimmed.to_string());
    }
    None
}

fn is_ipv4(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|part| {
        if part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()) {
            return false;
        }
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
        part.parse::<u8>().is_ok()
    })
}

fn is_day_number(token: &str) -> bool {
    if token.is_empty() || token.len() > 2 || !token.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    matches!(token.parse::<u32>(), Ok(day) if (1..=31).contains(&day))
}

fn is_year(token: &str) -> bool {
    token.len() == 4 && token.chars().all(|ch| ch.is_ascii_digit())
}

fn is_clock(token: &str) -> bool {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 {
        return false;
    }
    matches_bound(parts[0], 23) && matches_bound(parts[1], 59) && matches_bound(parts[2], 59)
}

fn matches_bound(text: &str, max: u32) -> bool {
    if text.len() != 2 || !text.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    matches!(text.parse::<u32>(), Ok(value) if value <= max)
}

fn clock_of(timestamp: &str) -> String {
    let bytes = timestamp.as_bytes();
    let mut index = 0;
    while index + 8 <= bytes.len() {
        if is_clock(&timestamp[index..index + 8]) {
            return timestamp[index..index + 8].to_string();
        }
        index += 1;
    }
    String::new()
}

enum EnvPath {
    Unset,
    Empty,
    Set(PathBuf),
}

fn env_path(key: &str) -> EnvPath {
    match std::env::var(key) {
        Ok(value) if value.is_empty() => EnvPath::Empty,
        Ok(value) => EnvPath::Set(PathBuf::from(value)),
        Err(_) => EnvPath::Unset,
    }
}

fn load_last() -> Loaded {
    match env_path("DEVGUARD_LAST_FILE") {
        EnvPath::Empty => Loaded {
            text: None,
            unavailable_detail: "last is not available",
        },
        EnvPath::Set(path) => read_path(&path, "last is not available"),
        EnvPath::Unset => load_tool(
            "DEVGUARD_LAST_BIN",
            "last",
            LAST_ARGS,
            "last is not available",
        ),
    }
}

fn load_journal() -> Loaded {
    match env_path("DEVGUARD_JOURNAL_FILE") {
        EnvPath::Empty => Loaded {
            text: None,
            unavailable_detail: "journal is not available",
        },
        EnvPath::Set(path) => read_path(&path, "journal is not available"),
        EnvPath::Unset => load_tool(
            "DEVGUARD_JOURNALCTL_BIN",
            "journalctl",
            JOURNAL_ARGS,
            "journal is not available",
        ),
    }
}

fn load_auth_log() -> Loaded {
    match env_path("DEVGUARD_AUTH_LOG") {
        EnvPath::Empty => Loaded {
            text: None,
            unavailable_detail: "auth log is unreadable",
        },
        EnvPath::Set(path) => read_path(&path, "auth log is unreadable"),
        EnvPath::Unset => read_path(Path::new(DEFAULT_AUTH_LOG), "auth log is unreadable"),
    }
}

fn load_tool(env_key: &str, program: &str, args: &[&str], missing: &'static str) -> Loaded {
    match resolve_bin(env_override(env_key), program) {
        Ok(path) => match capture_tool(&path, args) {
            Ok(text) => Loaded {
                text: Some(text),
                unavailable_detail: missing,
            },
            Err(_) => Loaded {
                text: None,
                unavailable_detail: missing,
            },
        },
        Err(detail) => Loaded {
            text: None,
            unavailable_detail: detail,
        },
    }
}

fn env_override(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn resolve_bin(override_value: Option<String>, program: &str) -> Result<PathBuf, &'static str> {
    if let Some(value) = override_value {
        if value.is_empty() || !Path::new(&value).is_absolute() || !Path::new(&value).is_file() {
            return Err(match program {
                "last" => "last is not available",
                _ => "journal is not available",
            });
        }
        return Ok(PathBuf::from(value));
    }
    find_on_path(program).ok_or(match program {
        "last" => "last is not available",
        _ => "journal is not available",
    })
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
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

fn read_path(path: &Path, missing: &'static str) -> Loaded {
    match read_tail(path) {
        Ok(text) => Loaded {
            text: Some(text),
            unavailable_detail: missing,
        },
        Err(_) => Loaded {
            text: None,
            unavailable_detail: missing,
        },
    }
}

fn read_tail(path: &Path) -> Result<String, ()> {
    let mut file = std::fs::File::open(path).map_err(|_| ())?;
    let len = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if len > CAPTURE_LIMIT as u64 {
        file.seek(SeekFrom::End(-(CAPTURE_LIMIT as i64)))
            .map_err(|_| ())?;
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|_| ())?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if len > CAPTURE_LIMIT as u64 {
        text = match text.split_once('\n') {
            Some((_, rest)) => rest.to_string(),
            None => text,
        };
    }
    Ok(text)
}

fn capture_tool(program: &Path, args: &[&str]) -> Result<String, String> {
    if !program.is_file() {
        return Err("tool is not available".into());
    }
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "tool is not available".to_string())?;
    let stdout = child.stdout.take();
    let reader = thread::spawn(move || read_bounded(stdout, CAPTURE_LIMIT));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let collected = reader
                    .join()
                    .unwrap_or_else(|_| Err("tool reader stopped".into()))?;
                if !status.success() {
                    return Err("tool is not available".into());
                }
                return Ok(collected);
            }
            Ok(None) => {
                if started.elapsed() > TOOL_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err("tool timed out".into());
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err("tool is not available".into());
            }
        }
    }
}

fn read_bounded(pipe: Option<impl Read>, limit: usize) -> Result<String, String> {
    let Some(mut pipe) = pipe else {
        return Ok(String::new());
    };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if out.len() >= limit {
            let mut extra = [0u8; 1];
            match pipe.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err("tool output exceeded the capture limit".into()),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("tool read failed".into()),
            }
        }
        let room = limit - out.len();
        let want = room.min(buf.len());
        match pipe.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("tool read failed".into()),
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAST: &str = include_str!("../fixtures/last.txt");
    const JOURNAL: &str = include_str!("../fixtures/journal-ssh.txt");
    const AUTH: &str = include_str!("../fixtures/auth-ssh.log");

    const SECRET_NEEDLES: &[&str] = &[
        "hunter2",
        "sudo-secret",
        "BEGIN OPENSSH",
        "PRIVATE KEY",
        "b3BlbnNzaC1rZXkBAAAA",
        "SHA256:",
        "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
        "password",
        "publickey",
        "keyboard-interactive",
    ];
    const USERNAMES: &[&str] = &["alice", "bob", "carol", "dave", "eve", "admin", "guest"];

    fn assert_redacted(text: &str) {
        let lower = text.to_ascii_lowercase();
        for needle in SECRET_NEEDLES {
            assert!(
                !lower.contains(&needle.to_ascii_lowercase()),
                "{needle} leaked in {text}"
            );
        }
        for name in USERNAMES {
            let leaked = lower
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .any(|token| token == *name);
            assert!(!leaked, "{name} leaked in {text}");
        }
    }

    #[test]
    fn fixture_reports_counts_timestamps_and_addresses() {
        let report = report_from_texts(Some(LAST), Some(JOURNAL), Some(AUTH));
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(!report.uses_sudo);
        assert!(!report.starts_sshd);
        assert!(!report.stops_sshd);
        assert!(!report.changes_sshd_config);
        assert!(!report.copies_credentials);
        assert!(!report.copies_journal);
        assert_eq!(report.last.status, CoverageStatus::Available);
        assert_eq!(report.journal.status, CoverageStatus::Available);
        assert_eq!(report.auth_log.status, CoverageStatus::Available);
        assert!(report.warnings().is_empty());

        assert_eq!(report.login_count, 5);
        assert_eq!(report.logins.len(), 5);
        assert_eq!(
            report.logins[0].timestamp.as_deref(),
            Some("Wed Oct 7 21:01:02 2026")
        );
        assert_eq!(
            report.logins[0].source_address.as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(
            report.logins[1].source_address.as_deref(),
            Some("198.51.100.4")
        );
        assert_eq!(
            report.logins[2].timestamp.as_deref(),
            Some("Sun Oct 4 12:30:00 2026")
        );
        assert!(report.logins[2].source_address.is_none());
        assert_eq!(
            report.logins[3].source_address.as_deref(),
            Some("203.0.113.50")
        );
        assert_eq!(
            report.logins[4].source_address.as_deref(),
            Some("2001:db8::10")
        );

        assert_eq!(report.failure_count, 5);
        assert_eq!(report.failures.len(), 5);
        assert_eq!(
            report.failures[0].timestamp.as_deref(),
            Some("2026-10-07T21:02:03-0400")
        );
        assert_eq!(
            report.failures[0].source_address.as_deref(),
            Some("203.0.113.10")
        );
        assert_eq!(
            report.failures[1].source_address.as_deref(),
            Some("198.51.100.4")
        );
        assert_eq!(
            report.failures[2].timestamp.as_deref(),
            Some("2026-10-07T21:02:06-0400")
        );
        assert_eq!(
            report.failures[3].timestamp.as_deref(),
            Some("Oct 7 21:03:10")
        );
        assert_eq!(
            report.failures[3].source_address.as_deref(),
            Some("192.0.2.15")
        );
        assert_eq!(
            report.failures[4].source_address.as_deref(),
            Some("192.0.2.8")
        );
        assert!(report.journal.detail.contains("3 failed auth event(s)"));
        assert!(report.auth_log.detail.contains("3 failed auth event(s)"));

        let json = serde_json::to_string(&report).expect("json");
        let human = format_ssh_auth_human(&report);
        assert_redacted(&json);
        assert_redacted(&human);
        assert!(human.contains("clean: yes"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("203.0.113.10"));
        assert!(human.contains("2001:db8::10"));
        assert!(!json.contains("sshd["));
        assert!(!json.contains("pts/"));
    }

    #[test]
    fn missing_journal_is_unavailable_and_not_clean() {
        let report = report_from_texts(Some(LAST), None, Some(AUTH));
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.journal.status, CoverageStatus::Unavailable);
        assert_eq!(report.journal.detail, "journal is not available");
        assert_eq!(report.last.status, CoverageStatus::Available);
        assert_eq!(report.auth_log.status, CoverageStatus::Available);
        assert_eq!(report.login_count, 5);
        assert_eq!(report.failure_count, 3);
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("journal unavailable")));
        let human = format_ssh_auth_human(&report);
        assert!(human.contains("journal: unavailable"));
        assert!(human.contains("clean: no"));
        assert_redacted(&human);
    }

    #[test]
    fn missing_last_and_unreadable_auth_log_are_not_clean() {
        let report = report_from_texts(None, Some(JOURNAL), None);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.last.status, CoverageStatus::Unavailable);
        assert_eq!(report.last.detail, "last is not available");
        assert_eq!(report.auth_log.status, CoverageStatus::Unavailable);
        assert_eq!(report.auth_log.detail, "auth log is unreadable");
        assert_eq!(report.journal.status, CoverageStatus::Available);
        assert_eq!(report.login_count, 0);
        assert!(report.logins.is_empty());
        assert_eq!(report.failure_count, 3);
        let human = format_ssh_auth_human(&report);
        assert!(human.contains("Logins\n  unavailable\n"));
        assert!(human.contains("Failed auth\n- 2026-10-07T21:02:03-0400"));
        assert_redacted(&serde_json::to_string(&report).expect("json"));
    }

    #[test]
    fn empty_sources_are_available_and_clean() {
        let report = report_from_texts(Some(""), Some(""), Some(""));
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert_eq!(report.login_count, 0);
        assert_eq!(report.failure_count, 0);
        assert!(report.logins.is_empty());
        assert!(report.failures.is_empty());
        let human = format_ssh_auth_human(&report);
        assert!(human.contains("Logins\n  none\n"));
        assert!(human.contains("Failed auth\n  none\n"));
    }

    #[test]
    fn accepted_logins_and_sudo_lines_are_not_failures() {
        let journal = "\
2026-10-07T21:05:00-0400 host sshd[9]: Accepted password for alice from 203.0.113.9 port 22 ssh2
2026-10-07T21:05:01-0400 host sudo: authentication failure password=hunter2
";
        let report = report_from_texts(Some(""), Some(journal), Some(""));
        assert_eq!(report.failure_count, 0);
        assert!(report.failures.is_empty());
        assert_redacted(&serde_json::to_string(&report).expect("json"));
    }

    #[test]
    fn failure_markers_keep_the_address_and_drop_the_line() {
        let journal = "\
2026-10-07T21:05:00-0400 host sshd[9]: Failed keyboard-interactive for alice from 192.0.2.20 port 22 ssh2
2026-10-07T21:05:01-0400 host sshd[9]: maximum authentication attempts exceeded for invalid user root from 192.0.2.21 port 22 ssh2 [preauth]
2026-10-07T21:05:02-0400 host sshd[9]: Disconnected from authenticating user alice 192.0.2.22 port 22 [preauth]
";
        let report = report_from_texts(Some(""), Some(journal), Some(""));
        assert!(report.clean);
        assert_eq!(report.failure_count, 3);
        assert_eq!(
            report.failures[0].source_address.as_deref(),
            Some("192.0.2.20")
        );
        assert_eq!(
            report.failures[1].source_address.as_deref(),
            Some("192.0.2.21")
        );
        assert_eq!(
            report.failures[2].source_address.as_deref(),
            Some("192.0.2.22")
        );
        assert!(report.failures[2].timestamp.is_some());
        let json = serde_json::to_string(&report).expect("json");
        assert_redacted(&json);
        assert!(!json.contains("root"));
    }

    #[test]
    fn missing_files_are_unavailable_and_do_not_read_a_journal() {
        let report = report_from_files(
            Path::new("/no/such/devguard-last"),
            Path::new("/no/such/devguard-journal"),
            Path::new("/no/such/devguard-auth.log"),
        );
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.last.status, CoverageStatus::Unavailable);
        assert_eq!(report.journal.status, CoverageStatus::Unavailable);
        assert_eq!(report.auth_log.status, CoverageStatus::Unavailable);
        assert_eq!(report.login_count, 0);
        assert_eq!(report.failure_count, 0);
        assert!(!report.uses_sudo);
    }

    #[test]
    fn fixture_files_parse_without_the_host_journal() {
        let dir = tempfile::tempdir().unwrap();
        let last = dir.path().join("last.txt");
        let journal = dir.path().join("journal.txt");
        let auth = dir.path().join("auth.log");
        std::fs::write(&last, LAST).unwrap();
        std::fs::write(&journal, JOURNAL).unwrap();
        std::fs::write(&auth, AUTH).unwrap();
        let report = report_from_files(&last, &journal, &auth);
        assert!(report.clean);
        assert_eq!(report.login_count, 5);
        assert_eq!(report.failure_count, 5);
        assert_redacted(&serde_json::to_string(&report).expect("json"));
    }

    #[test]
    fn fixture_program_is_parsed_without_the_host_journal() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("last");
        std::fs::write(
            &program,
            "#!/bin/sh\nprintf '%s\\n' 'zoe pts/9 203.0.113.77 Wed Oct 7 01:02:03 2026 - down (00:01)'\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&program).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&program, perms).unwrap();

        let text = capture_tool(&program, LAST_ARGS).expect("fixture last");
        let report = report_from_texts(Some(&text), Some(""), Some(""));
        assert_eq!(report.login_count, 1);
        assert_eq!(
            report.logins[0].source_address.as_deref(),
            Some("203.0.113.77")
        );
        assert_eq!(
            report.logins[0].timestamp.as_deref(),
            Some("Wed Oct 7 01:02:03 2026")
        );
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains("zoe"));
        assert!(!text.contains("BEGIN OPENSSH"));
    }

    #[test]
    fn missing_program_does_not_invent_logins() {
        let err = capture_tool(Path::new("/no/such/devguard-last"), LAST_ARGS);
        assert!(err.is_err());
    }

    #[test]
    fn tool_args_do_not_use_sudo_or_change_sshd() {
        for arg in LAST_ARGS.iter().chain(JOURNAL_ARGS.iter()) {
            assert_ne!(*arg, "sudo");
            assert!(!arg.contains("start"));
            assert!(!arg.contains("stop"));
            assert!(!arg.contains("sshd_config"));
            assert!(!arg.contains("systemctl"));
        }
        assert!(JOURNAL_ARGS.contains(&"--no-pager"));
        assert!(!JOURNAL_ARGS.contains(&"-f"));
    }
}
