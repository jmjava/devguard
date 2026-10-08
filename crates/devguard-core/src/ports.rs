//! Local listening-socket inventory for `devguard health ports`.
//!
//! Reads `ss -lntup` on this machine. A missing `ss` is unavailable and the
//! result is not clean. A listening row with no process name stays in the
//! inventory with attribution missing; that is not a closed port. The command
//! does not bind a port, contact a remote host, or keep command arguments.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

const SS_TIMEOUT: Duration = Duration::from_secs(5);
const SS_LIMIT: usize = 256 * 1024;

/// `available` or `unavailable`. A missing `ss` is never a clean result.
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

/// Whether `ss` printed a process name for a listening row.
///
/// `Missing` means the socket is still listening and the process name was not
/// in the row. It does not mean the port is closed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    Present,
    Missing,
}

/// One listening socket. `process` is the comm name only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenSocket {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub process: Option<String>,
    pub attribution: Attribution,
}

/// Human and JSON body for `devguard health ports`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortsReport {
    /// Always false. This command never binds a socket.
    pub opens_port: bool,
    /// Always false. This command never contacts another host.
    pub scans_remote: bool,
    /// Always false. Process names only; command arguments are dropped.
    pub collects_arguments: bool,
    /// False when `ss` is missing or any listening row lacks a process name.
    pub clean: bool,
    pub ss: SourceCoverage,
    pub sockets: Vec<ListenSocket>,
    /// Listening rows whose address or port could not be parsed.
    pub unparsed_rows: u32,
}

impl PortsReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.ss.status == CoverageStatus::Unavailable {
            warnings.push(format!("ss unavailable: {}", self.ss.detail));
        }
        let missing = self
            .sockets
            .iter()
            .filter(|socket| socket.attribution == Attribution::Missing)
            .count();
        if missing > 0 {
            warnings.push(format!(
                "{missing} listening socket(s) have attribution missing"
            ));
        }
        if self.unparsed_rows > 0 {
            warnings.push(format!(
                "{} listening row(s) could not be parsed",
                self.unparsed_rows
            ));
        }
        warnings
    }
}

/// Read this host once. A missing `ss` stays unavailable.
///
/// `DEVGUARD_SS_BIN`, when set, must be an absolute path to the `ss` program.
/// Tests use that override so they can parse a fixture listing.
pub fn scan_ports() -> PortsReport {
    match locate_ss() {
        SsBin::Found(path) => scan_program(&path),
        SsBin::Missing(detail) => unavailable_report(detail),
    }
}

/// Inventory produced from an `ss -lntup` listing. The tool is treated as present.
pub fn report_from_listing(text: &str) -> PortsReport {
    let parsed = parse_listing(text);
    finish(
        SourceCoverage {
            status: CoverageStatus::Available,
            detail: format!("ss returned {} listening socket(s)", parsed.sockets.len()),
        },
        parsed.sockets,
        parsed.unparsed,
    )
}

/// Inventory when `ss` cannot be run. The result is unavailable and not clean.
pub fn unavailable_report(detail: impl Into<String>) -> PortsReport {
    finish(
        SourceCoverage {
            status: CoverageStatus::Unavailable,
            detail: detail.into(),
        },
        Vec::new(),
        0,
    )
}

pub fn format_ports_human(report: &PortsReport) -> String {
    let ss = match report.ss.status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    };
    let mut out = format!(
        "\
DevGuard health ports
  opens a port: no
  scans a remote host: no
  collects command arguments: no
  ss: {ss} ({detail})
  clean: {clean}
",
        detail = report.ss.detail,
        clean = if report.clean { "yes" } else { "no" },
    );
    if report.ss.status == CoverageStatus::Unavailable {
        out.push_str("\nss is unavailable. The inventory is not clean. No port was opened.\n");
        return out;
    }
    if report.sockets.is_empty() {
        out.push_str("\nNo listening sockets.\n");
    } else {
        out.push_str("\nListening sockets\n");
        for socket in &report.sockets {
            match (&socket.attribution, &socket.process) {
                (Attribution::Present, Some(name)) => {
                    out.push_str(&format!(
                        "- {} {}:{} {}\n",
                        socket.protocol, socket.address, socket.port, name
                    ));
                }
                _ => {
                    out.push_str(&format!(
                        "- {} {}:{} attribution missing\n",
                        socket.protocol, socket.address, socket.port
                    ));
                }
            }
        }
    }
    if report.unparsed_rows > 0 {
        out.push_str(&format!(
            "\n{} listening row(s) could not be parsed.\n",
            report.unparsed_rows
        ));
    }
    out
}

fn finish(ss: SourceCoverage, sockets: Vec<ListenSocket>, unparsed: u32) -> PortsReport {
    let attributed = sockets
        .iter()
        .all(|socket| socket.attribution == Attribution::Present);
    let clean = ss.status == CoverageStatus::Available && unparsed == 0 && attributed;
    PortsReport {
        opens_port: false,
        scans_remote: false,
        collects_arguments: false,
        clean,
        ss,
        sockets,
        unparsed_rows: unparsed,
    }
}

struct ParsedListing {
    sockets: Vec<ListenSocket>,
    unparsed: u32,
}

/// Parse an `ss -lntup` listing. Established rows are ignored.
pub fn parse_listening(text: &str) -> Vec<ListenSocket> {
    parse_listing(text).sockets
}

fn parse_listing(text: &str) -> ParsedListing {
    let mut sockets = Vec::new();
    let mut unparsed = 0;
    for line in text.lines() {
        match parse_line(line) {
            LineParse::Socket(socket) => sockets.push(socket),
            LineParse::Unparsed => unparsed += 1,
            LineParse::Skip => {}
        }
    }
    ParsedListing { sockets, unparsed }
}

enum LineParse {
    Socket(ListenSocket),
    Unparsed,
    Skip,
}

fn parse_line(line: &str) -> LineParse {
    let line = line.trim();
    if line.is_empty() || line.starts_with("Netid") || line.starts_with("State ") {
        return LineParse::Skip;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return LineParse::Skip;
    }
    let (protocol, state, local_index) = if is_protocol(parts[0]) {
        if parts.len() < 5 {
            return LineParse::Unparsed;
        }
        (parts[0], parts[1], 4)
    } else if is_listening_state(parts[0]) {
        if parts.len() < 4 {
            return LineParse::Unparsed;
        }
        let protocol = if parts[0] == "LISTEN" { "tcp" } else { "udp" };
        (protocol, parts[0], 3)
    } else {
        return LineParse::Skip;
    };
    if !is_listening_state(state) {
        return LineParse::Skip;
    }
    let local = strip_users(parts[local_index]);
    let Some((address, port)) = split_address_port(local) else {
        return LineParse::Unparsed;
    };
    let process = process_name(line);
    let attribution = if process.is_some() {
        Attribution::Present
    } else {
        Attribution::Missing
    };
    LineParse::Socket(ListenSocket {
        protocol: protocol.to_string(),
        address,
        port,
        process,
        attribution,
    })
}

fn is_protocol(token: &str) -> bool {
    matches!(token, "tcp" | "tcp6" | "udp" | "udp6")
}

fn is_listening_state(token: &str) -> bool {
    matches!(token, "LISTEN" | "UNCONN")
}

fn strip_users(token: &str) -> &str {
    token.split("users:").next().unwrap_or(token)
}

fn split_address_port(token: &str) -> Option<(String, u16)> {
    if let Some(rest) = token.strip_prefix('[') {
        let (address, port) = rest.rsplit_once("]:")?;
        if address.is_empty() {
            return None;
        }
        let port = port.parse().ok()?;
        return Some((address.to_string(), port));
    }
    let (address, port) = token.rsplit_once(':')?;
    if address.is_empty() {
        return None;
    }
    let port = port.parse().ok()?;
    Some((address.to_string(), port))
}

/// First quoted comm in `users:(("name",pid=…))`. Flags and later words are dropped.
fn process_name(line: &str) -> Option<String> {
    let start = line.find("((\"")?;
    let after = &line[start + 3..];
    let end = after.find('"')?;
    let quoted = &after[..end];
    let first = quoted.split_whitespace().next()?;
    let base = first.rsplit('/').next().unwrap_or(first);
    if base.is_empty() || base.starts_with('-') || base.contains('=') || base.len() > 64 {
        return None;
    }
    Some(base.to_string())
}

enum SsBin {
    Found(PathBuf),
    Missing(String),
}

fn locate_ss() -> SsBin {
    if let Ok(value) = std::env::var("DEVGUARD_SS_BIN") {
        if value.is_empty() {
            return SsBin::Missing("ss is not on PATH".into());
        }
        let path = PathBuf::from(&value);
        if !path.is_absolute() {
            return SsBin::Missing("DEVGUARD_SS_BIN must be an absolute path".into());
        }
        if !path.is_file() {
            return SsBin::Missing("ss is not available".into());
        }
        return SsBin::Found(path);
    }
    match find_on_path("ss") {
        Some(path) => SsBin::Found(path),
        None => SsBin::Missing("ss is not on PATH".into()),
    }
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

fn scan_program(program: &Path) -> PortsReport {
    if !program.is_file() {
        return unavailable_report("ss is not available");
    }
    match capture_ss(program) {
        Ok(text) => report_from_listing(&text),
        Err(detail) => unavailable_report(detail),
    }
}

fn capture_ss(program: &Path) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(["-lntup", "-H"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                "ss is not available".to_string()
            } else {
                format!("ss failed to start: {err}")
            }
        })?;
    let stdout = child.stdout.take();
    let reader = thread::spawn(move || read_bounded(stdout, SS_LIMIT));
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let collected = reader
                    .join()
                    .unwrap_or_else(|_| Err("ss reader stopped".into()))?;
                if !status.success() {
                    return Err(format!("ss exited {}", status.code().unwrap_or(-1)));
                }
                return Ok(collected);
            }
            Ok(None) => {
                if started.elapsed() > SS_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err("ss timed out".into());
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(format!("ss failed: {err}"));
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
                Ok(_) => return Err("ss output exceeded the capture limit".into()),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(format!("ss read failed: {err}")),
            }
        }
        let room = limit - out.len();
        let want = room.min(buf.len());
        match pipe.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(format!("ss read failed: {err}")),
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../fixtures/ss-lntup.txt");

    #[test]
    fn fixture_parses_protocol_address_port_and_process_name() {
        let report = report_from_listing(FIXTURE);
        assert!(!report.opens_port);
        assert!(!report.scans_remote);
        assert!(!report.collects_arguments);
        assert_eq!(report.ss.status, CoverageStatus::Available);
        assert_eq!(report.unparsed_rows, 0);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);

        let sockets = &report.sockets;
        assert_eq!(sockets.len(), 10);
        assert_eq!(
            sockets[0],
            ListenSocket {
                protocol: "tcp".into(),
                address: "0.0.0.0".into(),
                port: 22,
                process: Some("sshd".into()),
                attribution: Attribution::Present,
            }
        );
        assert_eq!(sockets[1].port, 631);
        assert_eq!(sockets[1].address, "127.0.0.1");
        assert_eq!(sockets[1].attribution, Attribution::Missing);
        assert!(sockets[1].process.is_none());
        assert_eq!(sockets[2].address, "::");
        assert_eq!(sockets[2].port, 443);
        assert_eq!(sockets[2].process.as_deref(), Some("nginx"));
        assert_eq!(sockets[3].address, "::1");
        assert_eq!(sockets[3].process.as_deref(), Some("cupsd"));
        assert_eq!(sockets[4].protocol, "udp");
        assert_eq!(sockets[4].port, 68);
        assert_eq!(sockets[4].process.as_deref(), Some("systemd-network"));
        assert_eq!(sockets[5].address, "127.0.0.53%lo");
        assert_eq!(sockets[5].port, 53);
        assert_eq!(sockets[6].address, "*");
        assert_eq!(sockets[6].port, 9090);
        assert_eq!(sockets[6].attribution, Attribution::Missing);
        assert_eq!(sockets[7].address, "10.0.0.5");
        assert_eq!(sockets[7].process.as_deref(), Some("sshd"));
        assert_eq!(sockets[8].process.as_deref(), Some("python"));
        assert_eq!(sockets[9].protocol, "udp");
        assert_eq!(sockets[9].port, 3702);
        assert_eq!(sockets[9].process.as_deref(), Some("wsdd"));
    }

    #[test]
    fn fixture_drops_command_arguments_remote_peers_and_pids() {
        let report = report_from_listing(FIXTURE);
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains("http.server"));
        assert!(!json.contains("--bind"));
        assert!(!json.contains("pid="));
        assert!(!json.contains("203.0.113.10"));
        assert!(!json.contains("curl"));
        assert!(!json.contains("40000"));
        for socket in &report.sockets {
            if let Some(name) = &socket.process {
                assert!(!name.contains(' '), "{name}");
                assert!(!name.starts_with('-'), "{name}");
            }
        }
    }

    #[test]
    fn missing_attribution_stays_listening() {
        let report = report_from_listing(FIXTURE);
        let missing: Vec<_> = report
            .sockets
            .iter()
            .filter(|socket| socket.attribution == Attribution::Missing)
            .collect();
        assert_eq!(missing.len(), 2);
        assert!(missing.iter().any(|socket| socket.port == 631));
        assert!(missing.iter().any(|socket| socket.port == 9090));
        let human = format_ports_human(&report);
        assert!(human.contains("127.0.0.1:631 attribution missing"));
        assert!(human.contains("*:9090 attribution missing"));
        assert!(!human.contains("port closed"));
        assert!(report
            .warnings()
            .iter()
            .any(|warning| { warning.contains("attribution missing") }));
    }

    #[test]
    fn missing_ss_is_unavailable_and_not_clean() {
        let report = unavailable_report("ss is not on PATH");
        assert_eq!(report.ss.status, CoverageStatus::Unavailable);
        assert!(!report.clean);
        assert!(report.sockets.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert!(!report.opens_port);
        assert!(!report.scans_remote);
        let human = format_ports_human(&report);
        assert!(human.contains("ss: unavailable"));
        assert!(human.contains("clean: no"));
        assert!(human.contains("not clean"));
        assert!(!human.contains("No listening sockets"));
    }

    #[test]
    fn empty_listing_is_clean() {
        let report = report_from_listing(
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n",
        );
        assert!(report.clean);
        assert!(report.sockets.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert_eq!(report.ss.status, CoverageStatus::Available);
    }

    #[test]
    fn fully_attributed_listing_is_clean() {
        let listing = "\
tcp LISTEN 0 128 127.0.0.1:9 0.0.0.0:* users:((\"named\",pid=1,fd=2))
udp UNCONN 0 0 127.0.0.1:9 0.0.0.0:* users:((\"/usr/sbin/named\",pid=1,fd=3))
";
        let report = report_from_listing(listing);
        assert!(report.clean);
        assert_eq!(report.sockets.len(), 2);
        assert_eq!(report.sockets[1].process.as_deref(), Some("named"));
        assert!(report.warnings().is_empty());
    }

    #[test]
    fn unparsed_listening_row_is_not_clean() {
        let listing = "tcp LISTEN 0 128 not-an-address\n";
        let report = report_from_listing(listing);
        assert!(!report.clean);
        assert_eq!(report.unparsed_rows, 1);
        assert!(report.sockets.is_empty());
    }

    #[test]
    fn legacy_headerless_row_without_netid() {
        let listing = "LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n";
        let sockets = parse_listening(listing);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].protocol, "tcp");
        assert_eq!(sockets[0].port, 22);
        assert_eq!(sockets[0].process.as_deref(), Some("sshd"));
    }

    #[test]
    fn missing_program_does_not_read_live_ports() {
        let report = scan_program(Path::new("/no/such/devguard-ss"));
        assert_eq!(report.ss.status, CoverageStatus::Unavailable);
        assert!(!report.clean);
        assert!(report.sockets.is_empty());
        assert!(report.ss.detail.contains("not available"));
    }

    #[test]
    fn fixture_script_is_parsed_without_live_ports() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("ss");
        std::fs::write(
            &program,
            "#!/bin/sh\ncat <<'EOF'\ntcp LISTEN 0 128 127.0.0.1:9 0.0.0.0:* users:((\"fixture\",pid=4,fd=1))\ntcp LISTEN 0 128 127.0.0.1:10 0.0.0.0:*\nEOF\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&program).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&program, perms).unwrap();

        let report = scan_program(&program);
        assert_eq!(report.sockets.len(), 2);
        assert_eq!(report.sockets[0].process.as_deref(), Some("fixture"));
        assert_eq!(report.sockets[0].port, 9);
        assert_eq!(report.sockets[1].attribution, Attribution::Missing);
        assert_eq!(report.sockets[1].port, 10);
        assert!(!report.clean);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("pid="));
    }
}
