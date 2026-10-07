//! Allowlisted helpers for a downstairs WSL GPU host.
//!
//! The commands stay off until local config names an SSH host and user. Those
//! values are never printed and must not be committed.
//!
//! Allowlist:
//! - host up or down
//! - tunnel up or down
//! - Ollama tags, read with HTTP `/api/tags` through the local forward
//! - a fixed `nvidia-smi` GPU sample
//! - a fixed `devguard health fan` sample, when the remote has that command
//!
//! The tunnel is `ssh -N -L 127.0.0.1:local:127.0.0.1:remote`. It is not a
//! remote shell, a file upload, a firewall change, a public tunnel, a bind on
//! all interfaces, or a resident daemon. The operator opens it and closes it.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::redact::redact_text;

/// Actions this module is allowed to perform. Anything else is refused.
pub const ALLOWLIST: &[&str] = &[
    "host up or down",
    "tunnel up or down",
    "ollama tags",
    "gpu sample",
    "fan sample",
];

const SSH_CONNECT_TIMEOUT_SECS: u64 = 8;
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_WAIT: Duration = Duration::from_secs(10);

const GPU_ARGV: &[&str] = &[
    "nvidia-smi",
    "--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total",
    "--format=csv,noheader",
];

const FAN_ARGV: &[&str] = &["devguard", "health", "fan", "--json"];

/// SSH target loaded from local config. Fields stay private so callers cannot
/// retarget the forward at `0.0.0.0` or splice a shell command.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteTarget {
    host: String,
    user: String,
    port: u16,
    local_port: u16,
    remote_port: u16,
}

impl std::fmt::Debug for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RemoteTarget { redacted }")
    }
}

impl RemoteTarget {
    /// Build a target from config fields. Host and user are checked so they
    /// cannot carry shell syntax. Ports must be non-zero. `0.0.0.0` is refused.
    pub fn new(
        host: &str,
        user: &str,
        port: u16,
        local_port: u16,
        remote_port: u16,
    ) -> Result<Self, String> {
        let host = host.trim();
        let user = user.trim();
        if !valid_host(host) {
            return Err(
                "remote.host must be a hostname or IPv4 address without a wildcard bind".into(),
            );
        }
        if !valid_user(user) {
            return Err("remote.user must be a short account name without shell characters".into());
        }
        if port == 0 || local_port == 0 || remote_port == 0 {
            return Err("remote ports must be between 1 and 65535".into());
        }
        Ok(Self {
            host: host.to_string(),
            user: user.to_string(),
            port,
            local_port,
            remote_port,
        })
    }

    /// `127.0.0.1:local:127.0.0.1:remote`. Never `0.0.0.0`.
    pub fn forward_spec(&self) -> String {
        format!(
            "127.0.0.1:{}:127.0.0.1:{}",
            self.local_port, self.remote_port
        )
    }

    /// Remove host, user, and SSH port from text that might be shown.
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.to_string();
        let pair = format!("{}@{}", self.user, self.host);
        out = out.replace(&pair, "[user]@[host]");
        if self.host.len() >= 2 {
            out = out.replace(&self.host, "[host]");
        }
        if self.user.len() >= 2 {
            out = out.replace(&self.user, "[user]");
        }
        out = scrub_port(&out, self.port);
        redact_text(&out)
    }

    fn local_port(&self) -> u16 {
        self.local_port
    }
}

fn valid_host(host: &str) -> bool {
    let len = host.len();
    if !(2..=253).contains(&len) {
        return false;
    }
    if host == "0.0.0.0" || host == "*" {
        return false;
    }
    let ok_chars = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    ok_chars && !host.starts_with(['-', '.']) && !host.ends_with(['-', '.']) && !host.contains("..")
}

fn valid_user(user: &str) -> bool {
    let len = user.len();
    if !(1..=32).contains(&len) {
        return false;
    }
    let ok_chars = user
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.');
    ok_chars && !user.starts_with('-')
}

fn scrub_port(text: &str, port: u16) -> String {
    let token = port.to_string();
    let mut out = String::new();
    let mut rest = text;
    while let Some(index) = rest.find(&token) {
        let before_ok = index == 0 || !rest.as_bytes()[index - 1].is_ascii_digit();
        let after = index + token.len();
        let after_ok = after >= rest.len() || !rest.as_bytes()[after].is_ascii_digit();
        if before_ok && after_ok {
            out.push_str(&rest[..index]);
            out.push_str("[port]");
            rest = &rest[after..];
        } else {
            let end = index + 1;
            out.push_str(&rest[..end]);
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out
}

/// One allowlisted sample. `unavailable` is never reported as a clean success.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSample {
    pub state: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl RemoteSample {
    fn skipped(detail: impl Into<String>) -> Self {
        Self {
            state: "skipped".into(),
            detail: detail.into(),
            value: None,
        }
    }

    fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            state: "unavailable".into(),
            detail: detail.into(),
            value: None,
        }
    }

    fn ok(detail: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            state: "ok".into(),
            detail: detail.into(),
            value: Some(value.into()),
        }
    }
}

/// Reachability report. Host, user, and SSH port are not fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteStatusReport {
    pub target: String,
    pub host: String,
    pub host_detail: String,
    pub tunnel: String,
    pub tunnel_detail: String,
    pub tags: RemoteSample,
    pub gpu: RemoteSample,
    pub fan: RemoteSample,
    pub allowlist: Vec<String>,
    pub binds_all_interfaces: bool,
    pub public_tunnel: bool,
    pub arbitrary_exec: bool,
    pub resident_daemon: bool,
}

/// Result of opening or closing the Ollama local-forward.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelReport {
    pub tunnel: String,
    pub detail: String,
    pub forward: String,
    pub binds_all_interfaces: bool,
    pub public_tunnel: bool,
    pub arbitrary_exec: bool,
    pub resident_daemon: bool,
}

#[derive(Debug)]
pub struct RemoteError {
    message: String,
}

impl RemoteError {
    fn message(text: String) -> Self {
        Self { message: text }
    }
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RemoteError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshClass {
    Down,
    Refused,
}

/// Classify an SSH failure. Network failures are host down. Anything else
/// is a refused session, which is not reported as success.
fn classify_ssh_failure(stderr: &str) -> SshClass {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("no route to host")
        || lower.contains("network is unreachable")
        || lower.contains("connection timed out")
        || lower.contains("operation timed out")
        || lower.contains("timed out")
        || lower.contains("name or service not known")
        || lower.contains("temporary failure in name resolution")
        || lower.contains("could not resolve")
        || lower.contains("connection refused")
    {
        SshClass::Down
    } else {
        SshClass::Refused
    }
}

fn down_phrase(stderr: &str) -> &'static str {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("connection refused") {
        "connection refused"
    } else if lower.contains("timed out") {
        "connection timed out"
    } else if lower.contains("not known")
        || lower.contains("name resolution")
        || lower.contains("could not resolve")
    {
        "name resolution failed"
    } else {
        "no route to host"
    }
}

fn refused_phrase(stderr: &str) -> &'static str {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("host key") {
        "host key verification failed"
    } else if lower.contains("permission denied") || lower.contains("authentication") {
        "ssh authentication failed"
    } else {
        "ssh session failed"
    }
}

/// Human text for `devguard remote status`. Does not include the SSH target.
pub fn format_remote_status(report: &RemoteStatusReport) -> String {
    format!(
        "\
DevGuard remote
  target: {target}
  host: {host}
  host detail: {host_detail}
  tunnel: {tunnel}
  tunnel detail: {tunnel_detail}
  ollama tags: {tags}
  gpu: {gpu}
  fan: {fan}
",
        target = report.target,
        host = report.host,
        host_detail = report.host_detail,
        tunnel = report.tunnel,
        tunnel_detail = report.tunnel_detail,
        tags = format_sample(&report.tags),
        gpu = format_sample(&report.gpu),
        fan = format_sample(&report.fan),
    )
}

fn format_sample(sample: &RemoteSample) -> String {
    match sample.value.as_deref() {
        Some(value) if !value.is_empty() => format!("{} ({}) {value}", sample.state, sample.detail),
        _ => format!("{} ({})", sample.state, sample.detail),
    }
}

pub fn format_tunnel(report: &TunnelReport) -> String {
    format!(
        "\
DevGuard remote tunnel
  tunnel: {tunnel}
  forward: {forward}
  detail: {detail}
",
        tunnel = report.tunnel,
        forward = report.forward,
        detail = report.detail,
    )
}

fn flags() -> (bool, bool, bool, bool) {
    (false, false, false, false)
}

fn allowlist_owned() -> Vec<String> {
    ALLOWLIST.iter().map(|item| (*item).to_string()).collect()
}

/// Report reachability. A missing target is off, not a fake host-up.
/// Host down is a completed report. A refused SSH session is an error.
pub fn collect_status(
    target: Option<&RemoteTarget>,
    ssh_bin: &Path,
    state_dir: &Path,
) -> Result<RemoteStatusReport, RemoteError> {
    let (binds_all_interfaces, public_tunnel, arbitrary_exec, resident_daemon) = flags();
    let Some(target) = target else {
        return Ok(RemoteStatusReport {
            target: "off".into(),
            host: "unconfigured".into(),
            host_detail: "remote target is not configured".into(),
            tunnel: "down".into(),
            tunnel_detail: "remote target is not configured".into(),
            tags: RemoteSample::skipped("remote target is not configured"),
            gpu: RemoteSample::skipped("remote target is not configured"),
            fan: RemoteSample::skipped("remote target is not configured"),
            allowlist: allowlist_owned(),
            binds_all_interfaces,
            public_tunnel,
            arbitrary_exec,
            resident_daemon,
        });
    };

    let probe = run_ssh(ssh_bin, &probe_args(target), Duration::from_secs(10))?;
    if !probe.success {
        match classify_ssh_failure(&probe.stderr) {
            SshClass::Down => {
                let phrase = down_phrase(&probe.stderr);
                return Ok(status_shell(
                    target,
                    ssh_bin,
                    state_dir,
                    "down",
                    safe_detail(target, &probe.stderr, phrase),
                    "host down",
                    false,
                ));
            }
            SshClass::Refused => {
                let phrase = refused_phrase(&probe.stderr);
                return Err(RemoteError::message(safe_detail(
                    target,
                    &probe.stderr,
                    phrase,
                )));
            }
        }
    }

    Ok(status_shell(
        target,
        ssh_bin,
        state_dir,
        "up",
        "ssh session accepted".into(),
        "tunnel is down",
        true,
    ))
}

fn status_shell(
    target: &RemoteTarget,
    ssh_bin: &Path,
    state_dir: &Path,
    host: &str,
    host_detail: String,
    blocked_reason: &str,
    host_up: bool,
) -> RemoteStatusReport {
    let (binds_all_interfaces, public_tunnel, arbitrary_exec, resident_daemon) = flags();
    let tunnel = observe_tunnel(target, ssh_bin, state_dir);
    let (tunnel_state, tunnel_detail, tunnel_up) = match tunnel {
        TunnelObs::Up { .. } => (
            "up".to_string(),
            "ollama local-forward open".to_string(),
            true,
        ),
        TunnelObs::Down => ("down".to_string(), blocked_reason.to_string(), false),
        TunnelObs::Blocked { detail } => ("down".to_string(), detail, false),
    };
    let (tags, gpu, fan) = if !host_up {
        let reason = "host down";
        (
            RemoteSample::unavailable(reason),
            RemoteSample::unavailable(reason),
            RemoteSample::unavailable(reason),
        )
    } else if !tunnel_up {
        let reason = "tunnel is down";
        (
            RemoteSample::unavailable(reason),
            RemoteSample::unavailable(reason),
            RemoteSample::unavailable(reason),
        )
    } else {
        (
            sample_tags(target),
            sample_ssh(target, ssh_bin, GPU_ARGV, "gpu sample"),
            sample_ssh(target, ssh_bin, FAN_ARGV, "fan sample"),
        )
    };
    RemoteStatusReport {
        target: "configured".into(),
        host: host.into(),
        host_detail,
        tunnel: tunnel_state,
        tunnel_detail,
        tags,
        gpu,
        fan,
        allowlist: allowlist_owned(),
        binds_all_interfaces,
        public_tunnel,
        arbitrary_exec,
        resident_daemon,
    }
}

fn sample_tags(target: &RemoteTarget) -> RemoteSample {
    match fetch_ollama_tags(target.local_port()) {
        Ok(names) if names.is_empty() => RemoteSample::ok("no tags", ""),
        Ok(names) => RemoteSample::ok("ollama /api/tags", names.join(", ")),
        Err(detail) => RemoteSample::unavailable(detail),
    }
}

fn sample_ssh(target: &RemoteTarget, ssh_bin: &Path, argv: &[&str], label: &str) -> RemoteSample {
    let args = exec_args(target, argv);
    match run_ssh(ssh_bin, &args, SAMPLE_TIMEOUT) {
        Ok(output) if output.success => {
            let value = one_line(&target.scrub(&output.stdout));
            if value.is_empty() || value.contains(&target.host) {
                RemoteSample::unavailable(format!("{label} unavailable"))
            } else {
                RemoteSample::ok(label, clip(&value, 400))
            }
        }
        Ok(output) => RemoteSample::unavailable(safe_detail(
            target,
            &output.stderr,
            &format!("{label} unavailable"),
        )),
        Err(err) => {
            let detail = target.scrub(&err.to_string());
            if detail.contains(&target.host) {
                RemoteSample::unavailable(format!("{label} unavailable"))
            } else {
                RemoteSample::unavailable(detail)
            }
        }
    }
}

/// Open the Ollama local-forward. Returns an error when the host is down or
/// the forward does not bind `127.0.0.1`. Does not install a service.
pub fn tunnel_up(
    target: &RemoteTarget,
    ssh_bin: &Path,
    state_dir: &Path,
) -> Result<TunnelReport, RemoteError> {
    ensure_forward_allowed(target)?;
    fs::create_dir_all(state_dir)
        .map_err(|err| RemoteError::message(format!("failed to create tunnel state dir: {err}")))?;
    match observe_tunnel(target, ssh_bin, state_dir) {
        TunnelObs::Up { .. } => {
            return Ok(tunnel_report(
                "up",
                "ollama local-forward already open",
                target,
            ));
        }
        TunnelObs::Blocked { detail } => return Err(RemoteError::message(detail)),
        TunnelObs::Down => {}
    }

    let log_path = tunnel_log_path(state_dir);
    let log = open_private(&log_path)?;
    let args = tunnel_args(target);
    reject_forbidden(&args)?;
    let mut child = Command::new(ssh_bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .map_err(|err| RemoteError::message(format!("failed to start ssh: {err}")))?;

    let started = Instant::now();
    loop {
        if process_listens_loopback(child.id(), target.local_port()) {
            write_pid_file(state_dir, child.id(), &target.forward_spec())?;
            return Ok(tunnel_report("up", "ollama local-forward open", target));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let stderr = fs::read_to_string(&log_path).unwrap_or_default();
                let _ = fs::remove_file(&log_path);
                let _ = fs::remove_file(pid_path(state_dir));
                if !status.success() && classify_ssh_failure(&stderr) == SshClass::Down {
                    return Err(RemoteError::message(safe_detail(
                        target,
                        &stderr,
                        &format!("host down: {}", down_phrase(&stderr)),
                    )));
                }
                return Err(RemoteError::message(safe_detail(
                    target,
                    &stderr,
                    "ssh session failed",
                )));
            }
            Ok(None) => {}
            Err(err) => {
                stop_child(&mut child);
                return Err(RemoteError::message(format!(
                    "failed to wait for ssh: {err}"
                )));
            }
        }
        if started.elapsed() > TUNNEL_WAIT {
            stop_child(&mut child);
            let _ = fs::remove_file(&log_path);
            return Err(RemoteError::message("tunnel did not bind 127.0.0.1".into()));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Close only the local-forward this tool opened. Refuses to signal any
/// other process.
pub fn tunnel_down(
    target: &RemoteTarget,
    ssh_bin: &Path,
    state_dir: &Path,
) -> Result<TunnelReport, RemoteError> {
    match observe_tunnel(target, ssh_bin, state_dir) {
        TunnelObs::Down => {
            let _ = fs::remove_file(pid_path(state_dir));
            let _ = fs::remove_file(tunnel_log_path(state_dir));
            Ok(tunnel_report("down", "ollama local-forward closed", target))
        }
        TunnelObs::Blocked { detail } => Err(RemoteError::message(detail)),
        TunnelObs::Up { pid } => {
            signal_pid(pid)?;
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(2) {
                if !pid_alive(pid) {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            if pid_alive(pid) {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = fs::remove_file(pid_path(state_dir));
            let _ = fs::remove_file(tunnel_log_path(state_dir));
            Ok(tunnel_report("down", "ollama local-forward closed", target))
        }
    }
}

fn tunnel_report(state: &str, detail: &str, target: &RemoteTarget) -> TunnelReport {
    let (binds_all_interfaces, public_tunnel, arbitrary_exec, resident_daemon) = flags();
    TunnelReport {
        tunnel: state.into(),
        detail: detail.into(),
        forward: format!(
            "127.0.0.1:{} -> 127.0.0.1:{}",
            target.local_port, target.remote_port
        ),
        binds_all_interfaces,
        public_tunnel,
        arbitrary_exec,
        resident_daemon,
    }
}

fn ensure_forward_allowed(target: &RemoteTarget) -> Result<(), RemoteError> {
    let spec = target.forward_spec();
    if !spec.starts_with("127.0.0.1:") || !spec.contains(":127.0.0.1:") || spec.contains("0.0.0.0")
    {
        return Err(RemoteError::message(
            "refused forward that is not 127.0.0.1".into(),
        ));
    }
    Ok(())
}

enum TunnelObs {
    Up { pid: u32 },
    Down,
    Blocked { detail: String },
}

fn observe_tunnel(target: &RemoteTarget, ssh_bin: &Path, state_dir: &Path) -> TunnelObs {
    let path = pid_path(state_dir);
    if !path.exists() {
        return TunnelObs::Down;
    }
    if fs::symlink_metadata(&path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(true)
    {
        return TunnelObs::Blocked {
            detail: "refusing to follow tunnel state symlink".into(),
        };
    }
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => {
            return TunnelObs::Blocked {
                detail: "tunnel state is unreadable".into(),
            };
        }
    };
    let record: TunnelPid = match serde_json::from_str(&raw) {
        Ok(record) => record,
        Err(_) => {
            return TunnelObs::Blocked {
                detail: "tunnel state is unreadable".into(),
            };
        }
    };
    if record.forward != target.forward_spec() {
        return TunnelObs::Blocked {
            detail: "refusing to signal a process that is not the allowlisted forward".into(),
        };
    }
    if !pid_alive(record.pid) {
        return TunnelObs::Down;
    }
    match read_cmdline(record.pid) {
        Some(cmd) if cmdline_is_ours(&cmd, ssh_bin, &record.forward) => {
            TunnelObs::Up { pid: record.pid }
        }
        Some(_) => TunnelObs::Blocked {
            detail: "refusing to signal a process that is not the allowlisted forward".into(),
        },
        None => TunnelObs::Down,
    }
}

fn cmdline_is_ours(cmd: &[String], ssh_bin: &Path, forward: &str) -> bool {
    if cmd.is_empty() || forward.contains("0.0.0.0") {
        return false;
    }
    if cmd
        .iter()
        .any(|arg| arg == "-R" || arg == "-D" || arg.contains("0.0.0.0"))
    {
        return false;
    }
    let Some(bin_name) = ssh_bin.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if bin_name.is_empty() {
        return false;
    }
    let mentions_bin = cmd.iter().any(|arg| {
        arg == bin_name
            || Path::new(arg).file_name().and_then(|name| name.to_str()) == Some(bin_name)
    });
    let has_forward = cmd.iter().any(|arg| arg == forward);
    let has_n = cmd.iter().any(|arg| arg == "-N");
    let has_gateway = cmd.iter().any(|arg| arg == "GatewayPorts=no");
    mentions_bin && has_forward && has_n && has_gateway
}

#[derive(Debug, Serialize, Deserialize)]
struct TunnelPid {
    pid: u32,
    forward: String,
}

fn pid_path(state_dir: &Path) -> PathBuf {
    state_dir.join("remote-tunnel.json")
}

fn tunnel_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("remote-tunnel.log")
}

fn write_pid_file(state_dir: &Path, pid: u32, forward: &str) -> Result<(), RemoteError> {
    let path = pid_path(state_dir);
    if path
        .symlink_metadata()
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(RemoteError::message(
            "refusing to follow tunnel state symlink".into(),
        ));
    }
    let body = serde_json::to_vec(&TunnelPid {
        pid,
        forward: forward.to_string(),
    })
    .map_err(|err| RemoteError::message(format!("failed to encode tunnel state: {err}")))?;
    open_private_write(&path, &body)
}

fn open_private(path: &Path) -> Result<std::fs::File, RemoteError> {
    if path
        .symlink_metadata()
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(RemoteError::message(
            "refusing to follow tunnel log symlink".into(),
        ));
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| RemoteError::message(format!("failed to open tunnel state: {err}")))
}

fn open_private_write(path: &Path, bytes: &[u8]) -> Result<(), RemoteError> {
    let mut file = open_private(path)?;
    file.write_all(bytes)
        .map_err(|err| RemoteError::message(format!("failed to write tunnel state: {err}")))?;
    Ok(())
}

fn probe_args(target: &RemoteTarget) -> Vec<String> {
    let mut args = ssh_prefix(target, false);
    args.push("--".into());
    args.push("true".into());
    args
}

fn exec_args(target: &RemoteTarget, command: &[&str]) -> Vec<String> {
    let mut args = ssh_prefix(target, false);
    args.push("--".into());
    args.extend(command.iter().map(|part| (*part).to_string()));
    args
}

pub fn tunnel_args(target: &RemoteTarget) -> Vec<String> {
    ssh_prefix(target, true)
}

fn ssh_prefix(target: &RemoteTarget, tunnel: bool) -> Vec<String> {
    let mut args = vec!["-F".into(), "/dev/null".into(), "-T".into()];
    if tunnel {
        args.push("-N".into());
    }
    args.extend([
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECS}"),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        "GatewayPorts=no".into(),
        "-o".into(),
        "ForwardAgent=no".into(),
        "-o".into(),
        "ForwardX11=no".into(),
        "-o".into(),
        "PermitLocalCommand=no".into(),
    ]);
    if tunnel {
        args.extend([
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            "-L".into(),
            target.forward_spec(),
        ]);
    }
    args.extend([
        "-p".into(),
        target.port.to_string(),
        "-l".into(),
        target.user.clone(),
        target.host.clone(),
    ]);
    args
}

fn reject_forbidden(args: &[String]) -> Result<(), RemoteError> {
    if args.iter().any(|arg| {
        arg == "-R"
            || arg == "-D"
            || arg.contains("0.0.0.0")
            || arg.contains("GatewayPorts=yes")
            || arg.contains("ProxyCommand")
    }) {
        return Err(RemoteError::message(
            "refused a tunnel that is not the Ollama local-forward".into(),
        ));
    }
    Ok(())
}

struct SshOutput {
    success: bool,
    stderr: String,
    stdout: String,
}

fn run_ssh(ssh_bin: &Path, args: &[String], timeout: Duration) -> Result<SshOutput, RemoteError> {
    reject_forbidden(args)?;
    let mut child = Command::new(ssh_bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| RemoteError::message(format!("failed to start ssh: {err}")))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| RemoteError::message("ssh stdout was not piped".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| RemoteError::message("ssh stderr was not piped".into()))?;
    let stdout_handle = thread::spawn(move || read_capped(&mut stdout, 65_536));
    let stderr_handle = thread::spawn(move || read_capped(&mut stderr, 65_536));
    let status = wait_child(&mut child, timeout)?;
    let stdout = join_reader(stdout_handle)?;
    let stderr = join_reader(stderr_handle)?;
    Ok(SshOutput {
        success: status,
        stdout,
        stderr,
    })
}

fn join_reader(handle: thread::JoinHandle<std::io::Result<String>>) -> Result<String, RemoteError> {
    match handle.join() {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(err)) => Err(RemoteError::message(format!(
            "failed to read ssh output: {err}"
        ))),
        Err(_) => Err(RemoteError::message("ssh output reader failed".into())),
    }
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<bool, RemoteError> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if started.elapsed() > timeout => {
                stop_child(child);
                return Err(RemoteError::message("ssh timed out".into()));
            }
            Ok(None) => thread::sleep(Duration::from_millis(30)),
            Err(err) => {
                return Err(RemoteError::message(format!(
                    "failed to wait for ssh: {err}"
                )))
            }
        }
    }
}

fn stop_child(child: &mut Child) {
    let pid = child.id();
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn read_capped(reader: &mut impl Read, cap: usize) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if buf.len() >= cap {
            break;
        }
        let max = (cap - buf.len()).min(chunk.len());
        match reader.read(&mut chunk[..max]) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn safe_detail(target: &RemoteTarget, stderr: &str, fixed: &str) -> String {
    let scrubbed = one_line(&target.scrub(stderr));
    if scrubbed.is_empty()
        || scrubbed.contains(&target.host)
        || (target.user.len() >= 2 && scrubbed.contains(&target.user))
    {
        return fixed.to_string();
    }
    format!("{fixed}: {}", clip(&scrubbed, 160))
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn clip(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        text.chars().take(max_chars).collect()
    }
}

/// GET `http://127.0.0.1:{port}/api/tags`. The address is not configurable.
pub fn fetch_ollama_tags(port: u16) -> Result<Vec<String>, String> {
    if port == 0 {
        return Err("ollama tags unavailable".into());
    }
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|_| "ollama tags unavailable".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "ollama tags unavailable".to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "ollama tags unavailable".to_string())?;
    stream
        .write_all(b"GET /api/tags HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .map_err(|_| "ollama tags unavailable".to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if buf.len() >= 262_144 {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return Err("ollama tags unavailable".into());
            }
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                return Err("ollama tags unavailable".into());
            }
            Err(_) => return Err("ollama tags unavailable".into()),
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let Some((_, body)) = text.split_once("\r\n\r\n") else {
        return Err("ollama tags unavailable".into());
    };
    let status_line = text.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        return Err("ollama tags unavailable".into());
    }
    parse_tags(body)
}

fn parse_tags(body: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "ollama tags unavailable".to_string())?;
    let models = value
        .get("models")
        .and_then(|item| item.as_array())
        .ok_or_else(|| "ollama tags unavailable".to_string())?;
    let mut names = Vec::new();
    for model in models.iter().take(32) {
        let Some(name) = model.get("name").and_then(|item| item.as_str()) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 80 {
            continue;
        }
        if name.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
            continue;
        }
        names.push(name.to_string());
    }
    Ok(names)
}

fn process_listens_loopback(pid: u32, port: u16) -> bool {
    let token = format!("0100007F:{port:04X}");
    let inodes = socket_inodes(pid);
    if inodes.is_empty() {
        return false;
    }
    tcp_table_has(Path::new("/proc/net/tcp"), &token, &inodes)
}

fn socket_inodes(pid: u32) -> Vec<String> {
    let mut inodes = Vec::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return inodes;
    };
    for entry in entries.flatten() {
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };
        let text = link.to_string_lossy();
        if let Some(rest) = text.strip_prefix("socket:[") {
            if let Some(inode) = rest.strip_suffix(']') {
                if !inode.is_empty() && inode.bytes().all(|b| b.is_ascii_digit()) {
                    inodes.push(inode.to_string());
                }
            }
        }
    }
    inodes
}

fn tcp_table_has(path: &Path, token: &str, inodes: &[String]) -> bool {
    let Ok(table) = fs::read_to_string(path) else {
        return false;
    };
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        if !fields[1].eq_ignore_ascii_case(token) {
            continue;
        }
        if fields[3] != "0A" {
            continue;
        }
        if inodes.iter().any(|inode| inode == fields[9]) {
            return true;
        }
    }
    false
}

fn read_cmdline(pid: u32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    Some(
        raw.split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect(),
    )
}

fn pid_alive(pid: u32) -> bool {
    if pid <= 1 {
        return false;
    }
    Path::new(&format!("/proc/{pid}")).exists()
}

fn signal_pid(pid: u32) -> Result<(), RemoteError> {
    if pid <= 1 || pid == std::process::id() {
        return Err(RemoteError::message(
            "refusing to signal a process that is not the allowlisted forward".into(),
        ));
    }
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| RemoteError::message(format!("failed to signal tunnel: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(RemoteError::message(
            "failed to signal the allowlisted forward".into(),
        ))
    }
}

/// Fixed remote commands. There is no path that accepts a caller-supplied argv.
#[cfg(test)]
fn fixed_commands() -> Vec<Vec<String>> {
    vec![
        vec!["true".into()],
        GPU_ARGV.iter().map(|part| (*part).to_string()).collect(),
        FAN_ARGV.iter().map(|part| (*part).to_string()).collect(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, OnceLock};

    fn target() -> RemoteTarget {
        RemoteTarget::new("secret-downstairs", "labuser", 2222, 11434, 11434).unwrap()
    }

    fn ssh_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    #[test]
    fn off_when_host_and_user_missing() {
        let err_host = RemoteTarget::new("", "labuser", 22, 11434, 11434);
        assert!(err_host.is_err());
        let err_wild = RemoteTarget::new("0.0.0.0", "labuser", 22, 11434, 11434);
        assert!(err_wild.is_err());
        let err_inject = RemoteTarget::new("host;rm", "labuser", 22, 11434, 11434);
        assert!(err_inject.is_err());
    }

    #[test]
    fn forward_is_loopback_only() {
        let spec = target().forward_spec();
        assert_eq!(spec, "127.0.0.1:11434:127.0.0.1:11434");
        assert!(!spec.contains("0.0.0.0"));
        let args = tunnel_args(&target());
        assert!(args.iter().any(|arg| arg == "-N"));
        assert!(args.iter().any(|arg| arg == &spec));
        assert!(args.iter().any(|arg| arg == "GatewayPorts=no"));
        assert!(!args.iter().any(|arg| arg == "-R" || arg == "-D"));
        assert!(!args.iter().any(|arg| arg.contains("0.0.0.0")));
        assert!(!args.iter().any(|arg| arg.contains("ProxyCommand")));
        let joined = args.join(" ");
        assert!(!joined.contains("scp"));
        assert!(!joined.contains("sftp"));
    }

    #[test]
    fn fixed_commands_are_the_allowlist() {
        let commands = fixed_commands();
        assert_eq!(commands[0], vec!["true".to_string()]);
        assert_eq!(commands[1][0], "nvidia-smi");
        assert_eq!(
            commands[2],
            vec![
                "devguard".to_string(),
                "health".to_string(),
                "fan".to_string(),
                "--json".to_string()
            ]
        );
        let probe = probe_args(&target());
        assert_eq!(probe.last().map(String::as_str), Some("true"));
    }

    #[test]
    fn scrub_removes_host_user_and_port() {
        let target = target();
        let raw = "ssh: connect to host secret-downstairs port 2222: No route to host\nlabuser@secret-downstairs";
        let clean = target.scrub(raw);
        assert!(!clean.contains("secret-downstairs"));
        assert!(!clean.contains("labuser"));
        assert!(!clean.contains("2222"));
        assert!(clean.contains("[host]"));
    }

    #[test]
    fn classifies_no_route_as_host_down() {
        assert_eq!(
            classify_ssh_failure("ssh: connect to host example port 22: No route to host"),
            SshClass::Down
        );
        assert_eq!(classify_ssh_failure("Connection timed out"), SshClass::Down);
        assert_eq!(
            classify_ssh_failure("Permission denied (publickey)"),
            SshClass::Refused
        );
    }

    #[test]
    fn unconfigured_status_is_off() {
        let report = collect_status(None, Path::new("ssh"), Path::new("/tmp")).unwrap();
        assert_eq!(report.target, "off");
        assert_eq!(report.host, "unconfigured");
        assert!(!report.binds_all_interfaces);
        assert!(!report.public_tunnel);
        assert!(!report.arbitrary_exec);
        assert!(!report.resident_daemon);
        let text = format_remote_status(&report);
        assert!(text.contains("target: off"));
        assert!(!text.contains("secret"));
    }

    #[test]
    fn host_down_status_hides_the_target() {
        let _guard = ssh_lock();
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join("fake-ssh");
        write_down_ssh(&ssh);
        let report = collect_status(Some(&target()), &ssh, dir.path()).unwrap();
        assert_eq!(report.host, "down");
        assert_eq!(report.tunnel, "down");
        assert_eq!(report.tags.state, "unavailable");
        assert_eq!(report.gpu.state, "unavailable");
        assert_eq!(report.fan.state, "unavailable");
        let rendered = format!(
            "{} {}",
            format_remote_status(&report),
            serde_json::to_string(&report).unwrap()
        );
        assert!(!rendered.contains("secret-downstairs"));
        assert!(!rendered.contains("labuser"));
        assert!(!rendered.contains("2222"));
        assert!(rendered.contains("down"));
    }

    #[test]
    fn refused_session_is_not_success() {
        let _guard = ssh_lock();
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join("fake-ssh");
        std::fs::write(
            &ssh,
            "#!/bin/sh\necho 'Permission denied (publickey).' >&2\nexit 255\n",
        )
        .unwrap();
        make_exec(&ssh);
        let err = collect_status(Some(&target()), &ssh, dir.path()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("authentication") || text.contains("ssh"));
        assert!(!text.contains("secret-downstairs"));
        assert!(!text.contains("labuser"));
    }

    #[test]
    fn tunnel_up_down_and_samples_stay_on_loopback() {
        let _guard = ssh_lock();
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let target = RemoteTarget::new("secret-downstairs", "labuser", 2222, port, 11434).unwrap();
        let ssh = dir.path().join("fake-ssh");
        let log = dir.path().join("args");
        write_bind_ssh(&ssh, &log);
        let up = tunnel_up(&target, &ssh, dir.path()).unwrap();
        assert_eq!(up.tunnel, "up");
        assert!(up.forward.starts_with("127.0.0.1:"));
        assert!(!up.forward.contains("0.0.0.0"));
        assert!(!up.binds_all_interfaces);
        assert!(!up.resident_daemon);

        let args = std::fs::read_to_string(&log).unwrap();
        assert!(args.contains("127.0.0.1"));
        assert!(args.contains("-N"));
        assert!(!args.contains("0.0.0.0"));
        assert!(!args.contains("-R"));

        let report = collect_status(Some(&target), &ssh, dir.path()).unwrap();
        assert_eq!(report.host, "up");
        assert_eq!(report.tunnel, "up");
        assert_eq!(report.tags.state, "ok");
        assert_eq!(report.tags.value.as_deref(), Some("qwen3.5:9b"));
        assert_eq!(report.gpu.state, "ok");
        assert!(report
            .gpu
            .value
            .as_deref()
            .unwrap_or_default()
            .contains("Test GPU"));
        assert_eq!(report.fan.state, "unavailable");
        let rendered = format!(
            "{} {}",
            format_remote_status(&report),
            serde_json::to_string(&report).unwrap()
        );
        assert!(!rendered.contains("secret-downstairs"));
        assert!(!rendered.contains("labuser"));
        assert!(!rendered.contains("2222"));

        let down = tunnel_down(&target, &ssh, dir.path()).unwrap();
        assert_eq!(down.tunnel, "down");
        assert!(!pid_path(dir.path()).exists());
    }

    #[test]
    fn tunnel_down_refuses_unrelated_pid() {
        let dir = tempfile::tempdir().unwrap();
        let target = target();
        let record = serde_json::json!({
            "pid": std::process::id(),
            "forward": target.forward_spec(),
        });
        std::fs::write(pid_path(dir.path()), record.to_string()).unwrap();
        let err = tunnel_down(&target, Path::new("ssh"), dir.path()).unwrap_err();
        assert!(err.to_string().contains("refusing"));
        assert!(Path::new(&format!("/proc/{}", std::process::id())).exists());
    }

    #[test]
    fn detects_our_loopback_listen() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(process_listens_loopback(std::process::id(), port));
        assert!(!process_listens_loopback(std::process::id(), 1));
    }

    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    fn make_exec(path: &Path) {
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    fn write_down_ssh(path: &Path) {
        std::fs::write(
            path,
            "#!/bin/sh\necho 'ssh: connect to host secret-downstairs port 2222: No route to host' >&2\nexit 255\n",
        )
        .unwrap();
        make_exec(path);
    }

    fn write_bind_ssh(path: &Path, log: &Path) {
        let script = format!(
            r#"#!/usr/bin/env python3
import socket, sys, time
args = sys.argv[1:]
with open({log:?}, "a", encoding="utf-8") as handle:
    handle.write("\n".join(args) + "\n")
joined = " ".join(args)
if "nvidia-smi" in joined:
    print("Test GPU, 40, 1, 100 MiB, 8000 MiB")
    raise SystemExit(0)
if "health" in joined and "fan" in joined:
    sys.stderr.write("devguard: command not found\n")
    raise SystemExit(127)
if args[-1:] == ["true"]:
    raise SystemExit(0)
spec = None
for index, arg in enumerate(args):
    if arg == "-L" and index + 1 < len(args):
        spec = args[index + 1]
if not spec or not spec.startswith("127.0.0.1:") or "0.0.0.0" in spec:
    sys.stderr.write("refusing forward\n")
    raise SystemExit(1)
local_port = int(spec.split(":")[1])
body = b'{{"models":[{{"name":"qwen3.5:9b"}}]}}'
resp = (
    b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
) + body
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", local_port))
server.listen(8)
server.settimeout(0.5)
deadline = time.time() + 20
while time.time() < deadline:
    try:
        conn, _addr = server.accept()
    except socket.timeout:
        continue
    try:
        conn.settimeout(1)
        conn.recv(4096)
        conn.sendall(resp)
    except OSError:
        pass
    finally:
        conn.close()
"#,
            log = log,
        );
        std::fs::write(path, script).unwrap();
        make_exec(path);
    }
}
