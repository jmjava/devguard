//! Read-only firewall and SSH configuration for `devguard security firewall`.
//!
//! The command reports `ufw status verbose`, an nftables ruleset listing, and
//! SSH port, listen address, and authentication settings where `sshd_config`
//! is readable. A missing `ufw`, `nft`, or unreadable sshd config is
//! `unavailable`, and that result is not clean.
//!
//! It does not run `ufw enable` or `ufw disable`, does not change nftables
//! rules, and does not use sudo. The nftables listing is detection, not a
//! full audit. Tests parse fixtures and do not change the host firewall.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

const TOOL_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_INCLUDE_DEPTH: usize = 8;

/// Read-only `ufw` invocation. Never `enable` or `disable`.
const UFW_ARGS: &[&str] = &["status", "verbose"];
/// Read-only `nft` invocation. Never changes the ruleset.
const NFT_ARGS: &[&str] = &["list", "ruleset"];

const UFW_MISSING: &str = "`ufw` is not on PATH";
const UFW_UNREADABLE: &str = "`ufw` status was unreadable";
const NFT_MISSING: &str = "`nft` is not on PATH";
const NFT_UNREADABLE: &str = "`nft` ruleset was unreadable";
const SSH_UNREADABLE: &str = "sshd config is missing or unreadable";

const HOST_SSHD: &str = "/etc/ssh/sshd_config";
const HOST_SSHD_ROOT: &str = "/etc/ssh";

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

/// One rule from `ufw status verbose`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UfwRule {
    pub to: String,
    pub action: String,
    pub from: String,
}

/// Parsed `ufw status verbose` text. Empty strings mean the line was absent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UfwSnapshot {
    pub state: String,
    pub logging: String,
    pub default_incoming: String,
    pub default_outgoing: String,
    pub default_routed: String,
    pub rules: Vec<UfwRule>,
}

/// One base or regular chain. Rule text is counted, not stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftChain {
    pub name: String,
    pub hook: String,
    pub policy: String,
    pub rules: u32,
}

/// One table from `nft list ruleset`. This is detection, not a full audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NftTable {
    pub family: String,
    pub name: String,
    pub chains: Vec<NftChain>,
}

/// Global sshd settings. Match blocks are counted and not applied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshSnapshot {
    pub ports: Vec<u16>,
    /// True when no `Port` directive was set, so the port is the OpenSSH default.
    pub port_default: bool,
    pub listen_addresses: Vec<String>,
    /// True when no `ListenAddress` was set. OpenSSH then listens on all interfaces.
    pub listen_default_all: bool,
    /// True when a listen address is not loopback, or when the default is all interfaces.
    pub beyond_localhost: bool,
    /// Empty when the directive was not set in the global section.
    pub permit_root_login: String,
    pub password_authentication: String,
    pub pubkey_authentication: String,
    pub permit_empty_passwords: String,
    pub match_blocks: u32,
}

/// Human and JSON body for `devguard security firewall`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallReport {
    /// Always false. This command never invokes sudo.
    pub uses_sudo: bool,
    /// Always false. This command never runs `ufw enable`.
    pub enables_firewall: bool,
    /// Always false. This command never runs `ufw disable`.
    pub disables_firewall: bool,
    /// Always false. This command never changes nftables rules.
    pub changes_nftables: bool,
    /// Always false. nftables output is detection, not a full audit.
    pub claims_full_audit: bool,
    /// False when `ufw`, `nft`, or sshd config could not be read.
    pub clean: bool,
    pub status: CoverageStatus,
    pub ufw: SourceCoverage,
    pub nftables: SourceCoverage,
    pub ssh: SourceCoverage,
    pub ufw_status: Option<UfwSnapshot>,
    pub nft_tables: Vec<NftTable>,
    pub ssh_config: Option<SshSnapshot>,
}

impl FirewallReport {
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
        if self.ufw.status == CoverageStatus::Unavailable {
            warnings.push(format!("ufw unavailable: {}", self.ufw.detail));
        }
        if self.nftables.status == CoverageStatus::Unavailable {
            warnings.push(format!("nftables unavailable: {}", self.nftables.detail));
        }
        if self.ssh.status == CoverageStatus::Unavailable {
            warnings.push(format!("ssh unavailable: {}", self.ssh.detail));
        }
        warnings
    }
}

/// Read this host once.
///
/// `DEVGUARD_UFW_STATUS` and `DEVGUARD_NFT_RULESET` select fixture files and
/// skip the binaries. `DEVGUARD_UFW_BIN` and `DEVGUARD_NFT_BIN` select
/// binaries. `DEVGUARD_SSHD_CONFIG` selects the sshd config file. Includes
/// stay under that file's directory, or under `/etc/ssh` for the host path.
/// None of these paths run `ufw enable`, `ufw disable`, or an nftables change.
pub fn scan_firewall() -> FirewallReport {
    assemble(read_ufw(), read_nft(), read_ssh())
}

/// Parse `ufw status verbose` text. `None` when the text is not a status listing.
pub fn parse_ufw_status(text: &str) -> Option<UfwSnapshot> {
    let mut state = String::new();
    let mut logging = String::new();
    let mut default_incoming = String::new();
    let mut default_outgoing = String::new();
    let mut default_routed = String::new();
    let mut rules = Vec::new();
    let mut in_rules = false;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("ERROR:") || line.contains("You need to be root") {
            return None;
        }
        if let Some(value) = line.strip_prefix("Status:") {
            let value = value.trim();
            if value != "active" && value != "inactive" {
                return None;
            }
            if !state.is_empty() {
                return None;
            }
            state = value.to_string();
            continue;
        }
        if let Some(value) = line.strip_prefix("Logging:") {
            logging = value.trim().to_string();
            if !safe_phrase(&logging) {
                return None;
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("Default:") {
            let (incoming, outgoing, routed) = parse_default(value.trim())?;
            default_incoming = incoming;
            default_outgoing = outgoing;
            default_routed = routed;
            continue;
        }
        if line.starts_with("New profiles:") {
            continue;
        }
        let columns = split_columns(line);
        if columns.len() == 3
            && columns[0] == "To"
            && columns[1] == "Action"
            && columns[2] == "From"
        {
            continue;
        }
        if columns
            .iter()
            .all(|column| column.chars().all(|ch| ch == '-'))
            && !columns.is_empty()
        {
            in_rules = true;
            continue;
        }
        if !in_rules {
            return None;
        }
        if columns.len() != 3
            || !valid_action(&columns[1])
            || !safe_endpoint(&columns[0])
            || !safe_endpoint(&columns[2])
        {
            return None;
        }
        rules.push(UfwRule {
            to: columns[0].clone(),
            action: columns[1].clone(),
            from: columns[2].clone(),
        });
    }

    if state.is_empty() {
        return None;
    }
    Some(UfwSnapshot {
        state,
        logging,
        default_incoming,
        default_outgoing,
        default_routed,
        rules,
    })
}

/// Parse `nft list ruleset` text.
///
/// An empty listing is `Some` with no tables. Text that is not a ruleset is
/// `None`. Chain rules are counted and not copied. This is not a full audit.
pub fn parse_nft_ruleset(text: &str) -> Option<Vec<NftTable>> {
    let mut tables = Vec::new();
    let mut current: Option<NftTable> = None;
    let mut chain: Option<NftChain> = None;
    let mut depth: i32 = 0;

    for line in text.lines() {
        let (code, opens, closes) = code_and_braces(line);
        if code.is_empty() {
            depth += opens - closes;
            if depth < 0 {
                return None;
            }
            continue;
        }
        if depth == 0 {
            let (family, name) = parse_table_header(&code)?;
            if current.is_some() || chain.is_some() {
                return None;
            }
            current = Some(NftTable {
                family,
                name,
                chains: Vec::new(),
            });
        } else if depth == 1 {
            if code == "}" {
                // closed below
            } else if let Some(name) = parse_chain_header(&code) {
                if chain.is_some() {
                    return None;
                }
                chain = Some(NftChain {
                    name,
                    hook: String::new(),
                    policy: String::new(),
                    rules: 0,
                });
            }
        } else if let Some(active) = chain.as_mut() {
            if let Some((hook, policy)) = parse_chain_type(&code) {
                if active.hook.is_empty() {
                    active.hook = hook;
                    active.policy = policy;
                }
            } else if code != "}" && code != "{" {
                active.rules = active.rules.saturating_add(1);
            }
        }

        let start = depth;
        depth += opens - closes;
        if depth < 0 {
            return None;
        }
        if start >= 2 && depth < 2 {
            let finished = chain.take()?;
            current.as_mut()?.chains.push(finished);
        }
        if start >= 1 && depth == 0 {
            let finished = current.take()?;
            if chain.is_some() {
                return None;
            }
            tables.push(finished);
        }
    }

    if depth != 0 || current.is_some() || chain.is_some() {
        return None;
    }
    Some(tables)
}

/// Read sshd config and includes that stay under `include_root`.
///
/// A missing file, an unreadable include, or an include outside `include_root`
/// is `None`. Match blocks are counted and their settings are not applied.
pub fn read_ssh_config(path: &Path, include_root: &Path) -> Option<SshSnapshot> {
    let root = include_root.canonicalize().ok()?;
    let mut state = SshState::default();
    let mut stack = Vec::new();
    consume_sshd(path, &root, &mut state, &mut stack, 0)?;
    Some(state.finish())
}

pub fn format_firewall_human(report: &FirewallReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard security firewall\n");
    out.push_str("  uses sudo: no\n");
    out.push_str("  enables firewall: no\n");
    out.push_str("  disables firewall: no\n");
    out.push_str("  changes nftables: no\n");
    out.push_str("  claims full audit: no\n");
    out.push_str(&format!(
        "  ufw: {} — {}\n",
        status_word(report.ufw.status),
        report.ufw.detail
    ));
    out.push_str(&format!(
        "  nftables: {} — {}\n",
        status_word(report.nftables.status),
        report.nftables.detail
    ));
    out.push_str(&format!(
        "  ssh: {} — {}\n",
        status_word(report.ssh.status),
        report.ssh.detail
    ));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    format_ufw_section(&mut out, report);
    format_nft_section(&mut out, report);
    format_ssh_section(&mut out, report);
    out
}

fn assemble(
    ufw: std::result::Result<UfwSnapshot, &'static str>,
    nft: std::result::Result<Vec<NftTable>, &'static str>,
    ssh: std::result::Result<SshSnapshot, &'static str>,
) -> FirewallReport {
    let (ufw_coverage, ufw_status) = match ufw {
        Ok(snapshot) => {
            let rules = snapshot.rules.len();
            (
                SourceCoverage {
                    status: CoverageStatus::Available,
                    detail: format!("status {}, {rules} rule(s)", snapshot.state),
                },
                Some(snapshot),
            )
        }
        Err(detail) => (
            SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: detail.to_string(),
            },
            None,
        ),
    };
    let (nft_coverage, nft_tables) = match nft {
        Ok(tables) => {
            let count = tables.len();
            (
                SourceCoverage {
                    status: CoverageStatus::Available,
                    detail: format!("{count} table(s); not a full audit"),
                },
                tables,
            )
        }
        Err(detail) => (
            SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: detail.to_string(),
            },
            Vec::new(),
        ),
    };
    let (ssh_coverage, ssh_config) = match ssh {
        Ok(snapshot) => (
            SourceCoverage {
                status: CoverageStatus::Available,
                detail: ssh_detail(&snapshot),
            },
            Some(snapshot),
        ),
        Err(detail) => (
            SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: detail.to_string(),
            },
            None,
        ),
    };
    let clean = ufw_coverage.status == CoverageStatus::Available
        && nft_coverage.status == CoverageStatus::Available
        && ssh_coverage.status == CoverageStatus::Available;
    let status = if clean {
        CoverageStatus::Available
    } else {
        CoverageStatus::Unavailable
    };
    FirewallReport {
        uses_sudo: false,
        enables_firewall: false,
        disables_firewall: false,
        changes_nftables: false,
        claims_full_audit: false,
        clean,
        status,
        ufw: ufw_coverage,
        nftables: nft_coverage,
        ssh: ssh_coverage,
        ufw_status,
        nft_tables,
        ssh_config,
    }
}

fn read_ufw() -> std::result::Result<UfwSnapshot, &'static str> {
    if let Some(path) = env_path("DEVGUARD_UFW_STATUS") {
        let text = fs::read_to_string(path).map_err(|_| UFW_UNREADABLE)?;
        return parse_ufw_status(&text).ok_or(UFW_UNREADABLE);
    }
    let program = tool_bin("DEVGUARD_UFW_BIN", "ufw").ok_or(UFW_MISSING)?;
    let text = run_tool(&program, UFW_ARGS).map_err(|_| UFW_UNREADABLE)?;
    parse_ufw_status(&text).ok_or(UFW_UNREADABLE)
}

fn read_nft() -> std::result::Result<Vec<NftTable>, &'static str> {
    if let Some(path) = env_path("DEVGUARD_NFT_RULESET") {
        let text = fs::read_to_string(path).map_err(|_| NFT_UNREADABLE)?;
        return parse_nft_ruleset(&text).ok_or(NFT_UNREADABLE);
    }
    let program = tool_bin("DEVGUARD_NFT_BIN", "nft").ok_or(NFT_MISSING)?;
    let text = run_tool(&program, NFT_ARGS).map_err(|_| NFT_UNREADABLE)?;
    parse_nft_ruleset(&text).ok_or(NFT_UNREADABLE)
}

fn read_ssh() -> std::result::Result<SshSnapshot, &'static str> {
    let (path, root) = if let Some(path) = env_path("DEVGUARD_SSHD_CONFIG") {
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(SSH_UNREADABLE)?;
        (path, root)
    } else {
        (PathBuf::from(HOST_SSHD), PathBuf::from(HOST_SSHD_ROOT))
    };
    read_ssh_config(&path, &root).ok_or(SSH_UNREADABLE)
}

fn ssh_detail(ssh: &SshSnapshot) -> String {
    let ports = ssh
        .ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let ports = if ssh.port_default {
        format!("{ports} (default)")
    } else {
        ports
    };
    let listen = if ssh.listen_default_all {
        "default all interfaces".to_string()
    } else {
        ssh.listen_addresses.join(",")
    };
    format!("ports {ports}; listen {listen}")
}

fn format_ufw_section(out: &mut String, report: &FirewallReport) {
    out.push_str("\nUFW\n");
    let Some(ufw) = &report.ufw_status else {
        out.push_str("  unavailable\n");
        return;
    };
    out.push_str(&format!("  status: {}\n", ufw.state));
    if !ufw.logging.is_empty() {
        out.push_str(&format!("  logging: {}\n", ufw.logging));
    }
    if !ufw.default_incoming.is_empty() {
        out.push_str(&format!("  default incoming: {}\n", ufw.default_incoming));
        out.push_str(&format!("  default outgoing: {}\n", ufw.default_outgoing));
        out.push_str(&format!("  default routed: {}\n", ufw.default_routed));
    }
    if ufw.rules.is_empty() {
        out.push_str("  rules: none\n");
        return;
    }
    for rule in &ufw.rules {
        out.push_str(&format!(
            "- {}  {}  from {}\n",
            rule.to, rule.action, rule.from
        ));
    }
}

fn format_nft_section(out: &mut String, report: &FirewallReport) {
    out.push_str("\nnftables\n");
    if report.nftables.status == CoverageStatus::Unavailable {
        out.push_str("  unavailable\n");
        return;
    }
    if report.nft_tables.is_empty() {
        out.push_str("  none\n");
        return;
    }
    for table in &report.nft_tables {
        out.push_str(&format!("  table {} {}\n", table.family, table.name));
        for chain in &table.chains {
            let hook = if chain.hook.is_empty() {
                "(none)"
            } else {
                chain.hook.as_str()
            };
            let policy = if chain.policy.is_empty() {
                "(none)"
            } else {
                chain.policy.as_str()
            };
            out.push_str(&format!(
                "- chain {}  hook {hook}  policy {policy}  rules {}\n",
                chain.name, chain.rules
            ));
        }
    }
}

fn format_ssh_section(out: &mut String, report: &FirewallReport) {
    out.push_str("\nSSH\n");
    let Some(ssh) = &report.ssh_config else {
        out.push_str("  unavailable\n");
        return;
    };
    let ports = ssh
        .ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let ports = if ssh.port_default {
        format!("{ports} (default)")
    } else {
        ports
    };
    let listen = if ssh.listen_default_all {
        "default all interfaces".to_string()
    } else {
        ssh.listen_addresses.join(", ")
    };
    out.push_str(&format!("  ports: {ports}\n"));
    out.push_str(&format!("  listen: {listen}\n"));
    out.push_str(&format!(
        "  beyond localhost: {}\n",
        if ssh.beyond_localhost { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "  permit root login: {}\n",
        setting_word(&ssh.permit_root_login)
    ));
    out.push_str(&format!(
        "  password authentication: {}\n",
        setting_word(&ssh.password_authentication)
    ));
    out.push_str(&format!(
        "  pubkey authentication: {}\n",
        setting_word(&ssh.pubkey_authentication)
    ));
    out.push_str(&format!(
        "  permit empty passwords: {}\n",
        setting_word(&ssh.permit_empty_passwords)
    ));
    out.push_str(&format!(
        "  match blocks: {} (not applied)\n",
        ssh.match_blocks
    ));
}

fn setting_word(value: &str) -> &str {
    if value.is_empty() {
        "unspecified"
    } else {
        value
    }
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

fn parse_default(value: &str) -> Option<(String, String, String)> {
    let mut incoming = None;
    let mut outgoing = None;
    let mut routed = None;
    for part in value.split(',') {
        let part = part.trim();
        let (policy, kind) = part.split_once('(')?;
        let policy = policy.trim();
        let kind = kind.trim().trim_end_matches(')').trim();
        if !safe_word(policy) {
            return None;
        }
        match kind {
            "incoming" => incoming = Some(policy.to_string()),
            "outgoing" => outgoing = Some(policy.to_string()),
            "routed" => routed = Some(policy.to_string()),
            _ => return None,
        }
    }
    Some((incoming?, outgoing?, routed?))
}

fn split_columns(line: &str) -> Vec<String> {
    line.split("  ")
        .map(str::trim)
        .filter(|column| !column.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn valid_action(action: &str) -> bool {
    let mut parts = action.split_whitespace();
    let Some(verb) = parts.next() else {
        return false;
    };
    if !matches!(verb, "ALLOW" | "DENY" | "REJECT" | "LIMIT") {
        return false;
    }
    match parts.next() {
        None => true,
        Some("IN" | "OUT" | "FWD") => parts.next().is_none(),
        Some(_) => false,
    }
}

fn safe_phrase(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '(' | ')' | '-' | '/' | ','))
}

fn safe_word(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn safe_endpoint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && !value.chars().any(|ch| ch.is_control())
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(ch, '.' | ':' | '/' | '-' | '_' | ',' | '(' | ')' | ' ')
        })
}

fn code_and_braces(line: &str) -> (String, i32, i32) {
    let mut code = String::new();
    let mut opens = 0i32;
    let mut closes = 0i32;
    let mut in_quote = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_quote {
            code.push(ch);
            if ch == '\\' {
                if let Some(escaped) = chars.next() {
                    code.push(escaped);
                }
                continue;
            }
            if ch == '"' {
                in_quote = false;
            }
            continue;
        }
        if ch == '#' {
            break;
        }
        if ch == '"' {
            in_quote = true;
            code.push(ch);
            continue;
        }
        if ch == '{' {
            opens += 1;
        } else if ch == '}' {
            closes += 1;
        }
        code.push(ch);
    }
    (code.trim().to_string(), opens, closes)
}

fn parse_table_header(code: &str) -> Option<(String, String)> {
    let rest = code.strip_prefix("table ")?;
    let mut parts = rest.split_whitespace();
    let family = parts.next()?.trim_end_matches('{').to_string();
    let name = parts.next()?.trim_end_matches('{').to_string();
    let leftover: Vec<&str> = parts.collect();
    if leftover.len() > 1 || leftover.first().is_some_and(|token| *token != "{") {
        return None;
    }
    if !safe_word(&family) || !safe_word(&name) {
        return None;
    }
    Some((family, name))
}

fn parse_chain_header(code: &str) -> Option<String> {
    let rest = code.strip_prefix("chain ")?;
    let mut parts = rest.split_whitespace();
    let name = parts.next()?.trim_end_matches('{').to_string();
    let leftover: Vec<&str> = parts.collect();
    if leftover.len() > 1 || leftover.first().is_some_and(|token| *token != "{") {
        return None;
    }
    if !safe_word(&name) {
        return None;
    }
    Some(name)
}

fn parse_chain_type(code: &str) -> Option<(String, String)> {
    let rest = code.strip_prefix("type ")?;
    let after_hook = rest.split(" hook ").nth(1)?;
    let hook = after_hook
        .split_whitespace()
        .next()?
        .trim_end_matches(';')
        .to_string();
    if !safe_word(&hook) {
        return None;
    }
    let policy = if let Some(after) = code.split(" policy ").nth(1) {
        let policy = after
            .split_whitespace()
            .next()?
            .trim_end_matches(';')
            .to_string();
        if !safe_word(&policy) {
            return None;
        }
        policy
    } else {
        String::new()
    };
    Some((hook, policy))
}

#[derive(Debug, Default)]
struct SshState {
    ports: Vec<u16>,
    listen: Vec<String>,
    permit_root_login: String,
    password_authentication: String,
    pubkey_authentication: String,
    permit_empty_passwords: String,
    match_blocks: u32,
    in_match: bool,
    saw_port: bool,
    saw_listen: bool,
}

impl SshState {
    fn finish(mut self) -> SshSnapshot {
        self.ports.sort_unstable();
        self.ports.dedup();
        self.listen.sort();
        self.listen.dedup();
        let port_default = !self.saw_port;
        if port_default {
            self.ports.push(22);
        }
        let listen_default_all = !self.saw_listen;
        let beyond_localhost =
            listen_default_all || self.listen.iter().any(|addr| !is_loopback(addr));
        SshSnapshot {
            ports: self.ports,
            port_default,
            listen_addresses: self.listen,
            listen_default_all,
            beyond_localhost,
            permit_root_login: self.permit_root_login,
            password_authentication: self.password_authentication,
            pubkey_authentication: self.pubkey_authentication,
            permit_empty_passwords: self.permit_empty_passwords,
            match_blocks: self.match_blocks,
        }
    }
}

fn consume_sshd(
    path: &Path,
    root: &Path,
    state: &mut SshState,
    stack: &mut Vec<PathBuf>,
    depth: usize,
) -> Option<()> {
    if depth > MAX_INCLUDE_DEPTH {
        return None;
    }
    let canon = path.canonicalize().ok()?;
    if !canon.starts_with(root) {
        return None;
    }
    if stack.iter().any(|seen| seen == &canon) {
        return None;
    }
    let meta = fs::metadata(&canon).ok()?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let text = fs::read_to_string(&canon).ok()?;
    stack.push(canon);
    for line in text.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let keyword = parts.next()?.to_ascii_lowercase();
        if keyword == "match" {
            state.match_blocks = state.match_blocks.saturating_add(1);
            state.in_match = true;
            continue;
        }
        if state.in_match {
            continue;
        }
        if keyword == "include" {
            let patterns: Vec<&str> = parts.collect();
            if patterns.is_empty() {
                stack.pop();
                return None;
            }
            for pattern in patterns {
                if pattern.starts_with('"') || pattern.starts_with('\'') {
                    stack.pop();
                    return None;
                }
                let paths = expand_include(pattern, root)?;
                for included in paths {
                    consume_sshd(&included, root, state, stack, depth + 1)?;
                }
            }
            continue;
        }
        if recognized_keyword(&keyword) {
            let Some(value) = parts.next() else {
                stack.pop();
                return None;
            };
            if parts.next().is_some() {
                stack.pop();
                return None;
            }
            if apply_ssh_keyword(state, &keyword, value).is_none() {
                stack.pop();
                return None;
            }
        }
    }
    stack.pop();
    Some(())
}

fn recognized_keyword(keyword: &str) -> bool {
    matches!(
        keyword,
        "port"
            | "listenaddress"
            | "permitrootlogin"
            | "passwordauthentication"
            | "pubkeyauthentication"
            | "permitemptypasswords"
    )
}

fn apply_ssh_keyword(state: &mut SshState, keyword: &str, value: &str) -> Option<()> {
    match keyword {
        "port" => {
            let port: u16 = value.parse().ok()?;
            if port == 0 {
                return None;
            }
            state.saw_port = true;
            if !state.ports.contains(&port) {
                state.ports.push(port);
            }
        }
        "listenaddress" => {
            if !valid_listen(value) {
                return None;
            }
            state.saw_listen = true;
            if !state.listen.iter().any(|existing| existing == value) {
                state.listen.push(value.to_string());
            }
        }
        "permitrootlogin" => {
            let value = canonical_root_login(value)?;
            if state.permit_root_login.is_empty() {
                state.permit_root_login = value;
            }
        }
        "passwordauthentication" => set_yes_no(&mut state.password_authentication, value)?,
        "pubkeyauthentication" => set_yes_no(&mut state.pubkey_authentication, value)?,
        "permitemptypasswords" => set_yes_no(&mut state.permit_empty_passwords, value)?,
        _ => {}
    }
    Some(())
}

fn set_yes_no(slot: &mut String, value: &str) -> Option<()> {
    let value = canonical_yes_no(value)?;
    if slot.is_empty() {
        *slot = value;
    }
    Some(())
}

fn canonical_yes_no(value: &str) -> Option<String> {
    match value.to_ascii_lowercase().as_str() {
        "yes" => Some("yes".to_string()),
        "no" => Some("no".to_string()),
        _ => None,
    }
}

fn canonical_root_login(value: &str) -> Option<String> {
    match value.to_ascii_lowercase().as_str() {
        "yes" => Some("yes".to_string()),
        "no" => Some("no".to_string()),
        "prohibit-password" | "without-password" => Some("prohibit-password".to_string()),
        "forced-commands-only" => Some("forced-commands-only".to_string()),
        _ => None,
    }
}

fn valid_listen(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains("..")
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '%' | '-' | '[' | ']'))
}

fn is_loopback(addr: &str) -> bool {
    let host = listen_host(addr);
    matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost")
}

fn listen_host(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host.to_string();
        }
    }
    if addr.matches(':').count() == 1 {
        if let Some((host, port)) = addr.rsplit_once(':') {
            if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
                return host.to_string();
            }
        }
    }
    addr.to_string()
}

fn strip_comment(line: &str) -> &str {
    let mut in_quote = false;
    for (index, ch) in line.char_indices() {
        if ch == '"' {
            in_quote = !in_quote;
        } else if ch == '#' && !in_quote {
            return &line[..index];
        }
    }
    line
}

fn expand_include(pattern: &str, root: &Path) -> Option<Vec<PathBuf>> {
    if pattern.contains('[') || pattern.contains("**") {
        return None;
    }
    let path = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        root.join(pattern)
    };
    let name = path.file_name()?.to_str()?;
    let dir = path.parent()?;
    if is_glob(&dir.to_string_lossy()) {
        return None;
    }
    if !is_glob(name) {
        let canon = path.canonicalize().ok()?;
        if !canon.starts_with(root) {
            return None;
        }
        return Some(vec![canon]);
    }
    let Ok(dir) = dir.canonicalize() else {
        return Some(Vec::new());
    };
    if !dir.starts_with(root) {
        return None;
    }
    let mut matches = Vec::new();
    for entry in fs::read_dir(&dir).ok()? {
        let entry = entry.ok()?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !glob_match(name, file_name) {
            continue;
        }
        let candidate = entry.path();
        if !candidate.is_file() {
            continue;
        }
        let canon = candidate.canonicalize().ok()?;
        if !canon.starts_with(root) {
            return None;
        }
        matches.push(canon);
    }
    matches.sort();
    Some(matches)
}

fn is_glob(value: &str) -> bool {
    value.chars().any(|ch| ch == '*' || ch == '?')
}

fn glob_match(pattern: &str, name: &str) -> bool {
    glob_rec(pattern.as_bytes(), name.as_bytes())
}

fn glob_rec(pattern: &[u8], text: &[u8]) -> bool {
    let mut index = 0;
    let mut text_index = 0;
    while index < pattern.len() {
        if pattern[index] == b'*' {
            if index + 1 == pattern.len() {
                return true;
            }
            for start in text_index..=text.len() {
                if glob_rec(&pattern[index + 1..], &text[start..]) {
                    return true;
                }
            }
            return false;
        }
        if text_index >= text.len() {
            return false;
        }
        if pattern[index] != b'?' && pattern[index] != text[text_index] {
            return false;
        }
        index += 1;
        text_index += 1;
    }
    text_index == text.len()
}

fn env_path(key: &str) -> Option<PathBuf> {
    let value = std::env::var_os(key)?;
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

fn tool_bin(env_key: &str, name: &str) -> Option<PathBuf> {
    if let Some(value) = std::env::var_os(env_key) {
        if value.is_empty() {
            return None;
        }
        let path = PathBuf::from(value);
        return path.is_file().then_some(path);
    }
    find_tool(name)
}

fn find_tool(name: &str) -> Option<PathBuf> {
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

fn run_tool(program: &Path, args: &[&str]) -> std::io::Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let truncated = Arc::new(AtomicBool::new(false));
    let stdout_flag = Arc::clone(&truncated);
    let stderr_flag = Arc::clone(&truncated);
    let stdout_handle =
        thread::spawn(move || read_bounded(stdout, MAX_CAPTURE_BYTES, &stdout_flag));
    let stderr_handle =
        thread::spawn(move || read_bounded(stderr, MAX_CAPTURE_BYTES, &stderr_flag));
    let started = Instant::now();
    loop {
        if truncated.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "command output truncated",
            ));
        }
        if let Some(status) = child.try_wait()? {
            let stdout = stdout_handle.join().unwrap_or_default();
            let _ = stderr_handle.join();
            if truncated.load(Ordering::Relaxed) || !status.success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "command output unreadable",
                ));
            }
            let text = std::str::from_utf8(&stdout)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
            return Ok(text.to_string());
        }
        if started.elapsed() > TOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "command timed out",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_bounded(pipe: Option<impl Read>, limit: usize, truncated: &AtomicBool) -> Vec<u8> {
    let Some(mut pipe) = pipe else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if out.len() >= limit {
            let mut extra = [0u8; 1];
            match pipe.read(&mut extra) {
                Ok(0) => {}
                Ok(_) => truncated.store(true, Ordering::Relaxed),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {}
            }
            break;
        }
        let room = limit - out.len();
        let want = room.min(buf.len());
        match pipe.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const UFW_FIXTURE: &str = include_str!("../fixtures/ufw-status-verbose.txt");
    const NFT_FIXTURE: &str = include_str!("../fixtures/nft-ruleset.txt");

    #[test]
    fn readonly_args_do_not_change_the_firewall() {
        assert_eq!(UFW_ARGS, ["status", "verbose"]);
        assert_eq!(NFT_ARGS, ["list", "ruleset"]);
        for arg in UFW_ARGS.iter().chain(NFT_ARGS.iter()) {
            let verb = arg.to_ascii_lowercase();
            assert_ne!(verb, "enable");
            assert_ne!(verb, "disable");
            assert_ne!(verb, "sudo");
            assert_ne!(verb, "flush");
            assert_ne!(verb, "delete");
            assert_ne!(verb, "add");
            assert_ne!(verb, "insert");
            assert_ne!(verb, "replace");
        }
    }

    #[test]
    fn run_tool_passes_only_the_readonly_args() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("argv.txt");
        let script = dir.path().join("ufw");
        let body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$1\" \"$2\" \"$#\" > '{}'\nexit 0\n",
            log.display()
        );
        fs::write(&script, body).unwrap();
        let mut perms = fs::metadata(&script).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&script, perms).unwrap();

        let text = run_tool(&script, UFW_ARGS).expect("script");
        assert!(text.is_empty());
        let got = fs::read_to_string(&log).unwrap();
        assert_eq!(got, "status\nverbose\n2\n");
    }

    #[test]
    fn fixture_sources_are_available_and_clean() {
        let ufw = parse_ufw_status(UFW_FIXTURE).expect("ufw");
        let nft = parse_nft_ruleset(NFT_FIXTURE).expect("nft");
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/sshd");
        let ssh = read_ssh_config(&root.join("sshd_config"), &root).expect("ssh");
        let report = assemble(Ok(ufw), Ok(nft), Ok(ssh));

        assert!(report.clean);
        assert_eq!(report.status, CoverageStatus::Available);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert!(!report.uses_sudo);
        assert!(!report.enables_firewall);
        assert!(!report.disables_firewall);
        assert!(!report.changes_nftables);
        assert!(!report.claims_full_audit);

        let ufw = report.ufw_status.as_ref().unwrap();
        assert_eq!(ufw.state, "active");
        assert_eq!(ufw.logging, "on (low)");
        assert_eq!(ufw.default_incoming, "deny");
        assert_eq!(ufw.default_outgoing, "allow");
        assert_eq!(ufw.default_routed, "disabled");
        assert_eq!(ufw.rules.len(), 3);
        assert_eq!(ufw.rules[0].to, "22/tcp");
        assert_eq!(ufw.rules[0].action, "ALLOW IN");
        assert_eq!(ufw.rules[0].from, "Anywhere");
        assert_eq!(ufw.rules[1].action, "DENY IN");
        assert_eq!(ufw.rules[1].from, "192.168.1.0/24");
        assert_eq!(ufw.rules[2].to, "22/tcp (v6)");
        assert_eq!(ufw.rules[2].from, "Anywhere (v6)");

        assert_eq!(report.nft_tables.len(), 2);
        assert_eq!(report.nft_tables[0].family, "inet");
        assert_eq!(report.nft_tables[0].name, "filter");
        assert_eq!(report.nft_tables[0].chains[0].name, "input");
        assert_eq!(report.nft_tables[0].chains[0].hook, "input");
        assert_eq!(report.nft_tables[0].chains[0].policy, "drop");
        assert_eq!(report.nft_tables[0].chains[0].rules, 2);
        assert_eq!(report.nft_tables[0].chains[1].name, "forward");
        assert_eq!(report.nft_tables[0].chains[1].rules, 0);
        assert_eq!(report.nft_tables[1].family, "ip");
        assert_eq!(report.nft_tables[1].chains[0].hook, "prerouting");
        assert_eq!(report.nft_tables[1].chains[0].policy, "accept");
        assert!(report.nftables.detail.contains("not a full audit"));

        let ssh = report.ssh_config.as_ref().unwrap();
        assert_eq!(ssh.ports, vec![22, 2222]);
        assert!(!ssh.port_default);
        assert_eq!(ssh.listen_addresses, vec!["127.0.0.1".to_string()]);
        assert!(!ssh.listen_default_all);
        assert!(!ssh.beyond_localhost);
        assert_eq!(ssh.permit_root_login, "prohibit-password");
        assert_eq!(ssh.password_authentication, "no");
        assert_eq!(ssh.pubkey_authentication, "yes");
        assert_eq!(ssh.permit_empty_passwords, "no");
        assert_eq!(ssh.match_blocks, 1);

        let human = format_firewall_human(&report);
        assert!(human.contains("DevGuard security firewall"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("enables firewall: no"));
        assert!(human.contains("disables firewall: no"));
        assert!(human.contains("changes nftables: no"));
        assert!(human.contains("claims full audit: no"));
        assert!(human.contains("clean: yes"));
        assert!(human.contains("- 22/tcp  ALLOW IN  from Anywhere"));
        assert!(human.contains("beyond localhost: no"));
        assert!(human.contains("password authentication: no"));
        assert!(human.contains("match blocks: 1 (not applied)"));
        assert!(!human.contains("sk-fixture-token-do-not-print"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("sk-fixture-token-do-not-print"));
    }

    #[test]
    fn missing_source_is_unavailable_and_not_clean() {
        let ufw = parse_ufw_status("Status: inactive\n").expect("inactive");
        assert!(ufw.rules.is_empty());
        let nft = parse_nft_ruleset("").expect("empty ruleset");
        assert!(nft.is_empty());
        let report = assemble(Ok(ufw), Ok(nft), Err(SSH_UNREADABLE));
        assert!(!report.clean);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.ufw.status, CoverageStatus::Available);
        assert_eq!(report.nftables.status, CoverageStatus::Available);
        assert_eq!(report.ssh.status, CoverageStatus::Unavailable);
        assert!(report.ssh_config.is_none());
        assert!(report.ufw_status.is_some());
        assert!(report.warnings()[0].contains("ssh unavailable"));
        let human = format_firewall_human(&report);
        assert!(human.contains("clean: no"));
        assert!(human.contains("unavailable"));
        assert!(human.contains("rules: none"));
        assert!(!human.to_ascii_lowercase().contains("healthy"));
    }

    #[test]
    fn unreadable_ufw_and_nft_text_is_unavailable() {
        for text in [
            "",
            "ERROR: You need to be root to run this script\n",
            "Status: maybe\n",
        ] {
            assert!(parse_ufw_status(text).is_none(), "{text:?}");
        }
        assert!(parse_nft_ruleset("this is not nft\n").is_none());
        let report = assemble(Err(UFW_MISSING), Err(NFT_UNREADABLE), Err(SSH_UNREADABLE));
        assert!(!report.clean);
        assert!(report.ufw_status.is_none());
        assert!(report.nft_tables.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.warnings().len(), 3);
    }

    #[test]
    fn ssh_include_outside_the_root_is_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("secret.conf");
        fs::write(
            &outside,
            "ListenAddress 203.0.113.10\nPasswordAuthentication yes\n",
        )
        .unwrap();
        let root = dir.path().join("ssh");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("sshd_config"),
            format!("Include {}\nPort 22\n", outside.display()),
        )
        .unwrap();
        assert!(read_ssh_config(&root.join("sshd_config"), &root).is_none());

        fs::write(
            root.join("sshd_config"),
            "Include ../secret.conf\nPort 22\n",
        )
        .unwrap();
        assert!(read_ssh_config(&root.join("sshd_config"), &root).is_none());
    }

    #[test]
    fn missing_glob_include_keeps_global_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("sshd_config"),
            "Include missing.d/*.conf\nPort 2200\nListenAddress 127.0.0.1\n",
        )
        .unwrap();
        let ssh = read_ssh_config(&dir.path().join("sshd_config"), dir.path()).expect("ssh");
        assert_eq!(ssh.ports, vec![2200]);
        assert!(!ssh.beyond_localhost);
        assert!(ssh.permit_root_login.is_empty());
    }

    #[test]
    fn omitted_listen_address_is_exposed_by_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("sshd_config"), "PermitRootLogin no\n").unwrap();
        let ssh = read_ssh_config(&dir.path().join("sshd_config"), dir.path()).expect("ssh");
        assert!(ssh.port_default);
        assert_eq!(ssh.ports, vec![22]);
        assert!(ssh.listen_default_all);
        assert!(ssh.listen_addresses.is_empty());
        assert!(ssh.beyond_localhost);
        assert_eq!(ssh.permit_root_login, "no");
    }
}
