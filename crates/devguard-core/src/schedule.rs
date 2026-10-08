//! Opt-in systemd user timer for `devguard schedule dry-run`.
//!
//! The command prints a user service and timer for a later `devguard health scan`.
//! It does not write under `~/.config/systemd`, run `systemctl`, enable a timer,
//! or use sudo. Until `schedule.enabled` is true, the timer is not requested
//! and the result is not clean.
//!
//! The unit text is a fixed template. Calendar words come from a closed set
//! (`daily`, `hourly`, `weekly`). Config values that could hold a secret, a
//! token, or a password are not copied into the unit.

use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;

/// `available` when the unit text was rendered, `unavailable` when the timer
/// was not requested.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Available,
    Unavailable,
}

/// Whether the operator opted in through config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimerRequest {
    NotRequested,
    OptedIn,
}

/// Closed set of `OnCalendar` values. Anything else is rejected before render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCalendar {
    Daily,
    Hourly,
    Weekly,
}

impl ScanCalendar {
    /// Parse a config value. Returns `None` for any other string, including
    /// values that contain a secret. The rejected string is not returned.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "daily" => Some(Self::Daily),
            "hourly" => Some(Self::Hourly),
            "weekly" => Some(Self::Weekly),
            _ => None,
        }
    }

    fn on_calendar(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Hourly => "hourly",
            Self::Weekly => "weekly",
        }
    }
}

/// Human and JSON body for `devguard schedule dry-run`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduleDryRunReport {
    /// Always false. This command never writes a unit file.
    pub writes_unit_files: bool,
    /// Always false. This command never runs `systemctl`.
    pub runs_systemctl: bool,
    /// Always false. This command never enables a timer.
    pub enables_timer: bool,
    /// Always false. This command never uses sudo.
    pub uses_sudo: bool,
    /// `opted_in` or `not_requested`.
    pub timer: TimerRequest,
    /// `available` when the unit text was rendered. `unavailable` when the
    /// timer was not requested.
    pub status: CoverageStatus,
    /// False when the timer was not requested.
    pub clean: bool,
    /// Rendered service and timer text. Absent when the timer was not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_text: Option<String>,
}

impl ScheduleDryRunReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        if self.timer == TimerRequest::NotRequested {
            vec!["timer is not requested".into()]
        } else {
            Vec::new()
        }
    }
}

/// Print the opt-in user timer.
///
/// `enabled` comes from `schedule.enabled`. A false value does not render a
/// unit. This function does not create directories or files and does not
/// spawn a process.
pub fn schedule_dry_run(enabled: bool, calendar: ScanCalendar) -> ScheduleDryRunReport {
    if !enabled {
        return ScheduleDryRunReport {
            writes_unit_files: false,
            runs_systemctl: false,
            enables_timer: false,
            uses_sudo: false,
            timer: TimerRequest::NotRequested,
            status: CoverageStatus::Unavailable,
            clean: false,
            unit_text: None,
        };
    }
    ScheduleDryRunReport {
        writes_unit_files: false,
        runs_systemctl: false,
        enables_timer: false,
        uses_sudo: false,
        timer: TimerRequest::OptedIn,
        status: CoverageStatus::Available,
        clean: true,
        unit_text: Some(render_user_timer(calendar)),
    }
}

pub fn format_schedule_dry_run_human(report: &ScheduleDryRunReport) -> String {
    let mut out = String::new();
    out.push_str("DevGuard schedule dry-run\n");
    out.push_str("  writes unit files: no\n");
    out.push_str("  runs systemctl: no\n");
    out.push_str("  enables timer: no\n");
    out.push_str("  uses sudo: no\n");
    out.push_str(&format!("  timer: {}\n", timer_word(report.timer)));
    out.push_str(&format!("  status: {}\n", status_word(report.status)));
    out.push_str(&format!(
        "  clean: {}\n",
        if report.clean { "yes" } else { "no" }
    ));
    match report.unit_text.as_deref() {
        Some(text) => {
            out.push_str("\nUnit text\n");
            out.push_str(text);
            if !text.ends_with('\n') {
                out.push('\n');
            }
        }
        None => out.push_str("\nThe timer is not requested.\n"),
    }
    out
}

fn render_user_timer(calendar: ScanCalendar) -> String {
    format!(
        "\
# devguard-scan.service
# Dry-run only. This text is not written and the timer is not enabled.
[Unit]
Description=DevGuard scheduled scan

[Service]
Type=oneshot
ExecStart=devguard health scan

# devguard-scan.timer
# Dry-run only. This text is not written and the timer is not enabled.
[Unit]
Description=DevGuard scheduled scan timer

[Timer]
OnCalendar={on_calendar}
Persistent=true
Unit=devguard-scan.service

[Install]
WantedBy=timers.target
",
        on_calendar = calendar.on_calendar(),
    )
}

fn timer_word(timer: TimerRequest) -> &'static str {
    match timer {
        TimerRequest::NotRequested => "not requested",
        TimerRequest::OptedIn => "opted in",
    }
}

fn status_word(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Available => "available",
        CoverageStatus::Unavailable => "unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const DAILY_UNIT: &str = "\
# devguard-scan.service
# Dry-run only. This text is not written and the timer is not enabled.
[Unit]
Description=DevGuard scheduled scan

[Service]
Type=oneshot
ExecStart=devguard health scan

# devguard-scan.timer
# Dry-run only. This text is not written and the timer is not enabled.
[Unit]
Description=DevGuard scheduled scan timer

[Timer]
OnCalendar=daily
Persistent=true
Unit=devguard-scan.service

[Install]
WantedBy=timers.target
";

    #[test]
    fn not_requested_is_not_clean() {
        let report = schedule_dry_run(false, ScanCalendar::Daily);
        assert_eq!(report.timer, TimerRequest::NotRequested);
        assert_eq!(report.status, CoverageStatus::Unavailable);
        assert!(!report.clean);
        assert!(report.unit_text.is_none());
        assert!(!report.writes_unit_files);
        assert!(!report.runs_systemctl);
        assert!(!report.enables_timer);
        assert!(!report.uses_sudo);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(
            report.warnings(),
            vec!["timer is not requested".to_string()]
        );
        let human = format_schedule_dry_run_human(&report);
        assert!(human.contains("timer: not requested"));
        assert!(human.contains("status: unavailable"));
        assert!(human.contains("clean: no"));
        assert!(human.contains("The timer is not requested."));
        assert!(!human.contains("ExecStart"));
        assert!(!human.contains("[Timer]"));
    }

    #[test]
    fn opted_in_renders_the_daily_unit_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let user_units = dir.path().join(".config/systemd/user");
        let report = schedule_dry_run(true, ScanCalendar::Daily);
        assert_eq!(report.timer, TimerRequest::OptedIn);
        assert_eq!(report.status, CoverageStatus::Available);
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        let text = report.unit_text.as_deref().expect("unit text");
        assert_eq!(text, DAILY_UNIT);
        assert_unit_has_no_secret(text);
        assert!(!user_units.exists());
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
        let human = format_schedule_dry_run_human(&report);
        assert!(human.contains("timer: opted in"));
        assert!(human.contains("status: available"));
        assert!(human.contains("clean: yes"));
        assert!(human.contains("writes unit files: no"));
        assert!(human.contains("runs systemctl: no"));
        assert!(human.contains("enables timer: no"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains(DAILY_UNIT));
    }

    #[test]
    fn hourly_and_weekly_change_only_the_calendar_word() {
        for (calendar, word) in [
            (ScanCalendar::Hourly, "hourly"),
            (ScanCalendar::Weekly, "weekly"),
        ] {
            let text = schedule_dry_run(true, calendar)
                .unit_text
                .expect("unit text");
            let expected = DAILY_UNIT.replace("OnCalendar=daily", &format!("OnCalendar={word}"));
            assert_eq!(text, expected);
            assert_unit_has_no_secret(&text);
        }
    }

    #[test]
    fn calendar_parser_rejects_anything_outside_the_set() {
        assert_eq!(ScanCalendar::parse("daily"), Some(ScanCalendar::Daily));
        assert_eq!(ScanCalendar::parse(" hourly "), Some(ScanCalendar::Hourly));
        assert_eq!(ScanCalendar::parse("weekly"), Some(ScanCalendar::Weekly));
        assert!(ScanCalendar::parse("daily\nEnvironment=TOKEN=ghp_FIXTURE").is_none());
        assert!(ScanCalendar::parse("password=hunter2").is_none());
        assert!(ScanCalendar::parse("").is_none());
    }

    fn assert_unit_has_no_secret(text: &str) {
        let lower = text.to_ascii_lowercase();
        for needle in ["secret", "token", "password", "passwd", "ghp_", "api_key"] {
            assert!(!lower.contains(needle), "{needle} in unit:\n{text}");
        }
    }
}
