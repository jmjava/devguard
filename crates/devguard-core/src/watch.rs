//! In-process refresh for `devguard health watch`.
//!
//! One sample reuses the fan diagnostic. The command stays in the foreground:
//! it does not start a background service and it does not signal processes.

use std::time::Duration;

use crate::error::{DevGuardError, Result};
use crate::fan::{format_fan_human, CoverageStatus, FanReport};

/// Shortest accepted refresh interval.
pub const MIN_WATCH_INTERVAL: Duration = Duration::from_secs(1);
/// Longest accepted refresh interval.
pub const MAX_WATCH_INTERVAL: Duration = Duration::from_secs(300);

/// One foreground refresh of the fan diagnostic.
///
/// Construct it with [`refresh`]. The two flags are always false.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct WatchSample {
    pub interval: Duration,
    pub refresh_index: u64,
    pub report: FanReport,
    /// Always false. Watch does not fork a resident service.
    pub starts_background_service: bool,
    /// Always false. Watch does not signal other processes.
    pub signals_processes: bool,
}

/// Parse `5s`, `1m`, or `1000ms` and reject anything outside 1s..300s.
pub fn parse_watch_interval(raw: &str) -> Result<Duration> {
    let text = raw.trim();
    let (amount, unit) = split_watch_interval(text)?;
    let millis = match unit {
        "ms" => amount,
        "s" => amount
            .checked_mul(1_000)
            .ok_or_else(|| interval_overflow(text))?,
        "m" => amount
            .checked_mul(60_000)
            .ok_or_else(|| interval_overflow(text))?,
        _ => return Err(interval_format(text)),
    };
    let duration = Duration::from_millis(millis);
    if duration < MIN_WATCH_INTERVAL || duration > MAX_WATCH_INTERVAL {
        return Err(DevGuardError::Usage(format!(
            "interval {text} is outside {}s..{}s",
            MIN_WATCH_INTERVAL.as_secs(),
            MAX_WATCH_INTERVAL.as_secs()
        )));
    }
    Ok(duration)
}

/// Display a bounded interval the same way the CLI accepts it.
pub fn format_interval(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis % 60_000 == 0 {
        format!("{}m", millis / 60_000)
    } else if millis % 1_000 == 0 {
        format!("{}s", millis / 1_000)
    } else {
        format!("{millis}ms")
    }
}

/// Turn one fan report into a watch sample.
///
/// This does not read the host, start a service, or signal a process.
pub fn refresh(interval: Duration, refresh_index: u64, report: FanReport) -> WatchSample {
    WatchSample {
        interval,
        refresh_index,
        report,
        starts_background_service: false,
        signals_processes: false,
    }
}

/// Text for one refresh. Missing sensors and `nvidia-smi` stay `unavailable`.
pub fn render_watch(sample: &WatchSample) -> String {
    let mut out = String::new();
    out.push_str("DevGuard health watch\n");
    out.push_str(&format!(
        "  interval: {}\n",
        format_interval(sample.interval)
    ));
    out.push_str(&format!("  refresh: {}\n", sample.refresh_index));
    out.push_str(&format!(
        "  background service: {}\n",
        yes_no(sample.starts_background_service)
    ));
    out.push_str(&format!(
        "  process signals: {}\n",
        yes_no(sample.signals_processes)
    ));
    out.push_str("  Ctrl+C exits\n");
    out.push_str(&format!(
        "  sensors: {}\n",
        status_word(sample.report.sensors.status)
    ));
    out.push_str(&format!(
        "  nvidia-smi: {}\n",
        status_word(sample.report.nvidia_smi.status)
    ));
    out.push('\n');
    out.push_str(&format_fan_human(&sample.report));
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

fn split_watch_interval(text: &str) -> Result<(u64, &'static str)> {
    if text.is_empty() {
        return Err(interval_format(text));
    }
    let (unit, digits) = if let Some(digits) = text.strip_suffix("ms") {
        ("ms", digits)
    } else if let Some(digits) = text.strip_suffix('s') {
        ("s", digits)
    } else if let Some(digits) = text.strip_suffix('m') {
        ("m", digits)
    } else {
        return Err(interval_format(text));
    };
    if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(interval_format(text));
    }
    let amount: u64 = digits.parse().map_err(|_| interval_format(text))?;
    Ok((amount, unit))
}

fn interval_format(text: &str) -> DevGuardError {
    DevGuardError::Usage(format!(
        "interval `{text}` must look like 5s and stay within {}s..{}s",
        MIN_WATCH_INTERVAL.as_secs(),
        MAX_WATCH_INTERVAL.as_secs()
    ))
}

fn interval_overflow(text: &str) -> DevGuardError {
    DevGuardError::Usage(format!("interval `{text}` is outside 1s..300s"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fan::{diagnose, CoverageStatus, FanFacts, ModulePresence, SourceCoverage};

    fn unavailable_report() -> FanReport {
        diagnose(FanFacts {
            kernel: "test".into(),
            cpu_count: 4,
            load_1m: 0.2,
            sensors: SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: "`sensors` is not on PATH".into(),
            },
            nvidia_smi: SourceCoverage {
                status: CoverageStatus::Unavailable,
                detail: "`nvidia-smi` is not on PATH".into(),
            },
            hwmon: Vec::new(),
            gpus: Vec::new(),
            nvidia_module: ModulePresence::Absent,
            processes: Vec::new(),
        })
    }

    #[test]
    fn five_seconds_is_in_bounds_and_zero_is_not() {
        assert_eq!(parse_watch_interval("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(
            parse_watch_interval("5m").unwrap(),
            Duration::from_secs(300)
        );
        assert!(parse_watch_interval("0s").is_err());
        assert!(parse_watch_interval("999ms").is_err());
        assert!(parse_watch_interval("301s").is_err());
        assert!(parse_watch_interval("6m").is_err());
        assert!(parse_watch_interval("5h").is_err());
    }

    #[test]
    fn one_refresh_without_a_terminal_keeps_missing_tools_unavailable() {
        let sample = refresh(Duration::from_secs(5), 1, unavailable_report());
        assert!(!sample.starts_background_service);
        assert!(!sample.signals_processes);
        assert_eq!(sample.report.sensors.status, CoverageStatus::Unavailable);
        assert_eq!(sample.report.nvidia_smi.status, CoverageStatus::Unavailable);
        assert!(sample.report.gpus.is_empty());
        let text = render_watch(&sample);
        assert!(text.contains("interval: 5s"));
        assert!(text.contains("background service: no"));
        assert!(text.contains("process signals: no"));
        assert!(text.contains("Ctrl+C exits"));
        assert!(text.contains("sensors: unavailable"));
        assert!(text.contains("nvidia-smi: unavailable"));
        assert!(text.contains("GPU fan speed is unknown"));
        assert!(!text.contains("background service: yes"));
        assert!(!text.contains("process signals: yes"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
    }
}
