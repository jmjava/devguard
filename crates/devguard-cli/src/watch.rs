//! Ratatui display for `devguard health watch`.
//!
//! The loop runs on this thread. Ctrl+C is a key event, not a signal sent to
//! another process. Each refresh calls the fan diagnostic and then waits out
//! the remaining interval.

use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use devguard_core::exit::ExitCode;
use devguard_core::watch::{refresh, render_watch, WatchSample};
use devguard_core::{scan_fan, DevGuardError};
use ratatui::backend::CrosstermBackend;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

/// Draw one sample, then refresh when `interval` elapses. Ctrl+C returns.
pub fn run_watch(interval: Duration) -> Result<ExitCode, DevGuardError> {
    let mut session = WatchSession::enter()?;
    let result = session.run(interval);
    session.restore();
    result
}

/// Paint one refresh into a frame. Tests use this with `TestBackend`.
pub(crate) fn draw_watch(frame: &mut Frame, sample: &WatchSample) {
    let area = frame.area();
    let block = Block::default()
        .title(" health watch ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let paragraph = Paragraph::new(render_watch(sample)).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

struct WatchSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    restored: bool,
}

impl WatchSession {
    fn enter() -> Result<Self, DevGuardError> {
        enable_raw_mode()?;
        match (|| -> io::Result<Self> {
            let mut stdout = io::stdout();
            execute!(stdout, EnterAlternateScreen)?;
            let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
            Ok(Self {
                terminal,
                restored: false,
            })
        })() {
            Ok(session) => Ok(session),
            Err(err) => {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen);
                Err(err.into())
            }
        }
    }

    fn run(&mut self, interval: Duration) -> Result<ExitCode, DevGuardError> {
        let mut refresh_index = 1u64;
        loop {
            let started = Instant::now();
            let sample = refresh(interval, refresh_index, scan_fan());
            self.terminal.draw(|frame| draw_watch(frame, &sample))?;
            if wait_for_ctrl_c(started + interval)? {
                return Ok(ExitCode::Success);
            }
            refresh_index = refresh_index.saturating_add(1);
        }
    }

    fn restore(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

impl Drop for WatchSession {
    fn drop(&mut self) {
        self.restore();
    }
}

/// `true` when the operator pressed Ctrl+C. `false` when the interval elapsed.
fn wait_for_ctrl_c(deadline: Instant) -> Result<bool, DevGuardError> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let slice = (deadline - now).min(Duration::from_millis(100));
        if event::poll(slice)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press && is_ctrl_c(&key) => {
                    return Ok(true);
                }
                _ => {}
            }
        }
    }
}

fn is_ctrl_c(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use devguard_core::fan::{diagnose, CoverageStatus, FanFacts, ModulePresence, SourceCoverage};
    use ratatui::backend::TestBackend;

    fn unavailable_report() -> devguard_core::FanReport {
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

    fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
        let width = buffer.area.width;
        let height = buffer.area.height;
        let mut out = String::new();
        for y in 0..height {
            for x in 0..width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn one_refresh_without_a_terminal() {
        let sample = refresh(Duration::from_secs(5), 1, unavailable_report());
        let backend = TestBackend::new(120, 60);
        let mut terminal = Terminal::new(backend).expect("test backend");
        terminal
            .draw(|frame| draw_watch(frame, &sample))
            .expect("draw");
        let text = buffer_text(terminal.backend().buffer());
        assert!(text.contains("health watch"));
        assert!(text.contains("interval: 5s"));
        assert!(text.contains("background service: no"));
        assert!(text.contains("process signals: no"));
        assert!(text.contains("Ctrl+C exits"));
        assert!(text.contains("sensors: unavailable"));
        assert!(text.contains("nvidia-smi: unavailable"));
        assert!(!sample.starts_background_service);
        assert!(!sample.signals_processes);
        assert!(sample.report.gpus.is_empty());
        assert!(!text.contains("background service: yes"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
    }
}
