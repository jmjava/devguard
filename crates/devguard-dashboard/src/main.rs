//! Read-only DevGuard window.
//!
//! `--smoke` prints the library snapshot and returns before any window is created.

use std::process::ExitCode;

use clap::Parser;
use eframe::egui;

#[derive(Debug, Parser)]
#[command(
    name = "devguard-dashboard",
    version,
    about = "Read-only window for DevGuard doctor and status"
)]
struct Cli {
    /// Print a text snapshot and exit without opening a display.
    #[arg(long)]
    smoke: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let text = match devguard_dashboard::live_snapshot() {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    if cli.smoke {
        print!("{text}");
        return ExitCode::SUCCESS;
    }
    match run_window(text) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_window(text: String) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "DevGuard",
        options,
        Box::new(move |_creation| Ok(Box::new(DashboardApp { text }))),
    )
}

struct DashboardApp {
    text: String,
}

impl eframe::App for DashboardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("DevGuard");
            ui.label("Read-only doctor and status from the library.");
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.monospace(&self.text);
            });
        });
    }
}
