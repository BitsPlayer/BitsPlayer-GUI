//! Presentation layer: iced interface and the standalone verifier.

pub mod analyze;
pub mod app;
pub mod custody;
pub mod export_cli;
pub mod export_verify_cli;
pub mod extract;
pub mod progress;
pub mod report_cli;
pub mod theme;
pub mod verify_cli;
pub mod widgets;

pub fn run() -> iced::Result {
    iced::daemon(app::App::title, app::App::update, app::App::view)
        .theme(app::App::theme)
        .subscription(app::App::subscription)
        .antialiasing(true)
        .run_with(app::App::boot)
}
