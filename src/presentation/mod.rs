//! Presentation layer: iced interface and the standalone verifier.

pub mod analyze;
pub mod app;
pub mod extract;
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
