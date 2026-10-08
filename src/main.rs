pub use bitsplayer::forensic;

mod analyze;
mod app;
mod extract;
mod theme;
mod widgets;

fn main() -> iced::Result {
    iced::daemon(app::App::title, app::App::update, app::App::view)
        .theme(app::App::theme)
        .subscription(app::App::subscription)
        .antialiasing(true)
        .run_with(app::App::boot)
}
