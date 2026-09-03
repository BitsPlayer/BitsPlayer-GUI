mod analyze;
mod app;
mod extract;
mod theme;
mod widgets;

fn main() -> iced::Result {
    iced::application("BitsPlayer", app::App::update, app::App::view)
        .theme(app::App::theme)
        .subscription(app::App::subscription)
        .window_size(iced::Size::new(1280.0, 820.0))
        .antialiasing(true)
        .run()
}
