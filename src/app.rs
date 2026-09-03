use std::time::Duration;

use iced::{Element, Fill, Font, Subscription, Task, Theme};

use crate::analyze;
use crate::extract;
use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Analyze,
    Extract,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tab(Tab),
    Analyze(analyze::Message),
    Extract(extract::Message),
}

pub struct App {
    tab: Tab,
    analyze: analyze::State,
    extract: extract::State,
}

impl Default for App {
    fn default() -> Self {
        Self {
            tab: Tab::Analyze,
            analyze: analyze::State::default(),
            extract: extract::State::default(),
        }
    }
}

impl App {
    pub fn theme(&self) -> Theme {
        theme::bitsplayer_theme()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        if self.extract.running {
            iced::time::every(Duration::from_millis(80))
                .map(|_| Message::Extract(extract::Message::Tick))
        } else {
            Subscription::none()
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tab(tab) => {
                self.tab = tab;
                Task::none()
            }
            Message::Analyze(analyze::Message::OpenExtract) => {
                self.tab = Tab::Extract;
                if let Some(v) = self
                    .analyze
                    .analysis
                    .as_ref()
                    .and_then(|a| a.video.as_ref())
                {
                    if v.width > 0 && v.height > 0 {
                        self.extract.prefill(v.width, v.height);
                    }
                }
                Task::none()
            }
            Message::Analyze(msg) => {
                let prefill = matches!(&msg, analyze::Message::Finished(Ok(_)));
                let task = self.analyze.update(msg).map(Message::Analyze);
                if prefill {
                    if let Some(v) = self
                        .analyze
                        .analysis
                        .as_ref()
                        .and_then(|a| a.video.as_ref())
                    {
                        if v.width > 0 && v.height > 0 {
                            self.extract.prefill(v.width, v.height);
                        }
                    }
                }
                task
            }
            Message::Extract(msg) => self.extract.update(msg).map(Message::Extract),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let file_hint = match self.tab {
            Tab::Analyze => self
                .analyze
                .path
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .unwrap_or(""),
            Tab::Extract => self
                .extract
                .path
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .unwrap_or(""),
        };

        let header = iced::widget::container(
            iced::widget::row![
                iced::widget::column![
                    iced::widget::text("BitsPlayer").size(20).color(theme::TEXT),
                    iced::widget::text("MP4 forensics")
                        .size(12)
                        .color(theme::MUTED),
                ]
                .spacing(2),
                iced::widget::Space::with_width(24),
                tab_btn("Analyze", Tab::Analyze, self.tab),
                tab_btn("Extract", Tab::Extract, self.tab),
                iced::widget::Space::with_width(Fill),
                iced::widget::text(file_hint)
                    .size(12)
                    .font(Font::MONOSPACE)
                    .color(theme::MUTED),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
        )
        .padding([12, 16])
        .width(Fill)
        .style(theme::header_bar);

        let body: Element<_> = match self.tab {
            Tab::Analyze => self.analyze.view().map(Message::Analyze),
            Tab::Extract => self.extract.view().map(Message::Extract),
        };

        iced::widget::column![header, body].height(Fill).into()
    }
}

fn tab_btn(label: &'static str, tab: Tab, current: Tab) -> Element<'static, Message> {
    iced::widget::button(iced::widget::text(label).size(14))
        .on_press(Message::Tab(tab))
        .style(theme::tab_button(tab == current))
        .padding([8, 16])
        .into()
}
