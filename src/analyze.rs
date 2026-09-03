use std::path::PathBuf;

use bitplay::{Analysis, SpanKind};
use iced::widget::canvas::Canvas;
use iced::widget::{Space, button, column, container, row, scrollable, text};
use iced::{Element, Fill, Font, Task};

use crate::theme;
use crate::widgets::file_map::{FileMap, MapMessage};

#[derive(Debug, Clone)]
pub enum Message {
    Browse,
    Finished(Result<Analysis, String>),
    MapHover(Option<String>),
    OpenExtract,
}

pub struct State {
    pub path: Option<PathBuf>,
    pub busy: bool,
    pub error: Option<String>,
    pub analysis: Option<Analysis>,
    pub map: Option<FileMap>,
    pub status: String,
}

impl Default for State {
    fn default() -> Self {
        Self {
            path: None,
            busy: false,
            error: None,
            analysis: None,
            map: None,
            status: String::from("Open an MP4 to map its layout"),
        }
    }
}

impl State {
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Browse => {
                let picked = rfd::FileDialog::new()
                    .add_filter("MP4 video", &["mp4", "m4v", "mov"])
                    .pick_file();
                let Some(path) = picked else {
                    return Task::none();
                };
                self.path = Some(path.clone());
                self.busy = true;
                self.error = None;
                self.status = format!("Analyzing {}…", display_name(&path));
                Task::perform(
                    async move {
                        match tokio::task::spawn_blocking(move || {
                            bitplay::analyze(&path).map_err(|e| e.to_string())
                        })
                        .await
                        {
                            Ok(r) => r,
                            Err(e) => Err(e.to_string()),
                        }
                    },
                    Message::Finished,
                )
            }
            Message::Finished(result) => {
                self.busy = false;
                match result {
                    Ok(analysis) => {
                        self.map = Some(FileMap::from_analysis(&analysis));
                        self.status = if analysis.moov_present {
                            format!(
                                "{} · {}",
                                display_name(&analysis.path),
                                bitplay::human_bytes(analysis.file_size)
                            )
                        } else {
                            String::from(
                                "No moov index — layout is incomplete. Use Extract on truncated files.",
                            )
                        };
                        self.analysis = Some(analysis);
                        self.error = None;
                    }
                    Err(err) => {
                        self.error = Some(err);
                        self.status = String::from("Analysis failed");
                    }
                }
                Task::none()
            }
            Message::MapHover(status) => {
                if let Some(line) = status {
                    self.status = line;
                } else if let Some(analysis) = &self.analysis {
                    self.status = format!(
                        "{} · {}",
                        display_name(&analysis.path),
                        bitplay::human_bytes(analysis.file_size)
                    );
                }
                Task::none()
            }
            Message::OpenExtract => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let rail = container(self.rail())
            .width(268)
            .padding(16)
            .height(Fill)
            .style(theme::panel);

        let map = if let Some(map) = &self.map {
            container(
                Element::<MapMessage>::from(Canvas::new(map.clone()).width(Fill).height(Fill)).map(
                    |msg| match msg {
                        MapMessage::Hover(s) => Message::MapHover(s),
                    },
                ),
            )
            .padding(8)
            .width(Fill)
            .height(Fill)
            .style(theme::map_well)
        } else {
            container(self.empty_state())
                .width(Fill)
                .height(Fill)
                .center_x(Fill)
                .center_y(Fill)
                .style(theme::map_well)
        };

        let status = container(
            text(&self.status)
                .size(13)
                .font(Font::MONOSPACE)
                .color(theme::MUTED),
        )
        .width(Fill)
        .padding([8, 14])
        .style(theme::status_bar);

        let main = column![map, status].height(Fill);

        row![rail, main].height(Fill).into()
    }

    fn rail(&self) -> Element<'_, Message> {
        let mut col = column![
            text("ANALYZE").size(12).color(theme::MUTED),
            text("File structure").size(20).color(theme::TEXT),
            Space::with_height(8),
            button(
                text(if self.busy {
                    "Analyzing…"
                } else {
                    "Open MP4"
                })
                .size(14)
            )
            .on_press_maybe(if self.busy {
                None
            } else {
                Some(Message::Browse)
            })
            .style(theme::primary_button)
            .width(Fill)
            .padding([10, 14]),
        ]
        .spacing(10);

        if let Some(path) = &self.path {
            col = col.push(
                text(display_name(path))
                    .size(12)
                    .font(Font::MONOSPACE)
                    .color(theme::TEXT),
            );
        }

        if let Some(err) = &self.error {
            col = col.push(text(err).size(12).color(theme::DANGER));
        }

        if let Some(analysis) = &self.analysis {
            col = col.push(Space::with_height(8));
            col = col.push(meta_block(analysis));
            col = col.push(Space::with_height(8));
            col = col.push(legend());
            if !analysis.moov_present {
                col = col.push(
                    button(text("Open Extract").size(14))
                        .on_press(Message::OpenExtract)
                        .style(theme::secondary_button)
                        .width(Fill)
                        .padding([10, 14]),
                );
            }
        } else {
            col = col.push(Space::with_height(8));
            col = col.push(legend());
        }

        scrollable(col.spacing(10).width(Fill).height(iced::Length::Shrink))
            .width(Fill)
            .height(Fill)
            .into()
    }

    fn empty_state(&self) -> Element<'_, Message> {
        column![
            text("No file loaded").size(18).color(theme::TEXT),
            text("Open an MP4 to see how video, audio, and GOPs are laid out.")
                .size(13)
                .color(theme::MUTED),
            Space::with_height(8),
            button(text("Open MP4").size(14))
                .on_press(Message::Browse)
                .style(theme::primary_button)
                .padding([10, 16]),
        ]
        .spacing(10)
        .align_x(iced::Alignment::Center)
        .max_width(420)
        .into()
    }
}

fn meta_block(analysis: &Analysis) -> Element<'_, Message> {
    let mut lines: Vec<Element<'_, Message>> = vec![
        text("METADATA").size(11).color(theme::MUTED).into(),
        kv("Size", bitplay::human_bytes(analysis.file_size)),
    ];
    if let Some(d) = analysis.duration_secs {
        lines.push(kv("Duration", format!("{d:.2} s")));
    }
    if let Some(v) = &analysis.video {
        lines.push(kv("Video", format!("{} × {}", v.width, v.height)));
        lines.push(kv("Codec", v.codec.clone()));
        if let Some(p) = &v.profile {
            lines.push(kv("Profile", p.clone()));
        }
        if let Some(fps) = v.fps {
            lines.push(kv("FPS", format!("{fps:.3}")));
        }
        lines.push(kv("I-frames", v.iframe_count.to_string()));
        lines.push(kv("GOPs", v.gop_count.to_string()));
    } else {
        lines.push(kv("Video", "not indexed".into()));
    }
    if let Some(a) = &analysis.audio {
        lines.push(kv(
            "Audio",
            format!("{} · {} samples", a.codec, a.sample_count),
        ));
    }
    if !analysis.moov_present {
        lines.push(text("moov missing").size(12).color(theme::WARN).into());
    }
    column(lines).spacing(6).into()
}

fn kv(k: &str, v: String) -> Element<'_, Message> {
    column![
        text(k).size(11).color(theme::MUTED),
        text(v).size(13).font(Font::MONOSPACE).color(theme::TEXT),
    ]
    .spacing(2)
    .into()
}

fn legend() -> Element<'static, Message> {
    let items = [
        (theme::MAP_FTYP, "ftyp"),
        (theme::MAP_MOOV, "moov"),
        (theme::MAP_I, "I-frame"),
        (theme::MAP_P, "P-frame"),
        (theme::MAP_B, "B-frame"),
        (theme::MAP_AUDIO, "audio"),
        (theme::MAP_FREE, "free"),
        (theme::MAP_UNKNOWN, "unmapped"),
    ];
    let mut col = column![text("LEGEND").size(11).color(theme::MUTED)].spacing(6);
    for (color, label) in items {
        col = col.push(
            row![
                container(Space::with_width(12).height(12))
                    .width(12)
                    .height(12)
                    .style(theme::color_chip(color)),
                text(label).size(12).color(theme::TEXT),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
        );
    }
    let _ = SpanKind::Ftyp;
    col.into()
}

fn display_name(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled")
        .to_string()
}
