use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitplay::{Analysis, LayoutSpan, SpanKind};
use iced::widget::canvas::Canvas;
use iced::widget::{Space, button, column, container, row, scrollable, text};
use iced::{Element, Fill, Font, Task};

use crate::forensic::evidence::EvidenceRecord;
use crate::theme;
use crate::widgets::file_map::{FileMap, MapMessage};
use crate::widgets::hex_view;

#[derive(Debug, Clone)]
pub enum Message {
    Browse,
    Finished(Result<(Analysis, EvidenceRecord), String>),
    MapHover(Option<String>),
    MapSelect(usize),
    HexReady {
        seq: u64,
        result: Result<(Vec<u8>, u64), String>,
    },
    CloseHex,
    OpenExtract,
}

enum HexPane {
    Closed,
    Loading {
        span: LayoutSpan,
    },
    Ready {
        span: LayoutSpan,
        shown: u64,
        bytes: Arc<Vec<u8>>,
    },
    Failed {
        span: LayoutSpan,
        error: String,
    },
}

pub struct State {
    pub path: Option<PathBuf>,
    pub busy: bool,
    pub error: Option<String>,
    pub analysis: Option<Analysis>,
    pub evidence: Option<EvidenceRecord>,
    pub map: Option<FileMap>,
    pub status: String,
    hex: HexPane,
    hex_gen: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            path: None,
            busy: false,
            error: None,
            analysis: None,
            evidence: None,
            map: None,
            status: String::from("Open an MP4 to map its layout"),
            hex: HexPane::Closed,
            hex_gen: 0,
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

                self.analysis = None;
                self.evidence = None;
                self.map = None;

                self.close_hex();

                self.status = format!(
                    "Hashing and analyzing {}…",
                    display_name(&path)
                );

                Task::perform(
                    async move {
                        match tokio::task::spawn_blocking(move || {
                            let mut evidence =
                                EvidenceRecord::from_path(&path)
                                    .map_err(|e| {
                                        format!(
                                            "Evidence registration failed: {e}"
                                        )
                                    })?;

                            let analysis =
                                bitplay::analyze(&path)
                                    .map_err(|e| {
                                        format!(
                                            "MP4 analysis failed: {e}"
                                        )
                                    })?;

                            let verified =
                                evidence
                                    .verify_integrity()
                                    .map_err(|e| {
                                        format!(
                                            "Evidence integrity verification failed: {e}"
                                        )
                                    })?;

                            if !verified {
                                return Err(String::from(
                                    "CRITICAL: Evidence file changed during analysis",
                                ));
                            }

                            Ok::<(Analysis, EvidenceRecord), String>((
                                analysis,
                                evidence,
                            ))
                        })
                        .await
                        {
                            Ok(result) => result,
                            Err(e) => Err(format!(
                                "Background task failed: {e}"
                            )),
                        }
                    },
                    Message::Finished,
                )
            }

            Message::Finished(result) => {
                self.busy = false;
                self.close_hex();

                match result {
                    Ok((analysis, evidence)) => {
                        self.map = Some(FileMap::from_analysis(&analysis));

                        self.status = if analysis.moov_present {
                            format!(
                                "{} · {}",
                                display_name(&analysis.path),
                                bitplay::human_bytes(
                                    analysis.file_size
                                )
                            )
                        } else {
                            String::from(
                                "No moov index — layout is incomplete. Use Extract on truncated files.",
                            )
                        };

                        self.analysis = Some(analysis);
                        self.evidence = Some(evidence);
                        self.error = None;
                    }

                    Err(err) => {
                        self.error = Some(err);
                        self.status =
                            String::from("Analysis failed");
                    }
                }

                Task::none()
            }

            Message::MapHover(status) => {
                if let Some(line) = status {
                    self.status = line;
                } else if let Some(span) = self.hex_span() {
                    self.status = format!(
                        "{} · off {} (0x{:08X})",
                        span.status_line(),
                        span.offset,
                        span.offset
                    );
                } else if let Some(analysis) = &self.analysis {
                    self.status = format!(
                        "{} · {}",
                        display_name(&analysis.path),
                        bitplay::human_bytes(
                            analysis.file_size
                        )
                    );
                }

                Task::none()
            }

            Message::MapSelect(index) => {
                self.open_hex(index)
            }

            Message::HexReady { seq, result } => {
                if seq != self.hex_gen {
                    return Task::none();
                }

                let HexPane::Loading { span } =
                    &self.hex
                else {
                    return Task::none();
                };

                let span = span.clone();

                self.hex = match result {
                    Ok((bytes, shown)) => HexPane::Ready {
                        span,
                        shown,
                        bytes: Arc::new(bytes),
                    },

                    Err(error) => {
                        HexPane::Failed { span, error }
                    }
                };

                Task::none()
            }

            Message::CloseHex => {
                self.close_hex();
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
                Element::<MapMessage>::from(
                    Canvas::new(map.clone())
                        .width(Fill)
                        .height(Fill),
                )
                .map(|msg| match msg {
                    MapMessage::Hover(s) => {
                        Message::MapHover(s)
                    }
                    MapMessage::Select(i) => {
                        Message::MapSelect(i)
                    }
                }),
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

        row![rail, main]
            .height(Fill)
            .into()
    }

    fn open_hex(
        &mut self,
        index: usize,
    ) -> Task<Message> {
        let Some(analysis) = &self.analysis else {
            return Task::none();
        };

        let Some(span) =
            analysis.spans.get(index).cloned()
        else {
            return Task::none();
        };

        if let Some(map) = &self.map
            && map.selected == Some(index)
            && matches!(
                self.hex,
                HexPane::Ready { .. }
                    | HexPane::Loading { .. }
            )
        {
            return Task::none();
        }

        if let Some(map) = &mut self.map {
            map.selected = Some(index);
        }

        self.status = format!(
            "{} · off {} (0x{:08X})",
            span.status_line(),
            span.offset,
            span.offset
        );

        self.hex_gen =
            self.hex_gen.wrapping_add(1);

        let seq = self.hex_gen;

        self.hex = HexPane::Loading {
            span: span.clone(),
        };

        let Some(path) = self.path.clone()
        else {
            self.hex = HexPane::Failed {
                span,
                error: String::from(
                    "No file path"
                ),
            };

            return Task::none();
        };

        Task::perform(
            async move {
                match tokio::task::spawn_blocking(
                    move || {
                        read_span_hex(
                            &path,
                            span.offset,
                            span.size,
                        )
                    },
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => Err(e.to_string()),
                }
            },
            move |result| {
                Message::HexReady {
                    seq,
                    result,
                }
            },
        )
    }

    fn close_hex(&mut self) {
        self.hex = HexPane::Closed;

        if let Some(map) = &mut self.map {
            map.selected = None;
        }
    }

    fn hex_span(
        &self,
    ) -> Option<&LayoutSpan> {
        match &self.hex {
            HexPane::Closed => None,

            HexPane::Loading { span }
            | HexPane::Ready {
                span, ..
            }
            | HexPane::Failed {
                span, ..
            } => Some(span),
        }
    }

    pub fn hex_is_open(&self) -> bool {
        !matches!(
            self.hex,
            HexPane::Closed
        )
    }

    pub fn hex_title(&self) -> String {
        match self.hex_span() {
            Some(span) => {
                format!(
                    "Hex · {}",
                    span.kind.label()
                )
            }

            None => String::from("Hex"),
        }
    }

    pub fn hex_window_view(
        &self,
    ) -> Element<'_, Message> {
        let (span, body, note) =
            match &self.hex {
                HexPane::Closed => {
                    return container(
                        text(
                            "No block selected"
                        )
                        .color(
                            theme::MUTED
                        ),
                    )
                    .width(Fill)
                    .height(Fill)
                    .center_x(Fill)
                    .center_y(Fill)
                    .style(theme::panel)
                    .into();
                }

                HexPane::Loading {
                    span,
                } => (
                    span,
                    text("Reading bytes…")
                        .size(13)
                        .font(
                            Font::MONOSPACE
                        )
                        .color(
                            theme::MUTED
                        )
                        .into(),
                    None,
                ),

                HexPane::Failed {
                    span,
                    error,
                } => (
                    span,
                    text(error)
                        .size(13)
                        .color(
                            theme::DANGER
                        )
                        .into(),
                    None,
                ),

                HexPane::Ready {
                    span,
                    shown,
                    bytes,
                } => {
                    let note =
                        (*shown
                            < span.size)
                            .then(|| {
                                format!(
                                    "showing first {} of {}",
                                    bitplay::human_bytes(
                                        *shown
                                    ),
                                    bitplay::human_bytes(
                                        span.size
                                    )
                                )
                            });

                    let body:
                        Element<
                            '_,
                            Message,
                        > =
                        Element::from(
                            Canvas::new(
                                hex_view::HexDump {
                                    bytes:
                                        Arc::clone(
                                            bytes
                                        ),
                                    base:
                                        span.offset,
                                },
                            )
                            .width(Fill)
                            .height(Fill),
                        )
                        .map(|()| {
                            Message::CloseHex
                        });

                    (
                        span,
                        body,
                        note,
                    )
                }
            };

        let end =
            span.offset
                .saturating_add(
                    span.size
                );

        hex_view::window_view(
            theme::span_color(
                span.kind
            ),
            span.status_line(),
            format!(
                "0x{:08X} – 0x{:08X}",
                span.offset,
                end
            ),
            note,
            body,
            Message::CloseHex,
        )
    }

    fn rail(
        &self,
    ) -> Element<'_, Message> {
        let mut col = column![
            text("ANALYZE")
                .size(12)
                .color(
                    theme::MUTED
                ),

            text("File structure")
                .size(20)
                .color(
                    theme::TEXT
                ),

            Space::with_height(8),

            button(
                text(
                    if self.busy {
                        "Analyzing…"
                    } else {
                        "Open MP4"
                    }
                )
                .size(14)
            )
            .on_press_maybe(
                if self.busy {
                    None
                } else {
                    Some(
                        Message::Browse
                    )
                }
            )
            .style(
                theme::primary_button
            )
            .width(Fill)
            .padding([10, 14]),
        ]
        .spacing(10);

        if let Some(path) =
            &self.path
        {
            col = col.push(
                text(
                    display_name(path)
                )
                .size(12)
                .font(
                    Font::MONOSPACE
                )
                .color(
                    theme::TEXT
                ),
            );
        }

        if let Some(evidence) =
            &self.evidence
        {
            col = col.push(
                Space::with_height(8)
            );

            col = col.push(
                evidence_block(
                    evidence
                )
            );
        }

        if let Some(err) =
            &self.error
        {
            col = col.push(
                text(err)
                    .size(12)
                    .color(
                        theme::DANGER
                    ),
            );
        }

        if let Some(analysis) =
            &self.analysis
        {
            col = col.push(
                Space::with_height(8)
            );

            col = col.push(
                meta_block(analysis)
            );

            col = col.push(
                Space::with_height(8)
            );

            col = col.push(
                legend()
            );

            if !analysis.moov_present {
                col = col.push(
                    button(
                        text(
                            "Open Extract"
                        )
                        .size(14)
                    )
                    .on_press(
                        Message::OpenExtract
                    )
                    .style(
                        theme::secondary_button
                    )
                    .width(Fill)
                    .padding(
                        [10, 14]
                    ),
                );
            }
        } else {
            col = col.push(
                Space::with_height(8)
            );

            col = col.push(
                legend()
            );
        }

        scrollable(
            col.spacing(10)
                .width(Fill)
                .height(
                    iced::Length::Shrink
                ),
        )
        .width(Fill)
        .height(Fill)
        .into()
    }

    fn empty_state(
        &self,
    ) -> Element<'_, Message> {
        column![
            text(
                "No file loaded"
            )
            .size(18)
            .color(
                theme::TEXT
            ),

            text(
                "Open an MP4 to see how video, audio, and GOPs are laid out."
            )
            .size(13)
            .color(
                theme::MUTED
            ),

            text(
                "Click a block to inspect its bytes."
            )
            .size(13)
            .color(
                theme::MUTED
            ),

            Space::with_height(8),

            button(
                text(
                    "Open MP4"
                )
                .size(14)
            )
            .on_press(
                Message::Browse
            )
            .style(
                theme::primary_button
            )
            .padding(
                [10, 16]
            ),
        ]
        .spacing(10)
        .align_x(
            iced::Alignment::Center
        )
        .max_width(420)
        .into()
    }
}

fn evidence_block(
    evidence: &EvidenceRecord,
) -> Element<'_, Message> {
    column![
        text("FORENSIC EVIDENCE")
            .size(11)
            .color(theme::MUTED),

        kv(
            "File",
            evidence.filename.clone(),
        ),

        kv(
            "Size",
            bitplay::human_bytes(
                evidence.size_bytes
            ),
        ),

        text("SHA-256")
            .size(11)
            .color(theme::MUTED),

        text(
            format_hash(
                &evidence.sha256
            )
        )
        .size(11)
        .font(Font::MONOSPACE)
        .color(theme::TEXT),

        text(
            if evidence.integrity_verified {
                "Integrity verified"
            } else {
                "Integrity not verified"
            }
        )
        .size(12)
        .color(
            if evidence.integrity_verified {
                theme::TEXT
            } else {
                theme::WARN
            }
        ),
    ]
    .spacing(6)
    .into()
}

fn format_hash(
    hash: &str,
) -> String {
    hash.as_bytes()
        .chunks(16)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .unwrap_or("")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn meta_block(
    analysis: &Analysis,
) -> Element<'_, Message> {
    let mut lines:
        Vec<Element<'_, Message>> =
        vec![
            text("METADATA")
                .size(11)
                .color(
                    theme::MUTED
                )
                .into(),

            kv(
                "Size",
                bitplay::human_bytes(
                    analysis.file_size
                ),
            ),
        ];

    if let Some(d) =
        analysis.duration_secs
    {
        lines.push(
            kv(
                "Duration",
                format!(
                    "{d:.2} s"
                ),
            )
        );
    }

    if let Some(v) =
        &analysis.video
    {
        lines.push(
            kv(
                "Video",
                format!(
                    "{} × {}",
                    v.width,
                    v.height
                ),
            )
        );

        lines.push(
            kv(
                "Codec",
                v.codec.clone(),
            )
        );

        if let Some(p) =
            &v.profile
        {
            lines.push(
                kv(
                    "Profile",
                    p.clone(),
                )
            );
        }

        if let Some(fps) =
            v.fps
        {
            lines.push(
                kv(
                    "FPS",
                    format!(
                        "{fps:.3}"
                    ),
                )
            );
        }

        lines.push(
            kv(
                "I-frames",
                v.iframe_count
                    .to_string(),
            )
        );

        lines.push(
            kv(
                "GOPs",
                v.gop_count
                    .to_string(),
            )
        );
    } else {
        lines.push(
            kv(
                "Video",
                "not indexed"
                    .into(),
            )
        );
    }

    if let Some(a) =
        &analysis.audio
    {
        lines.push(
            kv(
                "Audio",
                format!(
                    "{} · {} samples",
                    a.codec,
                    a.sample_count
                ),
            )
        );
    }

    if !analysis.moov_present {
        lines.push(
            text("moov missing")
                .size(12)
                .color(
                    theme::WARN
                )
                .into(),
        );
    }

    column(lines)
        .spacing(6)
        .into()
}

fn kv(
    k: &str,
    v: String,
) -> Element<'_, Message> {
    column![
        text(k)
            .size(11)
            .color(
                theme::MUTED
            ),

        text(v)
            .size(13)
            .font(
                Font::MONOSPACE
            )
            .color(
                theme::TEXT
            ),
    ]
    .spacing(2)
    .into()
}

fn legend()
    -> Element<'static, Message>
{
    let items = [
        (
            theme::MAP_FTYP,
            "ftyp",
        ),
        (
            theme::MAP_MOOV,
            "moov",
        ),
        (
            theme::MAP_I,
            "I-frame",
        ),
        (
            theme::MAP_P,
            "P-frame",
        ),
        (
            theme::MAP_B,
            "B-frame",
        ),
        (
            theme::MAP_AUDIO,
            "audio",
        ),
        (
            theme::MAP_FREE,
            "free",
        ),
        (
            theme::MAP_UNKNOWN,
            "unmapped",
        ),
    ];

    let mut col =
        column![
            text("LEGEND")
                .size(11)
                .color(
                    theme::MUTED
                )
        ]
        .spacing(6);

    for (color, label) in items {
        col = col.push(
            row![
                container(
                    Space::with_width(12)
                        .height(12)
                )
                .width(12)
                .height(12)
                .style(
                    theme::color_chip(
                        color
                    )
                ),

                text(label)
                    .size(12)
                    .color(
                        theme::TEXT
                    ),
            ]
            .spacing(8)
            .align_y(
                iced::Alignment::Center
            ),
        );
    }

    let _ =
        SpanKind::Ftyp;

    col = col.push(
        text(
            "Click a block to inspect bytes"
        )
        .size(11)
        .color(
            theme::MUTED
        ),
    );

    col.into()
}

fn display_name(
    path: &std::path::Path,
) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled")
        .to_string()
}

fn read_span_hex(
    path: &Path,
    offset: u64,
    size: u64,
) -> Result<
    (Vec<u8>, u64),
    String,
> {
    let show =
        size.min(
            hex_view::MAX_BYTES
        ) as usize;

    if show == 0 {
        return Ok(
            (Vec::new(), 0)
        );
    }

    let mut file =
        std::fs::File::open(path)
            .map_err(
                |e| e.to_string()
            )?;

    file.seek(
        SeekFrom::Start(offset)
    )
    .map_err(
        |e| e.to_string()
    )?;

    let mut buf =
        vec![0u8; show];

    let n =
        file.read(&mut buf)
            .map_err(
                |e| e.to_string()
            )?;

    buf.truncate(n);

    Ok(
        (buf, n as u64)
    )
}