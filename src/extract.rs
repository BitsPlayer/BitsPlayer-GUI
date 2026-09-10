use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use iced::widget::image::Handle;
use iced::widget::{
    Space, button, checkbox, column, container, pick_list, responsive, row, scrollable, text,
    text_input,
};
use iced::{Element, Fill, Font, Task};
use iframe_extract::decode::{ColorMatrix, Frame};
use iframe_extract::extract::{self, FrameRecord, Options};
use iframe_extract::report::Reporter;

use crate::theme;
use crate::widgets::frame_grid::{self, Thumb};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatrixChoice {
    #[default]
    Bt709,
    Bt601,
}

impl MatrixChoice {
    const ALL: [MatrixChoice; 2] = [MatrixChoice::Bt709, MatrixChoice::Bt601];

    fn to_matrix(self) -> ColorMatrix {
        match self {
            Self::Bt709 => ColorMatrix::Bt709,
            Self::Bt601 => ColorMatrix::Bt601,
        }
    }
}

impl std::fmt::Display for MatrixChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Bt709 => "BT.709",
            Self::Bt601 => "BT.601",
        })
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Browse,
    Width(String),
    Height(String),
    Matrix(MatrixChoice),
    ToggleNonIdr(bool),
    TogglePartial(bool),
    ToggleAudio(bool),
    Run,
    Tick,
    Select(usize),
    ClosePreview,
    Save,
}

struct Progress {
    phase: String,
    done: u64,
    total: u64,
    detail: String,
    finished: Option<Result<Extracted, String>>,
}

#[derive(Clone)]
struct ChannelReporter {
    inner: Arc<Mutex<Progress>>,
}

impl Reporter for ChannelReporter {
    fn phase(&mut self, name: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.phase = name.to_string();
            g.done = 0;
            g.total = 0;
            g.detail.clear();
        }
    }

    fn progress(&mut self, done: u64, total: u64, detail: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.done = done;
            g.total = total;
            g.detail = detail.to_string();
        }
    }

    fn finish_phase(&mut self, detail: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.detail = detail.to_string();
            g.done = g.total.max(1);
        }
    }

    fn note(&mut self, msg: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.detail = msg.to_string();
        }
    }
}

struct DecodedFrame {
    record: FrameRecord,
    frame: Frame,
    thumb: Handle,
    preview: Handle,
    png: Vec<u8>,
}

struct Extracted {
    summary: String,
    frames: Vec<DecodedFrame>,
}

pub struct State {
    pub path: Option<PathBuf>,
    pub width: String,
    pub height: String,
    pub matrix: MatrixChoice,
    pub include_non_idr: bool,
    pub include_partial: bool,
    pub with_audio: bool,
    pub running: bool,
    pub error: Option<String>,
    pub status: String,
    pub selected: Option<usize>,
    progress: Arc<Mutex<Progress>>,
    result: Option<Extracted>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            path: None,
            width: String::new(),
            height: String::new(),
            matrix: MatrixChoice::Bt709,
            include_non_idr: false,
            include_partial: false,
            with_audio: false,
            running: false,
            error: None,
            status: String::from("Open a truncated MP4, set frame size, then extract"),
            selected: None,
            progress: Arc::new(Mutex::new(Progress {
                phase: String::new(),
                done: 0,
                total: 0,
                detail: String::new(),
                finished: None,
            })),
            result: None,
        }
    }
}

impl State {
    pub fn prefill(&mut self, width: u32, height: u32) {
        if width > 0 {
            self.width = width.to_string();
        }
        if height > 0 {
            self.height = height.to_string();
        }
        self.status = format!("Size prefilled from Analyze ({width}×{height})");
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Browse => {
                let picked = rfd::FileDialog::new()
                    .add_filter("MP4 video", &["mp4", "m4v", "mov"])
                    .pick_file();
                if let Some(path) = picked {
                    self.status = format!("Ready · {}", display_name(&path));
                    self.path = Some(path);
                    self.error = None;
                }
                Task::none()
            }
            Message::Width(v) => {
                self.width = v;
                Task::none()
            }
            Message::Height(v) => {
                self.height = v;
                Task::none()
            }
            Message::Matrix(m) => {
                self.matrix = m;
                Task::none()
            }
            Message::ToggleNonIdr(v) => {
                self.include_non_idr = v;
                Task::none()
            }
            Message::TogglePartial(v) => {
                self.include_partial = v;
                Task::none()
            }
            Message::ToggleAudio(v) => {
                self.with_audio = v;
                Task::none()
            }
            Message::Run => self.start_extract(),
            Message::Tick => {
                let finished = self
                    .progress
                    .lock()
                    .ok()
                    .and_then(|mut g| g.finished.take());
                if let Some(result) = finished {
                    self.running = false;
                    match result {
                        Ok(extracted) => {
                            self.status = extracted.summary.clone();
                            self.result = Some(extracted);
                            self.error = None;
                        }
                        Err(err) => {
                            self.error = Some(err);
                            self.status = String::from("Extraction failed");
                        }
                    }
                } else if self.running {
                    if let Ok(g) = self.progress.lock() {
                        let pct = if g.total > 0 {
                            (g.done.saturating_mul(100) / g.total).min(100)
                        } else {
                            0
                        };
                        self.status = format!("{}  {pct}%  {}", g.phase, g.detail);
                    }
                }
                Task::none()
            }
            Message::Select(i) => {
                self.selected = Some(i);
                Task::none()
            }
            Message::ClosePreview => {
                self.selected = None;
                Task::none()
            }
            Message::Save => {
                self.save_frames();
                Task::none()
            }
        }
    }

    fn start_extract(&mut self) -> Task<Message> {
        if self.running {
            return Task::none();
        }
        let Some(path) = self.path.clone() else {
            self.error = Some(String::from("Choose an MP4 file first"));
            return Task::none();
        };
        let width: u32 = match self.width.trim().parse() {
            Ok(w) if w > 0 => w,
            _ => {
                self.error = Some(String::from(
                    "Enter a valid width — required when SPS is lost",
                ));
                return Task::none();
            }
        };
        let height: u32 = match self.height.trim().parse() {
            Ok(h) if h > 0 => h,
            _ => {
                self.error = Some(String::from(
                    "Enter a valid height — required when SPS is lost",
                ));
                return Task::none();
            }
        };

        self.running = true;
        self.error = None;
        self.result = None;
        self.selected = None;
        self.status = String::from("Starting extraction…");
        {
            let mut g = self.progress.lock().expect("progress lock");
            g.phase = String::from("starting");
            g.done = 0;
            g.total = 0;
            g.detail.clear();
            g.finished = None;
        }

        let opts = Options {
            width,
            height,
            include_non_idr: self.include_non_idr,
            include_partial: self.include_partial,
            with_audio: self.with_audio,
        };
        let matrix = self.matrix.to_matrix();
        let progress = Arc::clone(&self.progress);
        std::thread::spawn(move || {
            let mut reporter = ChannelReporter {
                inner: Arc::clone(&progress),
            };
            let outcome = run_extract(&path, opts, matrix, &mut reporter);
            if let Ok(mut g) = progress.lock() {
                g.finished = Some(outcome);
            }
        });
        Task::none()
    }

    fn save_frames(&mut self) {
        let Some(result) = &self.result else {
            self.error = Some(String::from("Nothing to save yet"));
            return;
        };
        let Some(dir) = rfd::FileDialog::new().pick_folder() else {
            return;
        };
        if let Err(err) = std::fs::create_dir_all(&dir) {
            self.error = Some(err.to_string());
            return;
        }
        for decoded in &result.frames {
            let stem = format!(
                "frame_{:05}_off_{:010}{}",
                decoded.record.index,
                decoded.record.offset,
                if decoded.record.partial {
                    "_partial"
                } else {
                    ""
                }
            );
            let path = dir.join(format!("{stem}.png"));
            if let Err(err) = std::fs::write(&path, &decoded.png) {
                self.error = Some(format!("writing {}: {err}", path.display()));
                return;
            }
        }
        self.status = format!("{} frames saved to {}", result.frames.len(), dir.display());
    }

    pub fn view(&self) -> Element<'_, Message> {
        let controls = self.controls();
        let body = if let Some(result) = &self.result {
            self.result_view(result)
        } else {
            container(self.empty_state())
                .width(Fill)
                .height(Fill)
                .center_x(Fill)
                .center_y(Fill)
                .style(theme::map_well)
                .into()
        };

        let status = container(
            row![
                text(&self.status)
                    .size(13)
                    .font(Font::MONOSPACE)
                    .color(theme::MUTED),
                Space::with_width(Fill),
                progress_bar(self),
            ]
            .spacing(12)
            .align_y(iced::Alignment::Center),
        )
        .width(Fill)
        .padding([8, 14])
        .style(theme::status_bar);

        column![controls, body, status].height(Fill).into()
    }

    fn controls(&self) -> Element<'_, Message> {
        let open = button(
            text(if let Some(p) = &self.path {
                display_name(p)
            } else {
                String::from("Open truncated MP4")
            })
            .size(14),
        )
        .on_press_maybe(if self.running {
            None
        } else {
            Some(Message::Browse)
        })
        .style(theme::secondary_button)
        .padding([10, 14]);

        let size_row = row![
            text("Size").size(13).color(theme::MUTED),
            text_input("width", &self.width)
                .on_input(Message::Width)
                .style(theme::field)
                .width(88)
                .padding(8),
            text("×").size(16).color(theme::MUTED),
            text_input("height", &self.height)
                .on_input(Message::Height)
                .style(theme::field)
                .width(88)
                .padding(8),
            pick_list(MatrixChoice::ALL, Some(self.matrix), Message::Matrix,)
                .padding(8)
                .width(110),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center);

        let flags = row![
            checkbox("Include non-IDR", self.include_non_idr)
                .on_toggle(Message::ToggleNonIdr)
                .size(16)
                .text_size(13),
            checkbox("Include partial", self.include_partial)
                .on_toggle(Message::TogglePartial)
                .size(16)
                .text_size(13),
            checkbox("With audio", self.with_audio)
                .on_toggle(Message::ToggleAudio)
                .size(16)
                .text_size(13),
        ]
        .spacing(16);

        let run = button(
            text(if self.running {
                "Extracting…"
            } else {
                "Extract"
            })
            .size(14),
        )
        .on_press_maybe(if self.running {
            None
        } else {
            Some(Message::Run)
        })
        .style(theme::primary_button)
        .padding([10, 16]);

        let save = button(text("Save PNGs").size(14))
            .on_press_maybe(if self.result.is_some() && !self.running {
                Some(Message::Save)
            } else {
                None
            })
            .style(theme::secondary_button)
            .padding([10, 16]);

        let mut col = column![
            row![open, size_row, flags, Space::with_width(Fill), run, save]
                .spacing(12)
                .align_y(iced::Alignment::Center)
                .wrap()
        ]
        .spacing(8);

        if let Some(err) = &self.error {
            col = col.push(text(err).size(12).color(theme::DANGER));
        }

        container(col)
            .padding([12, 16])
            .width(Fill)
            .style(theme::header_bar)
            .into()
    }

    fn result_view(&self, result: &Extracted) -> Element<'_, Message> {
        let thumbs: Vec<Thumb> = result
            .frames
            .iter()
            .map(|f| Thumb {
                index: f.record.index,
                offset: f.record.offset,
                source_size: f.record.source_size,
                png_size: f.png.len() as u64,
                partial: f.record.partial,
                handle: f.thumb.clone(),
            })
            .collect();

        let preview = self.selected.and_then(|i| {
            result.frames.iter().find(|f| f.record.index == i).map(|f| {
                let caption = format!(
                    "frame {:05}  offset {}  {}×{}  src {} → png {}{}",
                    f.record.index,
                    f.record.offset,
                    f.frame.width,
                    f.frame.height,
                    iframe_extract::report::human_bytes(f.record.source_size),
                    iframe_extract::report::human_bytes(f.png.len() as u64),
                    if f.record.partial { "  partial" } else { "" }
                );
                (f.preview.clone(), caption)
            })
        });

        let selected_index = self.selected;
        let grid = responsive(move |size| {
            let cols = ((size.width / 186.0).floor() as usize).max(2);
            scrollable(frame_grid::view(
                &thumbs,
                selected_index,
                cols,
                Message::Select,
            ))
            .width(Fill)
            .height(Fill)
            .into()
        });

        let mut body = column![].spacing(12).width(Fill).height(Fill);
        if let Some((handle, caption)) = preview {
            body = body.push(
                container(
                    column![
                        row![
                            text("Preview").size(14).color(theme::TEXT),
                            Space::with_width(Fill),
                            button(text("Close").size(13))
                                .on_press(Message::ClosePreview)
                                .style(theme::secondary_button)
                                .padding([6, 12]),
                        ]
                        .align_y(iced::Alignment::Center),
                        frame_grid::preview(handle, caption),
                    ]
                    .spacing(8)
                    .height(iced::Length::Shrink),
                )
                .padding(12)
                .style(theme::panel),
            );
        }
        body = body.push(grid);
        container(body).padding(12).width(Fill).height(Fill).into()
    }

    fn empty_state(&self) -> Element<'_, Message> {
        column![
            text("No frames yet").size(18).color(theme::TEXT),
            text("I-frames are recovered from the bitstream. Size cannot be read from a lost SPS, so width × height must be set.")
                .size(13)
                .color(theme::MUTED),
        ]
        .spacing(10)
        .align_x(iced::Alignment::Center)
        .max_width(460)
        .into()
    }
}

fn progress_bar(state: &State) -> Element<'_, Message> {
    let (done, total) = if let Ok(g) = state.progress.lock() {
        (g.done, g.total.max(1))
    } else {
        (0, 1)
    };
    let filled = if state.running {
        (done.min(total) as u16).max(1)
    } else if state.result.is_some() {
        100
    } else {
        1
    };
    let rest = if state.running {
        ((total.saturating_sub(done)) as u16).max(1)
    } else {
        1
    };
    row![
        container(Space::with_width(Fill))
            .width(iced::Length::FillPortion(filled))
            .height(6)
            .style(|_| iced::widget::container::Style {
                background: Some(iced::Background::Color(if state.running {
                    theme::ACCENT
                } else if state.result.is_some() {
                    theme::MAP_P
                } else {
                    theme::ELEVATED
                })),
                border: iced::Border {
                    color: theme::HAIRLINE,
                    width: 0.0,
                    radius: 3.0.into(),
                },
                ..Default::default()
            }),
        container(Space::with_width(Fill))
            .width(iced::Length::FillPortion(if state.running {
                rest
            } else {
                1
            }))
            .height(6)
            .style(|_| iced::widget::container::Style {
                background: Some(iced::Background::Color(theme::ELEVATED)),
                border: iced::Border {
                    radius: 3.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
    ]
    .width(160)
    .into()
}

fn run_extract(
    path: &Path,
    opts: Options,
    matrix: ColorMatrix,
    reporter: &mut dyn Reporter,
) -> Result<Extracted, String> {
    let data = read_input(path, reporter).map_err(|e| e.to_string())?;
    let name = path.display().to_string();
    let extraction =
        extract::extract_with(&data, &name, &opts, reporter).map_err(|e| e.to_string())?;
    reporter.phase("rendering previews");
    let n = extraction.frames.len();
    let mut frames = Vec::with_capacity(n);
    for (i, (record, frame)) in extraction.frames.into_iter().enumerate() {
        let rgb = frame.to_rgb(matrix);
        let thumb = handle_from_rgb(&rgb, frame.width, frame.height, 200);
        let preview = handle_from_rgb(&rgb, frame.width, frame.height, 960);
        let png = encode_png(rgb, frame.width, frame.height)?;
        frames.push(DecodedFrame {
            record,
            frame,
            thumb,
            preview,
            png,
        });
        reporter.progress((i + 1) as u64, n as u64, &format!("{}/{n}", i + 1));
    }
    reporter.finish_phase(&format!("{n} frames"));
    let r = &extraction.report;
    let skipped = match r.skipped_regions {
        0 => String::new(),
        n => format!(
            " · stepped over {n} non-video region(s), {}",
            iframe_extract::report::human_bytes(r.skipped_bytes)
        ),
    };
    let summary = match r.truncation_offset {
        Some(off) => format!(
            "{} NALs · {} frames · chain broke at {off} ({:.2}% of file){skipped}",
            r.nal_count,
            frames.len(),
            off as f64 / data.len().max(1) as f64 * 100.0
        ),
        None => format!(
            "{} NALs · {} frames · chain ran to end of mdat{skipped}",
            r.nal_count,
            frames.len()
        ),
    };
    Ok(Extracted { summary, frames })
}

fn read_input(path: &Path, reporter: &mut dyn Reporter) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);
    reporter.phase("reading file");
    let mut reader = std::io::BufReader::with_capacity(1024 * 1024, file);
    let mut data = Vec::new();
    if total > 0 {
        data.reserve(total as usize);
    }
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        reporter.progress(
            data.len() as u64,
            total.max(data.len() as u64),
            &iframe_extract::report::human_bytes(data.len() as u64),
        );
    }
    reporter.finish_phase(&iframe_extract::report::human_bytes(data.len() as u64));
    Ok(data)
}

fn encode_png(rgb: Vec<u8>, w: usize, h: usize) -> Result<Vec<u8>, String> {
    let img = image::RgbImage::from_raw(w as u32, h as u32, rgb)
        .ok_or("frame dimensions did not match buffer")?;
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

fn handle_from_rgb(rgb: &[u8], w: usize, h: usize, max_side: u32) -> Handle {
    let (tw, th, rgba) = downscale_rgba(rgb, w, h, max_side);
    Handle::from_rgba(tw, th, rgba)
}

fn downscale_rgba(rgb: &[u8], w: usize, h: usize, max_side: u32) -> (u32, u32, Vec<u8>) {
    let max_side = max_side as usize;
    let scale = (max_side as f32 / w.max(h).max(1) as f32).min(1.0);
    let tw = ((w as f32 * scale).round() as usize).max(1);
    let th = ((h as f32 * scale).round() as usize).max(1);
    let mut out = vec![0u8; tw * th * 4];
    for y in 0..th {
        let sy = y * h / th;
        for x in 0..tw {
            let sx = x * w / tw;
            let si = (sy * w + sx) * 3;
            let di = (y * tw + x) * 4;
            if si + 2 < rgb.len() {
                out[di] = rgb[si];
                out[di + 1] = rgb[si + 1];
                out[di + 2] = rgb[si + 2];
                out[di + 3] = 255;
            }
        }
    }
    (tw as u32, th as u32, out)
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled")
        .to_string()
}
