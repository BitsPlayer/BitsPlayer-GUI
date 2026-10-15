use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use iced::widget::image::Handle;
use iced::widget::{
    Space, button, checkbox, column, container, pick_list, responsive, row, scrollable, text,
};
use iced::widget::scrollable::{AbsoluteOffset, Viewport};
use iced::{Element, Fill, Font, Task};
use iframe_extract::decode::{ColorMatrix, Frame};
use iframe_extract::extract::{self, FrameRecord, Selection};
use rayon::prelude::*;

use crate::forensic::artifact::{ArtifactRecord, write_artifact_new};
use crate::forensic::context::ExtractionParameters;
use crate::presentation::analyze::CarveResult;
use crate::presentation::progress::ChannelReporter;
use crate::presentation::theme;
use crate::presentation::widgets::frame_grid::{self, Thumb};
use crate::presentation::widgets::file_map::AuClass;

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
    Matrix(MatrixChoice),
    ToggleNonIdr(bool),
    TogglePartial(bool),
    ToggleAllFrames(bool),
    Run,
    RunSingle(usize),
    Tick,
    Select(usize),
    ClosePreview,
    Save,
    GridScrolled(Viewport),
    ThumbsReady(u64, Vec<(usize, Handle)>),
    PreviewReady(u64, usize, Handle),
}

#[derive(Debug, Clone)]
pub enum SaveOutcome {
    Cancelled,
    Wrote(Vec<ArtifactRecord>),
    Failed(Vec<ArtifactRecord>),
}

struct DecodedFrame {
    record: FrameRecord,
    class: AuClass,
    frame: Frame,
}

struct Extracted {
    summary: String,
    frames: Arc<Vec<DecodedFrame>>,
    matrix: ColorMatrix,
}

const THUMB_SIDE: u32 = 200;
/// Thumbnails beyond this many are dropped when they are far from the viewport.
const THUMB_CACHE: usize = 600;

type Finished = Arc<Mutex<Option<Result<Extracted, String>>>>;

pub struct State {
    pub path: Option<PathBuf>,
    pub matrix: MatrixChoice,
    pub include_non_idr: bool,
    pub include_partial: bool,
    pub all_frames: bool,
    pub running: bool,
    pub error: Option<String>,
    pub status: String,
    pub selected: Option<usize>,
    pub source_evidence_sha256: Option<String>,
    pub artifacts: Vec<ArtifactRecord>,
    carve: Option<Arc<CarveResult>>,
    single: Option<usize>,
    progress: ChannelReporter,
    finished: Finished,
    result: Option<Extracted>,
    last_save: Option<SaveOutcome>,
    generation: u64,
    thumbs: HashMap<usize, Handle>,
    thumbs_pending: HashSet<usize>,
    scroll_y: f32,
    viewport: (f32, f32),
    preview: Option<Handle>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            path: None,
            matrix: MatrixChoice::Bt709,
            include_non_idr: false,
            include_partial: false,
            all_frames: false,
            running: false,
            error: None,
            status: String::from("Carve the stream in Analyze first"),
            selected: None,
            source_evidence_sha256: None,
            artifacts: Vec::new(),
            carve: None,
            single: None,
            progress: ChannelReporter::default(),
            finished: Arc::new(Mutex::new(None)),
            result: None,
            last_save: None,
            generation: 0,
            thumbs: HashMap::new(),
            thumbs_pending: HashSet::new(),
            scroll_y: 0.0,
            viewport: (1920.0, 900.0),
            preview: None,
        }
    }
}

impl State {
    pub fn has_carve(&self) -> bool {
        self.carve.is_some()
    }

    pub fn set_carve(&mut self, carve: Arc<CarveResult>) {
        self.path = Some(carve.path.clone());
        self.source_evidence_sha256 = Some(carve.sha256.clone());
        self.status = format!(
            "Carve loaded from Analyze ({}×{}, {} access units)",
            carve.analysis.width,
            carve.analysis.height,
            carve.analysis.access_units.len()
        );
        self.carve = Some(carve);
        self.single = None;
        self.artifacts.clear();
        self.clear_result();
        self.error = None;
    }

    fn clear_result(&mut self) {
        self.result = None;
        self.selected = None;
        self.preview = None;
        self.thumbs.clear();
        self.thumbs_pending.clear();
        self.generation += 1;
    }


    pub fn clear_carve(&mut self) {
        if self.running {
            return;
        }
        *self = Self {
            matrix: self.matrix,
            include_non_idr: self.include_non_idr,
            include_partial: self.include_partial,
            all_frames: self.all_frames,
            ..Self::default()
        };
    }

    pub fn set_mode(&mut self, single: Option<usize>) {
        self.single = single;
    }

    pub fn forensic_parameters(&self) -> Result<ExtractionParameters, String> {
        let carve = self
            .carve
            .as_ref()
            .ok_or_else(|| String::from("No carve analysis available"))?;
        let frame_offset = match self.single {
            Some(i) => Some(
                carve
                    .analysis
                    .access_units
                    .get(i)
                    .ok_or_else(|| String::from("Selected access unit does not exist"))?
                    .offset,
            ),
            None => None,
        };
        Ok(ExtractionParameters {
            width: carve.analysis.width,
            height: carve.analysis.height,
            matrix: self.matrix.to_string(),
            include_non_idr: self.include_non_idr,
            include_partial: self.include_partial,
            with_audio: carve.analysis.with_audio,
            all_frames: self.all_frames,
            frame_offset,
        })
    }

    pub fn validate_forensic_run(&self) -> Result<(), String> {
        if self.running {
            return Err(String::from("Extraction is already running"));
        }
        if self.carve.is_none() || self.path.is_none() {
            return Err(String::from(
                "No carve analysis. Carve the evidence in Analyze before extracting.",
            ));
        }
        if self.source_evidence_sha256.is_none() {
            return Err(String::from(
                "Evidence is not verified. Analyze and verify the MP4/MOV before forensic extraction.",
            ));
        }
        Ok(())
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        self.last_save = None;
        match message {
            Message::Matrix(m) => {
                if !self.running {
                    self.matrix = m;
                }
                Task::none()
            }
            Message::ToggleNonIdr(v) => {
                if !self.running {
                    self.include_non_idr = v;
                }
                Task::none()
            }
            Message::TogglePartial(v) => {
                if !self.running {
                    self.include_partial = v;
                }
                Task::none()
            }
            Message::ToggleAllFrames(v) => {
                if !self.running {
                    self.all_frames = v;
                }
                Task::none()
            }
            Message::Run => {
                self.single = None;
                self.start_extract()
            }
            Message::RunSingle(i) => {
                self.single = Some(i);
                self.start_extract()
            }
            Message::Tick => {
                let finished = self.finished.lock().ok().and_then(|mut g| g.take());
                if let Some(result) = finished {
                    self.running = false;
                    match result {
                        Ok(extracted) => {
                            self.status = extracted.summary.clone();
                            let single = self.single.is_some() && !extracted.frames.is_empty();
                            self.result = Some(extracted);
                            self.error = None;
                            self.scroll_y = 0.0;
                            let mut tasks = vec![
                                scrollable::scroll_to(grid_id(), AbsoluteOffset { x: 0.0, y: 0.0 }),
                                self.request_thumbs(),
                            ];
                            if single {
                                tasks.push(self.open_preview(0));
                            }
                            return Task::batch(tasks);
                        }
                        Err(err) => {
                            self.error = Some(err);
                            self.status = String::from("Extraction failed");
                        }
                    }
                } else if self.running {
                    if let Ok(g) = self.progress.inner.lock() {
                        self.status = format!("{}  {}%  {}", g.phase, g.percent(), g.detail);
                    }
                }
                Task::none()
            }
            Message::Select(i) => self.open_preview(i),
            Message::ClosePreview => {
                self.selected = None;
                self.preview = None;
                Task::none()
            }
            Message::GridScrolled(viewport) => {
                self.scroll_y = viewport.absolute_offset().y;
                let bounds = viewport.bounds();
                self.viewport = (bounds.width, bounds.height);
                self.request_thumbs()
            }
            Message::ThumbsReady(generation, thumbs) => {
                if generation == self.generation {
                    for (position, handle) in thumbs {
                        self.thumbs_pending.remove(&position);
                        self.thumbs.insert(position, handle);
                    }
                    self.evict_thumbs();
                }
                Task::none()
            }
            Message::PreviewReady(generation, position, handle) => {
                if generation == self.generation && self.selected == Some(position) {
                    self.preview = Some(handle);
                }
                Task::none()
            }
            Message::Save => {
                self.last_save = Some(self.save_frames());
                Task::none()
            }
        }
    }

    fn start_extract(&mut self) -> Task<Message> {
        if let Err(err) = self.validate_forensic_run() {
            self.error = Some(err.clone());
            self.status = err;
            return Task::none();
        }
        let Some(carve) = self.carve.clone() else {
            return Task::none();
        };

        let selection = match self.single {
            Some(i) => {
                if i >= carve.analysis.access_units.len() {
                    self.error = Some(String::from("Selected access unit does not exist"));
                    return Task::none();
                }
                Selection::Single(i)
            }
            None => Selection::Filtered {
                include_non_idr: self.include_non_idr,
                include_partial: self.include_partial,
                all_frames: self.all_frames,
            },
        };

        self.running = true;
        self.error = None;
        self.clear_result();
        self.status = String::from("Starting extraction…");
        if let Ok(mut g) = self.progress.inner.lock() {
            g.reset("starting");
        }
        if let Ok(mut g) = self.finished.lock() {
            *g = None;
        }

        let matrix = self.matrix.to_matrix();
        let finished = Arc::clone(&self.finished);
        let mut reporter = self.progress.clone();
        std::thread::spawn(move || {
            let outcome = run_decode(&carve, &selection, matrix, &mut reporter);
            if let Ok(mut g) = finished.lock() {
                *g = Some(outcome);
            }
        });
        Task::none()
    }

    /// Positions of the frames in the rows currently on screen, plus one screen either side.
    fn visible_range(&self) -> std::ops::Range<usize> {
        let Some(result) = &self.result else {
            return 0..0;
        };
        let cols = frame_grid::columns_for(self.viewport.0);
        let first_row = ((self.scroll_y - self.viewport.1) / frame_grid::ROW_STRIDE)
            .floor()
            .max(0.0) as usize;
        let last_row = ((self.scroll_y + 2.0 * self.viewport.1) / frame_grid::ROW_STRIDE).ceil()
            as usize;
        let n = result.frames.len();
        (first_row * cols).min(n)..(last_row * cols + cols).min(n)
    }

    fn request_thumbs(&mut self) -> Task<Message> {
        let Some(result) = &self.result else {
            return Task::none();
        };
        let wanted: Vec<usize> = self
            .visible_range()
            .filter(|p| !self.thumbs.contains_key(p) && !self.thumbs_pending.contains(p))
            .collect();
        if wanted.is_empty() {
            return Task::none();
        }
        self.thumbs_pending.extend(wanted.iter().copied());
        let frames = Arc::clone(&result.frames);
        let matrix = result.matrix;
        let generation = self.generation;
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    wanted
                        .into_par_iter()
                        .map(|p| {
                            let f = &frames[p].frame;
                            (p, handle_from_rgb(&f.to_rgb(matrix), f.width, f.height, THUMB_SIDE))
                        })
                        .collect::<Vec<_>>()
                })
                .await
                .unwrap_or_default()
            },
            move |thumbs| Message::ThumbsReady(generation, thumbs),
        )
    }

    fn evict_thumbs(&mut self) {
        if self.thumbs.len() <= THUMB_CACHE {
            return;
        }
        let keep = self.visible_range();
        self.thumbs.retain(|p, _| keep.contains(p));
    }

    fn open_preview(&mut self, position: usize) -> Task<Message> {
        let Some(result) = &self.result else {
            return Task::none();
        };
        if position >= result.frames.len() || self.selected == Some(position) {
            return Task::none();
        }
        self.selected = Some(position);
        self.preview = None;
        let frames = Arc::clone(&result.frames);
        let matrix = result.matrix;
        let generation = self.generation;
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let f = &frames[position].frame;
                    Handle::from_rgba(
                        f.width as u32,
                        f.height as u32,
                        rgb_to_rgba(&f.to_rgb(matrix)),
                    )
                })
                .await
                .ok()
            },
            move |handle| match handle {
                Some(handle) => Message::PreviewReady(generation, position, handle),
                None => Message::ClosePreview,
            },
        )
    }

    pub fn preview_title(&self) -> String {
        self.selected_frame()
            .map(|f| format!("Frame {:05} · offset {}", f.record.index, f.record.offset))
            .unwrap_or_else(|| String::from("Frame preview"))
    }

    fn selected_frame(&self) -> Option<&DecodedFrame> {
        let result = self.result.as_ref()?;
        result.frames.get(self.selected?)
    }

    pub fn preview_window_view(&self) -> Element<'_, Message> {
        let caption = self
            .selected_frame()
            .map(|f| {
                format!(
                    "frame {:05}  offset {}  {}×{}  src {}{}",
                    f.record.index,
                    f.record.offset,
                    f.frame.width,
                    f.frame.height,
                    iframe_extract::report::human_bytes(f.record.source_size),
                    if f.record.partial { "  partial" } else { "" }
                )
            })
            .unwrap_or_default();
        container(frame_grid::preview(self.preview.clone(), caption))
            .width(Fill)
            .height(Fill)
            .style(theme::panel)
            .into()
    }

    fn save_frames(&mut self) -> SaveOutcome {
        let Some(source_evidence_sha256) = self.source_evidence_sha256.clone() else {
            self.error = Some(String::from(
                "Cannot save forensic artifacts: source evidence is not verified",
            ));
            return SaveOutcome::Failed(Vec::new());
        };
        let Some(result) = &self.result else {
            self.error = Some(String::from("Nothing to save yet"));
            return SaveOutcome::Failed(Vec::new());
        };
        let Some(dir) = rfd::FileDialog::new().pick_folder() else {
            return SaveOutcome::Cancelled;
        };
        if let Err(err) = std::fs::create_dir_all(&dir) {
            self.error = Some(err.to_string());
            return SaveOutcome::Failed(Vec::new());
        }
        let matrix = result.matrix;
        let pngs = match result
            .frames
            .par_iter()
            .map(|d| encode_png(d.frame.to_rgb(matrix), d.frame.width, d.frame.height))
            .collect::<Result<Vec<_>, String>>()
        {
            Ok(pngs) => pngs,
            Err(err) => {
                self.error = Some(format!("PNG encoding failed: {err}"));
                return SaveOutcome::Failed(Vec::new());
            }
        };
        let mut new_artifacts = Vec::new();
        for (decoded, png) in result.frames.iter().zip(&pngs) {
            let stem = format!(
                "frame_{:05}_off_{:010}{}",
                decoded.record.index,
                decoded.record.offset,
                if decoded.record.partial { "_partial" } else { "" }
            );
            let path = dir.join(format!("{stem}.png"));
            let artifact = match write_artifact_new(
                &path,
                png,
                "RECOVERED_FRAME_PNG",
                source_evidence_sha256.clone(),
            ) {
                Ok(artifact) => artifact,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.artifacts = new_artifacts.clone();
                    self.error = Some(format!(
                        "Refusing to overwrite existing forensic artifact: {}",
                        path.display()
                    ));
                    self.status = String::from(
                        "Artifact export stopped: existing file detected",
                    );
                    return SaveOutcome::Failed(new_artifacts);
                }
                Err(err) => {
                    self.artifacts = new_artifacts.clone();
                    self.error = Some(format!(
                        "Writing forensic artifact {} failed: {err}",
                        path.display()
                    ));
                    self.status = String::from("Artifact export failed");
                    return SaveOutcome::Failed(new_artifacts);
                }
            };
            new_artifacts.push(artifact);
        }
        let count = new_artifacts.len();
        self.artifacts = new_artifacts.clone();
        self.error = None;
        self.status = format!(
            "{count} forensic artifacts saved and SHA-256 hashed in {}",
            dir.display()
        );
        SaveOutcome::Wrote(new_artifacts)
    }
    pub fn take_last_save(&mut self) -> Option<SaveOutcome> {
        self.last_save.take()
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
        let matrix_control: Element<'_, Message> = if self.running {
            text(self.matrix.to_string())
                .size(14)
                .color(theme::MUTED)
                .into()
        } else {
            pick_list(MatrixChoice::ALL, Some(self.matrix), Message::Matrix)
                .padding(8)
                .width(110)
                .into()
        };

        let carve_info = match &self.carve {
            Some(c) => format!(
                "Carve {}×{} · {} access units",
                c.analysis.width,
                c.analysis.height,
                c.analysis.access_units.len()
            ),
            None => String::from("No carve"),
        };

        let flags = row![
            checkbox("Include all I-frames", self.include_non_idr)
                .on_toggle_maybe((!self.running).then_some(Message::ToggleNonIdr))
                .size(16)
                .text_size(13),
            checkbox("Include partial", self.include_partial)
                .on_toggle_maybe((!self.running).then_some(Message::TogglePartial))
                .size(16)
                .text_size(13),
            checkbox("All frames", self.all_frames)
                .on_toggle_maybe((!self.running).then_some(Message::ToggleAllFrames))
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
        .on_press_maybe((!self.running && self.carve.is_some()).then_some(Message::Run))
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
            row![
                text(carve_info)
                    .size(13)
                    .font(Font::MONOSPACE)
                    .color(theme::MUTED),
                matrix_control,
                flags,
                Space::with_width(Fill),
                run,
                save
            ]
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

    fn result_view<'a>(&'a self, result: &'a Extracted) -> Element<'a, Message> {
        let n = result.frames.len();
        let selected = self.selected;
        let scroll_y = self.scroll_y;
        let viewport_h = self.viewport.1;
        let grid = responsive(move |size| {
            let cols = frame_grid::columns_for(size.width);
            let total_rows = n.div_ceil(cols);
            let height = if viewport_h > 0.0 { viewport_h } else { size.height };
            let first_row = ((scroll_y / frame_grid::ROW_STRIDE).floor().max(0.0) as usize)
                .saturating_sub(1)
                .min(total_rows);
            let last_row = (((scroll_y + height) / frame_grid::ROW_STRIDE).ceil() as usize + 1)
                .min(total_rows);
            let visible = (first_row * cols..(last_row * cols).min(n))
                .map(|p| {
                    let f = &result.frames[p];
                    Thumb {
                        position: p,
                        index: f.record.index,
                        offset: f.record.offset,
                        source_size: f.record.source_size,
                        partial: f.record.partial,
                        class: f.class,
                        handle: self.thumbs.get(&p).cloned(),
                    }
                })
                .collect();
            scrollable(frame_grid::view(
                visible,
                first_row,
                total_rows,
                selected,
                cols,
                Message::Select,
            ))
            .id(grid_id())
            .on_scroll(Message::GridScrolled)
            .width(Fill)
            .height(Fill)
            .into()
        });
        container(grid).padding(12).width(Fill).height(Fill).into()
    }
    fn empty_state(&self) -> Element<'_, Message> {
        column![
            text("No frames yet").size(18).color(theme::TEXT),
            text("Run the carve in Analyze first. Extract decodes the carved access units, or a single frame chosen in the Analyze grid.")
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
let (done, total) = if let Ok(g) = state.progress.inner.lock() {
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

fn run_decode(
    carve: &CarveResult,
    selection: &Selection,
    matrix: ColorMatrix,
    reporter: &mut ChannelReporter,
) -> Result<Extracted, String> {
    let name = carve.path.display().to_string();
    let extraction = extract::decode(&carve.data, &carve.analysis, selection, &name, reporter)
        .map_err(|e| e.to_string())?;

    let frames: Vec<DecodedFrame> = extraction
        .frames
        .into_iter()
        .map(|(record, frame)| {
            let class = match carve
                .analysis
                .access_units
                .iter()
                .find(|au| au.offset == record.offset)
            {
                Some(au) if au.is_idr => AuClass::Idr,
                Some(au) if au.is_intra => AuClass::Intra,
                _ => AuClass::Inter,
            };
            DecodedFrame { record, class, frame }
        })
        .collect();

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
            "{} · {} NALs · {} frames · chain broke at {off} ({:.2}% of file){skipped}",
            r.codec.label(),
            r.nal_count,
            frames.len(),
            off as f64 / carve.data.len().max(1) as f64 * 100.0
        ),
        None => format!(
            "{} · {} NALs · {} frames · chain ran to end of mdat{skipped}",
            r.codec.label(),
            r.nal_count,
            frames.len()
        ),
    };
    Ok(Extracted {
        summary,
        frames: Arc::new(frames),
        matrix,
    })
}

fn encode_png(rgb: Vec<u8>, w: usize, h: usize) -> Result<Vec<u8>, String> {
let img = image::RgbImage::from_raw(w as u32, h as u32, rgb)
        .ok_or("frame dimensions did not match buffer")?;
let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .map_err(|e| e.to_string())?;
    Ok(out)
}
fn grid_id() -> scrollable::Id {
    scrollable::Id::new("extract-grid")
}

fn rgb_to_rgba(rgb: &[u8]) -> Vec<u8> {
    rgb.chunks_exact(3)
        .flat_map(|p| [p[0], p[1], p[2], 255])
        .collect()
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
