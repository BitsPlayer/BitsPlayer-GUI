use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitplay::Analysis;
use iframe_extract::extract::{CarveAnalysis, CarveOptions};
use sha2::{Digest, Sha256};

use iced::widget::canvas::Canvas;
use iced::widget::{
    button,
    checkbox,
    column,
    container,
    progress_bar,
    row,
    scrollable,
    text,
    text_input,
    Space,
};
use iced::{Element, Fill, Font, Task};

use crate::domain::evidence::VerifiedCopy;
use crate::forensic::context::CarveParameters;
use crate::forensic::evidence::{
    EvidenceRecord,
    IntegrityStatus,
};

use crate::presentation::progress::ChannelReporter;
use crate::presentation::theme;

use crate::presentation::widgets::file_map::{
    FileMap,
    MapKind,
    MapMessage,
    MapSpan,
};

use crate::presentation::widgets::hex_view;

#[derive(Debug, Clone)]
pub enum Message {
    Browse,

    CopyRequested(
        PathBuf,
    ),

    CopyReady(
        Result<VerifiedCopy, String>,
    ),

    /*
     * Evidence registration/hashing finishes first.
     *
     * App can audit EVIDENCE_REGISTERED and
     * ANALYSIS_STARTED before actual analysis begins.
     */
    EvidenceReady(
        Result<EvidenceRecord, String>,
    ),

    /*
     * Analysis now returns both the BitPlay analysis
     * and the verified EvidenceRecord.
     */
    Finished(
        Result<
            (
                Analysis,
                EvidenceRecord,
            ),
            String,
        >,
    ),

    MapHover(
        Option<String>,
    ),

    MapSelect(
        usize,
    ),

    HexReady {
        seq: u64,

        result:
            Result<
                (
                    Vec<u8>,
                    u64,
                ),
                String,
            >,
    },

    CloseHex,

    OpenExtract,

    CarveWidth(
        String,
    ),

    CarveHeight(
        String,
    ),

    CarveAudio(
        bool,
    ),

    Carve,

    CarveTick,

    CarveFinished(
        Result<
            Arc<CarveResult>,
            String,
        >,
    ),

    SetLayout(
        Layout,
    ),

    ExtractSelected(
        usize,
    ),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    Moov,
    Carved,
}

#[derive(Debug)]
pub struct CarveResult {
    pub data: Arc<Vec<u8>>,

    pub analysis: CarveAnalysis,

    pub path: PathBuf,

    pub sha256: String,
}

enum HexPane {
    Closed,

    Loading {
        span: MapSpan,
    },

    Ready {
        span: MapSpan,
        shown: u64,
        bytes: Arc<Vec<u8>>,
    },

    Failed {
        span: MapSpan,
        error: String,
    },
}

pub struct State {
    pub path: Option<PathBuf>,

    pub busy: bool,

    pub error: Option<String>,

    pub analysis: Option<Analysis>,

    /*
     * Forensic identity of the currently selected
     * evidence file.
     */
    pub evidence:
        Option<EvidenceRecord>,

    pub moov_map: Option<FileMap>,

    pub carve_map: Option<FileMap>,

    pub layout: Layout,

    pub width: String,

    pub height: String,

    pub with_audio: bool,

    pub carving: bool,

    pub carve: Option<Arc<CarveResult>>,

    carve_progress: ChannelReporter,

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

            moov_map: None,

            carve_map: None,

            layout: Layout::Moov,

            width: String::new(),

            height: String::new(),

            with_audio: false,

            carving: false,

            carve: None,

            carve_progress: ChannelReporter::default(),

            status:
                String::from(
                    "Open an MP4 to map its layout",
                ),

            hex:
                HexPane::Closed,

            hex_gen:
                0,
        }
    }
}

impl State {
    pub fn update(
        &mut self,
        message: Message,
    ) -> Task<Message> {
        match message {
            /*
             * ------------------------------------------------
             * STEP 1
             *
             * Choose evidence and register/hash it.
             * No MP4 analysis is performed yet.
             * ------------------------------------------------
             */
            Message::Browse => {
                let picked =
                    rfd::FileDialog::new()
                        .add_filter(
                            "MP4 video",
                            &[
                                "mp4",
                                "m4v",
                                "mov",
                            ],
                        )
                        .pick_file();

                let Some(path) =
                    picked
                else {
                    return Task::none();
                };

                self.path =
                    Some(
                        path.clone(),
                    );

                self.busy =
                    true;

                self.error =
                    None;

                self.analysis =
                    None;

                self.evidence =
                    None;

                self.moov_map =
                    None;

                self.carve_map =
                    None;

                self.carve =
                    None;

                self.carving =
                    false;

                self.layout =
                    Layout::Moov;

                self.width.clear();

                self.height.clear();

                self.close_hex();

                self.status =
                    format!(
                        "Copying evidence {}…",
                        display_name(
                            &path,
                        )
                    );

                Task::done(
                    Message::CopyRequested(
                        path,
                    ),
                )
            }

            /*
             * The App layer performs and audits the copy.
             */
            Message::CopyRequested(
                _,
            ) => {
                Task::none()
            }

            Message::CopyReady(
                result,
            ) => {
                match result {
                    Ok(copy) => {
                        let path =
                            copy.copy_path;

                        self.status =
                            format!(
                                "Registering evidence {}…",
                                self.path
                                    .as_deref()
                                    .map(display_name)
                                    .unwrap_or_default(),
                            );

                        Task::perform(
                            async move {
                                match tokio::task::spawn_blocking(
                                    move || {
                                        EvidenceRecord::from_path(
                                            &path,
                                        )
                                        .map_err(
                                            |e| {
                                                format!(
                                                    "Evidence registration failed: {e}"
                                                )
                                            },
                                        )
                                    },
                                )
                                .await
                                {
                                    Ok(result) => {
                                        result
                                    }

                                    Err(e) => {
                                        Err(
                                            format!(
                                                "Evidence registration task failed: {e}"
                                            ),
                                        )
                                    }
                                }
                            },

                            Message::EvidenceReady,
                        )
                    }

                    Err(error) => {
                        self.busy =
                            false;

                        self.error =
                            Some(
                                error,
                            );

                        self.status =
                            String::from(
                                "Evidence copy failed",
                            );

                        Task::none()
                    }
                }
            }

            /*
             * ------------------------------------------------
             * STEP 2
             *
             * Evidence has now been hashed and registered.
             *
             * The App layer sees this message first and writes:
             *
             * EVIDENCE_REGISTERED
             * ANALYSIS_STARTED
             *
             * Only then does this handler begin BitPlay analysis.
             * ------------------------------------------------
             */
            Message::EvidenceReady(
                result,
            ) => {
                match result {
                    Ok(evidence) => {
                        let Some(path) =
                            self.path.clone()
                        else {
                            self.busy =
                                false;

                            self.error =
                                Some(
                                    String::from(
                                        "Evidence path is missing",
                                    ),
                                );

                            self.status =
                                String::from(
                                    "Analysis failed",
                                );

                            return Task::none();
                        };

                        let analysis_path =
                            evidence.path.clone();

                        /*
                         * Keep the registered evidence identity
                         * available immediately for the App/audit
                         * layer.
                         */
                        self.evidence =
                            Some(
                                evidence.clone(),
                            );

                        self.status =
                            format!(
                                "Analyzing {}…",
                                display_name(
                                    &path,
                                )
                            );

                        Task::perform(
                            async move {
                                match tokio::task::spawn_blocking(
                                    move || {
                                        let mut evidence =
                                            evidence;

                                        /*
                                         * Original evidence SHA-256,
                                         * calculated before analysis.
                                         */
                                        let before_sha256 =
                                            evidence
                                                .sha256
                                                .clone();

                                        /*
                                         * BitPlay currently accepts only
                                         * a path, so it will internally
                                         * reopen the file.
                                         */
                                        let analysis =
                                            bitplay::analyze(
                                                &analysis_path,
                                            )
                                            .map_err(
                                                |e| {
                                                    format!(
                                                        "MP4 analysis failed: {e}"
                                                    )
                                                },
                                            )?;

                                        /*
                                         * ------------------------------------------------
                                         * ISSUE #4 HARDENING
                                         *
                                         * Immediately after BitPlay finishes,
                                         * verify:
                                         *
                                         * - file size
                                         * - modification time
                                         * - inode/device on Unix
                                         * - SHA-256
                                         *
                                         * against the pre-analysis evidence.
                                         * ------------------------------------------------
                                         */
                                        let unchanged =
                                            evidence
                                                .verify_unchanged_since(
                                                    &before_sha256,
                                                )
                                                .map_err(
                                                    |e| {
                                                        format!(
                                                            "Post-analysis evidence verification failed: {e}"
                                                        )
                                                    },
                                                )?;

                                        if !unchanged {
                                            return Err(
                                                String::from(
                                                    "CRITICAL: Evidence changed during analysis",
                                                ),
                                            );
                                        }

                                        /*
                                         * Perform the normal full forensic
                                         * integrity verification as well.
                                         */
                                        let status =
                                            evidence
                                                .verify_integrity()
                                                .map_err(
                                                    |e| {
                                                        format!(
                                                            "Evidence integrity verification failed: {e}"
                                                        )
                                                    },
                                                )?;

                                        if status
                                            != IntegrityStatus::Verified
                                        {
                                            return Err(
                                                String::from(
                                                    "CRITICAL: Evidence integrity verification failed",
                                                ),
                                            );
                                        }

                                        Ok::<
                                            (
                                                Analysis,
                                                EvidenceRecord,
                                            ),
                                            String,
                                        >((
                                            analysis,
                                            evidence,
                                        ))
                                    },
                                )
                                .await
                                {
                                    Ok(result) => {
                                        result
                                    }

                                    Err(e) => {
                                        Err(
                                            format!(
                                                "Background analysis task failed: {e}"
                                            ),
                                        )
                                    }
                                }
                            },

                            Message::Finished,
                        )
                    }

                    Err(err) => {
                        self.busy =
                            false;

                        self.error =
                            Some(
                                err,
                            );

                        self.status =
                            String::from(
                                "Evidence registration failed",
                            );

                        Task::none()
                    }
                }
            }

            /*
             * ------------------------------------------------
             * STEP 3
             *
             * Analysis and post-analysis integrity
             * verification have finished.
             * ------------------------------------------------
             */
            Message::Finished(
                result,
            ) => {
                self.busy =
                    false;

                self.close_hex();

                match result {
                    Ok((
                        analysis,
                        evidence,
                    )) => {
                        self.moov_map =
                            Some(
                                FileMap::from_analysis(
                                    &analysis,
                                ),
                            );

                        self.layout =
                            Layout::Moov;

                        if let Some(v) =
                            &analysis.video
                        {
                            if v.width > 0 {
                                self.width =
                                    v.width.to_string();
                            }

                            if v.height > 0 {
                                self.height =
                                    v.height.to_string();
                            }
                        }

                        self.status =
                            if analysis
                                .moov_present
                            {
                                format!(
                                    "{} · {} · Integrity verified",
                                    display_name(
                                        &analysis.path,
                                    ),
                                    bitplay::human_bytes(
                                        analysis.file_size,
                                    )
                                )
                            } else {
                                String::from(
                                    "No moov index — layout is incomplete. Evidence integrity verified. Carve the stream to map access units.",
                                )
                            };

                        self.analysis =
                            Some(
                                analysis,
                            );

                        self.evidence =
                            Some(
                                evidence,
                            );

                        self.error =
                            None;
                    }

                    Err(err) => {
                        /*
                         * Keep the previously registered
                         * EvidenceRecord in self.evidence so
                         * App can still associate the failure
                         * with the correct evidence SHA-256.
                         */
                        self.error =
                            Some(
                                err,
                            );

                        self.status =
                            String::from(
                                "Analysis failed",
                            );
                    }
                }

                Task::none()
            }

            Message::MapHover(
                status,
            ) => {
                if let Some(line) =
                    status
                {
                    self.status =
                        line;
                } else if let Some(span) =
                    self.hex_span()
                {
                    self.status =
                        format!(
                            "{} · off {} (0x{:08X})",
                            span.status_line(),
                            span.offset,
                            span.offset
                        );
                } else if let Some(
                    analysis,
                ) = &self.analysis
                {
                    self.status =
                        format!(
                            "{} · {}",
                            display_name(
                                &analysis.path,
                            ),
                            bitplay::human_bytes(
                                analysis.file_size,
                            )
                        );
                }

                Task::none()
            }

            Message::MapSelect(
                index,
            ) => {
                self.open_hex(
                    index,
                )
            }

            Message::HexReady {
                seq,
                result,
            } => {
                if seq
                    != self.hex_gen
                {
                    return Task::none();
                }

                let HexPane::Loading {
                    span,
                } = &self.hex
                else {
                    return Task::none();
                };

                let span =
                    span.clone();

                self.hex =
                    match result {
                        Ok((
                            bytes,
                            shown,
                        )) => {
                            HexPane::Ready {
                                span,

                                shown,

                                bytes:
                                    Arc::new(
                                        bytes,
                                    ),
                            }
                        }

                        Err(error) => {
                            HexPane::Failed {
                                span,
                                error,
                            }
                        }
                    };

                Task::none()
            }

            Message::CloseHex => {
                self.close_hex();

                Task::none()
            }

            Message::OpenExtract => {
                Task::none()
            }

            Message::ExtractSelected(
                _,
            ) => {
                Task::none()
            }

            Message::CarveWidth(
                v,
            ) => {
                if !self.carving {
                    self.width =
                        v;
                }

                Task::none()
            }

            Message::CarveHeight(
                v,
            ) => {
                if !self.carving {
                    self.height =
                        v;
                }

                Task::none()
            }

            Message::CarveAudio(
                v,
            ) => {
                if !self.carving {
                    self.with_audio =
                        v;
                }

                Task::none()
            }

            Message::Carve => {
                self.start_carve()
            }

            Message::CarveTick => {
                if self.carving
                    && let Ok(g) =
                        self.carve_progress.inner.lock()
                {
                    self.status =
                        format!(
                            "{}  {}%  {}",
                            g.phase,
                            g.percent(),
                            g.detail,
                        );
                }

                Task::none()
            }

            Message::CarveFinished(
                result,
            ) => {
                self.carving =
                    false;

                match result {
                    Ok(carve) => {
                        self.carve_map =
                            Some(
                                FileMap::from_carve(
                                    &carve.analysis,
                                    carve.data.len() as u64,
                                ),
                            );

                        self.status =
                            carve_summary(
                                &carve.analysis,
                                carve.data.len() as u64,
                            );

                        self.carve =
                            Some(
                                carve,
                            );

                        self.layout =
                            Layout::Carved;

                        self.error =
                            None;

                        self.close_hex();
                    }

                    Err(err) => {
                        self.error =
                            Some(
                                err,
                            );

                        self.status =
                            String::from(
                                "Carve failed",
                            );
                    }
                }

                Task::none()
            }

            Message::SetLayout(
                layout,
            ) => {
                let available =
                    match layout {
                        Layout::Moov => {
                            self.moov_map.is_some()
                                && self
                                    .analysis
                                    .as_ref()
                                    .is_some_and(
                                        |a| a.moov_present,
                                    )
                        }

                        Layout::Carved => {
                            self.carve_map.is_some()
                        }
                    };

                if available
                    && self.layout != layout
                {
                    self.layout =
                        layout;

                    self.close_hex();
                }

                Task::none()
            }
        }
    }

    pub fn carve_request(
        &self,
    ) -> Result<
        CarveParameters,
        String,
    > {
        if self.busy
            || self.carving
        {
            return Err(
                String::from(
                    "Analysis or carve already running",
                ),
            );
        }

        let verified =
            self.evidence
                .as_ref()
                .is_some_and(
                    |e| {
                        e.integrity_status
                            == IntegrityStatus::Verified
                    },
                );

        if !verified {
            return Err(
                String::from(
                    "Carve is blocked until evidence integrity is verified",
                ),
            );
        }

        let width =
            match self.width.trim().parse::<u32>() {
                Ok(w) if w > 0 => w,

                _ => {
                    return Err(
                        String::from(
                            "Enter a valid width — required when SPS is lost",
                        ),
                    );
                }
            };

        let height =
            match self.height.trim().parse::<u32>() {
                Ok(h) if h > 0 => h,

                _ => {
                    return Err(
                        String::from(
                            "Enter a valid height — required when SPS is lost",
                        ),
                    );
                }
            };

        Ok(
            CarveParameters {
                width,
                height,
                with_audio:
                    self.with_audio,
            },
        )
    }

    fn start_carve(
        &mut self,
    ) -> Task<Message> {
        let parameters =
            match self.carve_request() {
                Ok(p) => p,

                Err(err) => {
                    self.error =
                        Some(
                            err,
                        );

                    return Task::none();
                }
            };

        let Some(evidence) =
            self.evidence
                .clone()
        else {
            return Task::none();
        };

        self.carving =
            true;

        self.error =
            None;

        self.status =
            String::from(
                "Starting carve…",
            );

        if let Ok(mut g) =
            self.carve_progress.inner.lock()
        {
            g.reset(
                "starting",
            );
        }

        let mut reporter =
            self.carve_progress.clone();

        Task::perform(
            async move {
                match tokio::task::spawn_blocking(
                    move || {
                        run_carve(
                            &evidence,
                            &parameters,
                            &mut reporter,
                        )
                    },
                )
                .await
                {
                    Ok(result) => {
                        result
                    }

                    Err(e) => {
                        Err(
                            format!(
                                "Carve task failed: {e}"
                            ),
                        )
                    }
                }
            },

            Message::CarveFinished,
        )
    }

    fn active_map(
        &self,
    ) -> Option<&FileMap> {
        match self.layout {
            Layout::Moov => {
                self.moov_map.as_ref()
            }

            Layout::Carved => {
                self.carve_map.as_ref()
            }
        }
    }

    fn active_map_mut(
        &mut self,
    ) -> Option<&mut FileMap> {
        match self.layout {
            Layout::Moov => {
                self.moov_map.as_mut()
            }

            Layout::Carved => {
                self.carve_map.as_mut()
            }
        }
    }

    pub fn view(
        &self,
    ) -> Element<'_, Message> {
        let rail =
            container(
                self.rail(),
            )
            .width(
                320,
            )
            .padding(
                16,
            )
            .height(
                Fill,
            )
            .style(
                theme::panel,
            );

        let map =
            if let Some(map) =
                self.active_map()
            {
                container(
                    Element::<MapMessage>::from(
                        Canvas::new(
                            map.clone(),
                        )
                        .width(
                            Fill,
                        )
                        .height(
                            Fill,
                        ),
                    )
                    .map(
                        |msg| {
                            match msg {
                                MapMessage::Hover(
                                    s,
                                ) => {
                                    Message::MapHover(
                                        s,
                                    )
                                }

                                MapMessage::Select(
                                    i,
                                ) => {
                                    Message::MapSelect(
                                        i,
                                    )
                                }
                            }
                        },
                    ),
                )
                .padding(
                    8,
                )
                .width(
                    Fill,
                )
                .height(
                    Fill,
                )
                .style(
                    theme::map_well,
                )
            } else {
                container(
                    self.empty_state(),
                )
                .width(
                    Fill,
                )
                .height(
                    Fill,
                )
                .center_x(
                    Fill,
                )
                .center_y(
                    Fill,
                )
                .style(
                    theme::map_well,
                )
            };

        let status =
            container(
                text(
                    &self.status,
                )
                .size(
                    13,
                )
                .font(
                    Font::MONOSPACE,
                )
                .color(
                    theme::MUTED,
                ),
            )
            .width(
                Fill,
            )
            .padding([
                8,
                14,
            ])
            .style(
                theme::status_bar,
            );

        let main =
            column![
                map,
                status
            ]
            .height(
                Fill,
            );

        row![
            rail,
            main
        ]
        .height(
            Fill,
        )
        .into()
    }

    fn open_hex(
        &mut self,
        index: usize,
    ) -> Task<Message> {
        let Some(span) =
            self.active_map()
                .and_then(
                    |map| map.spans.get(index).cloned(),
                )
        else {
            return Task::none();
        };

        if let Some(map) =
            self.active_map()
            && map.selected
                == Some(index)
            && matches!(
                self.hex,
                HexPane::Ready {
                    ..
                }
                    | HexPane::Loading {
                        ..
                    }
            )
        {
            return Task::none();
        }

        if let Some(map) =
            self.active_map_mut()
        {
            map.selected =
                Some(
                    index,
                );
        }

        self.status =
            format!(
                "{} · off {} (0x{:08X})",
                span.status_line(),
                span.offset,
                span.offset
            );

        self.hex_gen =
            self.hex_gen
                .wrapping_add(
                    1,
                );

        let seq =
            self.hex_gen;

        self.hex =
            HexPane::Loading {
                span:
                    span.clone(),
            };

        let Some(path) =
            self.evidence
                .as_ref()
                .map(|evidence| evidence.path.clone())
        else {
            self.hex =
                HexPane::Failed {
                    span,

                    error:
                        String::from(
                            "No file path",
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

                    Err(e) => {
                        Err(
                            e.to_string(),
                        )
                    }
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

    fn close_hex(
        &mut self,
    ) {
        self.hex =
            HexPane::Closed;

        for map in [
            self.moov_map.as_mut(),
            self.carve_map.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            map.selected =
                None;
        }
    }

    fn hex_span(
        &self,
    ) -> Option<&MapSpan> {
        match &self.hex {
            HexPane::Closed => {
                None
            }

            HexPane::Loading {
                span,
            }
            | HexPane::Ready {
                span,
                ..
            }
            | HexPane::Failed {
                span,
                ..
            } => {
                Some(
                    span,
                )
            }
        }
    }

    pub fn hex_is_open(
        &self,
    ) -> bool {
        !matches!(
            self.hex,
            HexPane::Closed
        )
    }

    pub fn hex_title(
        &self,
    ) -> String {
        match self.hex_span() {
            Some(span) => {
                format!(
                    "Hex · {}",
                    span.kind.label()
                )
            }

            None => {
                String::from(
                    "Hex",
                )
            }
        }
    }

    pub fn hex_window_view(
        &self,
    ) -> Element<'_, Message> {
        let (
            span,
            body,
            note,
        ) =
            match &self.hex {
                HexPane::Closed => {
                    return container(
                        text(
                            "No block selected",
                        )
                        .color(
                            theme::MUTED,
                        ),
                    )
                    .width(
                        Fill,
                    )
                    .height(
                        Fill,
                    )
                    .center_x(
                        Fill,
                    )
                    .center_y(
                        Fill,
                    )
                    .style(
                        theme::panel,
                    )
                    .into();
                }

                HexPane::Loading {
                    span,
                } => (
                    span,

                    text(
                        "Reading bytes…",
                    )
                    .size(
                        13,
                    )
                    .font(
                        Font::MONOSPACE,
                    )
                    .color(
                        theme::MUTED,
                    )
                    .into(),

                    None,
                ),

                HexPane::Failed {
                    span,
                    error,
                } => (
                    span,

                    text(
                        error,
                    )
                    .size(
                        13,
                    )
                    .color(
                        theme::DANGER,
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
                        (
                            *shown
                                < span.size
                        )
                        .then(
                            || {
                                format!(
                                    "showing first {} of {}",
                                    bitplay::human_bytes(
                                        *shown,
                                    ),
                                    bitplay::human_bytes(
                                        span.size,
                                    )
                                )
                            },
                        );

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
                                            bytes,
                                        ),

                                    base:
                                        span.offset,
                                },
                            )
                            .width(
                                Fill,
                            )
                            .height(
                                Fill,
                            ),
                        )
                        .map(
                            |()| {
                                Message::CloseHex
                            },
                        );

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
                    span.size,
                );

        hex_view::window_view(
            theme::span_color(
                span.kind,
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

    fn verified(
        &self,
    ) -> bool {
        self.evidence
            .as_ref()
            .is_some_and(
                |e| {
                    e.integrity_status
                        == IntegrityStatus::Verified
                },
            )
    }

    fn details(
        &self,
    ) -> Option<Element<'_, Message>> {
        let span =
            self.hex_span()?;

        let mut lines:
            Vec<Element<'_, Message>> =
            vec![
                text(
                    "SELECTED BLOCK",
                )
                .size(
                    11,
                )
                .color(
                    theme::MUTED,
                )
                .into(),

                kv(
                    "Kind",
                    span.kind.label().to_string(),
                ),

                kv(
                    "Offset",
                    format!(
                        "{} (0x{:08X})",
                        span.offset,
                        span.offset,
                    ),
                ),

                kv(
                    "Size",
                    format!(
                        "{} ({})",
                        span.size,
                        bitplay::human_bytes(
                            span.size,
                        ),
                    ),
                ),
            ];

        if let Some(n) =
            span.slices
        {
            lines.push(
                kv(
                    "Slices",
                    n.to_string(),
                ),
            );
        }

        if let Some(gop) =
            span.kind.gop()
        {
            lines.push(
                kv(
                    "GOP",
                    gop.to_string(),
                ),
            );
        }

        if let MapKind::Au {
            complete,
            ..
        } = span.kind
        {
            lines.push(
                kv(
                    "State",
                    String::from(
                        if complete {
                            "complete"
                        } else {
                            "partial"
                        },
                    ),
                ),
            );
        }

        if let Some(au) =
            span.au
        {
            lines.push(
                button(
                    text(
                        "Extract this frame",
                    )
                    .size(
                        14,
                    ),
                )
                .on_press(
                    Message::ExtractSelected(
                        au,
                    ),
                )
                .style(
                    theme::primary_button,
                )
                .width(
                    Fill,
                )
                .padding([
                    10,
                    14,
                ])
                .into(),
            );
        }

        Some(
            column(
                lines,
            )
            .spacing(
                6,
            )
            .into(),
        )
    }

    fn carve_section(
        &self,
        analysis: &Analysis,
    ) -> Element<'_, Message> {
        let idle =
            !self.carving
                && !self.busy;

        let mut col =
            column![
                text(
                    "CARVE",
                )
                .size(
                    11,
                )
                .color(
                    theme::MUTED,
                ),

                row![
                    text_input(
                        "width",
                        &self.width,
                    )
                    .on_input_maybe(
                        idle.then_some(
                            Message::CarveWidth,
                        ),
                    )
                    .style(
                        theme::field,
                    )
                    .width(
                        88,
                    )
                    .padding(
                        8,
                    ),

                    text(
                        "×",
                    )
                    .size(
                        16,
                    )
                    .color(
                        theme::MUTED,
                    ),

                    text_input(
                        "height",
                        &self.height,
                    )
                    .on_input_maybe(
                        idle.then_some(
                            Message::CarveHeight,
                        ),
                    )
                    .style(
                        theme::field,
                    )
                    .width(
                        88,
                    )
                    .padding(
                        8,
                    ),
                ]
                .spacing(
                    8,
                )
                .align_y(
                    iced::Alignment::Center,
                ),

                checkbox(
                    "With audio",
                    self.with_audio,
                )
                .on_toggle_maybe(
                    idle.then_some(
                        Message::CarveAudio,
                    ),
                )
                .size(
                    16,
                )
                .text_size(
                    13,
                ),

                button(
                    text(
                        if self.carving {
                            "Carving…"
                        } else if self.carve.is_some() {
                            "Re-run carve"
                        } else {
                            "Carve"
                        },
                    )
                    .size(
                        14,
                    ),
                )
                .on_press_maybe(
                    (idle
                        && self.carve_request().is_ok())
                    .then_some(
                        Message::Carve,
                    ),
                )
                .style(
                    theme::primary_button,
                )
                .width(
                    Fill,
                )
                .padding([
                    10,
                    14,
                ]),
            ]
            .spacing(
                6,
            );

        if self.carving {
            let pct =
                self.carve_progress
                    .inner
                    .lock()
                    .map(|g| g.percent())
                    .unwrap_or(0);

            col =
                col.push(
                    progress_bar(
                        0.0..=100.0,
                        pct as f32,
                    )
                    .height(
                        6,
                    ),
                );
        }

        if self.carve.is_some() {
            let moov_enabled =
                analysis.moov_present;

            col =
                col.push(
                    row![
                        button(
                            text(
                                "Moov layout",
                            )
                            .size(
                                13,
                            ),
                        )
                        .on_press_maybe(
                            moov_enabled.then_some(
                                Message::SetLayout(
                                    Layout::Moov,
                                ),
                            ),
                        )
                        .style(
                            theme::tab_button(
                                self.layout == Layout::Moov,
                            ),
                        )
                        .padding([
                            6,
                            10,
                        ]),

                        button(
                            text(
                                "Carved layout",
                            )
                            .size(
                                13,
                            ),
                        )
                        .on_press(
                            Message::SetLayout(
                                Layout::Carved,
                            ),
                        )
                        .style(
                            theme::tab_button(
                                self.layout == Layout::Carved,
                            ),
                        )
                        .padding([
                            6,
                            10,
                        ]),
                    ]
                    .spacing(
                        6,
                    ),
                );
        }

        if let Some(carve) =
            &self.carve
        {
            col =
                col.push(
                    text(
                        carve_summary(
                            &carve.analysis,
                            carve.data.len() as u64,
                        ),
                    )
                    .size(
                        11,
                    )
                    .font(
                        Font::MONOSPACE,
                    )
                    .color(
                        theme::MUTED,
                    ),
                );
        }

        col.into()
    }

    fn rail(
        &self,
    ) -> Element<'_, Message> {
        let mut col =
            column![
                text(
                    "ANALYZE"
                )
                .size(
                    12
                )
                .color(
                    theme::MUTED
                ),

                text(
                    "File structure"
                )
                .size(
                    20
                )
                .color(
                    theme::TEXT
                ),

                Space::with_height(
                    8
                ),

                button(
                    text(
                        if self.busy {
                            "Analyzing…"
                        } else {
                            "Open MP4"
                        }
                    )
                    .size(
                        14
                    )
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
                .width(
                    Fill
                )
                .padding([
                    10,
                    14
                ]),
            ]
            .spacing(
                10,
            );

        if let Some(path) =
            &self.path
        {
            col =
                col.push(
                    text(
                        display_name(
                            path,
                        ),
                    )
                    .size(
                        12,
                    )
                    .font(
                        Font::MONOSPACE,
                    )
                    .color(
                        theme::TEXT,
                    ),
                );
        }

        if let Some(
            evidence,
        ) = &self.evidence
        {
            let integrity_text =
                match evidence
                    .integrity_status
                {
                    IntegrityStatus::Unverified => {
                        "Integrity: unverified"
                    }

                    IntegrityStatus::Verified => {
                        "Integrity: verified"
                    }

                    IntegrityStatus::Failed => {
                        "Integrity: FAILED"
                    }
                };

            let integrity_color =
                match evidence
                    .integrity_status
                {
                    IntegrityStatus::Unverified => {
                        theme::MUTED
                    }

                    IntegrityStatus::Verified => {
                        theme::TEXT
                    }

                    IntegrityStatus::Failed => {
                        theme::DANGER
                    }
                };

            col =
                col.push(
                    text(
                        integrity_text,
                    )
                    .size(
                        12,
                    )
                    .font(
                        Font::MONOSPACE,
                    )
                    .color(
                        integrity_color,
                    ),
                );

            col =
                col.push(
                    text(
                        format!(
                            "SHA-256 {}",
                            evidence.sha256
                        ),
                    )
                    .size(
                        10,
                    )
                    .font(
                        Font::MONOSPACE,
                    )
                    .color(
                        theme::MUTED,
                    ),
                );
        }

        if let Some(err) =
            &self.error
        {
            col =
                col.push(
                    text(
                        err,
                    )
                    .size(
                        12,
                    )
                    .color(
                        theme::DANGER,
                    ),
                );
        }

        if let Some(
            analysis,
        ) = &self.analysis
        {
            col =
                col.push(
                    Space::with_height(
                        8,
                    ),
                );

            col =
                col.push(
                    meta_block(
                        analysis,
                    ),
                );

            col =
                col.push(
                    Space::with_height(
                        8,
                    ),
                );

            if self.verified() {
                col =
                    col.push(
                        self.carve_section(
                            analysis,
                        ),
                    );
            }

            if let Some(details) =
                self.details()
            {
                col =
                    col.push(
                        details,
                    );
            }

            col =
                col.push(
                    legend(
                        self.layout,
                    ),
                );

            /*
             * Extraction is available only after
             * a carve has completed.
             */
            if self
                .carve
                .is_some()
            {
                col =
                    col.push(
                        button(
                            text(
                                "Open Extract",
                            )
                            .size(
                                14,
                            ),
                        )
                        .on_press(
                            Message::OpenExtract,
                        )
                        .style(
                            theme::secondary_button,
                        )
                        .width(
                            Fill,
                        )
                        .padding([
                            10,
                            14,
                        ]),
                    );
            }
        } else {
            col =
                col.push(
                    Space::with_height(
                        8,
                    ),
                );

            col =
                col.push(
                    legend(
                        self.layout,
                    ),
                );
        }

        scrollable(
            col
                .spacing(
                    10,
                )
                .padding(
                    iced::padding::right(
                        14,
                    ),
                )
                .width(
                    Fill,
                )
                .height(
                    iced::Length::Shrink,
                ),
        )
        .width(
            Fill,
        )
        .height(
            Fill,
        )
        .into()
    }

    fn empty_state(
        &self,
    ) -> Element<'_, Message> {
        column![
            text(
                "No file loaded"
            )
            .size(
                18
            )
            .color(
                theme::TEXT
            ),

            text(
                "Open an MP4 to see how video, audio, and GOPs are laid out."
            )
            .size(
                13
            )
            .color(
                theme::MUTED
            ),

            text(
                "Click a block to inspect its bytes."
            )
            .size(
                13
            )
            .color(
                theme::MUTED
            ),

            Space::with_height(
                8
            ),

            button(
                text(
                    "Open MP4"
                )
                .size(
                    14
                )
            )
            .on_press(
                Message::Browse
            )
            .style(
                theme::primary_button
            )
            .padding([
                10,
                16
            ]),
        ]
        .spacing(
            10,
        )
        .align_x(
            iced::Alignment::Center,
        )
        .max_width(
            420,
        )
        .into()
    }
}

fn meta_block(
    analysis: &Analysis,
) -> Element<'_, Message> {
    let mut lines:
        Vec<Element<'_, Message>> =
        vec![
            text(
                "METADATA",
            )
            .size(
                11,
            )
            .color(
                theme::MUTED,
            )
            .into(),

            kv(
                "Size",
                bitplay::human_bytes(
                    analysis.file_size,
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
            ),
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
            ),
        );

        lines.push(
            kv(
                "Codec",
                v.codec.clone(),
            ),
        );

        if let Some(p) =
            &v.profile
        {
            lines.push(
                kv(
                    "Profile",
                    p.clone(),
                ),
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
                ),
            );
        }

        lines.push(
            kv(
                "I-frames",
                v.iframe_count
                    .to_string(),
            ),
        );

        lines.push(
            kv(
                "GOPs",
                v.gop_count
                    .to_string(),
            ),
        );
    } else {
        lines.push(
            kv(
                "Video",
                "not indexed"
                    .into(),
            ),
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
            ),
        );
    }

    if !analysis
        .moov_present
    {
        lines.push(
            text(
                "moov missing",
            )
            .size(
                12,
            )
            .color(
                theme::WARN,
            )
            .into(),
        );
    }

    column(
        lines,
    )
    .spacing(
        6,
    )
    .into()
}

fn kv(
    k: &str,
    v: String,
) -> Element<'_, Message> {
    column![
        text(
            k
        )
        .size(
            11
        )
        .color(
            theme::MUTED
        ),

        text(
            v
        )
        .size(
            13
        )
        .font(
            Font::MONOSPACE
        )
        .color(
            theme::TEXT
        ),
    ]
    .spacing(
        2,
    )
    .into()
}

fn legend(
    layout: Layout,
) -> Element<'static, Message> {
    let items: &[(
        iced::Color,
        &str,
    )] =
        match layout {
            Layout::Moov => {
                &theme::MOOV_LEGEND
            }

            Layout::Carved => {
                &theme::CARVE_LEGEND
            }
        };

    let mut col =
        column![
            text(
                "LEGEND"
            )
            .size(
                11
            )
            .color(
                theme::MUTED
            )
        ]
        .spacing(
            6,
        );

    for &(
        color,
        label,
    ) in items
    {
        col =
            col.push(
                row![
                    container(
                        Space::with_width(
                            12
                        )
                        .height(
                            12
                        )
                    )
                    .width(
                        12
                    )
                    .height(
                        12
                    )
                    .style(
                        theme::color_chip(
                            color
                        )
                    ),

                    text(
                        label
                    )
                    .size(
                        12
                    )
                    .color(
                        theme::TEXT
                    ),
                ]
                .spacing(
                    8,
                )
                .align_y(
                    iced::Alignment::Center,
                ),
            );
    }

    col =
        col.push(
            text(
                "Click a block to inspect bytes",
            )
            .size(
                11,
            )
            .color(
                theme::MUTED,
            ),
        );

    col.into()
}

fn carve_summary(
    carve: &CarveAnalysis,
    file_size: u64,
) -> String {
    let intra =
        carve
            .access_units
            .iter()
            .filter(|au| au.is_intra)
            .count();

    let tail =
        match carve.truncation_offset {
            Some(off) => {
                format!(
                    "chain broke at {off} ({:.2}% of file)",
                    off as f64
                        / file_size.max(1) as f64
                        * 100.0,
                )
            }

            None => {
                String::from(
                    "chain ran to end of mdat",
                )
            }
        };

    let source =
        if carve.x264_options_found {
            "x264 options found"
        } else {
            "parameters guessed"
        };

    format!(
        "Carved {} NALs · {} access units ({} intra) · {} · {} skipped region(s) · {} · {} QP attempt(s)",
        carve.nals.len(),
        carve.access_units.len(),
        intra,
        tail,
        carve.skipped.len(),
        source,
        carve.qp_attempts,
    )
}

fn run_carve(
    evidence: &EvidenceRecord,
    parameters: &CarveParameters,
    reporter: &mut ChannelReporter,
) -> Result<
    Arc<CarveResult>,
    String,
> {
    use iframe_extract::report::Reporter;

    reporter.phase(
        "reading working copy",
    );

    let data =
        std::fs::read(
            &evidence.path,
        )
        .map_err(
            |e| {
                format!(
                    "Reading working copy failed: {e}"
                )
            },
        )?;

    reporter.finish_phase(
        &bitplay::human_bytes(
            data.len() as u64,
        ),
    );

    reporter.phase(
        "verifying SHA-256",
    );

    let sha256 =
        hex::encode(
            Sha256::digest(
                &data,
            ),
        );

    if sha256
        != evidence.sha256
    {
        return Err(
            String::from(
                "CRITICAL: working copy no longer matches the registered evidence SHA-256",
            ),
        );
    }

    reporter.finish_phase(
        "matches evidence",
    );

    let analysis =
        iframe_extract::extract::analyze(
            &data,
            &CarveOptions {
                width:
                    parameters.width,

                height:
                    parameters.height,

                with_audio:
                    parameters.with_audio,
            },
            reporter,
        )
        .map_err(
            |e| {
                format!(
                    "Carve failed: {e}"
                )
            },
        )?;

    Ok(
        Arc::new(
            CarveResult {
                data:
                    Arc::new(
                        data,
                    ),

                analysis,

                path:
                    evidence.path.clone(),

                sha256,
            },
        ),
    )
}

fn display_name(
    path: &Path,
) -> String {
    path.file_name()
        .and_then(
            |s| s.to_str(),
        )
        .unwrap_or(
            "untitled",
        )
        .to_string()
}

fn read_span_hex(
    path: &Path,
    offset: u64,
    size: u64,
) -> Result<
    (
        Vec<u8>,
        u64,
    ),
    String,
> {
    let show =
        size.min(
            hex_view::MAX_BYTES,
        ) as usize;

    if show == 0 {
        return Ok((
            Vec::new(),
            0,
        ));
    }

    let mut file =
        std::fs::File::open(
            path,
        )
        .map_err(
            |e| e.to_string(),
        )?;

    file.seek(
        SeekFrom::Start(
            offset,
        ),
    )
    .map_err(
        |e| e.to_string(),
    )?;

    let mut buf =
        vec![
            0u8;
            show
        ];

    let n =
        file.read(
            &mut buf,
        )
        .map_err(
            |e| e.to_string(),
        )?;

    buf.truncate(
        n,
    );

    Ok((
        buf,
        n as u64,
    ))
}