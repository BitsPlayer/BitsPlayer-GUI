use std::path::PathBuf;

use std::time::Duration;

use iced::window;

use iced::{Element, Fill, Font, Size, Subscription, Task, Theme};

use crate::analyze;

use crate::extract;

use crate::forensic::audit::{AuditAction, AuditLogger, AuditResult, EvidenceCopyContext, CopyAttemptContext};

use crate::forensic::case::Case;

use crate::forensic::closure::CaseClosure;

use crate::forensic::context::{HostContext, OperationContext};

use crate::forensic::evidence::IntegrityStatus;

use crate::forensic::signing::SigningIdentity;

use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]

pub enum Tab {

    #[default]

    Analyze,

    Extract,

}

#[derive(Debug, Clone)]

pub enum Message {

    MainOpened,

    HexOpened,

    WindowClosed(window::Id),

    Tab(Tab),

    Analyze(analyze::Message),

    Extract(extract::Message),

}

pub struct App {

    main_window: window::Id,

    hex_window: Option<window::Id>,

    tab: Tab,

    analyze: analyze::State,

    extract: extract::State,

    case: Case,

    audit: Option<AuditLogger>,

    case_closed: bool,

    pending_copy: Option<CopyAttemptContext>,

}

impl App {

    fn close_forensic_case(&mut self) {

        if self.case_closed {

            return;

        }

let case_metadata_sha256 = match self.case.metadata_sha256() {

            Ok(hash) => Some(hash),

            Err(err) => {

                eprintln!("Failed to hash case metadata during closure: {err}");

                None

            }

        };

let Some(logger) = self.audit.as_mut() else {

            eprintln!("Cannot close forensic case: audit logger unavailable");

            return;

        };

let closed_entry = match logger.close_case(self.case.id, case_metadata_sha256) {

            Ok(entry) => entry,

            Err(err) => {

                eprintln!("Failed to write CASE_CLOSED audit entry: {err}");

                return;

            }

        };

let closure = CaseClosure::new(

            self.case.id,

            closed_entry.sequence,

            closed_entry.entry_hash.clone(),

        );

let closure_path = match closure.save(&self.case.case_directory) {

            Ok(path) => path,

            Err(err) => {

                eprintln!("Failed to save case closure record: {err}");

                return;

            }

        };

        println!("Forensic case closed: {}", closure_path.display());

let case_metadata_sha256 = match self.case.metadata_sha256() {

            Ok(hash) => hash,

            Err(err) => {

                eprintln!("Failed to hash case metadata for signing: {err}");

                return;

            }

        };

let signing_identity = match SigningIdentity::load_or_create() {

            Ok(identity) => identity,

            Err(err) => {

                eprintln!("Failed to load/create signing identity: {err}");

                return;

            }

        };

let signature = match signing_identity.sign_case(

            self.case.id,

            closed_entry.sequence,

            &closed_entry.entry_hash,

            &case_metadata_sha256,

        ) {

            Ok(signature) => signature,

            Err(err) => {

                eprintln!("Failed to sign forensic case: {err}");

                return;

            }

        };

        match signature.save(&self.case.case_directory) {

            Ok(signature_path) => {

                println!("Case signature saved: {}", signature_path.display());

                self.case_closed = true;

            }

            Err(err) => {

                eprintln!("Failed to save case signature: {err}");

            }

        }

    }

    pub fn boot() -> (Self, Task<Message>) {

let (main_window, open) = window::open(window::Settings {

            size: Size::new(1280.0, 820.0),

            ..Default::default()

        });

let cases_directory = std::env::current_dir()

            .unwrap_or_else(|_| PathBuf::from("."))

            .join("cases");

let host_context = HostContext::collect();

let case = Case::new_in_base(

            "BitsPlayer Session",

            host_context.examiner.clone(),

            &cases_directory,

        );

        if let Err(err) = case.save() {

            eprintln!("Failed to save forensic case metadata: {err}");

        }

let case_metadata_sha256 = match case.metadata_sha256() {

            Ok(hash) => Some(hash),

            Err(err) => {

                eprintln!("Failed to hash case metadata: {err}");

                None

            }

        };

let audit_path = case.case_directory.join("logs").join("audit.jsonl");

let mut audit = match AuditLogger::new(&audit_path) {

            Ok(logger) => Some(logger),

            Err(err) => {

                eprintln!("Failed to initialize audit logger: {err}");

                None

            }

        };

        if let Some(logger) = audit.as_mut() {

            if let Err(err) = logger.log(

                case.id,

                AuditAction::CaseCreated,

                None,

                None,

                case_metadata_sha256,

                AuditResult::Success,

            ) {

                eprintln!("Failed to write CASE_CREATED audit entry: {err}");

            }

        }

let mut analyze_state = analyze::State::default();

        analyze_state.evidence_directory = Some(case.case_directory.join("evidence"));

        (

            Self {

                main_window,

                hex_window: None,

                tab: Tab::Analyze,

                analyze: analyze_state,

                extract: extract::State::default(),

                case,

                audit,

                case_closed: false,

                pending_copy: None,

            },

            open.map(|_| Message::MainOpened),

        )

    }

    pub fn title(&self, window: window::Id) -> String {

        if Some(window) == self.hex_window {

            self.analyze.hex_title()

        } else {

            String::from("BitsPlayer")

        }

    }

    pub fn theme(&self, _window: window::Id) -> Theme {

        theme::bitsplayer_theme()

    }

    pub fn subscription(&self) -> Subscription<Message> {

let closed = window::close_events().map(Message::WindowClosed);

        if self.extract.running {

            Subscription::batch([

                closed,

                iced::time::every(Duration::from_millis(80))

                    .map(|_| Message::Extract(extract::Message::Tick)),

            ])

        } else {

            closed

        }

    }

    pub fn update(&mut self, message: Message) -> Task<Message> {

        match message {

            Message::MainOpened | Message::HexOpened => Task::none(),

            Message::WindowClosed(id) => {

                if id == self.main_window {

                    self.close_forensic_case();

                    iced::exit()

                } else if Some(id) == self.hex_window {

                    self.hex_window = None;

let _ = self.analyze.update(analyze::Message::CloseHex);

                    Task::none()

                } else {

                    Task::none()

                }

            }

            Message::Tab(tab) => {

                self.tab = tab;

                Task::none()

            }

            Message::Analyze(analyze::Message::OpenExtract) => {

let evidence_verified = self

                    .analyze

                    .evidence

                    .as_ref()

                    .map(|evidence| evidence.integrity_status == IntegrityStatus::Verified)

                    .unwrap_or(false);

                if !evidence_verified {

                    return Task::none();

                }

                if let Some(evidence) = self.analyze.evidence.as_ref() {

                    self.extract

                        .set_verified_evidence(evidence.path.clone(), evidence.sha256.clone());

                }

                self.tab = Tab::Extract;

                if let Some(v) = self

                    .analyze

                    .analysis

                    .as_ref()

                    .and_then(|a| a.video.as_ref())

                    && v.width > 0

                    && v.height > 0

                {

                    self.extract.prefill(v.width, v.height);

                }

                Task::none()

            }

            Message::Analyze(msg) => self.update_analyze(msg),

            Message::Extract(msg) => self.update_extract(msg),

        }

    }

    fn update_analyze(&mut self, msg: analyze::Message) -> Task<Message> {
        if let analyze::Message::CopyRequested(source) = msg {
            if self.analyze.busy || self.pending_copy.is_some() { return Task::none(); }
            let destination = self.case.case_directory.join("evidence")
                .join(format!("working-{}.mp4", uuid::Uuid::new_v4()));
            let relative = match destination.strip_prefix(&self.case.case_directory) {
                Ok(path) => path.to_string_lossy().into_owned(),
                Err(_) => return Task::none(),
            };
            let attempt = CopyAttemptContext {
                source_path: source.to_string_lossy().into_owned(),
                destination_path: relative,
                error: None,
            };
            let Some(logger) = self.audit.as_mut() else {
                self.analyze.error = Some("Forensic audit logger unavailable; copying blocked".into());
                return Task::none();
            };
            if let Err(err) = logger.log_copy_attempt(
                self.case.id, AuditAction::EvidenceCopyStarted, attempt.clone()
            ) {
                self.analyze.error = Some(format!("Copy blocked: cannot record start: {err}"));
                return Task::none();
            }
            self.pending_copy = Some(attempt);
            return self.analyze.update(analyze::Message::CopyAuthorized { source, destination })
                .map(Message::Analyze);
        }

        if let analyze::Message::CopyReady(Err(ref failure)) = msg {
            let Some(mut attempt) = self.pending_copy.take() else {
                self.analyze.error = Some("Copy failed without a recorded start".into());
                self.analyze.busy = false;
                return Task::none();
            };
            attempt.error = Some(failure.clone());
            let result = self.audit.as_mut().ok_or_else(|| "audit logger unavailable".to_string())
                .and_then(|logger| logger.log_copy_attempt(
                    self.case.id, AuditAction::EvidenceCopyFailed, attempt
                ).map(|_| ()).map_err(|err| err.to_string()));
            let task = self.analyze.update(msg).map(Message::Analyze);
            if let Err(err) = result {
                self.analyze.error = Some(format!("Copy failed and audit logging failed: {err}"));
                self.analyze.status = "Copy failure audit error".into();
            }
            return task;
        }

        if let analyze::Message::CopyReady(Ok(_)) = &msg {
            if self.pending_copy.is_none() {
                self.analyze.busy = false;
                self.analyze.error = Some("Copy completion without audited start".into());
                return Task::none();
            }
        }


let selecting = matches!(msg, analyze::Message::MapSelect(_));

        if let analyze::Message::EvidenceReady(Ok(ref evidence)) = msg {

let context = OperationContext::evidence(self.analyze.original_path.as_deref().unwrap_or(&evidence.path));

let Some(logger) = self.audit.as_mut() else {

                self.analyze.busy = false;

                self.analyze.error = Some(String::from(

                    "Forensic audit logger is unavailable. Analysis aborted.",

                ));

                self.analyze.status = String::from("Analysis blocked: audit unavailable");

                return Task::none();

            };

            // The copy was created and protected by Analyze before EvidenceReady.
            // Never begin analysis without a signed copy relationship.
            let Some(original) = self.analyze.original_path.as_ref() else {
                self.analyze.busy = false;
                self.analyze.error = Some("Missing original evidence path".into());
                self.analyze.status = "Analysis blocked: source identity missing".into();
                return Task::none();
            };
            if original == &evidence.path {
                self.analyze.busy = false;
                self.analyze.error = Some("Analysis would use original evidence".into());
                self.analyze.status = "Analysis blocked: no working copy".into();
                return Task::none();
            }
            let size = evidence.size_bytes;
            let copy_context = EvidenceCopyContext {
                original_path: original.to_string_lossy().into_owned(),
                working_copy_path: match evidence.path.strip_prefix(&self.case.case_directory) {
                    Ok(relative) => relative.to_string_lossy().into_owned(),
                    Err(_) => {
                        self.analyze.busy = false;
                        self.analyze.error = Some("Working copy is outside this forensic case".into());
                        self.analyze.status = "Analysis blocked: invalid working-copy location".into();
                        return Task::none();
                    }
                },
                original_sha256: evidence.sha256.clone(),
                working_copy_sha256: evidence.sha256.clone(),
                size_bytes: size,
            };
            let Some(attempt) = self.pending_copy.as_ref() else {
                self.analyze.busy = false;
                self.analyze.error = Some("Missing copy-start audit context".into());
                return Task::none();
            };
            if attempt.source_path != copy_context.original_path
                || attempt.destination_path != copy_context.working_copy_path {
                self.analyze.busy = false;
                self.analyze.error = Some("Copy completion does not match audited start".into());
                return Task::none();
            }
            if let Err(err) = logger.log_evidence_copy(self.case.id, copy_context) {
                self.analyze.busy = false;
                self.analyze.error = Some(format!("Evidence-copy audit failed: {err}"));
                self.analyze.status = "Analysis blocked: copy audit failure".into();
                return Task::none();
            }

            self.pending_copy = None;

            if let Err(err) = logger.log_with_context(

                self.case.id,

                AuditAction::EvidenceRegistered,

                Some(evidence.filename.clone()),

                Some(evidence.sha256.clone()),

                None,

                AuditResult::Success,

                context.clone(),

            ) {

                self.analyze.busy = false;

                self.analyze.error = Some(format!(

                    "Failed to record evidence in forensic audit: {err}"

                ));

                self.analyze.status = String::from("Analysis blocked: audit write failed");

                return Task::none();

            }

            if let Err(err) = logger.log_with_context(

                self.case.id,

                AuditAction::AnalysisStarted,

                Some(evidence.filename.clone()),

                Some(evidence.sha256.clone()),

                None,

                AuditResult::Started,

                context,

            ) {

                self.analyze.busy = false;

                self.analyze.error = Some(format!(

                    "Failed to record analysis start in forensic audit: {err}"

                ));

                self.analyze.status = String::from("Analysis blocked: audit write failed");

                return Task::none();

            }

        }

let finished_successfully = matches!(&msg, analyze::Message::Finished(Ok(_)));

let finished_with_error = matches!(&msg, analyze::Message::Finished(Err(_)));

let failure_message = match &msg {

            analyze::Message::Finished(Err(err)) => Some(err.clone()),

            _ => None,

        };

let was_open = self.analyze.hex_is_open();

let task = self.analyze.update(msg).map(Message::Analyze);

        if finished_successfully {

            self.audit_analysis_success();

            if let Some(evidence) = self.analyze.evidence.as_ref()

                && evidence.integrity_status == IntegrityStatus::Verified

            {

                self.extract

                    .set_verified_evidence(evidence.path.clone(), evidence.sha256.clone());

            }

            if let Some(v) = self

                .analyze

                .analysis

                .as_ref()

                .and_then(|a| a.video.as_ref())

                && v.width > 0

                && v.height > 0

            {

                self.extract.prefill(v.width, v.height);

            }

        }

        if finished_with_error {

            self.audit_analysis_failure(

                failure_message

                    .as_deref()

                    .unwrap_or("unknown analysis failure"),

            );

        }

let now_open = self.analyze.hex_is_open();

        if was_open && !now_open {

            Task::batch([task, self.close_hex_window()])

        } else if now_open && (!was_open || selecting) {

            Task::batch([task, self.ensure_hex_window()])

        } else {

            task

        }

    }

    fn update_extract(&mut self, msg: extract::Message) -> Task<Message> {

        if matches!(msg, extract::Message::Run) {

            if let Err(err) = self.extract.validate_forensic_run() {

                self.extract.error = Some(err.clone());

                self.extract.status = err;

                return Task::none();

            }

let parameters = match self.extract.forensic_parameters() {

                Ok(parameters) => parameters,

                Err(err) => {

                    self.extract.error = Some(err.clone());

                    self.extract.status = err;

                    return Task::none();

                }

            };

let Some(path) = self.extract.path.clone() else {

                self.extract.error = Some(String::from("Choose an MP4 file first"));

                return Task::none();

            };

let context = OperationContext::extraction(&path, parameters);

let (filename, sha256) = self.extract_evidence_identity();

let Some(logger) = self.audit.as_mut() else {

                self.extract.error = Some(String::from(

                    "Forensic audit logger is unavailable. Extraction aborted.",

                ));

                self.extract.status = String::from("Extraction blocked: audit unavailable");

                return Task::none();

            };

            if let Err(err) = logger.log_with_context(

                self.case.id,

                AuditAction::ExtractStarted,

                filename,

                sha256,

                None,

                AuditResult::Started,

                context,

            ) {

                self.extract.error = Some(format!(

                    "Failed to record extraction start in forensic audit: {err}"

                ));

                self.extract.status = String::from("Extraction blocked: audit write failed");

                return Task::none();

            }

        }

let was_running = self.extract.running;

let is_tick = matches!(msg, extract::Message::Tick);

let is_save = matches!(msg, extract::Message::Save);

let task = self.extract.update(msg).map(Message::Extract);

        if is_tick && was_running && !self.extract.running {

let failed = self.extract.error.is_some();

let (filename, sha256) = self.extract_evidence_identity();

let context = self.current_extraction_context();

            if let Some(logger) = self.audit.as_mut() {

let result = match context {

                    Some(context) => logger.log_with_context(

                        self.case.id,

                        if failed {

                            AuditAction::ExtractFailed

                        } else {

                            AuditAction::ExtractCompleted

                        },

                        filename,

                        sha256,

                        None,

                        if failed {

                            AuditResult::Failed

                        } else {

                            AuditResult::Success

                        },

                        context,

                    ),

                    None => logger.log(

                        self.case.id,

                        if failed {

                            AuditAction::ExtractFailed

                        } else {

                            AuditAction::ExtractCompleted

                        },

                        filename,

                        sha256,

                        None,

                        if failed {

                            AuditResult::Failed

                        } else {

                            AuditResult::Success

                        },

                    ),

                };

                if let Err(err) = result {

                    self.extract.error = Some(format!(

                        "Extraction finished, but the forensic audit write failed: {err}"

                    ));

                    self.extract.status = String::from("Extraction audit failure");

                }

            }

        }

        if is_save {

            self.audit_saved_artifacts();

        }

        task

    }

    fn current_extraction_context(&self) -> Option<OperationContext> {

let path = self.extract.path.as_ref()?;

let parameters = self.extract.forensic_parameters().ok()?;

        Some(OperationContext::extraction(path, parameters))

    }

    fn extract_evidence_identity(&self) -> (Option<String>, Option<String>) {

let filename = self

            .extract

            .path

            .as_ref()

            .and_then(|p| p.file_name())

            .and_then(|s| s.to_str())

            .map(ToOwned::to_owned);

let sha256 = self.extract.source_evidence_sha256.clone();

        (filename, sha256)

    }

    fn audit_saved_artifacts(&mut self) {

let artifacts = self.extract.artifacts().to_vec();

        if artifacts.is_empty() {

            return;

        }

let (filename, sha256) = self.extract_evidence_identity();

let context = self.current_extraction_context();

let Some(logger) = self.audit.as_mut() else {

            self.extract.error = Some(String::from(

                "Artifacts were saved, but the forensic audit logger is unavailable.",

            ));

            self.extract.status = String::from("Artifact audit failure");

            return;

        };

        for artifact in &artifacts {

            if let Err(err) = logger.log_artifact_with_context(

                self.case.id,

                filename.clone(),

                sha256.clone(),

                artifact,

                context.clone(),

            ) {

                self.extract.error = Some(format!(

                    "Artifact was saved, but ARTIFACT_CREATED could not be logged: {err}"

                ));

                self.extract.status = String::from("Artifact audit failure");

                return;

            }

        }

    }

    fn audit_analysis_success(&mut self) {

let Some(evidence) = self.analyze.evidence.as_ref() else {

            return;

        };

let context = OperationContext::evidence(self.analyze.original_path.as_deref().unwrap_or(&evidence.path));

let Some(logger) = self.audit.as_mut() else {

            return;

        };

        if let Err(err) = logger.log_with_context(

            self.case.id,

            AuditAction::AnalysisCompleted,

            Some(evidence.filename.clone()),

            Some(evidence.sha256.clone()),

            None,

            AuditResult::Success,

            context.clone(),

        ) {

            eprintln!("Failed to write ANALYSIS_COMPLETED audit entry: {err}");

        }

let integrity_result = match evidence.integrity_status {

            IntegrityStatus::Verified => AuditResult::Verified,

            IntegrityStatus::Failed => AuditResult::Failed,

            IntegrityStatus::Unverified => AuditResult::Unverified,

        };

        if let Err(err) = logger.log_with_context(

            self.case.id,

            AuditAction::IntegrityVerification,

            Some(evidence.filename.clone()),

            Some(evidence.sha256.clone()),

            None,

            integrity_result,

            context,

        ) {

            eprintln!("Failed to write INTEGRITY_VERIFICATION audit entry: {err}");

        }

    }

    fn audit_analysis_failure(&mut self, failure: &str) {

let evidence = self.analyze.evidence.as_ref();

let filename = evidence.map(|e| e.filename.clone());

let sha256 = evidence.map(|e| e.sha256.clone());

let context = evidence.map(|e| OperationContext::evidence(&e.path));

let Some(logger) = self.audit.as_mut() else {

            return;

        };

let result = match context {

            Some(context) => logger.log_with_context(

                self.case.id,

                AuditAction::AnalysisFailed,

                filename,

                sha256,

                None,

                AuditResult::Failed,

                context,

            ),

            None => logger.log(

                self.case.id,

                AuditAction::AnalysisFailed,

                filename,

                sha256,

                None,

                AuditResult::Failed,

            ),

        };

        if let Err(err) = result {

            eprintln!("Failed to write ANALYSIS_FAILED audit entry: {err}");

        }

        eprintln!("Analysis failure recorded: {failure}");

    }

    fn ensure_hex_window(&mut self) -> Task<Message> {

        if let Some(id) = self.hex_window {

            return window::gain_focus(id);

        }

let (id, open) = window::open(window::Settings {

            size: Size::new(920.0, 640.0),

            position: window::Position::Centered,

            min_size: Some(Size::new(520.0, 360.0)),

            ..Default::default()

        });

        self.hex_window = Some(id);

        open.map(|_| Message::HexOpened)

    }

    fn close_hex_window(&mut self) -> Task<Message> {

        match self.hex_window.take() {

            Some(id) => window::close(id),

            None => Task::none(),

        }

    }

    pub fn view(&self, window: window::Id) -> Element<'_, Message> {

        if Some(window) == self.hex_window {

            return self.analyze.hex_window_view().map(Message::Analyze);

        }

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