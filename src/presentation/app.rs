use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iced::window;
use iced::{Element, Fill, Font, Size, Subscription, Task, Theme};

use crate::presentation::analyze;
use crate::presentation::extract::{self, SaveOutcome};
use crate::forensic::audit::{AuditAction, AuditLogger, AuditResult};
use crate::forensic::case::Case;
use crate::forensic::context::{HostContext, OperationContext};
use crate::forensic::evidence::IntegrityStatus;
use crate::forensic::seal::SealReport;
use crate::forensic::signing::IdentityOrigin;
use crate::presentation::theme;

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
    CloseRequested(window::Id),
    CaseSealed(Result<SealReport, String>),
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
    audit: Arc<Mutex<Option<AuditLogger>>>,
    case_closed: bool,
    sealing: bool,
    notice: Option<String>,
    active_extraction: Option<OperationContext>,
}

impl App {
    fn audit_mut(&self) -> std::sync::MutexGuard<'_, Option<AuditLogger>> {
        self.audit.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn spawn_seal(&self) -> Task<Message> {
        let audit = Arc::clone(&self.audit);
        let case = self.case.clone();
        Task::perform(
            async move {
                match tokio::task::spawn_blocking(move || {
                    let mut guard = audit.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let Some(logger) = guard.as_mut() else {
                        return Err(String::from(
                            "Cannot seal forensic case: audit logger is unavailable",
                        ));
                    };
                    crate::forensic::seal::seal_case(logger, &case).map_err(|err| err.to_string())
                })
                .await
                {
                    Ok(result) => result,
                    Err(err) => Err(format!("Forensic case seal task failed: {err}")),
                }
            },
            Message::CaseSealed,
        )
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

        (
            Self {
                main_window,
                hex_window: None,
                tab: Tab::Analyze,
                analyze: analyze::State::default(),
                extract: extract::State::default(),
                case,
                audit: Arc::new(Mutex::new(audit)),
                case_closed: false,
                sealing: false,
                notice: None,
                active_extraction: None,
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
        let closed = window::close_requests().map(Message::CloseRequested);
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
            Message::CloseRequested(id) => {
                if id == self.main_window {
                    if self.case_closed {
                        return iced::exit();
                    }
                    if self.sealing {
                        return Task::none();
                    }
                    self.sealing = true;
                    self.notice = Some(String::from("Sealing forensic case…"));
                    self.analyze.status = String::from("Sealing forensic case…");
                    self.spawn_seal()
                } else if Some(id) == self.hex_window {
                    self.hex_window = None;
                    let _ = self.analyze.update(analyze::Message::CloseHex);
                    window::close(id)
                } else {
                    Task::none()
                }
            }
            Message::CaseSealed(result) => {
                self.sealing = false;
                match result {
                    Ok(report) => {
                        self.case_closed = true;
                        if report.identity_origin == IdentityOrigin::Created {
                            let notice = format!(
                                "A new signing identity was created at {}. The case is sealed. Close the window again to exit.",
                                report.signing_directory.display()
                            );
                            self.notice = Some(notice.clone());
                            self.analyze.status = notice.clone();
                            self.extract.status = notice;
                            Task::none()
                        } else {
                            iced::exit()
                        }
                    }
                    Err(err) => {
                        let notice = format!("Forensic case was not sealed: {err}");
                        self.notice = Some(notice.clone());
                        self.analyze.error = Some(notice.clone());
                        self.analyze.status = String::from("Case seal failed");
                        self.extract.error = Some(notice);
                        self.extract.status = String::from("Case seal failed");
                        Task::none()
                    }
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
                    self.analyze.error = Some(String::from(
                        "Extraction is blocked until evidence integrity is verified and recorded in the audit log.",
                    ));
                    self.analyze.status = String::from("Extract blocked: evidence is not verified");
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
        let selecting = matches!(msg, analyze::Message::MapSelect(_));

        if let analyze::Message::EvidenceReady(Ok(ref evidence)) = msg {
            let context = OperationContext::evidence(&evidence.path);
            let filename = evidence.filename.clone();
            let sha256 = evidence.sha256.clone();
            let case_id = self.case.id;

            let registered = {
                let mut audit = self.audit_mut();
                let Some(logger) = audit.as_mut() else {
                    drop(audit);
                    self.analyze.busy = false;
                    self.analyze.error = Some(String::from(
                        "Forensic audit logger is unavailable. Analysis aborted.",
                    ));
                    self.analyze.status = String::from("Analysis blocked: audit unavailable");
                    return Task::none();
                };

                logger
                    .log_with_context(
                        case_id,
                        AuditAction::EvidenceRegistered,
                        Some(filename.clone()),
                        Some(sha256.clone()),
                        None,
                        AuditResult::Success,
                        context.clone(),
                    )
                    .and_then(|_| {
                        logger.log_with_context(
                            case_id,
                            AuditAction::AnalysisStarted,
                            Some(filename),
                            Some(sha256),
                            None,
                            AuditResult::Started,
                            context,
                        )
                    })
            };

            if let Err(err) = registered {
                self.analyze.busy = false;
                self.analyze.error = Some(format!(
                    "Failed to record analysis in the forensic audit: {err}"
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
            match self.audit_analysis_success() {
                Ok(()) => {
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
                Err(err) => {
                    self.analyze.error = Some(err);
                    self.analyze.status = String::from("Analysis audit failure");
                }
            }
        }

        if finished_with_error {
            let failure = failure_message
                .as_deref()
                .unwrap_or("unknown analysis failure");
            if let Err(err) = self.audit_analysis_failure(failure) {
                let existing = self
                    .analyze
                    .error
                    .clone()
                    .unwrap_or_else(|| failure.to_string());
                self.analyze.error = Some(format!(
                    "{existing}\nForensic audit write failed: {err}"
                ));
                self.analyze.status = String::from("Analysis audit failure");
            }
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
            let case_id = self.case.id;

            let started = {
                let mut audit = self.audit_mut();
                let Some(logger) = audit.as_mut() else {
                    drop(audit);
                    self.extract.error = Some(String::from(
                        "Forensic audit logger is unavailable. Extraction aborted.",
                    ));
                    self.extract.status = String::from("Extraction blocked: audit unavailable");
                    return Task::none();
                };
                logger.log_with_context(
                    case_id,
                    AuditAction::ExtractStarted,
                    filename,
                    sha256,
                    None,
                    AuditResult::Started,
                    context.clone(),
                )
            };

            if let Err(err) = started {
                self.extract.error = Some(format!(
                    "Failed to record extraction start in forensic audit: {err}"
                ));
                self.extract.status = String::from("Extraction blocked: audit write failed");
                return Task::none();
            }

            self.active_extraction = Some(context);
        }

        let was_running = self.extract.running;
        let is_tick = matches!(msg, extract::Message::Tick);
        let is_save = matches!(msg, extract::Message::Save);

        let task = self.extract.update(msg).map(Message::Extract);

        if is_tick && was_running && !self.extract.running {
            let failed = self.extract.error.is_some();
            let (filename, sha256) = self.extract_evidence_identity();
            let context = self.active_extraction.take();
            let case_id = self.case.id;

            let recorded = match context {
                None => Err(String::from(
                    "Extraction finished, but the forensic parameter snapshot is missing.",
                )),
                Some(context) => {
                    let mut audit = self.audit_mut();
                    match audit.as_mut() {
                        None => Err(String::from(
                            "Extraction finished, but the forensic audit logger is unavailable.",
                        )),
                        Some(logger) => logger
                            .log_with_context(
                                case_id,
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
                            )
                            .map(|_| ())
                            .map_err(|err| err.to_string()),
                    }
                }
            };

            if let Err(err) = recorded {
                let existing = self.extract.error.clone();
                self.extract.error = Some(match existing {
                    Some(previous) => format!("{previous}\nForensic audit write failed: {err}"),
                    None => format!("Extraction finished, but the forensic audit write failed: {err}"),
                });
                self.extract.status = String::from("Extraction audit failure");
            }
        }

        if is_save {
            if let Some(outcome) = self.extract.take_last_save() {
                self.audit_save_outcome(outcome);
            }
        }

        task
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

    fn audit_save_outcome(&mut self, outcome: SaveOutcome) {
        let artifacts = match outcome {
            SaveOutcome::Cancelled => return,
            SaveOutcome::Wrote(artifacts) | SaveOutcome::Failed(artifacts) => artifacts,
        };
        if artifacts.is_empty() {
            return;
        }

        let (filename, sha256) = self.extract_evidence_identity();
        let context = self.active_extraction.clone().or_else(|| {
            let path = self.extract.path.clone()?;
            let parameters = self.extract.forensic_parameters().ok()?;
            Some(OperationContext::extraction(&path, parameters))
        });
        let case_id = self.case.id;

        let logged = {
            let mut audit = self.audit_mut();
            match audit.as_mut() {
                None => Err(String::from(
                    "Artifacts were saved, but the forensic audit logger is unavailable.",
                )),
                Some(logger) => {
                    let mut result = Ok(());
                    for artifact in &artifacts {
                        if let Err(err) = logger.log_artifact_with_context(
                            case_id,
                            filename.clone(),
                            sha256.clone(),
                            artifact,
                            context.clone(),
                        ) {
                            result = Err(format!(
                                "Artifact was saved, but ARTIFACT_CREATED could not be logged: {err}"
                            ));
                            break;
                        }
                    }
                    result
                }
            }
        };

        if let Err(err) = logged {
            let existing = self.extract.error.clone();
            self.extract.error = Some(match existing {
                Some(previous) => format!("{previous}\n{err}"),
                None => format!("Artifact was saved, but ARTIFACT_CREATED could not be logged: {err}"),
            });
            self.extract.status = String::from("Artifact audit failure");
        }
    }

    fn audit_analysis_success(&mut self) -> Result<(), String> {
        let Some(evidence) = self.analyze.evidence.as_ref() else {
            return Err(String::from(
                "Analysis finished, but no evidence record is available to audit.",
            ));
        };

        let filename = evidence.filename.clone();
        let sha256 = evidence.sha256.clone();
        let path = evidence.path.clone();
        let integrity_result = match evidence.integrity_status {
            IntegrityStatus::Verified => AuditResult::Verified,
            IntegrityStatus::Failed => AuditResult::Failed,
            IntegrityStatus::Unverified => AuditResult::Unverified,
        };
        let context = OperationContext::evidence(&path);
        let case_id = self.case.id;

        let mut audit = self.audit_mut();
        let Some(logger) = audit.as_mut() else {
            return Err(String::from(
                "Forensic audit logger is unavailable. Analysis was not recorded.",
            ));
        };

        logger
            .log_with_context(
                case_id,
                AuditAction::AnalysisCompleted,
                Some(filename.clone()),
                Some(sha256.clone()),
                None,
                AuditResult::Success,
                context.clone(),
            )
            .map_err(|err| format!("Failed to write ANALYSIS_COMPLETED audit entry: {err}"))?;

        logger
            .log_with_context(
                case_id,
                AuditAction::IntegrityVerification,
                Some(filename),
                Some(sha256),
                None,
                integrity_result,
                context,
            )
            .map_err(|err| format!("Failed to write INTEGRITY_VERIFICATION audit entry: {err}"))?;

        Ok(())
    }

    fn audit_analysis_failure(&mut self, failure: &str) -> Result<(), String> {
        let evidence = self.analyze.evidence.as_ref();
        let filename = evidence.map(|e| e.filename.clone());
        let sha256 = evidence.map(|e| e.sha256.clone());
        let context = evidence.map(|e| OperationContext::evidence(&e.path));
        let case_id = self.case.id;

        let mut audit = self.audit_mut();
        let Some(logger) = audit.as_mut() else {
            return Err(String::from(
                "Forensic audit logger is unavailable. Analysis failure was not recorded.",
            ));
        };

        let result = match context {
            Some(context) => logger.log_with_context(
                case_id,
                AuditAction::AnalysisFailed,
                filename,
                sha256,
                None,
                AuditResult::Failed,
                context,
            ),
            None => logger.log(
                case_id,
                AuditAction::AnalysisFailed,
                filename,
                sha256,
                None,
                AuditResult::Failed,
            ),
        };

        result.map_err(|err| {
            format!("Failed to write ANALYSIS_FAILED audit entry for '{failure}': {err}")
        })?;
        Ok(())
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

        let mut column = iced::widget::column![header];
        if let Some(notice) = &self.notice {
            column = column.push(
                iced::widget::container(
                    iced::widget::text(notice).size(13).color(theme::WARN),
                )
                .padding([8, 16])
                .width(Fill)
                .style(theme::header_bar),
            );
        }

        column.push(body).height(Fill).into()
    }
}

fn tab_btn(label: &'static str, tab: Tab, current: Tab) -> Element<'static, Message> {
    iced::widget::button(iced::widget::text(label).size(14))
        .on_press(Message::Tab(tab))
        .style(theme::tab_button(tab == current))
        .padding([8, 16])
        .into()
}