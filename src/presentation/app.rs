use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iced::window;
use iced::{Element, Fill, Font, Size, Subscription, Task, Theme};

use crate::application::evidence_copy::copy_evidence_for_analysis;
use crate::infrastructure::adapters::FsEvidenceCopier;
use crate::presentation::analyze;
use crate::presentation::custody;
use crate::presentation::extract::{self, SaveOutcome};
use crate::forensic::audit::{AuditAction, AuditEntry, AuditLogger, AuditResult};
use crate::forensic::case::Case;
use crate::forensic::context::{CarveParameters, HostContext, OperationContext};
use crate::forensic::evidence::IntegrityStatus;
use crate::forensic::seal::SealReport;
use crate::forensic::verify::VerificationReport;
use crate::presentation::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Analyze,
    Extract,
    Custody,
}

#[derive(Debug, Clone)]
pub struct SealedCase {
    report: SealReport,
    entries: Result<Vec<AuditEntry>, String>,
    verification: Result<VerificationReport, String>,
}

#[derive(Debug, Clone)]
pub enum Message {
    MainOpened,
    HexOpened,
    CloseRequested(window::Id),
    CaseSealed(Result<SealedCase, String>),
    Exit,
    CloseSeal,
    CloseDiscard,
    CloseCancel,
    Tab(Tab),
    Analyze(analyze::Message),
    Extract(extract::Message),
}

pub struct App {
    main_window: window::Id,
    hex_window: Option<window::Id>,
    preview_window: Option<window::Id>,
    tab: Tab,
    analyze: analyze::State,
    extract: extract::State,
    case: Case,
    audit: Arc<Mutex<Option<AuditLogger>>>,
    audit_entries: Vec<AuditEntry>,
    artifact_directories: Vec<PathBuf>,
    case_closed: bool,
    sealing: bool,
    seal_review: Option<SealedCase>,
    close_prompt: bool,
    notice: Option<String>,
    active_extraction: Option<OperationContext>,
    active_carve: Option<OperationContext>,
}

impl App {
    fn audit_mut(&self) -> std::sync::MutexGuard<'_, Option<AuditLogger>> {
        self.audit.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn abandon_and_exit(&mut self) -> Task<Message> {
        let case_id = self.case.id;
        let logged = match self.audit_mut().as_mut() {
            Some(logger) => logger
                .log(
                    case_id,
                    AuditAction::CaseAbandoned,
                    None,
                    None,
                    None,
                    AuditResult::Success,
                )
                .map_err(|err| err.to_string()),
            None => Err(String::from("audit logger is unavailable")),
        };
        match logged {
            Ok(entry) => {
                self.audit_entries.push(entry);
                iced::exit()
            }
            Err(err) => {
                self.notice = Some(format!(
                    "Could not record CASE_ABANDONED, the case is still open: {err}"
                ));
                Task::none()
            }
        }
    }

    fn spawn_seal(&self) -> Task<Message> {
        let audit = Arc::clone(&self.audit);
        let case = self.case.clone();
        let artifact_directories = self.artifact_directories.clone();
        Task::perform(
            async move {
                match tokio::task::spawn_blocking(move || {
                    seal_and_verify(audit, case, artifact_directories)
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

    fn remember_artifact_directory(&mut self, path: &Path) {
        let Some(parent) = path.parent() else {
            return;
        };
        if parent.as_os_str().is_empty() || !parent.is_dir() {
            return;
        }
        if self.artifact_directories.iter().any(|existing| existing == parent) {
            return;
        }
        self.artifact_directories.push(parent.to_path_buf());
    }

    pub fn boot() -> (Self, Task<Message>) {
        let (main_window, open) = window::open(window::Settings {
            size: Size::new(1280.0, 820.0),
            exit_on_close_request: false,
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

        let mut audit_entries = Vec::new();
        if let Some(logger) = audit.as_mut() {
            match logger.log(
                case.id,
                AuditAction::CaseCreated,
                None,
                None,
                case_metadata_sha256,
                AuditResult::Success,
            ) {
                Ok(entry) => audit_entries.push(entry),
                Err(err) => eprintln!("Failed to write CASE_CREATED audit entry: {err}"),
            }
        }

        (
            Self {
                main_window,
                hex_window: None,
                preview_window: None,
                tab: Tab::Analyze,
                analyze: analyze::State::default(),
                extract: extract::State::default(),
                case,
                audit: Arc::new(Mutex::new(audit)),
                audit_entries,
                artifact_directories: Vec::new(),
                case_closed: false,
                sealing: false,
                seal_review: None,
                close_prompt: false,
                notice: None,
                active_extraction: None,
                active_carve: None,
            },
            open.map(|_| Message::MainOpened),
        )
    }

    pub fn title(&self, window: window::Id) -> String {
        if Some(window) == self.hex_window {
            self.analyze.hex_title()
        } else if Some(window) == self.preview_window {
            self.extract.preview_title()
        } else {
            String::from("BitsPlayer")
        }
    }

    pub fn theme(&self, _window: window::Id) -> Theme {
        theme::bitsplayer_theme()
    }

    pub fn subscription(&self) -> Subscription<Message> {
        let closed = window::close_requests().map(Message::CloseRequested);
        let mut subscriptions = vec![closed];
        if self.extract.running {
            subscriptions.push(
                iced::time::every(Duration::from_millis(80))
                    .map(|_| Message::Extract(extract::Message::Tick)),
            );
        }
        if self.analyze.carving {
            subscriptions.push(
                iced::time::every(Duration::from_millis(80))
                    .map(|_| Message::Analyze(analyze::Message::CarveTick)),
            );
        }
        Subscription::batch(subscriptions)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::MainOpened | Message::HexOpened => Task::none(),
            Message::Exit => iced::exit(),
            Message::CloseSeal => {
                self.close_prompt = false;
                if self.sealing || self.case_closed {
                    return Task::none();
                }
                self.sealing = true;
                self.notice = Some(String::from("Sealing forensic case…"));
                self.analyze.status = String::from("Sealing forensic case…");
                self.spawn_seal()
            }
            Message::CloseDiscard => {
                self.close_prompt = false;
                self.abandon_and_exit()
            }
            Message::CloseCancel => {
                self.close_prompt = false;
                Task::none()
            }
            Message::CloseRequested(id) => {
                if id == self.main_window {
                    if self.case_closed {
                        return iced::exit();
                    }
                    if self.sealing {
                        return Task::none();
                    }
                    let untouched = self
                        .audit_entries
                        .iter()
                        .all(|entry| entry.action == AuditAction::CaseCreated);
                    if untouched {
                        return self.abandon_and_exit();
                    }
                    self.close_prompt = true;
                    Task::none()
                } else if Some(id) == self.hex_window {
                    self.hex_window = None;
                    let _ = self.analyze.update(analyze::Message::CloseHex);
                    window::close(id)
                } else if Some(id) == self.preview_window {
                    self.preview_window = None;
                    let _ = self.extract.update(extract::Message::ClosePreview);
                    window::close(id)
                } else {
                    Task::none()
                }
            }
            Message::CaseSealed(result) => {
                self.sealing = false;
                match result {
                    Ok(sealed) => {
                        self.case_closed = true;
                        self.notice = None;
                        if let Ok(entries) = &sealed.entries {
                            self.audit_entries.clone_from(entries);
                        }
                        let status = match &sealed.verification {
                            Ok(_) => String::from("Forensic case sealed. Review the custody report before exiting."),
                            Err(_) => String::from("Forensic case sealed, but verification failed."),
                        };
                        self.analyze.status.clone_from(&status);
                        self.extract.status = status;
                        self.seal_review = Some(sealed);
                        Task::none()
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
                if self.seal_review.is_some() {
                    return Task::none();
                }
                self.tab = tab;
                Task::none()
            }
            Message::Analyze(analyze::Message::OpenExtract) => {
                if !self.extract.has_carve() {
                    self.analyze.error = Some(String::from(
                        "Extraction is blocked until a carve analysis has completed and been recorded in the audit log.",
                    ));
                    self.analyze.status = String::from("Extract blocked: no carve analysis");
                    return Task::none();
                }

                self.tab = Tab::Extract;
                Task::none()
            }
            Message::Analyze(analyze::Message::ExtractSelected(index)) => {
                if !self.extract.has_carve() {
                    self.analyze.error = Some(String::from(
                        "Extraction is blocked until a carve analysis has completed and been recorded in the audit log.",
                    ));
                    self.analyze.status = String::from("Extract blocked: no carve analysis");
                    return Task::none();
                }

                self.tab = Tab::Extract;
                self.update_extract(extract::Message::RunSingle(index))
            }
            Message::Analyze(msg) => self.update_analyze(msg),
            Message::Extract(msg) => self.update_extract(msg),
        }
    }

    fn spawn_evidence_copy(&self, source: PathBuf) -> Task<Message> {
        let audit = Arc::clone(&self.audit);
        let case_id = self.case.id;
        let case_directory = self.case.case_directory.clone();
        Task::perform(
            async move {
                match tokio::task::spawn_blocking(move || {
                    let mut guard = audit.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let Some(logger) = guard.as_mut() else {
                        return Err(String::from(
                            "Forensic audit logger is unavailable. Analysis aborted.",
                        ));
                    };
                    copy_evidence_for_analysis(
                        logger,
                        &FsEvidenceCopier,
                        case_id,
                        &case_directory,
                        &source,
                    )
                    .map_err(|err| format!("Evidence copy failed: {err}"))
                })
                .await
                {
                    Ok(result) => result,
                    Err(err) => Err(format!("Evidence copy task failed: {err}")),
                }
            },
            |result| Message::Analyze(analyze::Message::CopyReady(result)),
        )
    }

    fn update_analyze(&mut self, msg: analyze::Message) -> Task<Message> {
        if let analyze::Message::CopyRequested(source) = msg {
            return self.spawn_evidence_copy(source);
        }

        if matches!(msg, analyze::Message::CopyReady(_)) {
            let audit_path = self.case.case_directory.join("logs").join("audit.jsonl");
            if let Ok(entries) = crate::forensic::audit::read_verified_audit(&audit_path, self.case.id) {
                self.audit_entries = entries;
            }
        }

        if matches!(msg, analyze::Message::Browse) {
            self.extract.clear_carve();
        }

        if matches!(msg, analyze::Message::Carve) {
            if let Err(err) = self.start_carve_audit() {
                self.analyze.error = Some(err);
                self.analyze.status = String::from("Carve blocked");
                return Task::none();
            }
        }

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

                let mut committed = Vec::new();
                let mut failure = None;
                match logger.log_with_context(
                    case_id,
                    AuditAction::EvidenceRegistered,
                    Some(filename.clone()),
                    Some(sha256.clone()),
                    None,
                    AuditResult::Success,
                    context.clone(),
                ) {
                    Ok(entry) => committed.push(entry),
                    Err(err) => failure = Some(err.to_string()),
                }
                if failure.is_none() {
                    match logger.log_with_context(
                        case_id,
                        AuditAction::AnalysisStarted,
                        Some(filename),
                        Some(sha256),
                        None,
                        AuditResult::Started,
                        context,
                    ) {
                        Ok(entry) => committed.push(entry),
                        Err(err) => failure = Some(err.to_string()),
                    }
                }
                (committed, failure)
            };

            let (committed, failure) = registered;
            self.audit_entries.extend(committed);
            if let Some(err) = failure {
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

        let carve_outcome = match &msg {
            analyze::Message::CarveFinished(result) => Some(result.clone()),
            _ => None,
        };

        let was_open = self.analyze.hex_is_open();
        let task = self.analyze.update(msg).map(Message::Analyze);

        if let Some(result) = carve_outcome {
            self.finish_carve_audit(result);
        }

        if finished_successfully {
            match self.audit_analysis_success() {
                Ok(()) => {}
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
        if matches!(msg, extract::Message::Run | extract::Message::RunSingle(_)) {
            self.extract.set_mode(match msg {
                extract::Message::RunSingle(index) => Some(index),
                _ => None,
            });

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
                self.extract.error = Some(String::from("Choose an MP4 or MOV file first"));
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

            match started {
                Ok(entry) => self.audit_entries.push(entry),
                Err(err) => {
                    self.extract.error = Some(format!(
                        "Failed to record extraction start in forensic audit: {err}"
                    ));
                    self.extract.status = String::from("Extraction blocked: audit write failed");
                    return Task::none();
                }
            }

            self.active_extraction = Some(context);
        }

        let was_running = self.extract.running;
        let is_tick = matches!(msg, extract::Message::Tick);
        let is_save = matches!(msg, extract::Message::Save);

        let selected_before = self.extract.selected;
        let task = self.extract.update(msg).map(Message::Extract);
        let task = match (selected_before, self.extract.selected) {
            (Some(_), None) => Task::batch([task, self.close_preview_window()]),
            (before, Some(now)) if before != Some(now) => {
                Task::batch([task, self.ensure_preview_window()])
            }
            _ => task,
        };

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
                            .map_err(|err| err.to_string()),
                    }
                }
            };

            match recorded {
                Ok(entry) => self.audit_entries.push(entry),
                Err(err) => {
                    let existing = self.extract.error.clone();
                    self.extract.error = Some(match existing {
                        Some(previous) => format!("{previous}\nForensic audit write failed: {err}"),
                        None => format!(
                            "Extraction finished, but the forensic audit write failed: {err}"
                        ),
                    });
                    self.extract.status = String::from("Extraction audit failure");
                }
            }
        }

        if is_save {
            if let Some(outcome) = self.extract.take_last_save() {
                self.audit_save_outcome(outcome);
            }
        }

        task
    }

    fn start_carve_audit(&mut self) -> Result<(), String> {
        if self.extract.running {
            return Err(String::from("Wait for the running extraction to finish"));
        }
        let parameters = self.analyze.carve_request()?;
        let evidence = self
            .analyze
            .evidence
            .as_ref()
            .ok_or_else(|| String::from("No evidence loaded"))?;
        let filename = evidence.filename.clone();
        let sha256 = evidence.sha256.clone();
        let context = carve_context(&evidence.path, parameters);
        let case_id = self.case.id;

        let entry = {
            let mut audit = self.audit_mut();
            let Some(logger) = audit.as_mut() else {
                return Err(String::from(
                    "Forensic audit logger is unavailable. Carve aborted.",
                ));
            };
            logger
                .log_with_context(
                    case_id,
                    AuditAction::CarveAnalysisStarted,
                    Some(filename),
                    Some(sha256),
                    None,
                    AuditResult::Started,
                    context.clone(),
                )
                .map_err(|err| format!("Failed to record carve start in forensic audit: {err}"))?
        };
        self.audit_entries.push(entry);
        self.active_carve = Some(context);
        Ok(())
    }

    fn finish_carve_audit(&mut self, result: Result<Arc<analyze::CarveResult>, String>) {
        let evidence = self.analyze.evidence.as_ref();
        let filename = evidence.map(|e| e.filename.clone());
        let sha256 = evidence.map(|e| e.sha256.clone());
        let failed = result.is_err();
        let case_id = self.case.id;

        let recorded = match self.active_carve.take() {
            None => Err(String::from(
                "Carve finished, but the forensic parameter snapshot is missing.",
            )),
            Some(context) => {
                let mut audit = self.audit_mut();
                match audit.as_mut() {
                    None => Err(String::from(
                        "Carve finished, but the forensic audit logger is unavailable.",
                    )),
                    Some(logger) => logger
                        .log_with_context(
                            case_id,
                            if failed {
                                AuditAction::CarveAnalysisFailed
                            } else {
                                AuditAction::CarveAnalysisCompleted
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
                        .map_err(|err| err.to_string()),
                }
            }
        };

        match recorded {
            Ok(entry) => {
                self.audit_entries.push(entry);
                if let Ok(carve) = result {
                    self.extract.set_carve(carve);
                }
            }
            Err(err) => {
                let existing = self.analyze.error.clone();
                self.analyze.error = Some(match existing {
                    Some(previous) => format!("{previous}\nForensic audit write failed: {err}"),
                    None => format!("Carve finished, but the forensic audit write failed: {err}"),
                });
                self.analyze.status = String::from("Carve audit failure");
            }
        }
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
                None => Err((
                    Vec::new(),
                    Vec::new(),
                    String::from(
                        "Artifacts were saved, but the forensic audit logger is unavailable.",
                    ),
                )),
                Some(logger) => {
                    let mut entries = Vec::new();
                    let mut paths = Vec::new();
                    let mut failure = None;
                    for artifact in &artifacts {
                        match logger.log_artifact_with_context(
                            case_id,
                            filename.clone(),
                            sha256.clone(),
                            artifact,
                            context.clone(),
                        ) {
                            Ok(entry) => {
                                paths.push(artifact.path.clone());
                                entries.push(entry);
                            }
                            Err(err) => {
                                failure = Some(format!(
                                    "Artifact was saved, but ARTIFACT_CREATED could not be logged: {err}"
                                ));
                                break;
                            }
                        }
                    }
                    match failure {
                        Some(err) => Err((entries, paths, err)),
                        None => Ok((entries, paths)),
                    }
                }
            }
        };

        let (entries, paths, failure) = match logged {
            Ok((entries, paths)) => (entries, paths, None),
            Err((entries, paths, err)) => (entries, paths, Some(err)),
        };
        self.audit_entries.extend(entries);
        for path in paths {
            self.remember_artifact_directory(&path);
        }
        if let Some(err) = failure {
            let existing = self.extract.error.clone();
            self.extract.error = Some(match existing {
                Some(previous) => format!("{previous}\n{err}"),
                None => err,
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

        let entries = {
            let mut audit = self.audit_mut();
            let Some(logger) = audit.as_mut() else {
                return Err(String::from(
                    "Forensic audit logger is unavailable. Analysis was not recorded.",
                ));
            };

            let mut committed = Vec::new();
            let mut failure = None;
            match logger.log_with_context(
                case_id,
                AuditAction::AnalysisCompleted,
                Some(filename.clone()),
                Some(sha256.clone()),
                None,
                AuditResult::Success,
                context.clone(),
            ) {
                Ok(entry) => committed.push(entry),
                Err(err) => {
                    failure = Some(format!(
                        "Failed to write ANALYSIS_COMPLETED audit entry: {err}"
                    ));
                }
            }
            if failure.is_none() {
                match logger.log_with_context(
                    case_id,
                    AuditAction::IntegrityVerification,
                    Some(filename),
                    Some(sha256),
                    None,
                    integrity_result,
                    context,
                ) {
                    Ok(entry) => committed.push(entry),
                    Err(err) => {
                        failure = Some(format!(
                            "Failed to write INTEGRITY_VERIFICATION audit entry: {err}"
                        ));
                    }
                }
            }
            (committed, failure)
        };
        let (committed, failure) = entries;
        self.audit_entries.extend(committed);
        if let Some(err) = failure {
            return Err(err);
        }
        Ok(())
    }

    fn audit_analysis_failure(&mut self, failure: &str) -> Result<(), String> {
        let evidence = self.analyze.evidence.as_ref();
        let filename = evidence.map(|e| e.filename.clone());
        let sha256 = evidence.map(|e| e.sha256.clone());
        let context = evidence.map(|e| OperationContext::evidence(&e.path));
        let case_id = self.case.id;

        let entry = {
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
            })?
        };
        self.audit_entries.push(entry);
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
            exit_on_close_request: false,
            ..Default::default()
        });

        self.hex_window = Some(id);
        open.map(|_| Message::HexOpened)
    }

    fn ensure_preview_window(&mut self) -> Task<Message> {
        if let Some(id) = self.preview_window {
            return window::gain_focus(id);
        }

        let (id, open) = window::open(window::Settings {
            size: Size::new(1000.0, 700.0),
            position: window::Position::Centered,
            min_size: Some(Size::new(400.0, 300.0)),
            exit_on_close_request: false,
            ..Default::default()
        });

        self.preview_window = Some(id);
        open.map(|_| Message::HexOpened)
    }

    fn close_preview_window(&mut self) -> Task<Message> {
        match self.preview_window.take() {
            Some(id) => window::close(id),
            None => Task::none(),
        }
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
        if Some(window) == self.preview_window {
            return self.extract.preview_window_view().map(Message::Extract);
        }

        let reviewing = self.seal_review.is_some();
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
            Tab::Custody => self
                .case
                .case_directory
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(""),
        };

        let header = iced::widget::container(
            iced::widget::row![
                iced::widget::column![
                    iced::widget::text("BitsPlayer").size(20).color(theme::TEXT),
                    iced::widget::text("MP4/MOV forensics")
                        .size(12)
                        .color(theme::MUTED),
                ]
                .spacing(2),
                iced::widget::Space::with_width(24),
                tab_btn(
                    "Analyze",
                    Tab::Analyze,
                    !reviewing && self.tab == Tab::Analyze,
                    !reviewing,
                ),
                tab_btn(
                    "Extract",
                    Tab::Extract,
                    !reviewing && self.tab == Tab::Extract,
                    !reviewing,
                ),
                tab_btn(
                    "Custody",
                    Tab::Custody,
                    !reviewing && self.tab == Tab::Custody,
                    !reviewing,
                ),
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

        let body: Element<_> = if let Some(sealed) = &self.seal_review {
            custody::seal_review(
                custody::Review {
                    report: &sealed.report,
                    verification: &sealed.verification,
                },
                Message::Exit,
            )
        } else {
            match self.tab {
                Tab::Analyze => self.analyze.view().map(Message::Analyze),
                Tab::Extract => self.extract.view().map(Message::Extract),
                Tab::Custody => custody::view(custody::Snapshot {
                    case_name: &self.case.name,
                    case_id: self.case.id,
                    examiner: self.case.examiner.as_deref(),
                    case_directory: &self.case.case_directory,
                    created_at: self.case.created_at,
                    open: !self.case_closed,
                    entries: &self.audit_entries,
                }),
            }
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

        let main: Element<_> = column.push(body).height(Fill).into();
        if self.close_prompt {
            iced::widget::stack![main, close_dialog()].into()
        } else {
            main
        }
    }
}

fn close_dialog() -> Element<'static, Message> {
    use iced::widget::{button, center, column, container, mouse_area, opaque, row, text, Space};

    let dialog = container(
        column![
            text("Close this case?").size(18).color(theme::TEXT),
            text(
                "Seal writes the report, closes the audit log with CASE_CLOSED and signs it. \
                 Discard records CASE_ABANDONED and exits; the case stays on disk unsealed \
                 and will not verify.",
            )
            .size(13)
            .color(theme::MUTED),
            row![
                Space::with_width(Fill),
                button(text("Cancel").size(14))
                    .on_press(Message::CloseCancel)
                    .style(theme::secondary_button)
                    .padding([8, 14]),
                button(text("Discard").size(14))
                    .on_press(Message::CloseDiscard)
                    .style(theme::secondary_button)
                    .padding([8, 14]),
                button(text("Seal case").size(14))
                    .on_press(Message::CloseSeal)
                    .style(theme::primary_button)
                    .padding([8, 14]),
            ]
            .spacing(8),
        ]
        .spacing(14),
    )
    .padding(20)
    .max_width(460)
    .style(theme::panel);

    opaque(
        mouse_area(
            center(opaque(dialog)).style(|_| container::Style {
                background: Some(iced::Background::Color(iced::Color {
                    a: 0.6,
                    ..iced::Color::BLACK
                })),
                ..Default::default()
            }),
        )
        .on_press(Message::CloseCancel),
    )
}

fn carve_context(path: &Path, parameters: CarveParameters) -> OperationContext {
    OperationContext {
        carve_parameters: Some(parameters),
        ..OperationContext::evidence(path)
    }
}

fn tab_btn(
    label: &'static str,
    tab: Tab,
    active: bool,
    enabled: bool,
) -> Element<'static, Message> {
    let button = iced::widget::button(iced::widget::text(label).size(14))
        .style(theme::tab_button(active))
        .padding([8, 16]);
    if enabled {
        button.on_press(Message::Tab(tab)).into()
    } else {
        button.into()
    }
}

fn seal_and_verify(
    audit: Arc<Mutex<Option<AuditLogger>>>,
    case: Case,
    artifact_directories: Vec<PathBuf>,
) -> Result<SealedCase, String> {
    let report = {
        let mut guard = audit.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(logger) = guard.as_mut() else {
            return Err(String::from(
                "Cannot seal forensic case: audit logger is unavailable",
            ));
        };
        crate::forensic::seal::seal_case(logger, &case).map_err(|err| err.to_string())?
    };

    let audit_path = case.case_directory.join("logs").join("audit.jsonl");
    let entries = crate::forensic::audit::read_verified_audit(&audit_path, case.id);
    let verification = match &entries {
        Ok(_) => crate::forensic::verify::verify_case_directories(
            &case.case_directory,
            &artifact_directories,
            &report.signing_directory.join("public.key"),
        ),
        Err(err) => Err(format!("sealed audit log could not be re-read: {err}")),
    };

    Ok(SealedCase {
        report,
        entries,
        verification,
    })
}