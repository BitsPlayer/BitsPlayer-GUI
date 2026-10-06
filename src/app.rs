use std::path::PathBuf;
use std::time::Duration;

use iced::window;
use iced::{Element, Fill, Font, Size, Subscription, Task, Theme};

use crate::analyze;
use crate::extract;
use crate::forensic::audit::AuditLogger;
use crate::forensic::case::Case;
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

    // Forensic session state
    case: Case,
    audit: Option<AuditLogger>,
}

impl App {
    pub fn boot() -> (Self, Task<Message>) {
        let (main_window, open) = window::open(window::Settings {
            size: Size::new(1280.0, 820.0),
            ..Default::default()
        });

        let cases_directory = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("cases");

        let case = Case::new_in_base(
            "BitsPlayer Session",
            None,
            &cases_directory,
        );

        if let Err(err) = case.save() {
            eprintln!(
                "Failed to save forensic case metadata: {err}"
            );
        }

        let audit_path = case
            .case_directory
            .join("logs")
            .join("audit.jsonl");

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
                "CASE_CREATED",
                None,
                None,
                "success",
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
                audit,
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
        let closed =
            window::close_events().map(Message::WindowClosed);

        if self.extract.running {
            Subscription::batch([
                closed,
                iced::time::every(
                    Duration::from_millis(80),
                )
                .map(|_| {
                    Message::Extract(
                        extract::Message::Tick,
                    )
                }),
            ])
        } else {
            closed
        }
    }

    pub fn update(
        &mut self,
        message: Message,
    ) -> Task<Message> {
        match message {
            Message::MainOpened
            | Message::HexOpened => Task::none(),

            Message::WindowClosed(id) => {
                if id == self.main_window {
                    iced::exit()
                } else if Some(id)
                    == self.hex_window
                {
                    self.hex_window = None;

                    let _ = self.analyze.update(
                        analyze::Message::CloseHex,
                    );

                    Task::none()
                } else {
                    Task::none()
                }
            }

            Message::Tab(tab) => {
                self.tab = tab;
                Task::none()
            }

            Message::Analyze(
                analyze::Message::OpenExtract,
            ) => {
                self.tab = Tab::Extract;

                if let Some(v) = self
                    .analyze
                    .analysis
                    .as_ref()
                    .and_then(|a| a.video.as_ref())
                    && v.width > 0
                    && v.height > 0
                {
                    self.extract.prefill(
                        v.width,
                        v.height,
                    );
                }

                Task::none()
            }

            Message::Analyze(msg) => {
                self.update_analyze(msg)
            }

            Message::Extract(msg) => {
                self.extract
                    .update(msg)
                    .map(Message::Extract)
            }
        }
    }

    fn update_analyze(
        &mut self,
        msg: analyze::Message,
    ) -> Task<Message> {
        let selecting =
            matches!(
                msg,
                analyze::Message::MapSelect(_)
            );

        let finished_successfully =
            matches!(
                &msg,
                analyze::Message::Finished(Ok(_))
            );

        let was_open =
            self.analyze.hex_is_open();

        let task =
            self.analyze
                .update(msg)
                .map(Message::Analyze);

        if finished_successfully {
            self.audit_analysis_success();

            if let Some(v) = self
                .analyze
                .analysis
                .as_ref()
                .and_then(|a| a.video.as_ref())
                && v.width > 0
                && v.height > 0
            {
                self.extract.prefill(
                    v.width,
                    v.height,
                );
            }
        }

        let now_open =
            self.analyze.hex_is_open();

        if was_open && !now_open {
            Task::batch([
                task,
                self.close_hex_window(),
            ])
        } else if now_open
            && (!was_open || selecting)
        {
            Task::batch([
                task,
                self.ensure_hex_window(),
            ])
        } else {
            task
        }
    }

    fn audit_analysis_success(&mut self) {
        let Some(evidence) =
            self.analyze.evidence.as_ref()
        else {
            return;
        };

        let Some(logger) =
            self.audit.as_mut()
        else {
            return;
        };

        if let Err(err) = logger.log(
            self.case.id,
            "EVIDENCE_REGISTERED",
            Some(
                evidence.filename.clone()
            ),
            Some(
                evidence.sha256.clone()
            ),
            "success",
        ) {
            eprintln!(
                "Failed to write EVIDENCE_REGISTERED audit entry: {err}"
            );
        }

        if let Err(err) = logger.log(
            self.case.id,
            "ANALYSIS_COMPLETED",
            Some(
                evidence.filename.clone()
            ),
            Some(
                evidence.sha256.clone()
            ),
            "success",
        ) {
            eprintln!(
                "Failed to write ANALYSIS_COMPLETED audit entry: {err}"
            );
        }

        let integrity_result =
            if evidence.integrity_verified {
                "verified"
            } else {
                "failed"
            };

        if let Err(err) = logger.log(
            self.case.id,
            "INTEGRITY_VERIFICATION",
            Some(
                evidence.filename.clone()
            ),
            Some(
                evidence.sha256.clone()
            ),
            integrity_result,
        ) {
            eprintln!(
                "Failed to write INTEGRITY_VERIFICATION audit entry: {err}"
            );
        }
    }

    fn ensure_hex_window(
        &mut self,
    ) -> Task<Message> {
        if let Some(id) =
            self.hex_window
        {
            return window::gain_focus(id);
        }

        let (id, open) =
            window::open(
                window::Settings {
                    size: Size::new(
                        920.0,
                        640.0,
                    ),

                    position:
                        window::Position::Centered,

                    min_size: Some(
                        Size::new(
                            520.0,
                            360.0,
                        ),
                    ),

                    ..Default::default()
                },
            );

        self.hex_window =
            Some(id);

        open.map(
            |_| Message::HexOpened
        )
    }

    fn close_hex_window(
        &mut self,
    ) -> Task<Message> {
        match self.hex_window.take() {
            Some(id) => {
                window::close(id)
            }

            None => Task::none(),
        }
    }

    pub fn view(
        &self,
        window: window::Id,
    ) -> Element<'_, Message> {
        if Some(window)
            == self.hex_window
        {
            return self
                .analyze
                .hex_window_view()
                .map(Message::Analyze);
        }

        let file_hint =
            match self.tab {
                Tab::Analyze => self
                    .analyze
                    .path
                    .as_ref()
                    .and_then(
                        |p| p.file_name()
                    )
                    .and_then(
                        |s| s.to_str()
                    )
                    .unwrap_or(""),

                Tab::Extract => self
                    .extract
                    .path
                    .as_ref()
                    .and_then(
                        |p| p.file_name()
                    )
                    .and_then(
                        |s| s.to_str()
                    )
                    .unwrap_or(""),
            };

        let header =
            iced::widget::container(
                iced::widget::row![
                    iced::widget::column![
                        iced::widget::text(
                            "BitsPlayer"
                        )
                        .size(20)
                        .color(
                            theme::TEXT
                        ),

                        iced::widget::text(
                            "MP4 forensics"
                        )
                        .size(12)
                        .color(
                            theme::MUTED
                        ),
                    ]
                    .spacing(2),

                    iced::widget::Space::with_width(
                        24
                    ),

                    tab_btn(
                        "Analyze",
                        Tab::Analyze,
                        self.tab
                    ),

                    tab_btn(
                        "Extract",
                        Tab::Extract,
                        self.tab
                    ),

                    iced::widget::Space::with_width(
                        Fill
                    ),

                    iced::widget::text(
                        file_hint
                    )
                    .size(12)
                    .font(
                        Font::MONOSPACE
                    )
                    .color(
                        theme::MUTED
                    ),
                ]
                .spacing(8)
                .align_y(
                    iced::Alignment::Center
                ),
            )
            .padding([12, 16])
            .width(Fill)
            .style(
                theme::header_bar
            );

        let body: Element<_> =
            match self.tab {
                Tab::Analyze => self
                    .analyze
                    .view()
                    .map(
                        Message::Analyze
                    ),

                Tab::Extract => self
                    .extract
                    .view()
                    .map(
                        Message::Extract
                    ),
            };

        iced::widget::column![
            header,
            body
        ]
        .height(Fill)
        .into()
    }
}

fn tab_btn(
    label: &'static str,
    tab: Tab,
    current: Tab,
) -> Element<'static, Message> {
    iced::widget::button(
        iced::widget::text(label)
            .size(14),
    )
    .on_press(
        Message::Tab(tab)
    )
    .style(
        theme::tab_button(
            tab == current
        )
    )
    .padding([8, 16])
    .into()
}