use chrono::{DateTime, Utc};

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Element, Fill, Font};
use uuid::Uuid;

use crate::forensic::audit::{AuditAction, AuditEntry, AuditResult};
use crate::forensic::context::ExtractionParameters;
use crate::forensic::seal::SealReport;
use crate::forensic::signing::IdentityOrigin;
use crate::forensic::verify::VerificationReport;
use crate::presentation::theme;

pub struct Snapshot<'a> {
    pub case_name: &'a str,
    pub case_id: Uuid,
    pub examiner: Option<&'a str>,
    pub case_directory: &'a std::path::Path,
    pub created_at: DateTime<Utc>,
    pub open: bool,
    pub entries: &'a [AuditEntry],
}

pub struct Review<'a> {
    pub report: &'a SealReport,
    pub verification: &'a Result<VerificationReport, String>,
}

pub fn view<'a, Message: 'a>(snapshot: Snapshot<'a>) -> Element<'a, Message> {
    let mut body = column![
        section_title("Case"),
        fact("Name", snapshot.case_name),
        fact("Case ID", &snapshot.case_id.to_string()),
        fact(
            "Examiner",
            snapshot.examiner.unwrap_or("not recorded"),
        ),
        fact("Directory", snapshot.case_directory.display().to_string()),
        fact("Created", format_time(snapshot.created_at)),
        fact(
            "Status",
            if snapshot.open { "Open" } else { "Sealed" },
        ),
    ]
    .spacing(6)
    .width(Fill);

    body = body.push(Space::with_height(16));
    body = body.push(section_title("Host and build"));

    if let Some(first) = snapshot.entries.first() {
        body = body.push(fact(
            "Host",
            first.host_context.host_name.as_deref().unwrap_or("not recorded"),
        ));
        body = body.push(fact("Operating system", &first.host_context.operating_system));
        body = body.push(fact("Architecture", &first.host_context.architecture));
        body = body.push(fact("Tool version", &first.tool_version));
        body = body.push(fact("Git commit", &first.git_commit));
        body = body.push(fact("Cargo.lock", &first.cargo_lock_sha256));
        body = body.push(fact("Binary", &first.binary_sha256));
    } else {
        body = body.push(muted("No audit entries recorded."));
    }

    let head = snapshot
        .entries
        .last()
        .map(|entry| entry.entry_hash.as_str())
        .unwrap_or("none");

    body = body.push(Space::with_height(16));
    body = body.push(section_title("Audit chain"));
    body = body.push(fact("Entries", snapshot.entries.len().to_string()));
    body = body.push(fact("Head", head));
    body = body.push(Space::with_height(8));

    if snapshot.entries.is_empty() {
        body = body.push(muted("The chain is empty."));
    } else {
        for entry in snapshot.entries {
            body = body.push(entry_card(entry));
        }
    }

    scrollable(
        container(body)
            .padding(16)
            .width(Fill),
    )
    .width(Fill)
    .height(Fill)
    .into()
}

pub fn seal_review<'a, Message: Clone + 'a>(
    review: Review<'a>,
    exit: Message,
) -> Element<'a, Message> {
    let mut body = column![section_title("Seal review")].spacing(6).width(Fill);

    let headline = match review.verification {
        Ok(report) if report.warnings.is_empty() => "Sealed case verified",
        Ok(_) => "Sealed case verified with warnings",
        Err(_) => "Case sealed, verification failed",
    };
    body = body.push(text(headline).size(18).color(theme::TEXT));

    if review.report.identity_origin == IdentityOrigin::Created {
        body = body.push(
            text(format!(
                "A new signing identity was created at {}. Trust this public key before relying on the signature.",
                review.report.signing_directory.display()
            ))
            .size(13)
            .color(theme::WARN),
        );
    } else {
        body = body.push(muted(format!(
            "Signing identity loaded from {}",
            review.report.signing_directory.display()
        )));
    }

    body = body.push(Space::with_height(8));
    body = body.push(fact(
        "Closure",
        review.report.closure_path.display().to_string(),
    ));
    body = body.push(fact(
        "Signature",
        review.report.signature_path.display().to_string(),
    ));
    body = body.push(fact(
        "Public key",
        review
            .report
            .signing_directory
            .join("public.key")
            .display()
            .to_string(),
    ));

    body = body.push(Space::with_height(16));
    body = body.push(section_title("Verifier"));

    match review.verification {
        Ok(report) => {
            for check in &report.checks {
                body = body.push(text(format!("[OK] {check}")).size(13).color(theme::TEXT));
            }
            for warning in &report.warnings {
                body = body.push(
                    text(format!("[WARNING] {warning}"))
                        .size(13)
                        .color(theme::WARN),
                );
            }
        }
        Err(error) => {
            body = body.push(text(error).size(13).color(theme::DANGER));
        }
    }

    body = body.push(Space::with_height(16));
    body = body.push(muted(
        "The case is already sealed on disk. Close the window again to exit.",
    ));
    body = body.push(
        button(text("Exit").size(14))
            .on_press(exit)
            .style(theme::primary_button)
            .padding([10, 16]),
    );

    scrollable(container(body).padding(16).width(Fill))
        .width(Fill)
        .height(Fill)
        .into()
}

fn entry_card<'a, Message: 'a>(entry: &'a AuditEntry) -> Element<'a, Message> {
    let mut lines = column![
        row![
            text(format!("#{}", entry.sequence))
                .size(13)
                .font(Font::MONOSPACE)
                .color(theme::ACCENT),
            Space::with_width(12),
            text(action_label(entry.action))
                .size(13)
                .color(theme::TEXT),
            Space::with_width(12),
            text(result_label(entry.result))
                .size(13)
                .color(result_color(entry.result)),
            Space::with_width(Fill),
            text(format_time(entry.timestamp))
                .size(12)
                .color(theme::MUTED),
        ]
        .align_y(iced::Alignment::Center)
        .width(Fill),
        text(entry_subject(entry))
            .size(12)
            .font(Font::MONOSPACE)
            .color(theme::TEXT),
    ]
    .spacing(4)
    .width(Fill);

    if let Some(hash) = entry
        .artifact_sha256
        .as_deref()
        .or(entry.evidence_sha256.as_deref())
    {
        lines = lines.push(
            text(format!("SHA-256 {}", short_hash(hash)))
                .size(12)
                .font(Font::MONOSPACE)
                .color(theme::MUTED),
        );
    }

    if let Some(parameters) = entry
        .operation_context
        .as_ref()
        .and_then(|context| context.extraction_parameters.as_ref())
    {
        lines = lines.push(
            text(extraction_detail(parameters))
                .size(12)
                .color(theme::MUTED),
        );
    }

    lines = lines.push(
        text(format!("entry {}", short_hash(&entry.entry_hash)))
            .size(12)
            .font(Font::MONOSPACE)
            .color(theme::MUTED),
    );

    container(lines)
        .padding(12)
        .width(Fill)
        .style(theme::panel)
        .into()
}

fn section_title<'a, Message: 'a>(label: &'a str) -> Element<'a, Message> {
    text(label).size(12).color(theme::MUTED).into()
}

fn fact<'a, Message: 'a>(label: impl Into<String>, value: impl Into<String>) -> Element<'a, Message> {
    row![
        text(label.into()).size(13).color(theme::MUTED).width(140),
        text(value.into())
            .size(13)
            .font(Font::MONOSPACE)
            .color(theme::TEXT)
            .width(Fill),
    ]
    .spacing(8)
    .width(Fill)
    .into()
}

fn muted<'a, Message: 'a>(value: impl Into<String>) -> Element<'a, Message> {
    text(value.into()).size(13).color(theme::MUTED).into()
}

fn entry_subject(entry: &AuditEntry) -> String {
    if let Some(filename) = entry.artifact_filename.as_deref() {
        let kind = entry.artifact_type.as_deref().unwrap_or("artifact");
        return format!("{kind} {filename}");
    }
    if let Some(filename) = entry.evidence_filename.as_deref() {
        return filename.to_string();
    }
    String::from("—")
}

fn extraction_detail(parameters: &ExtractionParameters) -> String {
    format!(
        "{}×{} {} · non-IDR {} · partial {} · audio {} · all frames {}",
        parameters.width,
        parameters.height,
        parameters.matrix,
        on_off(parameters.include_non_idr),
        on_off(parameters.include_partial),
        on_off(parameters.with_audio),
        on_off(parameters.all_frames),
    )
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn action_label(action: AuditAction) -> &'static str {
    match action {
        AuditAction::CaseCreated => "CASE_CREATED",
        AuditAction::CaseMetadataUpdated => "CASE_METADATA_UPDATED",
        AuditAction::EvidenceCopyStarted => "EVIDENCE_COPY_STARTED",
        AuditAction::EvidenceCopyCompleted => "EVIDENCE_COPY_COMPLETED",
        AuditAction::EvidenceCopyFailed => "EVIDENCE_COPY_FAILED",
        AuditAction::EvidenceRegistered => "EVIDENCE_REGISTERED",
        AuditAction::AnalysisStarted => "ANALYSIS_STARTED",
        AuditAction::AnalysisCompleted => "ANALYSIS_COMPLETED",
        AuditAction::AnalysisFailed => "ANALYSIS_FAILED",
        AuditAction::IntegrityVerification => "INTEGRITY_VERIFICATION",
        AuditAction::ExtractStarted => "EXTRACT_STARTED",
        AuditAction::ExtractCompleted => "EXTRACT_COMPLETED",
        AuditAction::ExtractFailed => "EXTRACT_FAILED",
        AuditAction::ArtifactCreated => "ARTIFACT_CREATED",
        AuditAction::CaseClosed => "CASE_CLOSED",
    }
}

fn result_label(result: AuditResult) -> &'static str {
    match result {
        AuditResult::Started => "STARTED",
        AuditResult::Success => "SUCCESS",
        AuditResult::Failed => "FAILED",
        AuditResult::Verified => "VERIFIED",
        AuditResult::Unverified => "UNVERIFIED",
    }
}

fn result_color(result: AuditResult) -> iced::Color {
    match result {
        AuditResult::Failed => theme::DANGER,
        AuditResult::Unverified => theme::WARN,
        AuditResult::Started => theme::MUTED,
        AuditResult::Success | AuditResult::Verified => theme::TEXT,
    }
}

fn format_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn short_hash(value: &str) -> String {
    if value.len() <= 16 {
        return value.to_string();
    }
    format!("{}…{}", &value[..8], &value[value.len() - 8..])
}
