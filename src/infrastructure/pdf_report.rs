use chrono::{DateTime, Datelike, Timelike, Utc};
use pdf_writer::{Content, Date, Name, Pdf, Primitive, Rect, Ref, Str, TextStr};
use sha2::{Digest, Sha256};
use std::io;
use uuid::Uuid;

use crate::domain::report::{REPORT_TITLE, ReportEvidence};
use crate::infrastructure::pdf_signing::{PdfSigningIdentity, SignerDetails};

const PAGE_WIDTH: f32 = 595.28;
const PAGE_HEIGHT: f32 = 841.89;
const MARGIN: f32 = 50.0;
const LEFT: f32 = MARGIN;
const RIGHT: f32 = PAGE_WIDTH - MARGIN;
const TOP: f32 = PAGE_HEIGHT - MARGIN;
const BOTTOM: f32 = MARGIN;
const CONTENT_WIDTH: f32 = PAGE_WIDTH - 2.0 * MARGIN;
const LABEL_WIDTH: f32 = 130.0;
const CELL_PADDING: f32 = 4.0;
const FIELD_GAP: f32 = 4.0;
const HEADING_BAND: f32 = 22.0;
const FOOTER_BASELINE: f32 = 28.0;

const BYTE_RANGE_PLACEHOLDER: &[u8] = b"[0 0000000000 0000000000 0000000000]";
const CONTENTS_HEX_LEN: usize = 16384;
const SIGNATURE_REASON: &str = "Forensic case report";
const FONT_NAMES: [&[u8]; 3] = [b"F1", b"F2", b"F3"];

const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
    611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
    222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];

const HELVETICA_BOLD: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667,
    611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
    667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556,
    278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
];

const PDF_DATE_FORMAT: &str = "D:%Y%m%d%H%M%S+00'00'";

pub struct PdfReportContent {
    pub case_name: String,
    pub case_id: Uuid,
    pub examiner: Option<String>,
    pub case_created_at: DateTime<Utc>,
    pub case_directory: String,
    pub case_json_sha256: Option<String>,
    pub evidence: Vec<ReportEvidence>,
    pub artifacts: Vec<ArtifactRow>,
    pub timeline: Vec<TimelineRow>,
    pub seal: SealSummary,
    pub signer: SignerDetails,
    pub generated_at: DateTime<Utc>,
    pub tool_version: String,
}

pub struct ArtifactRow {
    pub filename: String,
    pub artifact_type: String,
    pub size_bytes: Option<u64>,
    pub created_at: DateTime<Utc>,
}

pub struct TimelineRow {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub result: String,
    pub detail: String,
}

pub struct SealSummary {
    pub final_sequence: u64,
    pub final_head_hash: String,
    pub report_manifest_sha256: Option<String>,
    pub public_key: String,
    pub signature: String,
    pub closure_path: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Face {
    Regular,
    Bold,
    Mono,
}

#[derive(Clone, Copy)]
struct Style {
    face: Face,
    size: f32,
    leading: f32,
    gray: f32,
}

const BODY: Style = Style {
    face: Face::Regular,
    size: 10.0,
    leading: 13.0,
    gray: 0.1,
};
const LABEL: Style = Style {
    face: Face::Regular,
    size: 10.0,
    leading: 13.0,
    gray: 0.38,
};
const MONO: Style = Style {
    face: Face::Mono,
    size: 8.5,
    leading: 11.0,
    gray: 0.15,
};
const TABLE: Style = Style {
    face: Face::Regular,
    size: 9.0,
    leading: 11.5,
    gray: 0.1,
};
const TABLE_MONO: Style = Style {
    face: Face::Mono,
    size: 8.5,
    leading: 11.0,
    gray: 0.15,
};
const TABLE_HEAD: Style = Style {
    face: Face::Bold,
    size: 9.0,
    leading: 11.5,
    gray: 0.1,
};
const HEADING: Style = Style {
    face: Face::Bold,
    size: 13.0,
    leading: 16.0,
    gray: 0.1,
};
const TITLE: Style = Style {
    face: Face::Bold,
    size: 20.0,
    leading: 24.0,
    gray: 0.05,
};
const FOOTER: Style = Style {
    face: Face::Regular,
    size: 8.0,
    leading: 10.0,
    gray: 0.45,
};

struct Column {
    title: &'static str,
    width: f32,
    style: Style,
}

pub fn render(content: &PdfReportContent) -> Vec<u8> {
    write_document(content, build_pages(content))
}

pub fn sign_pdf(mut pdf: Vec<u8>, identity: &PdfSigningIdentity) -> io::Result<Vec<u8>> {
    let malformed = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "signature placeholder is malformed",
        )
    };

    let range_at = find_bytes(&pdf, BYTE_RANGE_PLACEHOLDER).ok_or_else(malformed)?;
    let lt = range_at
        + pdf[range_at..]
            .iter()
            .position(|&byte| byte == b'<')
            .ok_or_else(malformed)?;
    let gt = lt + 1 + CONTENTS_HEX_LEN;
    if pdf.get(gt) != Some(&b'>') || !pdf[lt + 1..gt].iter().all(|&byte| byte == b'0') {
        return Err(malformed());
    }

    let total = pdf.len();
    let byte_range = format!("[0 {:<10} {:<10} {:<10}]", lt, gt + 1, total - gt - 1);
    if byte_range.len() != BYTE_RANGE_PLACEHOLDER.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ByteRange does not fit its placeholder",
        ));
    }
    pdf[range_at..range_at + byte_range.len()].copy_from_slice(byte_range.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&pdf[..lt]);
    hasher.update(&pdf[gt + 1..]);
    let digest = hasher.finalize();

    let signature = identity.cms_signature(&digest)?;
    let encoded = hex::encode_upper(&signature);
    if encoded.len() > CONTENTS_HEX_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "signature needs {} hex characters, placeholder holds {CONTENTS_HEX_LEN}",
                encoded.len()
            ),
        ));
    }
    pdf[lt + 1..lt + 1 + encoded.len()].copy_from_slice(encoded.as_bytes());
    Ok(pdf)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct Raw<'a>(&'a [u8]);

impl Primitive for Raw<'_> {
    fn write(self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0);
    }
}

fn write_document(content: &PdfReportContent, pages: Vec<Content>) -> Vec<u8> {
    let mut pdf = Pdf::new();
    let catalog_id = Ref::new(1);
    let page_tree_id = Ref::new(2);
    let info_id = Ref::new(3);
    let font_ids = [Ref::new(4), Ref::new(5), Ref::new(6)];

    let page_count = pages.len();
    let page_ids: Vec<(Ref, Ref)> = (0..page_count)
        .map(|index| {
            let base = 7 + 2 * index as i32;
            (Ref::new(base), Ref::new(base + 1))
        })
        .collect();
    let signature_field_id = Ref::new(7 + 2 * page_count as i32);
    let signature_id = Ref::new(8 + 2 * page_count as i32);
    let last_page_id = page_ids[page_count - 1].0;

    {
        let mut info = pdf.document_info(info_id);
        info.title(TextStr(REPORT_TITLE))
            .producer(TextStr(&format!("BitsPlayer {}", content.tool_version)))
            .creation_date(pdf_date(content.generated_at));
        if let Some(examiner) = content.examiner.as_deref() {
            info.author(TextStr(examiner));
        }
    }

    {
        let mut catalog = pdf.catalog(catalog_id);
        catalog.pages(page_tree_id);
        let mut form = catalog.insert(Name(b"AcroForm")).dict();
        form.insert(Name(b"Fields"))
            .array()
            .item(signature_field_id);
        form.pair(Name(b"SigFlags"), 3);
    }

    pdf.pages(page_tree_id)
        .kids(page_ids.iter().map(|(page, _)| *page))
        .count(page_count as i32);

    pdf.type1_font(font_ids[0])
        .base_font(Name(b"Helvetica"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));
    pdf.type1_font(font_ids[1])
        .base_font(Name(b"Helvetica-Bold"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));
    pdf.type1_font(font_ids[2])
        .base_font(Name(b"Courier"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));

    for (index, (page, (page_id, content_id))) in pages.into_iter().zip(page_ids).enumerate() {
        let data = page.finish();
        pdf.stream(content_id, &data);

        let mut writer = pdf.page(page_id);
        writer
            .parent(page_tree_id)
            .media_box(Rect::new(0.0, 0.0, PAGE_WIDTH, PAGE_HEIGHT))
            .contents(content_id);
        {
            let mut resources = writer.resources();
            let mut fonts = resources.fonts();
            for (name, id) in FONT_NAMES.into_iter().zip(font_ids) {
                fonts.pair(Name(name), id);
            }
        }
        if index + 1 == page_count {
            writer.annotations([signature_field_id]);
        }
    }

    {
        let mut field = pdf.indirect(signature_field_id).dict();
        field
            .pair(Name(b"Type"), Name(b"Annot"))
            .pair(Name(b"Subtype"), Name(b"Widget"))
            .pair(Name(b"FT"), Name(b"Sig"))
            .pair(Name(b"T"), TextStr("Signature"))
            .pair(Name(b"V"), signature_id)
            .pair(Name(b"Rect"), Rect::new(0.0, 0.0, 0.0, 0.0))
            .pair(Name(b"F"), 132)
            .pair(Name(b"P"), last_page_id);
    }

    let signing_time = content.generated_at.format(PDF_DATE_FORMAT).to_string();
    let contents_placeholder = format!("<{}>", "0".repeat(CONTENTS_HEX_LEN));
    {
        let mut signature = pdf.indirect(signature_id).dict();
        signature
            .pair(Name(b"Type"), Name(b"Sig"))
            .pair(Name(b"Filter"), Name(b"Adobe.PPKLite"))
            .pair(Name(b"SubFilter"), Name(b"ETSI.CAdES.detached"))
            .pair(Name(b"Name"), TextStr(&content.signer.common_name))
            .pair(Name(b"M"), Str(signing_time.as_bytes()))
            .pair(Name(b"Reason"), TextStr(SIGNATURE_REASON))
            .pair(Name(b"ByteRange"), Raw(BYTE_RANGE_PLACEHOLDER))
            .pair(Name(b"Contents"), Raw(contents_placeholder.as_bytes()));
    }

    pdf.finish()
}

fn pdf_date(time: DateTime<Utc>) -> Date {
    Date::new(time.year() as u16)
        .month(time.month() as u8)
        .day(time.day() as u8)
        .hour(time.hour() as u8)
        .minute(time.minute() as u8)
        .second(time.second() as u8)
        .utc_offset_hour(0)
}

fn build_pages(content: &PdfReportContent) -> Vec<Content> {
    let mut layout = Layout::new();

    layout.title_block(content);

    layout.heading("Case");
    layout.field("Name", &content.case_name, BODY);
    layout.field("Case ID", &content.case_id.to_string(), MONO);
    layout.field(
        "Examiner",
        content.examiner.as_deref().unwrap_or("not recorded"),
        BODY,
    );
    layout.field("Created", &format_time(content.case_created_at), BODY);
    layout.field("Directory", &content.case_directory, MONO);
    layout.field(
        "case.json SHA-256",
        content.case_json_sha256.as_deref().unwrap_or("not present"),
        MONO,
    );

    layout.heading("Evidence");
    let evidence_rows: Vec<Vec<String>> = content
        .evidence
        .iter()
        .map(|evidence| {
            vec![
                evidence.filename.clone(),
                sized(evidence.size_bytes),
                evidence.sha256.clone(),
            ]
        })
        .collect();
    layout.table(
        &[
            Column {
                title: "File",
                width: 165.0,
                style: TABLE,
            },
            Column {
                title: "Size",
                width: 95.0,
                style: TABLE,
            },
            Column {
                title: "SHA-256",
                width: 235.28,
                style: TABLE_MONO,
            },
        ],
        &evidence_rows,
    );

    layout.heading("Artifacts");
    let artifact_rows: Vec<Vec<String>> = content
        .artifacts
        .iter()
        .map(|artifact| {
            vec![
                artifact.filename.clone(),
                artifact.artifact_type.clone(),
                artifact
                    .size_bytes
                    .map(sized)
                    .unwrap_or_else(|| String::from("unknown")),
                format_time(artifact.created_at),
            ]
        })
        .collect();
    layout.table(
        &[
            Column {
                title: "File",
                width: 180.0,
                style: TABLE,
            },
            Column {
                title: "Type",
                width: 110.0,
                style: TABLE,
            },
            Column {
                title: "Size",
                width: 95.0,
                style: TABLE,
            },
            Column {
                title: "Created",
                width: 110.28,
                style: TABLE,
            },
        ],
        &artifact_rows,
    );

    layout.heading("Audit timeline");
    let timeline_rows: Vec<Vec<String>> = content
        .timeline
        .iter()
        .map(|row| {
            vec![
                row.sequence.to_string(),
                format_time(row.timestamp),
                row.action.clone(),
                row.result.clone(),
                row.detail.clone(),
            ]
        })
        .collect();
    layout.table(
        &[
            Column {
                title: "#",
                width: 26.0,
                style: TABLE,
            },
            Column {
                title: "Timestamp",
                width: 124.0,
                style: TABLE,
            },
            Column {
                title: "Action",
                width: 150.0,
                style: TABLE,
            },
            Column {
                title: "Result",
                width: 62.0,
                style: TABLE,
            },
            Column {
                title: "Detail",
                width: 133.28,
                style: TABLE,
            },
        ],
        &timeline_rows,
    );

    layout.heading("Seal");
    layout.field(
        "Final sequence",
        &content.seal.final_sequence.to_string(),
        BODY,
    );
    layout.field("Final head hash", &content.seal.final_head_hash, MONO);
    layout.field(
        "Report manifest SHA-256",
        content
            .seal
            .report_manifest_sha256
            .as_deref()
            .unwrap_or("not recorded"),
        MONO,
    );
    layout.field("Ed25519 public key", &content.seal.public_key, MONO);
    layout.field("Ed25519 signature", &content.seal.signature, MONO);
    layout.field("Closure record", &content.seal.closure_path, MONO);

    layout.heading("Digital signature");
    layout.field("Signer", &content.signer.common_name, BODY);
    layout.field("Certificate subject", &content.signer.subject, BODY);
    layout.field(
        "Certificate SHA-256",
        &content.signer.certificate_sha256,
        MONO,
    );
    layout.field(
        "Signature format",
        "PAdES, ETSI.CAdES.detached, ECDSA P-256 with SHA-256",
        BODY,
    );
    layout.space(6.0);
    layout.paragraph(
        "This document carries an embedded PAdES digital signature that covers every byte of the file except the signature itself. The signing certificate is self-signed, so a PDF reader can confirm that the document is unchanged but will report the signer as untrusted until the certificate is explicitly trusted.",
        BODY,
    );

    let mut pages = layout.finish();
    let total = pages.len();
    for (index, page) in pages.iter_mut().enumerate() {
        let footer_id = format!("Case ID {}", content.case_id);
        draw_text(page, FOOTER, LEFT, FOOTER_BASELINE, &footer_id);
        let numbering = format!("Page {} of {}", index + 1, total);
        let x = RIGHT - text_width(&numbering, FOOTER);
        draw_text(page, FOOTER, x, FOOTER_BASELINE, &numbering);
    }
    pages
}

struct Layout {
    finished: Vec<Content>,
    page: Content,
    y: f32,
}

impl Layout {
    fn new() -> Self {
        Self {
            finished: Vec::new(),
            page: Content::new(),
            y: TOP,
        }
    }

    fn finish(mut self) -> Vec<Content> {
        self.finished.push(self.page);
        self.finished
    }

    fn has_room(&self, height: f32) -> bool {
        self.y - height >= BOTTOM
    }

    fn new_page(&mut self) {
        let page = std::mem::replace(&mut self.page, Content::new());
        self.finished.push(page);
        self.y = TOP;
    }

    fn space(&mut self, height: f32) {
        self.y -= height;
    }

    fn title_block(&mut self, content: &PdfReportContent) {
        let top = self.y;
        draw_text(&mut self.page, TITLE, LEFT, top - TITLE.size, REPORT_TITLE);
        self.y = top - TITLE.leading - 4.0;
        let subtitle = format!(
            "Case: {}   |   Generated: {}",
            content.case_name,
            format_time(content.generated_at)
        );
        self.paragraph(&subtitle, LABEL);
        self.space(4.0);
        hline(&mut self.page, LEFT, RIGHT, self.y, 0.55, 0.6);
        self.space(14.0);
    }

    fn heading(&mut self, title: &str) {
        if !self.has_room(HEADING_BAND + 2.0 * BODY.leading) {
            self.new_page();
        }
        self.space(14.0);
        let top = self.y;
        fill_rect(
            &mut self.page,
            LEFT,
            top - HEADING_BAND,
            CONTENT_WIDTH,
            HEADING_BAND,
            0.92,
        );
        draw_text(
            &mut self.page,
            HEADING,
            LEFT + 8.0,
            top - HEADING_BAND + 6.5,
            title,
        );
        self.y = top - HEADING_BAND - 10.0;
    }

    fn field(&mut self, label: &str, value: &str, style: Style) {
        let lines = wrap(value, style, CONTENT_WIDTH - LABEL_WIDTH);
        let height = lines.len() as f32 * style.leading + FIELD_GAP;
        if !self.has_room(height) {
            self.new_page();
        }
        let top = self.y;
        draw_text(
            &mut self.page,
            LABEL,
            LEFT,
            baseline(top, 0.0, LABEL, 0),
            label,
        );
        for (index, line) in lines.iter().enumerate() {
            draw_text(
                &mut self.page,
                style,
                LEFT + LABEL_WIDTH,
                baseline(top, 0.0, style, index),
                line,
            );
        }
        self.y = top - height;
    }

    fn paragraph(&mut self, text: &str, style: Style) {
        let lines = wrap(text, style, CONTENT_WIDTH);
        for line in lines {
            let height = style.leading;
            if !self.has_room(height) {
                self.new_page();
            }
            let top = self.y;
            draw_text(
                &mut self.page,
                style,
                LEFT,
                baseline(top, 0.0, style, 0),
                &line,
            );
            self.y = top - height;
        }
    }

    fn table(&mut self, columns: &[Column], rows: &[Vec<String>]) {
        if rows.is_empty() {
            self.paragraph("None recorded.", LABEL);
            self.space(4.0);
            return;
        }

        let laid_out: Vec<(Vec<Vec<String>>, f32)> = rows
            .iter()
            .map(|row| {
                let cells: Vec<Vec<String>> = columns
                    .iter()
                    .zip(row)
                    .map(|(column, text)| {
                        wrap(text, column.style, column.width - 2.0 * CELL_PADDING)
                    })
                    .collect();
                let height = cells
                    .iter()
                    .zip(columns)
                    .map(|(lines, column)| lines.len() as f32 * column.style.leading)
                    .fold(0.0_f32, f32::max)
                    + 2.0 * CELL_PADDING;
                (cells, height)
            })
            .collect();

        let header_height = TABLE_HEAD.leading + 2.0 * CELL_PADDING;
        if !self.has_room(header_height + laid_out[0].1) {
            self.new_page();
        }
        self.table_header(columns);

        for (index, (cells, height)) in laid_out.iter().enumerate() {
            if !self.has_room(*height) {
                self.new_page();
                self.table_header(columns);
            }
            let top = self.y;
            if index % 2 == 1 {
                fill_rect(
                    &mut self.page,
                    LEFT,
                    top - height,
                    CONTENT_WIDTH,
                    *height,
                    0.97,
                );
            }
            let mut x = LEFT;
            for (column, lines) in columns.iter().zip(cells) {
                for (line_index, line) in lines.iter().enumerate() {
                    draw_text(
                        &mut self.page,
                        column.style,
                        x + CELL_PADDING,
                        baseline(top, CELL_PADDING, column.style, line_index),
                        line,
                    );
                }
                x += column.width;
            }
            hline(&mut self.page, LEFT, RIGHT, top - height, 0.3, 0.84);
            self.y = top - height;
        }
        self.space(6.0);
    }

    fn table_header(&mut self, columns: &[Column]) {
        let height = TABLE_HEAD.leading + 2.0 * CELL_PADDING;
        let top = self.y;
        fill_rect(
            &mut self.page,
            LEFT,
            top - height,
            CONTENT_WIDTH,
            height,
            0.88,
        );
        let mut x = LEFT;
        for column in columns {
            draw_text(
                &mut self.page,
                TABLE_HEAD,
                x + CELL_PADDING,
                baseline(top, CELL_PADDING, TABLE_HEAD, 0),
                column.title,
            );
            x += column.width;
        }
        self.y = top - height;
    }
}

fn baseline(top: f32, padding: f32, style: Style, line: usize) -> f32 {
    top - padding - style.size - line as f32 * style.leading
}

fn draw_text(content: &mut Content, style: Style, x: f32, y: f32, text: &str) {
    let face = match style.face {
        Face::Regular => 0,
        Face::Bold => 1,
        Face::Mono => 2,
    };
    let bytes = winansi(text);
    content
        .set_fill_gray(style.gray)
        .begin_text()
        .set_font(Name(FONT_NAMES[face]), style.size)
        .set_text_matrix([1.0, 0.0, 0.0, 1.0, x, y])
        .show(Str(&bytes))
        .end_text();
}

fn fill_rect(content: &mut Content, x: f32, y: f32, width: f32, height: f32, gray: f32) {
    content
        .set_fill_gray(gray)
        .rect(x, y, width, height)
        .fill_nonzero();
}

fn hline(content: &mut Content, x1: f32, x2: f32, y: f32, width: f32, gray: f32) {
    content
        .set_line_width(width)
        .set_stroke_gray(gray)
        .move_to(x1, y)
        .line_to(x2, y)
        .stroke();
}

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            ' '..='~' | '\u{a0}'..='\u{ff}' => character,
            _ => '?',
        })
        .collect()
}

fn winansi(text: &str) -> Vec<u8> {
    sanitize(text)
        .chars()
        .map(|character| character as u8)
        .collect()
}

fn glyph_width(face: Face, character: char) -> f32 {
    let code = character as u32;
    match face {
        Face::Mono => 600.0,
        Face::Regular | Face::Bold if !(32..=126).contains(&code) => 556.0,
        Face::Regular => f32::from(HELVETICA[(code - 32) as usize]),
        Face::Bold => f32::from(HELVETICA_BOLD[(code - 32) as usize]),
    }
}

fn text_width(text: &str, style: Style) -> f32 {
    text.chars()
        .map(|character| glyph_width(style.face, character))
        .sum::<f32>()
        * style.size
        / 1000.0
}

fn wrap(text: &str, style: Style, width: f32) -> Vec<String> {
    let text = sanitize(text);
    let space_width = glyph_width(style.face, ' ') * style.size / 1000.0;
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut line_width = 0.0_f32;

    for word in text.split_whitespace() {
        let word_width = text_width(word, style);
        let gap = if line.is_empty() { 0.0 } else { space_width };
        if line_width + gap + word_width <= width {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
            line_width += gap + word_width;
            continue;
        }

        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
            line_width = 0.0;
        }
        for character in word.chars() {
            let character_width = glyph_width(style.face, character) * style.size / 1000.0;
            if !line.is_empty() && line_width + character_width > width {
                lines.push(std::mem::take(&mut line));
                line_width = 0.0;
            }
            line.push(character);
            line_width += character_width;
        }
    }

    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn sized(bytes: u64) -> String {
    let human = if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    };
    format!("{human} ({bytes} bytes)")
}

fn format_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use cms::{content_info::ContentInfo, signed_data::SignedData};
    use der::{Decode, asn1::OctetString};

    fn sample_content(timeline_rows: usize) -> PdfReportContent {
        let when = Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap();
        PdfReportContent {
            case_name: String::from("Sample case"),
            case_id: Uuid::nil(),
            examiner: Some(String::from("Examiner (A)")),
            case_created_at: when,
            case_directory: String::from("/cases/CASE-0000"),
            case_json_sha256: Some("ab".repeat(32)),
            evidence: vec![ReportEvidence {
                filename: String::from("clip.mp4"),
                path: String::from("evidence/clip.mp4"),
                sha256: "cd".repeat(32),
                size_bytes: 4_200_000,
            }],
            artifacts: Vec::new(),
            timeline: (0..timeline_rows as u64)
                .map(|sequence| TimelineRow {
                    sequence: sequence + 1,
                    timestamp: when,
                    action: String::from("EXTRACT_COMPLETED"),
                    result: String::from("SUCCESS"),
                    detail: String::from(
                        "clip.mp4 960x540 BT.709 non-IDR off partial on audio off all frames on",
                    ),
                })
                .collect(),
            seal: SealSummary {
                final_sequence: timeline_rows as u64 + 1,
                final_head_hash: "ef".repeat(32),
                report_manifest_sha256: Some("12".repeat(32)),
                public_key: String::from("cHVibGljIGtleQ=="),
                signature: String::from("c2lnbmF0dXJl"),
                closure_path: String::from("/cases/CASE-0000/case_closure.json"),
            },
            signer: SignerDetails {
                common_name: String::from("Examiner (A)"),
                subject: String::from("CN=Examiner (A),O=BitsPlayer"),
                certificate_sha256: "34".repeat(32),
            },
            generated_at: when,
            tool_version: String::from("0.1.0"),
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("bitsplayer_{name}_{unique}"))
    }

    fn read_der_length(bytes: &[u8]) -> (usize, usize) {
        let first = bytes[1];
        if first < 0x80 {
            return (2, usize::from(first));
        }
        let count = usize::from(first & 0x7f);
        let length = bytes[2..2 + count]
            .iter()
            .fold(0usize, |acc, &byte| (acc << 8) | usize::from(byte));
        (2 + count, length)
    }

    #[test]
    fn wrapped_lines_never_exceed_the_requested_width() {
        let text = "The quick brown fox jumps over the lazy dog, then keeps running through a very long sentence with many words.";
        let width = 120.0;
        for style in [BODY, TABLE, MONO] {
            let lines = wrap(text, style, width);
            assert!(lines.len() > 1);
            for line in &lines {
                assert!(
                    text_width(line, style) <= width + 0.01,
                    "line too wide: {line:?}"
                );
            }
            assert_eq!(
                lines.join(" ").split_whitespace().collect::<Vec<_>>(),
                text.split_whitespace().collect::<Vec<_>>()
            );
        }

        let hash = "0123456789abcdef".repeat(4);
        let lines = wrap(&hash, MONO, 60.0);
        assert!(lines.len() > 1);
        assert_eq!(lines.concat(), hash);
        for line in &lines {
            assert!(text_width(line, MONO) <= 60.0 + 0.01);
        }
    }

    #[test]
    fn signed_pdf_byte_range_covers_everything_but_the_signature() {
        let directory = temp_dir("pdf_sign");
        let identity =
            PdfSigningIdentity::load_or_create_in(&directory, Some("Examiner (A)")).unwrap();
        let signed = sign_pdf(render(&sample_content(3)), &identity).unwrap();

        assert!(signed.starts_with(b"%PDF-"));

        let range_at = find_bytes(&signed, b"/ByteRange [").unwrap() + b"/ByteRange ".len();
        let end = range_at + signed[range_at..].iter().position(|&b| b == b']').unwrap() + 1;
        let values: Vec<usize> = std::str::from_utf8(&signed[range_at + 1..end - 1])
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 4);
        assert_eq!(values[0], 0);
        let (lt, after) = (values[1], values[2]);
        assert_eq!(signed[lt], b'<');
        assert_eq!(signed[after - 1], b'>');
        assert_eq!(after - lt, CONTENTS_HEX_LEN + 2);
        assert_eq!(values[3], signed.len() - after);

        let hex_text = std::str::from_utf8(&signed[lt + 1..after - 1]).unwrap();
        let der_bytes: Vec<u8> = (0..hex_text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex_text[index..index + 2], 16).unwrap())
            .collect();
        let (header, length) = read_der_length(&der_bytes);
        let cms = &der_bytes[..header + length];

        let content_info = ContentInfo::from_der(cms).unwrap();
        let signed_data: SignedData = content_info.content.decode_as().unwrap();
        let signer = signed_data.signer_infos.0.iter().next().unwrap();
        let attributes = signer.signed_attrs.as_ref().unwrap();
        let message_digest = attributes
            .iter()
            .find(|attribute| attribute.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
            .unwrap();
        let digest: OctetString = message_digest
            .values
            .iter()
            .next()
            .unwrap()
            .decode_as()
            .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&signed[..lt]);
        hasher.update(&signed[after..]);
        assert_eq!(digest.as_bytes(), hasher.finalize().as_slice());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn long_timelines_span_multiple_pages_with_numbered_footers() {
        let pages = build_pages(&sample_content(200));
        assert!(pages.len() > 1);

        let rendered = render(&sample_content(200));
        let text = String::from_utf8_lossy(&rendered);
        assert!(text.contains(&format!("/Count {}", pages.len())));
    }
}
