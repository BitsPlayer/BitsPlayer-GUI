use std::sync::Arc;

use bitplay::{Analysis, SpanKind, human_bytes};
use iframe_extract::extract::CarveAnalysis;
use iced::mouse;
use iced::widget::canvas::{self, Event, Geometry};
use iced::{Color, Point, Rectangle, Renderer, Size, Theme};

use crate::presentation::theme;

#[derive(Debug, Clone)]
pub enum MapMessage {
    Hover(Option<String>),
    /// Index into `spans` for the block under the cursor.
    Select(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuClass {
    Idr,
    Intra,
    Inter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Ftyp,
    Moov,
    MdatHeader,
    Free,
    Unknown,
    Audio,
    VideoI { gop: u32 },
    VideoP { gop: u32 },
    VideoB { gop: u32 },
    Au { class: AuClass, complete: bool, gop: u32 },
    Skipped,
    Truncated,
}

impl MapKind {
    pub fn gop(self) -> Option<u32> {
        match self {
            Self::VideoI { gop }
            | Self::VideoP { gop }
            | Self::VideoB { gop }
            | Self::Au { gop, .. } => Some(gop),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ftyp => "ftyp",
            Self::Moov => "moov",
            Self::MdatHeader => "mdat header",
            Self::Free => "free",
            Self::Unknown => "unmapped",
            Self::Audio => "audio",
            Self::VideoI { .. } => "I-frame",
            Self::VideoP { .. } => "P-frame",
            Self::VideoB { .. } => "B-frame",
            Self::Au { class: AuClass::Idr, .. } => "IDR",
            Self::Au { class: AuClass::Intra, .. } => "I-frame (non-IDR)",
            Self::Au { class: AuClass::Inter, .. } => "P-frame",
            Self::Skipped => "skipped region",
            Self::Truncated => "truncated tail",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MapSpan {
    pub offset: u64,
    pub size: u64,
    pub kind: MapKind,
    /// Index into `CarveAnalysis::access_units` for carved access units.
    pub au: Option<usize>,
    pub slices: Option<usize>,
}

impl MapSpan {
    fn plain(offset: u64, size: u64, kind: MapKind) -> Self {
        Self {
            offset,
            size,
            kind,
            au: None,
            slices: None,
        }
    }

    pub fn contains(&self, byte: u64) -> bool {
        byte >= self.offset && byte < self.offset.saturating_add(self.size)
    }

    pub fn is_partial(&self) -> bool {
        matches!(self.kind, MapKind::Au { complete: false, .. })
    }

    pub fn status_line(&self) -> String {
        let size = human_bytes(self.size);
        let partial = if self.is_partial() { " · partial" } else { "" };
        match self.kind.gop() {
            Some(gop) => format!("{} · GOP {gop} · {size}{partial}", self.kind.label()),
            None => format!("{} · {size}", self.kind.label()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileMap {
    pub spans: Arc<Vec<MapSpan>>,
    pub file_size: u64,
    pub selected: Option<usize>,
}

impl FileMap {
    pub fn from_analysis(analysis: &Analysis) -> Self {
        let spans = analysis
            .spans
            .iter()
            .map(|s| {
                let kind = match s.kind {
                    SpanKind::Ftyp => MapKind::Ftyp,
                    SpanKind::Moov => MapKind::Moov,
                    SpanKind::MdatHeader => MapKind::MdatHeader,
                    SpanKind::Free => MapKind::Free,
                    SpanKind::Unknown => MapKind::Unknown,
                    SpanKind::VideoI { gop } => MapKind::VideoI { gop },
                    SpanKind::VideoP { gop } => MapKind::VideoP { gop },
                    SpanKind::VideoB { gop } => MapKind::VideoB { gop },
                    SpanKind::Audio => MapKind::Audio,
                };
                MapSpan::plain(s.offset, s.size, kind)
            })
            .collect();
        Self {
            spans: Arc::new(spans),
            file_size: analysis.file_size.max(1),
            selected: None,
        }
    }

    pub fn from_carve(carve: &CarveAnalysis, file_size: u64) -> Self {
        let file_size = file_size.max(1);
        let mut found: Vec<MapSpan> = Vec::new();

        let header = carve.mdat_payload_start.min(8);
        if header > 0 {
            found.push(MapSpan::plain(
                carve.mdat_payload_start - header,
                header,
                MapKind::MdatHeader,
            ));
        }

        let mut gop_ordinal = 0u32;
        let mut current_gop: Option<usize> = None;
        for (i, au) in carve.access_units.iter().enumerate() {
            match current_gop {
                Some(g) if g == au.gop => {}
                Some(_) => {
                    gop_ordinal += 1;
                    current_gop = Some(au.gop);
                }
                None => current_gop = Some(au.gop),
            }
            let class = if au.is_idr {
                AuClass::Idr
            } else if au.is_intra {
                AuClass::Intra
            } else {
                AuClass::Inter
            };
            found.push(MapSpan {
                offset: au.offset,
                size: au.size,
                kind: MapKind::Au {
                    class,
                    complete: au.complete,
                    gop: gop_ordinal,
                },
                au: Some(i),
                slices: Some(au.nal_indices.len()),
            });
        }

        for &(offset, len) in &carve.skipped {
            found.push(MapSpan::plain(offset, len, MapKind::Skipped));
        }

        if let Some(offset) = carve.truncation_offset
            && offset < file_size
        {
            found.push(MapSpan::plain(offset, file_size - offset, MapKind::Truncated));
        }

        found.sort_by_key(|s| s.offset);

        let mut spans: Vec<MapSpan> = Vec::with_capacity(found.len() * 2 + 1);
        let mut cursor = 0u64;
        for mut span in found {
            if span.offset < cursor {
                let cut = cursor - span.offset;
                if cut >= span.size {
                    continue;
                }
                span.offset += cut;
                span.size -= cut;
            }
            if span.size == 0 || span.offset >= file_size {
                continue;
            }
            if span.offset > cursor {
                spans.push(MapSpan::plain(cursor, span.offset - cursor, MapKind::Unknown));
            }
            cursor = span.offset + span.size;
            spans.push(span);
        }
        if cursor < file_size {
            spans.push(MapSpan::plain(cursor, file_size - cursor, MapKind::Unknown));
        }

        Self {
            spans: Arc::new(spans),
            file_size,
            selected: None,
        }
    }

    fn span_index_at(&self, offset: u64) -> Option<usize> {
        let i = self
            .spans
            .partition_point(|s| s.offset.saturating_add(s.size) <= offset);
        self.spans.get(i).filter(|s| s.contains(offset)).map(|_| i)
    }

    fn status_for(&self, i: usize) -> String {
        let span = &self.spans[i];
        format!(
            "{} · off {} (0x{:08X})",
            span.status_line(),
            span.offset,
            span.offset
        )
    }

    /// Span under the cursor, as an index into `spans`.
    fn span_at_cursor(&self, bounds: Rectangle, cursor: mouse::Cursor) -> Option<usize> {
        let pos = cursor.position_in(bounds)?;
        let ribbon = ribbon_for(bounds.size());
        let at = ribbon.position_at(pos.x, pos.y)?;
        let byte = (at / ribbon.total * self.file_size as f64).floor() as u64;
        self.span_index_at(byte.min(self.file_size.saturating_sub(1)))
    }
}

#[derive(Debug, Default)]
pub struct MapState {
    hover: Option<String>,
}

const ROW_H: f32 = 12.0;
const ROW_GAP: f32 = 2.0;
/// Sub-pixel spans are widened to this so no frame disappears entirely.
const MIN_W: f64 = 0.75;
/// Rectangles at least this wide get a divider so frame edges stay readable.
const DIVIDER_MIN_W: f32 = 4.0;

/// The file laid out as one continuous byte ribbon, wrapped into rows.
#[derive(Clone, Copy)]
struct Ribbon {
    rows: usize,
    row_w: f64,
    total: f64,
}

fn ribbon_for(bounds: Size) -> Ribbon {
    let stride = ROW_H + ROW_GAP;
    let rows = ((bounds.height + ROW_GAP) / stride).floor().max(1.0) as usize;
    let row_w = bounds.width.max(1.0) as f64;
    Ribbon {
        rows,
        row_w,
        total: rows as f64 * row_w,
    }
}

impl Ribbon {
    fn position_at(&self, x: f32, y: f32) -> Option<f64> {
        if x < 0.0 || y < 0.0 {
            return None;
        }
        let row = (y / (ROW_H + ROW_GAP)).floor() as usize;
        if row >= self.rows {
            return None;
        }
        let x = (x as f64).min(self.row_w);
        Some(row as f64 * self.row_w + x)
    }

    fn byte_range(&self, span: &MapSpan, file_size: u64) -> (f64, f64) {
        let scale = self.total / file_size as f64;
        let x0 = span.offset as f64 * scale;
        let x1 = span.offset.saturating_add(span.size) as f64 * scale;
        (x0.min(self.total), x1.max(x0 + MIN_W).min(self.total))
    }
}

/// Draws `x0..x1` of the ribbon, splitting it across rows where it wraps.
fn draw_run(frame: &mut canvas::Frame, ribbon: Ribbon, x0: f64, x1: f64, color: Color) {
    let mut start = x0;
    while start < x1 {
        let row = (start / ribbon.row_w).floor();
        if row as usize >= ribbon.rows {
            break;
        }
        let end = x1.min((row + 1.0) * ribbon.row_w);
        let x = (start - row * ribbon.row_w) as f32;
        let y = row as f32 * (ROW_H + ROW_GAP);
        let w = (end - start) as f32;
        frame.fill_rectangle(Point::new(x, y), Size::new(w, ROW_H), color);
        if end >= x1 && w >= DIVIDER_MIN_W {
            frame.fill_rectangle(Point::new(x + w - 1.0, y), Size::new(1.0, ROW_H), theme::BG);
        }
        start = end;
    }
}

fn highlight(color: Color) -> Color {
    Color {
        r: (color.r + 0.18).min(1.0),
        g: (color.g + 0.18).min(1.0),
        b: (color.b + 0.18).min(1.0),
        a: 1.0,
    }
}

impl canvas::Program<MapMessage> for FileMap {
    type State = MapState;

    fn update(
        &self,
        state: &mut Self::State,
        event: Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> (canvas::event::Status, Option<MapMessage>) {
        if cursor.position_in(bounds).is_none() {
            if state.hover.take().is_some() {
                return (
                    canvas::event::Status::Captured,
                    Some(MapMessage::Hover(None)),
                );
            }
            return (canvas::event::Status::Ignored, None);
        }

        let span = self.span_at_cursor(bounds, cursor);
        let status = span.map(|i| self.status_for(i));

        match event {
            Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                if state.hover != status {
                    state.hover = status.clone();
                    return (
                        canvas::event::Status::Captured,
                        Some(MapMessage::Hover(status)),
                    );
                }
                (canvas::event::Status::Captured, None)
            }
            Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) => {
                if let Some(i) = span {
                    (canvas::event::Status::Captured, Some(MapMessage::Select(i)))
                } else {
                    (canvas::event::Status::Captured, None)
                }
            }
            _ => (canvas::event::Status::Ignored, None),
        }
    }

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        frame.fill_rectangle(Point::ORIGIN, bounds.size(), theme::BG);

        let ribbon = ribbon_for(bounds.size());
        for row in 0..ribbon.rows {
            let y = row as f32 * (ROW_H + ROW_GAP);
            frame.fill_rectangle(
                Point::new(0.0, y),
                Size::new(ribbon.row_w as f32, ROW_H),
                theme::MAP_UNKNOWN,
            );
        }

        let hovered = self.span_at_cursor(bounds, cursor);

        // Consecutive sub-pixel spans of the same colour are drawn as one run so
        // a file with 100k frames does not cost 100k fills per redraw.
        let mut pending: Option<(f64, f64, Color)> = None;
        for (i, span) in self.spans.iter().enumerate() {
            let (x0, x1) = ribbon.byte_range(span, self.file_size);
            let lit = Some(i) == hovered || Some(i) == self.selected;
            let color = match lit {
                true => highlight(theme::span_color(span.kind)),
                false => theme::span_color(span.kind),
            };

            if let Some((px0, px1, pc)) = pending {
                if !lit && pc == color && x0 - px1 < 0.01 && x1 - x0 < 1.0 {
                    pending = Some((px0, x1.max(px1), pc));
                    continue;
                }
                draw_run(&mut frame, ribbon, px0, px1, pc);
            }

            if lit {
                draw_run(&mut frame, ribbon, x0, x1, color);
                pending = None;
            } else {
                pending = Some((x0, x1, color));
            }
        }
        if let Some((x0, x1, color)) = pending {
            draw_run(&mut frame, ribbon, x0, x1, color);
        }

        vec![frame.into_geometry()]
    }

    fn mouse_interaction(
        &self,
        _state: &Self::State,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        if cursor.is_over(bounds) {
            mouse::Interaction::Pointer
        } else {
            mouse::Interaction::None
        }
    }
}
