use std::sync::Arc;

use iced::alignment::{Horizontal, Vertical};
use iced::mouse;
use iced::widget::canvas::{self, Event, Geometry, Text};
use iced::widget::{Space, button, column, container, row, text};
use iced::{Color, Element, Fill, Font, Point, Rectangle, Renderer, Size, Theme};

use crate::presentation::theme;

/// Bytes shown in the hex window. Larger spans are truncated with a note.
pub const MAX_BYTES: u64 = 64 * 1024;

const BYTES_PER_LINE: usize = 16;
const ROW_H: f32 = 20.0;
const FONT_SIZE: f32 = 13.0;
const PAD_X: f32 = 10.0;
const PAD_Y: f32 = 8.0;

#[derive(Debug, Clone)]
pub struct HexDump {
    pub bytes: Arc<Vec<u8>>,
    pub base: u64,
}

#[derive(Debug, Default)]
pub struct HexState {
    scroll: f32,
}

fn line_count(len: usize) -> usize {
    len.div_ceil(BYTES_PER_LINE).max(1)
}

fn max_scroll(len: usize, bounds_h: f32) -> f32 {
    let visible = ((bounds_h - PAD_Y).max(ROW_H) / ROW_H).floor().max(1.0);
    (line_count(len) as f32 - visible).max(0.0)
}

fn format_line(bytes: &[u8], base: u64, row: usize) -> (String, String, String) {
    let start = row * BYTES_PER_LINE;
    let chunk = if start >= bytes.len() {
        &[][..]
    } else {
        &bytes[start..bytes.len().min(start + BYTES_PER_LINE)]
    };
    let off = base + start as u64;
    let end = base.saturating_add(bytes.len() as u64);
    let width = if end > 0xFFFF_FFFF { 12 } else { 8 };

    let mut hex = String::with_capacity(3 * BYTES_PER_LINE + 1);
    for col in 0..BYTES_PER_LINE {
        if col == 8 {
            hex.push(' ');
        }
        if let Some(b) = chunk.get(col) {
            hex.push_str(&format!("{b:02X} "));
        } else {
            hex.push_str("   ");
        }
    }

    let mut ascii = String::with_capacity(BYTES_PER_LINE);
    for b in chunk {
        ascii.push(if b.is_ascii_graphic() || *b == b' ' {
            *b as char
        } else {
            '.'
        });
    }

    (format!("{off:0width$X}"), hex, ascii)
}

fn fill_mono(frame: &mut canvas::Frame, content: String, x: f32, y: f32, color: Color) {
    frame.fill_text(Text {
        content,
        position: Point::new(x, y),
        color,
        size: iced::Pixels(FONT_SIZE),
        line_height: iced::widget::text::LineHeight::Absolute(iced::Pixels(ROW_H)),
        font: Font::MONOSPACE,
        horizontal_alignment: Horizontal::Left,
        vertical_alignment: Vertical::Top,
        shaping: iced::widget::text::Shaping::Basic,
    });
}

impl canvas::Program<()> for HexDump {
    type State = HexState;

    fn update(
        &self,
        state: &mut Self::State,
        event: Event,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> (canvas::event::Status, Option<()>) {
        let Event::Mouse(mouse::Event::WheelScrolled { delta }) = event else {
            return (canvas::event::Status::Ignored, None);
        };
        let lines = match delta {
            mouse::ScrollDelta::Lines { y, .. } => y,
            mouse::ScrollDelta::Pixels { y, .. } => y / ROW_H,
        };
        let max = max_scroll(self.bytes.len(), bounds.height);
        state.scroll = (state.scroll - lines * 3.0).clamp(0.0, max);
        (canvas::event::Status::Captured, None)
    }

    fn draw(
        &self,
        state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        frame.fill_rectangle(Point::ORIGIN, bounds.size(), theme::BG);

        let total = line_count(self.bytes.len());
        let visible = ((bounds.height - PAD_Y).max(ROW_H) / ROW_H)
            .floor()
            .max(1.0) as usize;
        let max = max_scroll(self.bytes.len(), bounds.height);
        let row0 = state.scroll.clamp(0.0, max).floor() as usize;
        let row1 = (row0 + visible + 1).min(total);

        let offset_x = PAD_X;
        let hex_x = PAD_X + 9.0 * 8.0;
        let ascii_x = hex_x + 50.0 * 8.0;

        for row in row0..row1 {
            let y = PAD_Y + (row - row0) as f32 * ROW_H;
            let (off, hex, ascii) = format_line(&self.bytes, self.base, row);
            fill_mono(&mut frame, off, offset_x, y, theme::MUTED);
            fill_mono(&mut frame, hex, hex_x, y, theme::TEXT);
            fill_mono(&mut frame, ascii, ascii_x, y, theme::ACCENT);
        }

        if total > visible {
            let track_w = 6.0;
            let track_x = bounds.width - track_w - 4.0;
            let ratio = visible as f32 / total as f32;
            let bar_h = (bounds.height * ratio).max(16.0);
            let bar_y = (row0 as f32 / total as f32) * (bounds.height - bar_h).max(0.0);
            frame.fill_rectangle(
                Point::new(track_x, 0.0),
                Size::new(track_w, bounds.height),
                theme::ELEVATED,
            );
            frame.fill_rectangle(
                Point::new(track_x, bar_y),
                Size::new(track_w, bar_h),
                theme::ACCENT_DIM,
            );
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
            mouse::Interaction::Idle
        } else {
            mouse::Interaction::None
        }
    }
}

pub fn window_view<'a, Message: Clone + 'a>(
    color: iced::Color,
    title: String,
    range: String,
    note: Option<String>,
    body: Element<'a, Message>,
    on_close: Message,
) -> Element<'a, Message> {
    let mut titles = column![
        text(title)
            .size(14)
            .font(Font::MONOSPACE)
            .color(theme::TEXT),
        text(range)
            .size(12)
            .font(Font::MONOSPACE)
            .color(theme::MUTED),
    ]
    .spacing(2);

    if let Some(note) = note {
        titles = titles.push(text(note).size(11).color(theme::WARN));
    }

    let header = row![
        container(Space::with_width(10).height(10))
            .width(10)
            .height(10)
            .style(theme::color_chip(color)),
        titles,
        Space::with_width(Fill),
        button(text("Close").size(13))
            .on_press(on_close)
            .style(theme::secondary_button)
            .padding([6, 12]),
    ]
    .spacing(10)
    .align_y(iced::Alignment::Center);

    container(
        column![
            header,
            container(body)
                .width(Fill)
                .height(Fill)
                .padding(8)
                .style(theme::hex_well),
        ]
        .spacing(10),
    )
    .width(Fill)
    .height(Fill)
    .padding(12)
    .style(theme::panel)
    .into()
}
