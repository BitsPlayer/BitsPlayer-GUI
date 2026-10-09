use iced::widget::image::Handle;
use iced::widget::{Space, column, container, image, mouse_area, row, text};
use iced::{ContentFit, Element, Length};
use iframe_extract::report::human_bytes;

use crate::presentation::theme;

pub const CARD_W: f32 = 176.0;
pub const CARD_H: f32 = 150.0;
pub const SPACING: f32 = 10.0;
pub const ROW_STRIDE: f32 = CARD_H + SPACING;

#[derive(Clone)]
pub struct Thumb {
    pub position: usize,
    pub index: usize,
    pub offset: u64,
    pub source_size: u64,
    pub partial: bool,
    pub handle: Option<Handle>,
}

pub fn columns_for(width: f32) -> usize {
    ((width / (CARD_W + SPACING)).floor() as usize).max(2)
}

/// Rows `first_row..first_row + visible.len() / cols` of a `total_rows` grid. Rows outside that
/// range are replaced by spacers of the same height so the scrollbar stays accurate.
pub fn view(
    visible: Vec<Thumb>,
    first_row: usize,
    total_rows: usize,
    selected: Option<usize>,
    cols: usize,
    on_select: impl Fn(usize) -> crate::presentation::extract::Message + Copy + 'static,
) -> Element<'static, crate::presentation::extract::Message> {
    if total_rows == 0 {
        return column![].into();
    }
    let cols = cols.max(1);
    let shown_rows = visible.len().div_ceil(cols);
    let mut rows = column![].spacing(SPACING).height(Length::Shrink);
    if first_row > 0 {
        rows = rows.push(Space::with_height(first_row as f32 * ROW_STRIDE - SPACING));
    }
    for chunk in visible.chunks(cols) {
        let mut r = row![].spacing(SPACING);
        for thumb in chunk {
            r = r.push(thumb_card(thumb, selected == Some(thumb.position), on_select));
        }
        rows = rows.push(r);
    }
    let after = total_rows.saturating_sub(first_row + shown_rows);
    if after > 0 {
        rows = rows.push(Space::with_height(after as f32 * ROW_STRIDE - SPACING));
    }
    rows.into()
}

fn thumb_card(
    thumb: &Thumb,
    selected: bool,
    on_select: impl Fn(usize) -> crate::presentation::extract::Message + Copy + 'static,
) -> Element<'static, crate::presentation::extract::Message> {
    let label = format!(
        "I {:>5}  off {:>10}{}",
        thumb.index,
        thumb.offset,
        if thumb.partial { "  partial" } else { "" }
    );
    let sizes = format!("src {}", human_bytes(thumb.source_size));
    let picture: Element<'static, _> = match &thumb.handle {
        Some(handle) => image(handle.clone())
            .width(Length::Fill)
            .height(108)
            .into(),
        None => Space::new(Length::Fill, 108).into(),
    };
    let card = column![
        container(picture)
            .width(Length::Fill)
            .height(112)
            .style(if selected {
                theme::elevated
            } else {
                theme::map_well
            }),
        column![
            text(label)
                .size(11)
                .font(iced::Font::MONOSPACE)
                .color(theme::MUTED),
            text(sizes)
                .size(11)
                .font(iced::Font::MONOSPACE)
                .color(theme::MUTED),
        ]
        .spacing(2),
    ]
    .spacing(6)
    .width(CARD_W)
    .height(CARD_H);

    mouse_area(card).on_press(on_select(thumb.position)).into()
}

pub fn preview<'a>(
    handle: Option<Handle>,
    caption: String,
) -> Element<'a, crate::presentation::extract::Message> {
    let picture: Element<'a, _> = match handle {
        Some(handle) => image(handle)
            .width(Length::Fill)
            .height(Length::Fill)
            .content_fit(ContentFit::Contain)
            .into(),
        None => text("Rendering…").color(theme::MUTED).into(),
    };
    column![
        container(picture)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .style(theme::map_well)
            .padding(4),
        text(caption)
            .size(12)
            .font(iced::Font::MONOSPACE)
            .color(theme::MUTED),
    ]
    .spacing(8)
    .padding(12)
    .into()
}
