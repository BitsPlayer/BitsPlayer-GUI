use iced::widget::image::Handle;
use iced::widget::{Space, column, container, image, mouse_area, row, text};
use iced::{Element, Length};
use iframe_extract::report::human_bytes;

use crate::theme;

#[derive(Clone)]
pub struct Thumb {
    pub index: usize,
    pub offset: u64,
    pub source_size: u64,
    pub png_size: u64,
    pub partial: bool,
    pub handle: Handle,
}

pub fn view(
    thumbs: &[Thumb],
    selected: Option<usize>,
    cols: usize,
    on_select: impl Fn(usize) -> crate::extract::Message + Copy + 'static,
) -> Element<'static, crate::extract::Message> {
    if thumbs.is_empty() {
        return column![].into();
    }
    let cols = cols.max(1);
    let mut rows = column![].spacing(10).height(Length::Shrink);
    for chunk in thumbs.chunks(cols) {
        let mut r = row![].spacing(10);
        for thumb in chunk {
            r = r.push(thumb_card(thumb, selected == Some(thumb.index), on_select));
        }
        rows = rows.push(r);
    }
    rows.into()
}

fn thumb_card(
    thumb: &Thumb,
    selected: bool,
    on_select: impl Fn(usize) -> crate::extract::Message + Copy + 'static,
) -> Element<'static, crate::extract::Message> {
    let label = format!(
        "I {:>5}  off {:>10}{}",
        thumb.index,
        thumb.offset,
        if thumb.partial { "  partial" } else { "" }
    );
    let sizes = format!(
        "src {} → png {}",
        human_bytes(thumb.source_size),
        human_bytes(thumb.png_size)
    );
    let card = column![
        container(image(thumb.handle.clone()).width(Length::Fill).height(108))
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
    .width(176);

    mouse_area(card).on_press(on_select(thumb.index)).into()
}

pub fn preview<'a>(handle: Handle, caption: String) -> Element<'a, crate::extract::Message> {
    column![
        container(image(handle).width(Length::Fill))
            .width(Length::Fill)
            .max_height(520)
            .style(theme::map_well)
            .padding(4),
        text(caption)
            .size(12)
            .font(iced::Font::MONOSPACE)
            .color(theme::MUTED),
        Space::with_height(4),
    ]
    .spacing(8)
    .into()
}
