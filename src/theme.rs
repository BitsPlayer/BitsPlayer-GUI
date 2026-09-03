use iced::Color;

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::from_rgb(r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0)
}

pub const BG: Color = rgb(0x12, 0x14, 0x16);
pub const SURFACE: Color = rgb(0x1C, 0x1E, 0x21);
pub const ELEVATED: Color = rgb(0x26, 0x28, 0x2C);
pub const HAIRLINE: Color = rgb(0x3A, 0x3D, 0x42);
pub const TEXT: Color = rgb(0xE6, 0xE8, 0xEB);
pub const MUTED: Color = rgb(0x9A, 0xA0, 0xA6);
pub const ACCENT: Color = rgb(0x7A, 0x9E, 0xAD);
pub const ACCENT_DIM: Color = rgb(0x4E, 0x6B, 0x78);
pub const DANGER: Color = rgb(0xD0, 0x6C, 0x6C);
pub const WARN: Color = rgb(0xC9, 0xA2, 0x27);

pub const MAP_FTYP: Color = rgb(0xE0, 0xA0, 0x40);
pub const MAP_MOOV: Color = rgb(0xC9, 0xA2, 0x27);
pub const MAP_MDAT: Color = rgb(0x6A, 0x70, 0x78);
pub const MAP_I: Color = rgb(0x4C, 0x8D, 0xFF);
pub const MAP_P: Color = rgb(0x3D, 0x9B, 0x6E);
pub const MAP_B: Color = rgb(0x7B, 0xA0, 0x5B);
pub const MAP_AUDIO: Color = rgb(0x8B, 0x6B, 0xB5);
pub const MAP_FREE: Color = rgb(0x5C, 0x5F, 0x64);
pub const MAP_UNKNOWN: Color = rgb(0x3E, 0x42, 0x46);

use bitplay::SpanKind;
use iced::border::Radius;
use iced::widget::{button, container, text_input};
use iced::{Background, Border, Shadow, Theme, Vector};

pub fn bitsplayer_theme() -> Theme {
    Theme::custom(
        String::from("BitsPlayer"),
        iced::theme::Palette {
            background: BG,
            text: TEXT,
            primary: ACCENT,
            success: MAP_P,
            danger: DANGER,
        },
    )
}

pub fn span_color(kind: SpanKind) -> Color {
    let (base, gop) = match kind {
        SpanKind::Ftyp => (MAP_FTYP, None),
        SpanKind::Moov => (MAP_MOOV, None),
        SpanKind::MdatHeader => (MAP_MDAT, None),
        SpanKind::Free => (MAP_FREE, None),
        SpanKind::Unknown => (MAP_UNKNOWN, None),
        SpanKind::VideoI { gop } => (MAP_I, Some(gop)),
        SpanKind::VideoP { gop } => (MAP_P, Some(gop)),
        SpanKind::VideoB { gop } => (MAP_B, Some(gop)),
        SpanKind::Audio => (MAP_AUDIO, None),
    };
    match gop {
        Some(g) if g % 2 == 1 => dim(base, 0.72),
        _ => base,
    }
}

fn dim(c: Color, f: f32) -> Color {
    Color {
        r: c.r * f,
        g: c.g * f,
        b: c.b * f,
        a: 1.0,
    }
}

pub fn hairline() -> Border {
    Border {
        color: HAIRLINE,
        width: 1.0,
        radius: Radius::from(6.0),
    }
}

pub fn panel(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(SURFACE)),
        text_color: Some(TEXT),
        border: hairline(),
        shadow: Shadow::default(),
    }
}

pub fn elevated(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(ELEVATED)),
        text_color: Some(TEXT),
        border: hairline(),
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
            offset: Vector::new(0.0, 1.0),
            blur_radius: 8.0,
        },
    }
}

pub fn header_bar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(SURFACE)),
        text_color: Some(TEXT),
        border: Border {
            color: HAIRLINE,
            width: 1.0,
            radius: Radius::from(0.0),
        },
        shadow: Shadow::default(),
    }
}

pub fn status_bar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(ELEVATED)),
        text_color: Some(MUTED),
        border: Border {
            color: HAIRLINE,
            width: 1.0,
            radius: Radius::from(0.0),
        },
        shadow: Shadow::default(),
    }
}

pub fn map_well(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG)),
        text_color: Some(TEXT),
        border: hairline(),
        shadow: Shadow::default(),
    }
}

pub fn color_chip(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_theme: &Theme| container::Style {
        background: Some(Background::Color(color)),
        text_color: None,
        border: Border {
            color: Color::from_rgba(1.0, 1.0, 1.0, 0.12),
            width: 1.0,
            radius: Radius::from(2.0),
        },
        shadow: Shadow::default(),
    }
}

pub fn primary_button(theme: &Theme, status: button::Status) -> button::Style {
    let mut bg = ACCENT;
    match status {
        button::Status::Hovered => bg = rgb(0x8F, 0xB4, 0xC2),
        button::Status::Pressed => bg = ACCENT_DIM,
        button::Status::Disabled => {
            return button::Style {
                background: Some(Background::Color(ELEVATED)),
                text_color: MUTED,
                border: hairline(),
                shadow: Shadow::default(),
            };
        }
        button::Status::Active => {}
    }
    let _ = theme;
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: BG,
        border: Border {
            color: bg,
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
    }
}

pub fn secondary_button(theme: &Theme, status: button::Status) -> button::Style {
    let mut border_c = HAIRLINE;
    let mut bg = ELEVATED;
    match status {
        button::Status::Hovered => {
            bg = rgb(0x30, 0x33, 0x38);
            border_c = ACCENT_DIM;
        }
        button::Status::Pressed => bg = SURFACE,
        button::Status::Disabled => {
            return button::Style {
                background: Some(Background::Color(SURFACE)),
                text_color: MUTED,
                border: hairline(),
                shadow: Shadow::default(),
            };
        }
        button::Status::Active => {}
    }
    let _ = theme;
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: TEXT,
        border: Border {
            color: border_c,
            width: 1.0,
            radius: Radius::from(6.0),
        },
        shadow: Shadow::default(),
    }
}

pub fn tab_button(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        if active {
            primary_button(theme, status)
        } else {
            secondary_button(theme, status)
        }
    }
}

pub fn field(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let border = match status {
        text_input::Status::Focused => Border {
            color: ACCENT,
            width: 2.0,
            radius: Radius::from(6.0),
        },
        text_input::Status::Hovered => Border {
            color: ACCENT_DIM,
            width: 1.0,
            radius: Radius::from(6.0),
        },
        text_input::Status::Disabled => hairline(),
        text_input::Status::Active => hairline(),
    };
    let _ = theme;
    text_input::Style {
        background: Background::Color(ELEVATED),
        border,
        icon: MUTED,
        placeholder: MUTED,
        value: TEXT,
        selection: ACCENT_DIM,
    }
}
