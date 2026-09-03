use std::sync::Arc;

use bitplay::{Analysis, LayoutSpan};
use iced::mouse;
use iced::widget::canvas::{self, Event, Geometry};
use iced::{Color, Point, Rectangle, Renderer, Size, Theme};

use crate::theme;

#[derive(Debug, Clone)]
pub enum MapMessage {
    Hover(Option<String>),
}

#[derive(Debug, Clone)]
pub struct FileMap {
    pub spans: Arc<Vec<LayoutSpan>>,
    pub file_size: u64,
}

impl FileMap {
    pub fn from_analysis(analysis: &Analysis) -> Self {
        Self {
            spans: Arc::new(analysis.spans.clone()),
            file_size: analysis.file_size.max(1),
        }
    }

    fn span_at_byte(&self, offset: u64) -> Option<&LayoutSpan> {
        let i = self
            .spans
            .partition_point(|s| s.offset.saturating_add(s.size) <= offset);
        self.spans.get(i).filter(|s| s.contains(offset))
    }
}

#[derive(Debug, Default)]
pub struct MapState {
    hover: Option<String>,
    selected_cell: Option<usize>,
}

#[derive(Clone, Copy)]
struct Grid {
    cols: usize,
    rows: usize,
    cell: f32,
    gap: f32,
    cells: usize,
}

fn grid_for(bounds: Size) -> Grid {
    const GAP: f32 = 1.0;
    const CELL: f32 = 10.0;
    let cols = ((bounds.width + GAP) / (CELL + GAP)).floor().max(1.0) as usize;
    let rows = ((bounds.height + GAP) / (CELL + GAP)).floor().max(1.0) as usize;
    let cells = cols.saturating_mul(rows).max(1);
    Grid {
        cols,
        rows,
        cell: CELL,
        gap: GAP,
        cells,
    }
}

fn cell_index(grid: Grid, bounds: Rectangle, cursor: Point) -> Option<usize> {
    if cursor.x < bounds.x || cursor.y < bounds.y {
        return None;
    }
    let lx = cursor.x - bounds.x;
    let ly = cursor.y - bounds.y;
    let stride = grid.cell + grid.gap;
    let col = (lx / stride).floor() as isize;
    let row = (ly / stride).floor() as isize;
    if col < 0 || row < 0 {
        return None;
    }
    let (col, row) = (col as usize, row as usize);
    if col >= grid.cols || row >= grid.rows {
        return None;
    }
    let local_x = lx - col as f32 * stride;
    let local_y = ly - row as f32 * stride;
    if local_x > grid.cell || local_y > grid.cell {
        return None;
    }
    Some(row * grid.cols + col)
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
        let Some(pos) = cursor.position_in(bounds) else {
            if state.hover.take().is_some() {
                return (
                    canvas::event::Status::Captured,
                    Some(MapMessage::Hover(None)),
                );
            }
            return (canvas::event::Status::Ignored, None);
        };
        // position_in returns coordinates relative to bounds
        let rel = Rectangle {
            x: 0.0,
            y: 0.0,
            width: bounds.width,
            height: bounds.height,
        };
        let grid = grid_for(bounds.size());
        let cell = cell_index(grid, rel, Point::new(pos.x, pos.y));
        let status = cell.and_then(|i| {
            let quantum = (self.file_size as f64 / grid.cells as f64).max(1.0);
            let offset = (i as f64 * quantum).floor() as u64;
            self.span_at_byte(offset.min(self.file_size.saturating_sub(1)))
                .map(|s| s.status_line())
        });

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
                state.selected_cell = cell;
                (
                    canvas::event::Status::Captured,
                    Some(MapMessage::Hover(status)),
                )
            }
            _ => (canvas::event::Status::Ignored, None),
        }
    }

    fn draw(
        &self,
        state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        frame.fill_rectangle(Point::ORIGIN, bounds.size(), theme::BG);

        let grid = grid_for(bounds.size());
        let quantum = (self.file_size as f64 / grid.cells as f64).max(1.0);
        let hover_cell = cursor.position_in(bounds).and_then(|pos| {
            cell_index(
                grid,
                Rectangle {
                    x: 0.0,
                    y: 0.0,
                    width: bounds.width,
                    height: bounds.height,
                },
                Point::new(pos.x, pos.y),
            )
        });

        for row in 0..grid.rows {
            for col in 0..grid.cols {
                let i = row * grid.cols + col;
                let offset = (i as f64 * quantum).floor() as u64;
                let kind = self
                    .span_at_byte(offset.min(self.file_size.saturating_sub(1)))
                    .map(|s| s.kind);
                let mut color = kind.map(theme::span_color).unwrap_or(theme::MAP_UNKNOWN);
                if Some(i) == state.selected_cell || Some(i) == hover_cell {
                    color = Color {
                        r: (color.r + 0.18).min(1.0),
                        g: (color.g + 0.18).min(1.0),
                        b: (color.b + 0.18).min(1.0),
                        a: 1.0,
                    };
                }
                let x = col as f32 * (grid.cell + grid.gap);
                let y = row as f32 * (grid.cell + grid.gap);
                frame.fill_rectangle(Point::new(x, y), Size::new(grid.cell, grid.cell), color);
            }
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
