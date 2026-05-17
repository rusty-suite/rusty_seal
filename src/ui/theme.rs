use egui::{Color32, Stroke, Style, Visuals};

pub const GREEN: Color32 = Color32::from_rgb(80, 210, 80);
pub const YELLOW: Color32 = Color32::from_rgb(220, 160, 60);
pub const RED: Color32 = Color32::from_rgb(220, 80, 80);
pub const GREEN_SOFT: Color32 = Color32::from_rgb(80, 200, 80);
pub const RED_DANGER: Color32 = Color32::from_rgb(220, 70, 70);
pub const GRAY: Color32 = Color32::from_rgb(140, 140, 140);

pub fn apply(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = Visuals::dark();
    style.visuals.window_rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(4.0);
    style.visuals.widgets.inactive.rounding = egui::Rounding::same(4.0);
    style.visuals.widgets.active.rounding = egui::Rounding::same(4.0);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(4.0);
    ctx.set_style(style);
}

pub fn status_dot(locked: bool) -> (&'static str, Color32) {
    if locked {
        ("●", RED)
    } else {
        ("●", GREEN)
    }
}

pub fn expiry_color(days_left: u64) -> Color32 {
    if days_left <= 1 {
        RED
    } else if days_left <= 7 {
        YELLOW
    } else {
        GREEN
    }
}
