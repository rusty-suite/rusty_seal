use egui::{Color32, FontData, FontDefinitions, FontFamily, Visuals};

pub const GREEN: Color32 = Color32::from_rgb(80, 210, 80);
pub const YELLOW: Color32 = Color32::from_rgb(220, 160, 60);
pub const RED: Color32 = Color32::from_rgb(220, 80, 80);
pub const GREEN_SOFT: Color32 = Color32::from_rgb(80, 200, 80);
pub const RED_DANGER: Color32 = Color32::from_rgb(220, 70, 70);
pub const GRAY: Color32 = Color32::from_rgb(140, 140, 140);

// Emoji candidate fonts, tried in order
const EMOJI_FONT_PATHS: &[&str] = &[
    // Windows
    r"C:\Windows\Fonts\seguiemj.ttf",  // Segoe UI Emoji (Windows 10/11)
    r"C:\Windows\Fonts\seguisym.ttf",  // Segoe UI Symbol (fallback symbols)
    // macOS
    "/System/Library/Fonts/Apple Color Emoji.ttc",
    // Linux
    "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
    "/usr/share/fonts/noto/NotoColorEmoji.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
];

pub fn apply(ctx: &egui::Context) {
    load_emoji_font(ctx);

    let mut style = (*ctx.style()).clone();
    style.visuals = Visuals::dark();
    style.visuals.window_rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(4.0);
    style.visuals.widgets.inactive.rounding = egui::Rounding::same(4.0);
    style.visuals.widgets.active.rounding = egui::Rounding::same(4.0);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(4.0);
    ctx.set_style(style);
}

fn load_emoji_font(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    for path in EMOJI_FONT_PATHS {
        if let Ok(data) = std::fs::read(path) {
            fonts.font_data.insert(
                "emoji".to_owned(),
                FontData::from_owned(data),
            );
            // Append emoji font as fallback after the default proportional font
            // so that ASCII/Latin glyphs still come from the crisp default font
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .push("emoji".to_owned());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push("emoji".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);
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
