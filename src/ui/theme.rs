use egui::{Color32, FontData, FontDefinitions, FontFamily, Visuals};

pub const GREEN: Color32       = Color32::from_rgb(80, 210, 80);
pub const YELLOW: Color32      = Color32::from_rgb(220, 160, 60);
pub const RED: Color32         = Color32::from_rgb(220, 80, 80);
pub const GREEN_SOFT: Color32  = Color32::from_rgb(80, 200, 80);
pub const RED_DANGER: Color32  = Color32::from_rgb(220, 70, 70);
pub const GRAY: Color32        = Color32::from_rgb(140, 140, 140);

// Fonds explicites utilisés pour les panneaux (appliqués via Frame)
pub const BG_PANEL: Color32    = Color32::from_rgb(22, 22, 30);
pub const BG_TOPBAR: Color32   = Color32::from_rgb(18, 18, 26);
pub const BG_STATUS: Color32   = Color32::from_rgb(16, 16, 24);

// Texte des onglets inactifs : visible sur fond sombre, pas blanc pur
pub const TAB_INACTIVE: Color32 = Color32::from_rgb(185, 195, 210);

const EMOJI_FONT_PATHS: &[&str] = &[
    r"C:\Windows\Fonts\seguiemj.ttf",
    r"C:\Windows\Fonts\seguisym.ttf",
    "/System/Library/Fonts/Apple Color Emoji.ttc",
    "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
    "/usr/share/fonts/noto/NotoColorEmoji.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
];

/// Construit les Visuals sombres — appelé chaque frame dans update()
/// pour garantir que le thème n'est jamais écrasé par eframe/OS.
pub fn dark_visuals() -> Visuals {
    let mut vis = Visuals::dark();

    vis.panel_fill       = BG_PANEL;
    vis.window_fill      = Color32::from_rgb(28, 28, 38);
    vis.extreme_bg_color = Color32::from_rgb(12, 12, 18);   // champs de saisie
    vis.faint_bg_color   = Color32::from_rgb(30, 30, 40);

    // Forcer un blanc cassé pour tout texte sans couleur explicite
    vis.override_text_color = Some(Color32::from_gray(225));

    // Non-interactif : labels, groupes, séparateurs
    vis.widgets.noninteractive.fg_stroke.color = Color32::from_gray(210);
    vis.widgets.noninteractive.bg_fill         = Color32::from_rgb(34, 34, 46);
    vis.widgets.noninteractive.bg_stroke.color = Color32::from_rgb(55, 55, 75);
    vis.widgets.noninteractive.rounding        = egui::Rounding::same(4.0);

    // Inactif : boutons et selectable_label non survolés
    vis.widgets.inactive.fg_stroke.color = Color32::from_gray(215);
    vis.widgets.inactive.bg_fill         = Color32::from_rgb(42, 42, 56);
    vis.widgets.inactive.rounding        = egui::Rounding::same(4.0);

    // Survolé
    vis.widgets.hovered.fg_stroke.color = Color32::WHITE;
    vis.widgets.hovered.bg_fill         = Color32::from_rgb(55, 55, 75);
    vis.widgets.hovered.rounding        = egui::Rounding::same(4.0);

    // Actif (clic en cours)
    vis.widgets.active.fg_stroke.color = Color32::WHITE;
    vis.widgets.active.bg_fill         = Color32::from_rgb(62, 62, 85);
    vis.widgets.active.rounding        = egui::Rounding::same(4.0);

    // Menu/popup ouvert
    vis.widgets.open.fg_stroke.color = Color32::WHITE;
    vis.widgets.open.bg_fill         = Color32::from_rgb(48, 48, 65);
    vis.widgets.open.rounding        = egui::Rounding::same(4.0);

    // Sélection (selectable_label actif, texte sélectionné)
    vis.selection.bg_fill = Color32::from_rgb(30, 80, 30);
    vis.selection.stroke  = egui::Stroke::new(1.0, Color32::WHITE);

    vis.window_rounding = egui::Rounding::same(6.0);

    vis
}

/// Appelé une seule fois à l'init : charge les polices ET applique le thème.
pub fn apply(ctx: &egui::Context) {
    load_emoji_font(ctx);
    ctx.set_visuals(dark_visuals());
}

fn load_emoji_font(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    for path in EMOJI_FONT_PATHS {
        if let Ok(data) = std::fs::read(path) {
            fonts.font_data.insert("emoji".to_owned(), FontData::from_owned(data));
            fonts.families.entry(FontFamily::Proportional).or_default().push("emoji".to_owned());
            fonts.families.entry(FontFamily::Monospace).or_default().push("emoji".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);
}

pub fn status_dot(locked: bool) -> (&'static str, Color32) {
    if locked { ("●", RED) } else { ("●", GREEN) }
}

pub fn expiry_color(days_left: u64) -> Color32 {
    if days_left <= 1 { RED } else if days_left <= 7 { YELLOW } else { GREEN }
}
