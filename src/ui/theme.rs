//! Couleurs de Rusty Seal, reliées aux tokens de la charte Rusty Suite.
//!
//! Le thème complet (polices, couleurs des contrôles, rayons) est appliqué par
//! `rusty_ui::install`. Ce module garde les noms utilisés par les panneaux et les
//! fait pointer vers les tokens (`rusty_ui::tokens`), pour qu'aucune couleur ne soit
//! écrite en dur ailleurs (charte, 07).

use egui::Color32;
use rusty_ui::tokens as t;

/// Réussite, valeur valide.
pub const GREEN: Color32 = t::SUCCESS;
/// Avertissement, traitement en cours.
pub const YELLOW: Color32 = t::WARNING;
/// Erreur (texte et icônes).
pub const RED: Color32 = t::DANGER_TEXT;
/// Réussite discrète (messages de confirmation).
pub const GREEN_SOFT: Color32 = t::SUCCESS;
/// Action destructive.
pub const RED_DANGER: Color32 = t::DANGER;
/// Texte secondaire, désactivé.
pub const GRAY: Color32 = t::TEXT_MUTED;

/// Applique la charte au démarrage.
pub fn apply(ctx: &egui::Context) {
    rusty_ui::install(ctx);
}

/// Point d'état d'un coffre : rouge verrouillé, vert déverrouillé (avec texte à côté).
pub fn status_dot(locked: bool) -> (&'static str, Color32) {
    if locked { ("●", t::DANGER) } else { ("●", t::SUCCESS) }
}

/// Couleur d'expiration d'un certificat selon les jours restants.
pub fn expiry_color(days_left: u64) -> Color32 {
    if days_left <= 1 { t::DANGER } else if days_left <= 7 { t::WARNING } else { t::SUCCESS }
}
