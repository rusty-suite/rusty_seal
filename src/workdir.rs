//! Dossier de travail de Rusty Seal (coffres, journal d'audit, langues, réglages).
//!
//! Les programmes de la suite sont portables : par défaut, les données vivent dans
//! `rusty_seal-data` à côté de l'exécutable (`rusty_core::paths`). Pour ne jamais
//! « perdre » les coffres d'une version précédente, l'ancien dossier
//! (`%APPDATA%\rusty-suite\rusty-seal` ou `~/rusty-seal`) reste utilisé s'il contient
//! déjà des données.

use std::path::PathBuf;

/// Identifiant de l'application (dossier portable, journal, mises à jour).
pub const APP_ID: &str = "rusty_seal";
const LEGACY_NAME: &str = "rusty-seal";

/// Anciens emplacements des versions ≤ 0.2.
fn legacy_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        dirs.push(PathBuf::from(appdata).join("rusty-suite").join(LEGACY_NAME));
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        dirs.push(PathBuf::from(home).join(LEGACY_NAME));
    }
    dirs
}

/// Dossier portable déjà présent à côté de l'exécutable : il l'emporte toujours sur
/// l'ancien dossier (choix explicite de l'utilisateur).
fn existing_portable_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.join(format!("{APP_ID}-data"));
    dir.is_dir().then_some(dir)
}

/// Dossier de travail : dossier portable existant, sinon ancien dossier s'il contient
/// des coffres, sinon nouveau dossier portable.
pub fn resolve_workdir() -> PathBuf {
    if let Some(dir) = existing_portable_dir() {
        return dir;
    }
    legacy_dirs()
        .into_iter()
        .find(|d| d.join("vaults.json").is_file())
        .unwrap_or_else(|| rusty_core::paths::data_dir(APP_ID))
}
