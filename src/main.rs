// =============================================================================
// Rusty Seal — point d'entrée
//
// Avant l'interface : dossier de travail (portable, ou ancien dossier s'il contient
// des coffres), journal, réglages, contrôle de la dernière mise à jour (retour
// arrière automatique) et instance unique : un clic droit « Signer » sur d'autres
// fichiers les transmet à la fenêtre déjà ouverte au lieu d'en ouvrir une nouvelle.
// =============================================================================

mod app;
mod audit;
mod cert;
mod error;
mod i18n;
mod profile;
mod signing;
mod ui;
mod vault;
mod workdir;

use app::{AppState, RustySealApp};
use audit::AuditLog;
use rusty_core::{instance, journal, lang, settings, update};
use std::path::PathBuf;
use vault::types::VaultRecord;
use vault::Vault;

/// Icône de la fenêtre, intégrée au binaire.
const ICON_PNG: &[u8] = include_bytes!("../assets/img/rusty-seal.png");

/// Fichiers passés après `--sign` (clic droit « Signer avec Rusty Seal »).
pub fn parse_sign_args(args: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--sign" {
            i += 1;
            while i < args.len() && !args[i].starts_with("--") {
                files.push(PathBuf::from(&args[i]));
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    files
}

fn main() -> eframe::Result<()> {
    let workdir = workdir::resolve_workdir();
    std::fs::create_dir_all(&workdir).ok();
    journal::init(workdir::APP_ID, app::VERSION, &workdir);
    lang::install_local(i18n::PACKS, &workdir, app::VERSION);

    let mut settings: app::Settings = settings::load(&workdir);
    if settings.common.language.is_empty() {
        // Reprend le choix de langue des versions précédentes (lang_chosen.txt).
        if let Some(stem) = i18n::legacy_choice(&workdir) {
            settings.common.language = stem;
            let _ = settings::save(&workdir, &settings);
        }
    }

    let rolled_back = match update::startup(&workdir, app::VERSION) {
        update::Startup::Relaunched => return Ok(()),
        update::Startup::RolledBack(v) => Some(v),
        update::Startup::Normal => None,
    };

    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    let args_rx = match instance::start(workdir::APP_ID, &cli_args) {
        instance::Instance::Secondary => return Ok(()),
        instance::Instance::Primary(rx) => rx,
    };
    update::mark_healthy_later(workdir.clone());

    let lang = i18n::Lang::load(&workdir, &settings.common.language);
    let registry_path = workdir.join("vaults.json");
    let mut registry = app::load_vault_registry(&registry_path);
    // Premier lancement : entrée provisoire, l'utilisateur doit nommer le coffre.
    if registry.is_empty() {
        registry.push(VaultRecord { name: String::new(), path: workdir.join("default.rsvc") });
        app::save_vault_registry(&registry_path, &registry);
    }
    let active_idx = 0;
    let vault = Vault::new(registry[active_idx].path.clone());
    let audit = AuditLog::load(workdir.join("audit.log"));

    let sign_files = parse_sign_args(&cli_args);
    let mut state = AppState::new(lang, vault, audit, registry, registry_path, active_idx, workdir);
    let initial_tab = if sign_files.is_empty() {
        app::Tab::Vault
    } else {
        state.quick_sign_mode = true;
        state.sign_files = sign_files;
        state.pw_input.clear();
        app::Tab::Sign
    };

    let native_opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Rusty Seal")
            .with_inner_size([1000.0, 560.0])
            .with_min_inner_size([720.0, 480.0])
            .with_icon(load_icon()),
        // Centrée, 560 pt de haut : la fenêtre reste au-dessus de la barre des tâches
        // sur un écran 1080p à 150 % (le centrage ignore la barre des tâches).
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "Rusty Seal",
        native_opts,
        Box::new(move |cc| Ok(Box::new(RustySealApp::new(cc, state, initial_tab, settings, args_rx, rolled_back)))),
    )
}

fn load_icon() -> egui::IconData {
    use image::ImageReader;
    use std::io::Cursor;
    let img = ImageReader::new(Cursor::new(ICON_PNG))
        .with_guessed_format()
        .expect("format PNG valide")
        .decode()
        .expect("décodage PNG réussi")
        .into_rgba8();
    let (width, height) = img.dimensions();
    egui::IconData { rgba: img.into_raw(), width, height }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_arguments_are_parsed() {
        let args: Vec<String> = ["--sign", "a.exe", "b.ps1", "--other"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_sign_args(&args), vec![PathBuf::from("a.exe"), PathBuf::from("b.ps1")]);
        assert!(parse_sign_args(&[]).is_empty());
    }
}
