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
use vault::Vault;

// Image embarquée à la compilation — chemin relatif depuis la racine du crate
const ICON_PNG: &[u8] = include_bytes!("../assets/img/rusty-seal.png");

fn main() -> eframe::Result<()> {
    let workdir = workdir::resolve_workdir();
    let lang_dir = workdir::lang_dir(&workdir);

    std::fs::create_dir_all(&lang_dir).ok();
    std::fs::create_dir_all(&workdir).ok();

    let lang = i18n::load_lang(&lang_dir);

    let vault_path = workdir.join("vault.rsvc");
    let vault = Vault::new(vault_path);

    let audit_path = workdir.join("audit.log");
    let audit = AuditLog::load(audit_path);

    let state = AppState::new(lang, vault, audit);

    let native_opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Rusty Seal")
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([700.0, 500.0])
            .with_icon(load_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "Rusty Seal",
        native_opts,
        Box::new(|cc| Ok(Box::new(RustySealApp::new(cc, state)))),
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
    egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    }
}
