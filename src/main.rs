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
            .with_icon(default_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "Rusty Seal",
        native_opts,
        Box::new(|cc| Ok(Box::new(RustySealApp::new(cc, state)))),
    )
}

fn default_icon() -> egui::IconData {
    egui::IconData {
        rgba: vec![0u8; 4 * 32 * 32],
        width: 32,
        height: 32,
    }
}
