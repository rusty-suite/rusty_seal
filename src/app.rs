use std::path::PathBuf;

use egui::Color32;

use crate::audit::AuditLog;
use crate::i18n::Lang;
use crate::signing::VerifyResult;
use crate::ui::theme;
use crate::vault::types::{KeyAlgorithm, Profile, SigningMetadata, VaultRecord};
use crate::vault::Vault;

#[derive(Debug)]
pub struct NewCertForm {
    pub alias: String,
    pub algorithm: KeyAlgorithm,
    pub common_name: String,
    pub org: String,
    pub country: String,
    pub email: String,
    pub valid_days: u32,
}

impl Default for KeyAlgorithm {
    fn default() -> Self { Self::Ed25519 }
}

impl Default for NewCertForm {
    fn default() -> Self {
        Self {
            alias: String::new(),
            algorithm: KeyAlgorithm::Ed25519,
            common_name: String::new(),
            org: String::new(),
            country: "US".into(),
            email: String::new(),
            valid_days: 365,
        }
    }
}

// ── Background task infrastructure ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BgCertContext { CertPanel, QuickSignInline }

pub struct BgCertGen {
    pub rx: std::sync::mpsc::Receiver<crate::error::Result<crate::vault::types::CertEntry>>,
    pub label: String,
    pub context: BgCertContext,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BgSignContext { SignPanel, QuickSign }

pub struct BgSign {
    pub rx: std::sync::mpsc::Receiver<crate::signing::SignJobResult>,
    pub progress: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub total: usize,
    pub context: BgSignContext,
}

// ── Tab ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Vault,
    Certificates,
    Profiles,
    Sign,
    Verify,
    Audit,
    Settings,
}

pub struct AppState {
    pub lang: Lang,
    pub vault: Vault,
    pub audit: AuditLog,

    // Multi-vault registry
    pub vault_registry: Vec<VaultRecord>,
    pub vault_registry_path: PathBuf,
    pub active_vault_idx: usize,

    // Vault UI
    pub pw_input: String,
    pub pw_confirm: String,
    pub keyfile_path: Option<PathBuf>,
    pub chpw_old: String,
    pub chpw_new: String,
    pub chpw_confirm: String,
    pub export_pw: String,

    // Multi-vault UI
    pub show_add_vault_form: bool,
    pub new_vault_name: String,
    pub delete_target_idx: Option<usize>,
    pub delete_confirm_code: Option<String>,
    pub delete_confirm_input: String,
    pub rename_target_idx: Option<usize>,
    pub rename_name_input: String,

    // Cert UI
    pub selected_cert: Option<String>,
    pub new_cert: NewCertForm,
    pub import_cert_alias: String,
    pub confirm_delete_cert: Option<String>,

    // Profile UI
    pub selected_profile: Option<String>,
    pub edit_profile: Option<Profile>,
    pub custom_key_input: String,
    pub custom_val_input: String,

    // Sign UI
    pub sign_files: Vec<PathBuf>,
    pub sign_filter: String,
    pub sign_selected_profile: Option<String>,
    pub sign_cert_alias: String,
    pub sign_meta: SigningMetadata,

    // Verify UI
    pub verify_binary: Option<PathBuf>,
    pub verify_sig: Option<PathBuf>,
    pub verify_result: Option<VerifyResult>,

    // Audit UI
    pub audit_filter: String,

    // Global status
    pub status_msg: Option<(String, Color32)>,
    pub status_timer: f32,

    // Tab navigation requested from within a panel
    pub pending_tab_switch: Option<Tab>,

    /// Dossier de travail (coffres, audit, langues, réglages).
    pub workdir: std::path::PathBuf,

    // Sign output options
    pub sign_output_dir: Option<std::path::PathBuf>,
    pub sign_overwrite_sig: bool,

    // Quick Sign mode (launched via --sign CLI / context menu)
    pub quick_sign_mode: bool,
    pub quick_sign_done: Option<(usize, usize)>, // (signed, skipped)
    pub quick_sign_signed_paths: Vec<(std::path::PathBuf, std::path::PathBuf)>,
    pub quick_sign_errors: Vec<String>,
    // Remembers the profile active when an incompatibility was detected,
    // so we can offer to create a similar profile with the new compatible cert.
    pub sign_profile_before_compat_change: Option<String>,
    pub close_requested: bool,
    pub quick_sign_show_create_cert: bool,
    // (cert_alias, profile_id): offer to add newly-created inline cert to active profile
    pub quick_sign_offer_add_cert_to_profile: Option<(String, String)>,
    // When true: copy the original file and sign the copy (prefix set by lang key)
    pub sign_create_copy: bool,

    // Background tasks
    pub bg_cert_gen: Option<BgCertGen>,
    pub bg_sign: Option<BgSign>,
    /// Pending cert gen result - consumed by the panel that started the task.
    pub bg_cert_result: Option<(BgCertContext, crate::error::Result<crate::vault::types::CertEntry>)>,
    /// Pending sign result - consumed by the panel that started the task.
    pub bg_sign_result: Option<(BgSignContext, crate::signing::SignJobResult)>,
}

impl AppState {
    pub fn new(
        lang: Lang,
        vault: Vault,
        audit: AuditLog,
        vault_registry: Vec<VaultRecord>,
        vault_registry_path: PathBuf,
        active_vault_idx: usize,
        workdir: PathBuf,
    ) -> Self {
        Self {
            lang,
            vault,
            audit,
            vault_registry,
            vault_registry_path,
            active_vault_idx,
            pw_input: String::new(),
            pw_confirm: String::new(),
            keyfile_path: None,
            chpw_old: String::new(),
            chpw_new: String::new(),
            chpw_confirm: String::new(),
            export_pw: String::new(),
            show_add_vault_form: false,
            new_vault_name: String::new(),
            delete_target_idx: None,
            delete_confirm_code: None,
            delete_confirm_input: String::new(),
            rename_target_idx: None,
            rename_name_input: String::new(),
            selected_cert: None,
            new_cert: NewCertForm::default(),
            import_cert_alias: String::new(),
            confirm_delete_cert: None,
            selected_profile: None,
            edit_profile: None,
            custom_key_input: String::new(),
            custom_val_input: String::new(),
            sign_files: vec![],
            sign_filter: String::new(),
            sign_selected_profile: None,
            sign_cert_alias: String::new(),
            sign_meta: SigningMetadata::default(),
            verify_binary: None,
            verify_sig: None,
            verify_result: None,
            audit_filter: String::new(),
            status_msg: None,
            status_timer: 0.0,
            pending_tab_switch: None,
            workdir,
            sign_output_dir: None,
            sign_overwrite_sig: true,
            quick_sign_mode: false,
            quick_sign_done: None,
            quick_sign_signed_paths: vec![],
            quick_sign_errors: vec![],
            sign_profile_before_compat_change: None,
            close_requested: false,
            quick_sign_show_create_cert: false,
            quick_sign_offer_add_cert_to_profile: None,
            sign_create_copy: false,
            bg_cert_gen: None,
            bg_sign: None,
            bg_cert_result: None,
            bg_sign_result: None,
        }
    }
}

pub fn save_vault_registry(path: &std::path::Path, registry: &[VaultRecord]) {
    if let Ok(json) = serde_json::to_string_pretty(registry) {
        std::fs::write(path, json).ok();
    }
}

pub fn load_vault_registry(path: &std::path::Path) -> Vec<VaultRecord> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

// ── Application (charte Rusty Suite) ────────────────────────────────────────

use rusty_core::settings::CommonSettings;
use rusty_core::update::{self, Release};
use rusty_ui::rusty_logo::{Logo, LogoAnim};
use rusty_ui::{self as ui, ChromeAction, Tone};
use std::sync::mpsc::{self, Receiver};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const LICENSE: &str = env!("CARGO_PKG_LICENSE");
const REPOSITORY: &str = "https://github.com/rusty-suite/rusty_seal";

/// Agent HTTP générique (jamais d'information personnelle).
pub fn user_agent() -> String {
    format!("{}/{VERSION}", crate::workdir::APP_ID)
}

/// Réglages persistants (langue, menu réduit, mises à jour).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub common: CommonSettings,
}

/// Sections du menu latéral (Paramètres est le rouage de la barre d'outils, charte 01).
const SECTIONS: [Tab; 6] = [Tab::Vault, Tab::Certificates, Tab::Profiles, Tab::Sign, Tab::Verify, Tab::Audit];

fn section_icon(tab: Tab) -> &'static str {
    match tab {
        Tab::Vault => ui::icons::SHIELD,
        Tab::Certificates => ui::icons::FILE,
        Tab::Profiles => ui::icons::FOLDER,
        Tab::Sign => ui::icons::CHECK,
        Tab::Verify => ui::icons::SEARCH,
        Tab::Audit => ui::icons::LOG,
        Tab::Settings => ui::icons::GEAR,
    }
}

fn section_key(tab: Tab) -> &'static str {
    match tab {
        Tab::Vault => "tab.vault",
        Tab::Certificates => "tab.certs",
        Tab::Profiles => "tab.profiles",
        Tab::Sign => "tab.sign",
        Tab::Verify => "tab.verify",
        Tab::Audit => "tab.audit",
        Tab::Settings => "tab.settings",
    }
}

pub struct RustySealApp {
    state: AppState,
    current_tab: Tab,
    settings: Settings,
    logo: Logo,
    toasts: ui::Toasts,
    zones: ui::Zones,
    show_language: bool,
    show_about: bool,
    show_update: bool,
    online: Option<bool>,
    net_rx: Option<Receiver<bool>>,
    lang_rx: Option<Receiver<Result<usize, String>>>,
    update: Option<Release>,
    update_rx: Option<Receiver<Result<Option<Release>, String>>>,
    install_rx: Option<Receiver<Result<(), String>>>,
    args_rx: Receiver<Vec<String>>,
    had_bg_task: bool,
}

impl RustySealApp {
    pub fn new(cc: &eframe::CreationContext<'_>, state: AppState, initial_tab: Tab, settings: Settings, args_rx: Receiver<Vec<String>>, rolled_back: Option<String>) -> Self {
        theme::apply(&cc.egui_ctx);
        let mut logo = Logo::new(LogoAnim::Encrypt);
        logo.play_launch(0.0);
        let mut app = Self {
            state,
            current_tab: initial_tab,
            settings,
            logo,
            toasts: ui::Toasts::default(),
            zones: ui::Zones::default(),
            show_language: false,
            show_about: false,
            show_update: false,
            online: None,
            net_rx: Some(rusty_core::net::check_in_background(user_agent())),
            lang_rx: None,
            update: None,
            update_rx: None,
            install_rx: None,
            args_rx,
            had_bg_task: false,
        };
        app.apply_texts(&cc.egui_ctx);
        if let Some(v) = rolled_back {
            let core = app.state.lang.core();
            let text = core.tf("kit.update_restored_text", &[("version", &v)]);
            app.toasts.push(Tone::Warning, core.t("kit.update_restored"), text);
        }
        app
    }

    fn apply_texts(&self, ctx: &egui::Context) {
        let core = self.state.lang.core().clone();
        ui::set_texts(ctx, ui::KitTexts::from_lookup(|k| core.t(k)));
    }

    fn save_settings(&self) {
        if let Err(e) = rusty_core::settings::save(&self.state.workdir, &self.settings) {
            log::warn!("Réglages non enregistrés : {e}");
        }
    }

    fn set_language(&mut self, ctx: &egui::Context, stem: String) {
        self.settings.common.language = stem;
        self.save_settings();
        self.reload_language(ctx);
    }

    fn reload_language(&mut self, ctx: &egui::Context) {
        self.state.lang = Lang::load(&self.state.workdir, &self.settings.common.language);
        self.apply_texts(ctx);
    }

    /// Tâches de fond : réseau, langues distantes, mises à jour, autre instance.
    fn poll_background(&mut self, ctx: &egui::Context) {
        if let Some(online) = self.net_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.net_rx = None;
            self.online = Some(online);
            if online {
                let (dir, ua) = (self.state.workdir.clone(), user_agent());
                let (tx, rx) = mpsc::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(rusty_core::lang::refresh_remote(crate::workdir::APP_ID, crate::i18n::PACKS, &dir, &ua));
                });
                self.lang_rx = Some(rx);
                if self.settings.common.check_updates {
                    let (tx, rx) = mpsc::channel();
                    std::thread::spawn(move || {
                        let id = crate::workdir::APP_ID;
                        let _ = tx.send(update::check(id, id, VERSION, &user_agent()).map_err(|e| e.to_string()));
                    });
                    self.update_rx = Some(rx);
                }
            }
        }
        if let Some(Ok(n)) = self.lang_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.lang_rx = None;
            if n > 0 {
                self.reload_language(ctx);
            }
        }
        if let Some(result) = self.update_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.update_rx = None;
            match result {
                Ok(release) => self.update = release,
                Err(e) => log::warn!("Vérification des mises à jour impossible : {e}"),
            }
        }
        if let Some(result) = self.install_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.install_rx = None;
            match result {
                Ok(()) => {
                    if let Ok(exe) = std::env::current_exe() {
                        let _ = std::process::Command::new(exe).spawn();
                    }
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Err(e) => {
                    self.show_update = false;
                    self.toasts.push(Tone::Error, self.state.lang.core().t("kit.update_failed"), e);
                }
            }
        }
        // Clic droit « Signer » sur d'autres fichiers pendant que la fenêtre est ouverte.
        for args in self.args_rx.try_iter().collect::<Vec<_>>() {
            let files = crate::parse_sign_args(&args);
            if !files.is_empty() {
                for f in files {
                    if !self.state.sign_files.contains(&f) {
                        self.state.sign_files.push(f);
                    }
                }
                self.state.quick_sign_mode = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            }
        }
    }

    fn start_install(&mut self) {
        let Some(release) = self.update.clone() else { return };
        let (dir, ua) = (self.state.workdir.clone(), user_agent());
        let checksum_text = self.state.lang.core().t("kit.update_checksum");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = update::install(&release, VERSION, &dir, &ua).map_err(|e| match e {
                update::UpdateError::Checksum => checksum_text,
                other => other.to_string(),
            });
            let _ = tx.send(r);
        });
        self.install_rx = Some(rx);
    }

    /// Messages d'état des panneaux → notifications de la charte (et journal).
    fn flush_status(&mut self) {
        if let Some((msg, color)) = self.state.status_msg.take() {
            let tone = if color == theme::GREEN { Tone::Success } else if color == theme::YELLOW { Tone::Warning } else if color == theme::RED || color == theme::RED_DANGER { Tone::Error } else { Tone::Info };
            log::info!("{msg}");
            self.toasts.push(tone, msg, "");
            self.state.status_timer = 0.0;
        }
    }

    /// Bandeau de progression des tâches de fond (génération de certificat, signature).
    fn background_progress(&self, ui: &mut egui::Ui) {
        use std::sync::atomic::Ordering;
        if let Some(bg) = &self.state.bg_cert_gen {
            ui::progress_bar(ui, "bg_cert", 0.0, &bg.label, "", &[]);
        } else if let Some(bg) = &self.state.bg_sign {
            let current = bg.progress.load(Ordering::Relaxed);
            let frac = if bg.total > 0 { current as f32 / bg.total as f32 } else { 0.0 };
            ui::progress_bar(ui, "bg_sign", frac, self.state.lang.get("sign.signing_progress"), &format!("{current}/{}", bg.total), &[]);
        }
    }

    fn status_info<'a>(&'a self, languages: &'a str, update_version: Option<&'a str>) -> ui::StatusInfo<'a> {
        ui::StatusInfo { online: self.online, languages, update: update_version, version: VERSION }
    }
}

impl eframe::App for RustySealApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let now = ctx.input(|i| i.time);
        self.zones.begin_frame(ctx);
        self.poll_background(ctx);

        // ── Tâches de fond ─────────────────────────────────────────────────
        if let Some(bg) = &self.state.bg_cert_gen {
            if let Ok(result) = bg.rx.try_recv() {
                let context = bg.context;
                self.state.bg_cert_gen = None;
                self.state.bg_cert_result = Some((context, result));
            }
        }
        if let Some(bg) = &self.state.bg_sign {
            if let Ok(result) = bg.rx.try_recv() {
                let context = bg.context;
                for entry in result.audit_entries.iter().cloned() {
                    self.state.audit.append(entry).ok();
                }
                self.state.bg_sign = None;
                self.state.bg_sign_result = Some((context, crate::signing::SignJobResult {
                    ok_count: result.ok_count,
                    skipped: result.skipped,
                    errors: result.errors,
                    pairs: result.pairs,
                    audit_entries: vec![],
                }));
            }
        }
        let has_bg_task = self.state.bg_cert_gen.is_some() || self.state.bg_sign.is_some();
        // Le point du logo suit les tâches de fond (charte, 04).
        if has_bg_task && !self.had_bg_task {
            self.logo.start(now);
        } else if !has_bg_task && self.had_bg_task {
            let ok = self.state.bg_sign_result.as_ref().map(|(_, r)| r.errors.is_empty()).unwrap_or(true);
            self.logo.finish(ok, now);
        }
        self.had_bg_task = has_bg_task;
        if has_bg_task {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
        // Pas de fermeture pendant une tâche de fond.
        if has_bg_task && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.state.status_msg = Some((self.state.lang.get("common.task_running").to_string(), theme::YELLOW));
        }
        if self.state.close_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        self.state.vault.tick_auto_lock();

        let core = self.state.lang.core().clone();
        let languages = core.tf("kit.languages_count", &[("count", &rusty_core::lang::STEMS.len().to_string())]);
        let update_version = self.update.as_ref().map(|r| r.version.clone());
        let info = ui::AppInfo { name: "Rusty Seal".into(), description: self.state.lang.get("app.description").to_string(), version: VERSION.into() };
        let mut action = ui::status_bar(ctx, &self.status_info(&languages, update_version.as_deref()));

        if self.state.quick_sign_mode {
            // Signature rapide (clic droit ou --sign) : page « une tâche ».
            let a = ui::app_header(ctx, &mut self.logo, &info, &core.code());
            if a != ChromeAction::None {
                action = a;
            }
            ui::content(ctx, true, |ui| {
                self.background_progress(ui);
                crate::ui::quick_sign_panel::show(ui, &mut self.state);
            });
        } else {
            if let Some(tab) = self.state.pending_tab_switch.take() {
                self.current_tab = tab;
            }
            let labels: Vec<String> = SECTIONS.iter().map(|t| self.state.lang.get(section_key(*t)).to_string()).collect();
            let items: Vec<ui::SidebarItem> = SECTIONS.iter().zip(&labels).map(|(t, l)| ui::SidebarItem { icon: section_icon(*t), label: l }).collect();
            // Paramètres n'est pas dans le menu : aucun élément actif dans ce cas.
            let mut selected = SECTIONS.iter().position(|t| *t == self.current_tab).unwrap_or(usize::MAX);
            let before = (selected, self.settings.common.sidebar_collapsed);
            let a = ui::sidebar(ctx, &mut self.logo, &info, &items, &mut selected, &mut self.settings.common.sidebar_collapsed);
            if a != ChromeAction::None {
                action = a;
            }
            if selected != before.0 && selected < SECTIONS.len() {
                self.current_tab = SECTIONS[selected];
            }
            if self.settings.common.sidebar_collapsed != before.1 {
                self.save_settings();
            }
            let title = self.state.lang.get(section_key(self.current_tab)).to_string();
            let a = ui::toolbar(ctx, &title, |_| {});
            if a != ChromeAction::None {
                action = a;
            }
            ui::content(ctx, false, |ui| {
                self.background_progress(ui);
                match self.current_tab {
                    Tab::Vault => crate::ui::vault_panel::show(ui, &mut self.state),
                    Tab::Certificates => crate::ui::cert_panel::show(ui, &mut self.state),
                    Tab::Profiles => crate::ui::profile_panel::show(ui, &mut self.state),
                    Tab::Sign => crate::ui::sign_panel::show(ui, &mut self.state),
                    Tab::Verify => crate::ui::verify_panel::show(ui, &mut self.state),
                    Tab::Audit => crate::ui::audit_panel::show(ui, &mut self.state),
                    Tab::Settings => crate::ui::settings_panel::show(ui, &mut self.state),
                }
            });
        }
        match action {
            ChromeAction::Settings => {
                self.current_tab = Tab::Settings;
                self.state.quick_sign_mode = false;
            }
            ChromeAction::Language => self.show_language = true,
            ChromeAction::About => self.show_about = true,
            ChromeAction::Update => self.show_update = true,
            ChromeAction::None => {}
        }

        // Fenêtres communes.
        let tr = |k: &str| core.t(k);
        let langs: Vec<(String, String)> = rusty_core::lang::STEMS.iter().map(|s| (s.to_string(), rusty_core::lang::language_name(crate::i18n::PACKS, s))).collect();
        let folder = self.state.workdir.join("lang").display().to_string();
        if let Some(stem) = ui::language_window(ctx, &mut self.show_language, &tr, &core.stem, &langs, &folder) {
            self.set_language(ctx, stem);
        }
        ui::about_window(ctx, &mut self.show_about, &tr, &info, LICENSE, REPOSITORY, "rusty-suite");
        if let Some(v) = update_version {
            let installing = self.install_rx.is_some();
            if ui::update_window(ctx, &mut self.show_update, &tr, &v, installing) == ui::UpdateChoice::Install && !installing {
                self.start_install();
            }
        }

        self.flush_status();
        self.toasts.show(ctx);
        self.zones.end_frame(ctx);
        // Verrouillage automatique du coffre et notifications : rafraîchir chaque seconde.
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        update::mark_healthy(&self.state.workdir);
    }
}
