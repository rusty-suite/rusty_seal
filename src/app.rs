use std::path::PathBuf;

use egui::{Color32, RichText};

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
            valid_days: 365,
        }
    }
}

#[derive(Debug, PartialEq)]
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

    // Settings
    pub lang_dir: std::path::PathBuf,

    // Sign output options
    pub sign_output_dir: Option<std::path::PathBuf>,
    pub sign_overwrite_sig: bool,
}

impl AppState {
    pub fn new(
        lang: Lang,
        vault: Vault,
        audit: AuditLog,
        vault_registry: Vec<VaultRecord>,
        vault_registry_path: PathBuf,
        active_vault_idx: usize,
        lang_dir: PathBuf,
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
            lang_dir,
            sign_output_dir: None,
            sign_overwrite_sig: true,
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

pub struct RustySealApp {
    state: AppState,
    current_tab: Tab,
}

impl RustySealApp {
    pub fn new(cc: &eframe::CreationContext<'_>, state: AppState, initial_tab: Tab) -> Self {
        theme::apply(&cc.egui_ctx);
        Self {
            state,
            current_tab: initial_tab,
        }
    }
}

impl eframe::App for RustySealApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Réappliquer le thème sombre chaque frame — eframe/OS peut le réinitialiser
        ctx.set_visuals(theme::dark_visuals());

        self.state.vault.tick_auto_lock();

        if let Some(tab) = self.state.pending_tab_switch.take() {
            self.current_tab = tab;
        }

        let lang = self.state.lang.clone();

        // Barre d'onglets avec fond explicitement sombre
        let topbar_frame = egui::Frame::none()
            .fill(theme::BG_TOPBAR)
            .inner_margin(egui::Margin::symmetric(4.0, 4.0));

        egui::TopBottomPanel::top("tab_bar")
            .frame(topbar_frame)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let vault_locked = self.state.vault.is_locked();
                    let (dot, col) = theme::status_dot(vault_locked);
                    ui.label(RichText::new(dot).color(col).size(10.0));
                    ui.label(RichText::new("Rusty Seal").strong().size(14.0).color(egui::Color32::WHITE));

                    ui.separator();

                    let tabs = [
                        (Tab::Vault,        "🔒", lang.get("tab.vault")),
                        (Tab::Certificates, "📄", lang.get("tab.certs")),
                        (Tab::Profiles,     "📁", lang.get("tab.profiles")),
                        (Tab::Sign,         "✓",  lang.get("tab.sign")),
                        (Tab::Verify,       "🔍", lang.get("tab.verify")),
                        (Tab::Audit,        "📋", lang.get("tab.audit")),
                    ];

                    for (tab, icon, label) in &tabs {
                        let is_active = &self.current_tab == tab;
                        // Actif : vert vif  |  Inactif : bleu-gris clair (lisible sur fond sombre)
                        let col = if is_active { theme::GREEN_SOFT } else { theme::TAB_INACTIVE };
                        let text = RichText::new(format!("{} {}", icon, label)).color(col);

                        if ui.selectable_label(is_active, text).clicked() {
                            self.current_tab = match tab {
                                Tab::Vault        => Tab::Vault,
                                Tab::Certificates => Tab::Certificates,
                                Tab::Profiles     => Tab::Profiles,
                                Tab::Sign         => Tab::Sign,
                                Tab::Verify       => Tab::Verify,
                                Tab::Audit        => Tab::Audit,
                                Tab::Settings     => Tab::Settings,
                            };
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let is_settings = self.current_tab == Tab::Settings;
                        let col = if is_settings { theme::GREEN_SOFT } else { theme::TAB_INACTIVE };
                        if ui.selectable_label(is_settings, RichText::new("⚙").color(col))
                            .on_hover_text(lang.get("tab.settings"))
                            .clicked()
                        {
                            self.current_tab = Tab::Settings;
                        }
                    });
                });
            });

        // Barre de statut avec fond explicitement sombre
        if let Some((msg, color)) = &self.state.status_msg.clone() {
            let status_frame = egui::Frame::none()
                .fill(theme::BG_STATUS)
                .inner_margin(egui::Margin::symmetric(6.0, 2.0));

            egui::TopBottomPanel::bottom("status_bar")
                .frame(status_frame)
                .show(ctx, |ui| {
                    ui.label(RichText::new(msg).color(*color).small());
                });

            self.state.status_timer += ctx.input(|i| i.unstable_dt);
            if self.state.status_timer > 5.0 {
                self.state.status_msg = None;
                self.state.status_timer = 0.0;
            }
        }

        // Panneau central avec fond explicitement sombre
        let main_frame = egui::Frame::none()
            .fill(theme::BG_PANEL)
            .inner_margin(egui::Margin::same(8.0));

        egui::CentralPanel::default().frame(main_frame).show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.current_tab {
                    Tab::Vault        => crate::ui::vault_panel::show(ui, &mut self.state),
                    Tab::Certificates => crate::ui::cert_panel::show(ui, &mut self.state),
                    Tab::Profiles     => crate::ui::profile_panel::show(ui, &mut self.state),
                    Tab::Sign         => crate::ui::sign_panel::show(ui, &mut self.state),
                    Tab::Verify       => crate::ui::verify_panel::show(ui, &mut self.state),
                    Tab::Audit        => crate::ui::audit_panel::show(ui, &mut self.state),
                    Tab::Settings     => crate::ui::settings_panel::show(ui, &mut self.state),
                }
            });
        });

        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}
