use std::path::PathBuf;

use egui::{Color32, RichText};

use crate::audit::AuditLog;
use crate::i18n::Lang;
use crate::signing::VerifyResult;
use crate::ui::theme;
use crate::vault::types::{KeyAlgorithm, Profile, SigningMetadata};
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
}

pub struct AppState {
    pub lang: Lang,
    pub vault: Vault,
    pub audit: AuditLog,

    // Vault UI
    pub pw_input: String,
    pub pw_confirm: String,
    pub keyfile_path: Option<PathBuf>,
    pub chpw_old: String,
    pub chpw_new: String,
    pub chpw_confirm: String,
    pub export_pw: String,

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
}

impl AppState {
    pub fn new(lang: Lang, vault: Vault, audit: AuditLog) -> Self {
        Self {
            lang,
            vault,
            audit,
            pw_input: String::new(),
            pw_confirm: String::new(),
            keyfile_path: None,
            chpw_old: String::new(),
            chpw_new: String::new(),
            chpw_confirm: String::new(),
            export_pw: String::new(),
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
        }
    }
}

pub struct RustySealApp {
    state: AppState,
    current_tab: Tab,
}

impl RustySealApp {
    pub fn new(cc: &eframe::CreationContext<'_>, state: AppState) -> Self {
        theme::apply(&cc.egui_ctx);
        Self {
            state,
            current_tab: Tab::Vault,
        }
    }
}

impl eframe::App for RustySealApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.state.vault.tick_auto_lock();

        let lang = self.state.lang.clone();

        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(4.0);

                let vault_locked = self.state.vault.is_locked();
                let (dot, col) = theme::status_dot(vault_locked);
                ui.label(RichText::new(dot).color(col).size(10.0));
                ui.label(RichText::new("Rusty Seal").strong().size(14.0));

                ui.separator();

                let tabs = [
                    (Tab::Vault, "🔒", lang.get("tab.vault")),
                    (Tab::Certificates, "📄", lang.get("tab.certs")),
                    (Tab::Profiles, "📁", lang.get("tab.profiles")),
                    (Tab::Sign, "✓", lang.get("tab.sign")),
                    (Tab::Verify, "🔍", lang.get("tab.verify")),
                    (Tab::Audit, "📋", lang.get("tab.audit")),
                ];

                for (tab, icon, label) in &tabs {
                    let is_active = &self.current_tab == tab;
                    let text = RichText::new(format!("{} {}", icon, label))
                        .color(if is_active { theme::GREEN_SOFT } else { egui::Color32::WHITE });

                    if ui.selectable_label(is_active, text).clicked() {
                        self.current_tab = match tab {
                            Tab::Vault => Tab::Vault,
                            Tab::Certificates => Tab::Certificates,
                            Tab::Profiles => Tab::Profiles,
                            Tab::Sign => Tab::Sign,
                            Tab::Verify => Tab::Verify,
                            Tab::Audit => Tab::Audit,
                        };
                    }
                }
            });
        });

        if let Some((msg, color)) = &self.state.status_msg.clone() {
            egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(msg).color(*color).small());
                });
            });
            self.state.status_timer += ctx.input(|i| i.unstable_dt);
            if self.state.status_timer > 5.0 {
                self.state.status_msg = None;
                self.state.status_timer = 0.0;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.current_tab {
                    Tab::Vault => crate::ui::vault_panel::show(ui, &mut self.state),
                    Tab::Certificates => crate::ui::cert_panel::show(ui, &mut self.state),
                    Tab::Profiles => crate::ui::profile_panel::show(ui, &mut self.state),
                    Tab::Sign => crate::ui::sign_panel::show(ui, &mut self.state),
                    Tab::Verify => crate::ui::verify_panel::show(ui, &mut self.state),
                    Tab::Audit => crate::ui::audit_panel::show(ui, &mut self.state),
                }
            });
        });

        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}
