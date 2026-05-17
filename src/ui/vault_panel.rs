use egui::{RichText, Ui};
use crate::app::AppState;
use crate::ui::theme;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.heading(RichText::new(lang.get("vault.title")).size(18.0).strong());
    ui.separator();
    ui.add_space(4.0);

    if state.vault.is_locked() {
        show_locked(ui, state);
    } else {
        show_unlocked(ui, state);
    }
}

fn show_locked(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    let (dot, col) = theme::status_dot(true);
    ui.horizontal(|ui| {
        ui.label(RichText::new(dot).color(col));
        ui.label(RichText::new(lang.get("vault.locked")).color(theme::YELLOW));
    });
    ui.add_space(8.0);

    if state.vault.exists() {
        ui.group(|ui| {
            ui.label(RichText::new(lang.get("vault.unlock")).strong());
            ui.add_space(4.0);

            egui::Grid::new("unlock_grid").num_columns(2).show(ui, |ui| {
                ui.label(lang.get("vault.password"));
                ui.add(egui::TextEdit::singleline(&mut state.pw_input)
                    .password(true)
                    .desired_width(240.0));
                ui.end_row();

                ui.label(lang.get("vault.keyfile"));
                ui.horizontal(|ui| {
                    let kf_label = state.keyfile_path
                        .as_ref()
                        .map(|p: &std::path::PathBuf| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
                        .unwrap_or_else(|| lang.get("vault.keyfile_none").to_string());
                    ui.label(RichText::new(&kf_label).small().weak());
                    if ui.small_button("📁").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            state.keyfile_path = Some(p);
                        }
                    }
                    if state.keyfile_path.is_some() && ui.small_button("✗").clicked() {
                        state.keyfile_path = None;
                    }
                });
                ui.end_row();
            });

            ui.add_space(4.0);
            if ui.button(lang.get("vault.btn_unlock")).clicked() {
                let keyfile_data = state.keyfile_path.as_ref().and_then(|p| std::fs::read(p).ok());
                match state.vault.unlock(&state.pw_input, keyfile_data.as_deref()) {
                    Ok(()) => {
                        state.status_msg = Some((lang.get("vault.unlocked_ok").to_string(), theme::GREEN));
                        state.pw_input.clear();
                        state.audit.append(crate::audit::AuditEntry::new(
                            crate::audit::AuditAction::VaultUnlock,
                            "operator".into(), None, None, None, None, true,
                        )).ok();
                    }
                    Err(e) => {
                        state.status_msg = Some((e.to_string(), theme::RED));
                        state.audit.append(crate::audit::AuditEntry::new(
                            crate::audit::AuditAction::VaultUnlock,
                            "operator".into(), None, None, None, Some(e.to_string()), false,
                        )).ok();
                    }
                }
            }
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(RichText::new(lang.get("vault.or_create")).weak().small());
    }

    ui.add_space(8.0);
    show_vault_location(ui, state);
}

fn show_vault_location(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.group(|ui| {
        ui.label(RichText::new(lang.get("vault.location")).strong());
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let path_str = state.vault.path.to_string_lossy().to_string();
            ui.label(RichText::new(&path_str).small().monospace());
            if ui.small_button("📁").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .set_title(lang.get("vault.choose_location"))
                    .set_file_name("vault.rsvc")
                    .save_file()
                {
                    state.vault.path = p;
                }
            }
        });

        ui.add_space(4.0);

        if !state.vault.exists() {
            egui::Grid::new("create_grid").num_columns(2).show(ui, |ui| {
                ui.label(lang.get("vault.password"));
                ui.add(egui::TextEdit::singleline(&mut state.pw_input)
                    .password(true)
                    .desired_width(240.0));
                ui.end_row();

                ui.label(lang.get("vault.confirm_password"));
                ui.add(egui::TextEdit::singleline(&mut state.pw_confirm)
                    .password(true)
                    .desired_width(240.0));
                ui.end_row();
            });
            ui.add_space(4.0);

            if ui.button(lang.get("vault.btn_create")).clicked() {
                if state.pw_input != state.pw_confirm {
                    state.status_msg = Some((lang.get("vault.pw_mismatch").to_string(), theme::RED));
                } else if state.pw_input.is_empty() {
                    state.status_msg = Some((lang.get("vault.pw_empty").to_string(), theme::RED));
                } else {
                    match state.vault.create(&state.pw_input, None) {
                        Ok(()) => {
                            state.status_msg = Some((lang.get("vault.created_ok").to_string(), theme::GREEN));
                            state.pw_input.clear();
                            state.pw_confirm.clear();
                            state.audit.append(crate::audit::AuditEntry::new(
                                crate::audit::AuditAction::VaultCreate,
                                "operator".into(), None, None, None, None, true,
                            )).ok();
                        }
                        Err(e) => {
                            state.status_msg = Some((e.to_string(), theme::RED));
                        }
                    }
                }
            }
        } else {
            if ui.button(lang.get("vault.btn_open_existing")).clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("Rusty Seal Vault", &["rsvc"])
                    .pick_file()
                {
                    state.vault.path = p;
                }
            }
        }
    });

    ui.add_space(8.0);
    show_import_export(ui, state);
}

fn show_unlocked(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    let (dot, col) = theme::status_dot(false);
    ui.horizontal(|ui| {
        ui.label(RichText::new(dot).color(col));
        ui.label(RichText::new(lang.get("vault.unlocked")).color(theme::GREEN_SOFT));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(RichText::new(lang.get("vault.btn_lock")).color(theme::YELLOW)).clicked() {
                state.vault.lock();
                state.audit.append(crate::audit::AuditEntry::new(
                    crate::audit::AuditAction::VaultLock,
                    "operator".into(), None, None, None, None, true,
                )).ok();
            }
        });
    });

    ui.add_space(4.0);
    ui.label(RichText::new(state.vault.path.to_string_lossy().to_string()).small().weak());
    ui.add_space(8.0);

    let expiring = state.vault.expiring_certs(&state.vault.config.warn_expiry_days.clone());
    if !expiring.is_empty() {
        ui.group(|ui| {
            ui.label(RichText::new("⚠ Certificates expiring soon").color(theme::YELLOW).strong());
            for (cert, days) in &expiring {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&cert.alias).strong());
                    ui.label(RichText::new(format!("— {} days left", days))
                        .color(theme::expiry_color(*days)));
                });
            }
        });
        ui.add_space(8.0);
    }

    show_vault_settings(ui, state);
    ui.add_space(8.0);
    show_change_password(ui, state);
    ui.add_space(8.0);
    show_import_export(ui, state);
}

fn show_vault_settings(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();
    ui.collapsing(lang.get("vault.settings"), |ui| {
        egui::Grid::new("vault_settings_grid").num_columns(2).show(ui, |ui| {
            ui.label(lang.get("vault.auto_lock_min"));
            ui.add(egui::DragValue::new(&mut state.vault.config.auto_lock_minutes)
                .range(0..=480)
                .suffix(" min"));
            ui.end_row();
        });
    });
}

fn show_change_password(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();
    ui.collapsing(lang.get("vault.change_password"), |ui| {
        egui::Grid::new("chpw_grid").num_columns(2).show(ui, |ui| {
            ui.label(lang.get("vault.old_password"));
            ui.add(egui::TextEdit::singleline(&mut state.chpw_old).password(true).desired_width(200.0));
            ui.end_row();
            ui.label(lang.get("vault.new_password"));
            ui.add(egui::TextEdit::singleline(&mut state.chpw_new).password(true).desired_width(200.0));
            ui.end_row();
            ui.label(lang.get("vault.confirm_password"));
            ui.add(egui::TextEdit::singleline(&mut state.chpw_confirm).password(true).desired_width(200.0));
            ui.end_row();
        });
        if ui.button(lang.get("vault.btn_change_password")).clicked() {
            if state.chpw_new != state.chpw_confirm {
                state.status_msg = Some((lang.get("vault.pw_mismatch").to_string(), theme::RED));
            } else {
                match state.vault.change_password(&state.chpw_old, &state.chpw_new, None) {
                    Ok(()) => {
                        state.status_msg = Some((lang.get("vault.pw_changed").to_string(), theme::GREEN));
                        state.chpw_old.clear();
                        state.chpw_new.clear();
                        state.chpw_confirm.clear();
                    }
                    Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                }
            }
        }
    });
}

fn show_import_export(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();
    ui.collapsing(lang.get("vault.import_export"), |ui| {
        ui.label(RichText::new(lang.get("vault.export_desc")).weak().small());
        ui.add_space(4.0);

        egui::Grid::new("impexp_grid").num_columns(2).show(ui, |ui| {
            ui.label(lang.get("vault.export_password"));
            ui.add(egui::TextEdit::singleline(&mut state.export_pw).password(true).desired_width(200.0));
            ui.end_row();
        });

        ui.horizontal(|ui| {
            if ui.button(lang.get("vault.btn_export")).clicked() {
                if !state.vault.is_locked() {
                    if let Some(dest) = rfd::FileDialog::new()
                        .set_title(lang.get("vault.choose_export"))
                        .set_file_name("vault_export.rsvx")
                        .add_filter("Vault Export", &["rsvx"])
                        .save_file()
                    {
                        match state.vault.export_encrypted(&dest, &state.export_pw) {
                            Ok(()) => {
                                state.status_msg = Some((lang.get("vault.exported_ok").to_string(), theme::GREEN));
                                state.audit.append(crate::audit::AuditEntry::new(
                                    crate::audit::AuditAction::VaultExport,
                                    "operator".into(), None,
                                    Some(dest.to_string_lossy().to_string()),
                                    None, None, true,
                                )).ok();
                            }
                            Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                        }
                        state.export_pw.clear();
                    }
                } else {
                    state.status_msg = Some((lang.get("vault.must_unlock_first").to_string(), theme::YELLOW));
                }
            }

            if ui.button(lang.get("vault.btn_import")).clicked() {
                if let Some(src) = rfd::FileDialog::new()
                    .add_filter("Vault Export", &["rsvx"])
                    .pick_file()
                {
                    if let Some(dest) = rfd::FileDialog::new()
                        .set_file_name("vault.rsvc")
                        .add_filter("Rusty Seal Vault", &["rsvc"])
                        .save_file()
                    {
                        match crate::vault::Vault::import_encrypted(&src, &dest, &state.export_pw) {
                            Ok(()) => {
                                state.vault.path = dest;
                                state.status_msg = Some((lang.get("vault.imported_ok").to_string(), theme::GREEN));
                                state.audit.append(crate::audit::AuditEntry::new(
                                    crate::audit::AuditAction::VaultImport,
                                    "operator".into(), None, None, None, None, true,
                                )).ok();
                            }
                            Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                        }
                        state.export_pw.clear();
                    }
                }
            }
        });
    });
}
