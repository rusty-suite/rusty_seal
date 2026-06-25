use egui::{RichText, Ui};
use crate::app::{self, AppState};
use crate::audit::{AuditAction, AuditEntry};
use crate::ui::theme;
use crate::vault::types::{KeyAlgorithm, VaultRecord};
use crate::vault::Vault;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_min_width(190.0);
            ui.set_max_width(190.0);
            show_vault_list(ui, state);
        });

        ui.separator();

        ui.vertical(|ui| {
            if state.delete_target_idx.is_some() {
                show_delete_confirm(ui, state);
            } else if state.show_add_vault_form {
                show_add_vault_form(ui, state);
            } else if state.vault.is_locked() {
                show_locked(ui, state);
            } else {
                show_unlocked(ui, state);
            }
        });
    });
}

fn generate_confirm_code() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..6).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

fn show_vault_list(ui: &mut Ui, state: &mut AppState) {
    ui.label(RichText::new("Vaults").strong().size(13.0));
    ui.separator();
    ui.add_space(4.0);

    let registry_len = state.vault_registry.len();
    let active_idx = state.active_vault_idx;

    let mut switch_to: Option<usize> = None;
    let mut start_delete: Option<usize> = None;

    for i in 0..registry_len {
        let name = state.vault_registry[i].name.clone();
        let path = state.vault_registry[i].path.clone();
        let is_active = i == active_idx;

        let (dot, dot_col) = if is_active {
            theme::status_dot(state.vault.is_locked())
        } else if path.exists() {
            ("●", theme::GRAY)
        } else {
            ("○", theme::GRAY)
        };

        ui.horizontal(|ui| {
            ui.label(RichText::new(dot).color(dot_col).size(8.0));

            let label_text = if is_active {
                RichText::new(&name).strong()
            } else {
                RichText::new(&name)
            };

            let resp = ui.selectable_label(is_active, label_text);
            if resp.clicked() && !is_active {
                switch_to = Some(i);
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(RichText::new("🗑").color(theme::RED).size(11.0))
                    .on_hover_text("Delete vault")
                    .clicked()
                {
                    start_delete = Some(i);
                }
            });
        });
    }

    if let Some(idx) = switch_to {
        state.vault.lock();
        let new_path = state.vault_registry[idx].path.clone();
        state.vault = Vault::new(new_path);
        state.active_vault_idx = idx;
        state.delete_target_idx = None;
        state.show_add_vault_form = false;
        state.pw_input.clear();
        state.pw_confirm.clear();
    }

    if let Some(idx) = start_delete {
        state.delete_target_idx = Some(idx);
        state.delete_confirm_code = Some(generate_confirm_code());
        state.delete_confirm_input.clear();
        state.show_add_vault_form = false;
    }

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(4.0);

    if ui.button("+ Add Vault").clicked() {
        state.show_add_vault_form = true;
        state.delete_target_idx = None;
        state.new_vault_name.clear();
    }
}

fn show_add_vault_form(ui: &mut Ui, state: &mut AppState) {
    ui.heading(RichText::new("Add Vault").strong());
    ui.separator();
    ui.add_space(8.0);

    egui::Grid::new("add_vault_grid").num_columns(2).show(ui, |ui| {
        ui.label("Name");
        ui.add(egui::TextEdit::singleline(&mut state.new_vault_name)
            .desired_width(220.0)
            .hint_text("e.g. Production"));
        ui.end_row();
    });

    ui.add_space(12.0);
    ui.label(RichText::new("Choose an option:").weak());
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        if ui.button("📄 Create New Vault…").clicked() {
            let suggested = name_to_filename(&state.new_vault_name);
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Choose location for new vault")
                .set_file_name(&suggested)
                .add_filter("Rusty Seal Vault", &["rsvc"])
                .save_file()
            {
                let name = vault_display_name(&state.new_vault_name, &p);
                add_and_switch(state, name, p);
            }
        }

        if ui.button("📁 Load Existing…").clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Open existing vault file")
                .add_filter("Rusty Seal Vault", &["rsvc"])
                .pick_file()
            {
                let name = vault_display_name(&state.new_vault_name, &p);
                add_and_switch(state, name, p);
            }
        }

        if ui.button("Cancel").clicked() {
            state.show_add_vault_form = false;
            state.new_vault_name.clear();
        }
    });
}

fn name_to_filename(name: &str) -> String {
    let slug = name.trim().to_lowercase().replace(' ', "_");
    if slug.is_empty() {
        "vault.rsvc".to_string()
    } else {
        format!("{}.rsvc", slug)
    }
}

fn vault_display_name(input: &str, path: &std::path::Path) -> String {
    if input.trim().is_empty() {
        path.file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    } else {
        input.trim().to_string()
    }
}

fn add_and_switch(state: &mut AppState, name: String, path: std::path::PathBuf) {
    // Avoid duplicates by path
    let already = state.vault_registry.iter().position(|r| r.path == path);
    let new_idx = if let Some(existing_idx) = already {
        existing_idx
    } else {
        state.vault_registry.push(VaultRecord { name, path: path.clone() });
        state.vault_registry.len() - 1
    };
    app::save_vault_registry(&state.vault_registry_path, &state.vault_registry);

    state.vault.lock();
    state.vault = Vault::new(path);
    state.active_vault_idx = new_idx;
    state.show_add_vault_form = false;
    state.new_vault_name.clear();
    state.pw_input.clear();
    state.pw_confirm.clear();
}

fn show_delete_confirm(ui: &mut Ui, state: &mut AppState) {
    let target_idx = match state.delete_target_idx {
        Some(i) => i,
        None => return,
    };
    if target_idx >= state.vault_registry.len() {
        state.delete_target_idx = None;
        return;
    }

    let vault_name = state.vault_registry[target_idx].name.clone();
    let vault_path = state.vault_registry[target_idx].path.clone();

    ui.heading(RichText::new("⚠ Delete Vault").color(theme::RED_DANGER).strong());
    ui.separator();
    ui.add_space(8.0);

    ui.label(format!("You are about to permanently delete \"{}\".", vault_name));
    ui.label(RichText::new(vault_path.to_string_lossy().to_string()).small().weak().monospace());
    ui.add_space(6.0);
    ui.label(RichText::new("This will erase the vault file from disk. All certificates and keys inside will be lost forever.").color(theme::YELLOW));
    ui.add_space(12.0);

    let code = match &state.delete_confirm_code {
        Some(c) => c.clone(),
        None => return,
    };

    ui.label("To confirm deletion, type this code exactly:");
    ui.add_space(4.0);
    ui.label(RichText::new(&code).monospace().size(26.0).strong().color(theme::RED_DANGER));
    ui.add_space(10.0);

    ui.add(egui::TextEdit::singleline(&mut state.delete_confirm_input)
        .desired_width(160.0)
        .hint_text("Type code here"));

    ui.add_space(10.0);

    let code_matches = state.delete_confirm_input.trim() == code.as_str();

    ui.horizontal(|ui| {
        if ui.button("Cancel").clicked() {
            state.delete_target_idx = None;
            state.delete_confirm_code = None;
            state.delete_confirm_input.clear();
        }

        let del_btn = egui::Button::new(
            RichText::new("Delete Permanently").color(theme::RED_DANGER)
        );
        if ui.add_enabled(code_matches, del_btn).clicked() {
            perform_delete(state, target_idx, vault_name, vault_path);
        }
    });
}

fn perform_delete(
    state: &mut AppState,
    target_idx: usize,
    vault_name: String,
    vault_path: std::path::PathBuf,
) {
    let is_active = target_idx == state.active_vault_idx;

    // Delete file from disk if it exists
    if vault_path.exists() {
        std::fs::remove_file(&vault_path).ok();
    }

    // Remove from registry
    state.vault_registry.remove(target_idx);
    app::save_vault_registry(&state.vault_registry_path, &state.vault_registry);

    // Fix active_vault_idx and reload active vault if needed
    if state.vault_registry.is_empty() {
        // No vaults left — create a placeholder default entry
        let workdir = state.vault_registry_path.parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        let default_path = workdir.join("default.rsvc");
        state.vault_registry.push(crate::vault::types::VaultRecord {
            name: String::new(),
            path: default_path.clone(),
        });
        app::save_vault_registry(&state.vault_registry_path, &state.vault_registry);
        state.vault = Vault::new(default_path);
        state.active_vault_idx = 0;
    } else if is_active {
        let new_idx = if target_idx >= state.vault_registry.len() {
            state.vault_registry.len() - 1
        } else {
            target_idx
        };
        let new_path = state.vault_registry[new_idx].path.clone();
        state.vault = Vault::new(new_path);
        state.active_vault_idx = new_idx;
    } else if target_idx < state.active_vault_idx {
        state.active_vault_idx -= 1;
    }

    state.delete_target_idx = None;
    state.delete_confirm_code = None;
    state.delete_confirm_input.clear();
    state.pw_input.clear();
    state.pw_confirm.clear();

    state.status_msg = Some((
        format!("Vault \"{}\" deleted permanently.", vault_name),
        theme::GREEN,
    ));

    state.audit.append(AuditEntry::new(
        AuditAction::VaultDelete,
        "operator".into(), None,
        Some(vault_path.to_string_lossy().to_string()),
        None, None, true,
    )).ok();
}

// ── Locked / unlocked views (unchanged logic, adjusted imports) ──────────────

fn show_locked(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    let (dot, col) = theme::status_dot(true);
    ui.horizontal(|ui| {
        ui.label(RichText::new(dot).color(col));
        ui.label(RichText::new(lang.get("vault.locked")).color(theme::YELLOW));
    });
    ui.add_space(6.0);

    // Vault name from registry
    if let Some(rec) = state.vault_registry.get(state.active_vault_idx) {
        ui.label(RichText::new(&rec.name).strong().size(14.0));
        ui.label(RichText::new(rec.path.to_string_lossy().to_string()).small().weak().monospace());
    }
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
                        state.audit.append(AuditEntry::new(
                            AuditAction::VaultUnlock,
                            "operator".into(), None, None, None, None, true,
                        )).ok();
                    }
                    Err(e) => {
                        state.status_msg = Some((e.to_string(), theme::RED));
                        state.audit.append(AuditEntry::new(
                            AuditAction::VaultUnlock,
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
                let suggested = state.vault_registry
                    .get(state.active_vault_idx)
                    .map(|r| name_to_filename(&r.name))
                    .unwrap_or_else(|| "vault.rsvc".to_string());
                if let Some(p) = rfd::FileDialog::new()
                    .set_title(lang.get("vault.choose_location"))
                    .set_file_name(&suggested)
                    .save_file()
                {
                    // Update path in both vault and registry
                    state.vault.path = p.clone();
                    if let Some(rec) = state.vault_registry.get_mut(state.active_vault_idx) {
                        rec.path = p;
                    }
                    app::save_vault_registry(&state.vault_registry_path, &state.vault_registry);
                }
            }
        });

        ui.add_space(4.0);

        if !state.vault.exists() {
            let idx = state.active_vault_idx;
            let parent_dir = state.vault.path.parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();
            let mut vault_name = state.vault_registry.get(idx)
                .map(|r| r.name.clone())
                .unwrap_or_default();

            egui::Grid::new("create_grid").num_columns(2).show(ui, |ui| {
                ui.label(lang.get("vault.name"));
                if ui.add(
                    egui::TextEdit::singleline(&mut vault_name)
                        .desired_width(240.0)
                        .hint_text("My Vault"),
                ).changed() && !vault_name.is_empty() {
                    let new_path = parent_dir.join(name_to_filename(&vault_name));
                    if let Some(rec) = state.vault_registry.get_mut(idx) {
                        rec.name = vault_name.clone();
                        rec.path = new_path.clone();
                    }
                    state.vault.path = new_path;
                    app::save_vault_registry(&state.vault_registry_path, &state.vault_registry);
                }
                ui.end_row();

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

            let vault_name_for_create = state.vault_registry
                .get(state.active_vault_idx)
                .map(|r| r.name.clone())
                .unwrap_or_default();
            if ui.button(lang.get("vault.btn_create")).clicked() {
                if vault_name_for_create.trim().is_empty() {
                    state.status_msg = Some((lang.get("vault.name_required").to_string(), theme::RED));
                } else if state.pw_input != state.pw_confirm {
                    state.status_msg = Some((lang.get("vault.pw_mismatch").to_string(), theme::RED));
                } else if state.pw_input.is_empty() {
                    state.status_msg = Some((lang.get("vault.pw_empty").to_string(), theme::RED));
                } else {
                    match state.vault.create(&state.pw_input, None) {
                        Ok(()) => {
                            state.status_msg = Some((lang.get("vault.created_ok").to_string(), theme::GREEN));
                            state.pw_input.clear();
                            state.pw_confirm.clear();
                            state.audit.append(AuditEntry::new(
                                AuditAction::VaultCreate,
                                "operator".into(), None, None, None, None, true,
                            )).ok();
                            // Guide user to create a signing cert immediately
                            state.pending_tab_switch = Some(crate::app::Tab::Certificates);
                            state.new_cert = crate::app::NewCertForm {
                                alias: "Code Signing".into(),
                                algorithm: KeyAlgorithm::Rsa2048,
                                common_name: "Code Signing".into(),
                                org: String::new(),
                                country: "US".into(),
                                email: String::new(),
                                valid_days: 730,
                            };
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
                    state.vault.path = p.clone();
                    if let Some(rec) = state.vault_registry.get_mut(state.active_vault_idx) {
                        rec.path = p;
                    }
                    app::save_vault_registry(&state.vault_registry_path, &state.vault_registry);
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
                state.audit.append(AuditEntry::new(
                    AuditAction::VaultLock,
                    "operator".into(), None, None, None, None, true,
                )).ok();
            }
        });
    });

    ui.add_space(4.0);
    if let Some(rec) = state.vault_registry.get(state.active_vault_idx) {
        ui.label(RichText::new(&rec.name).strong().size(14.0));
    }
    ui.label(RichText::new(state.vault.path.to_string_lossy().to_string()).small().weak());
    ui.add_space(8.0);

    let cert_count = state.vault.certificates().map(|c| c.len()).unwrap_or(0);
    let profile_count = state.vault.profiles().map(|p| p.len()).unwrap_or(0);

    ui.group(|ui| {
        ui.label(RichText::new("Contenu du vault").strong());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(format!("📄 {} certificat(s)", cert_count));
            if ui.small_button("Gérer →").clicked() {
                state.pending_tab_switch = Some(crate::app::Tab::Certificates);
            }
        });
        ui.horizontal(|ui| {
            ui.label(format!("📁 {} profil(s)", profile_count));
            if ui.small_button("Gérer →").clicked() {
                state.pending_tab_switch = Some(crate::app::Tab::Profiles);
            }
        });
        if cert_count == 0 {
            ui.add_space(4.0);
            if ui.button("+ Ajouter un certificat").clicked() {
                state.pending_tab_switch = Some(crate::app::Tab::Certificates);
            }
        }
    });
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
                                state.audit.append(AuditEntry::new(
                                    AuditAction::VaultExport,
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
                                // Add the imported vault to registry and switch to it
                                let name = dest.file_stem()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                add_and_switch(state, name, dest);
                                state.status_msg = Some((lang.get("vault.imported_ok").to_string(), theme::GREEN));
                                state.audit.append(AuditEntry::new(
                                    AuditAction::VaultImport,
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
