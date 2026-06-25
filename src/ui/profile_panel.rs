use egui::{RichText, Ui};
use uuid::Uuid;

use crate::app::AppState;
use crate::ui::theme;
use crate::vault::types::{Profile, SigningMetadata};

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    if state.vault.is_locked() {
        ui.label(RichText::new(format!("🔒 {}", lang.get("common.vault_locked"))).color(theme::YELLOW));
        return;
    }

    ui.heading(RichText::new(lang.get("profile.title")).size(18.0).strong());
    ui.separator();
    ui.add_space(4.0);

    ui.columns(2, |cols| {
        cols[0].group(|ui| {
            show_profile_list(ui, state);
        });
        cols[1].group(|ui| {
            show_profile_editor(ui, state);
        });
    });
}

fn show_profile_list(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();
    ui.label(RichText::new(lang.get("profile.list")).strong());
    ui.add_space(4.0);

    let profiles: Vec<_> = state.vault.profiles()
        .unwrap_or_default()
        .into_iter()
        .cloned()
        .collect();

    if profiles.is_empty() {
        ui.label(RichText::new(lang.get("profile.none")).weak().italics());
    } else {
        for profile in &profiles {
            let selected = state.selected_profile.as_deref() == Some(profile.id.as_str());
            if ui.selectable_label(selected, RichText::new(&profile.name).strong()).clicked() {
                state.selected_profile = Some(profile.id.clone());
                state.edit_profile = Some(profile.clone());
            }
        }
    }

    ui.add_space(8.0);
    if ui.button(lang.get("profile.new")).clicked() {
        state.selected_profile = None;
        state.edit_profile = Some(Profile {
            id: Uuid::new_v4().to_string(),
            name: String::new(),
            cert_alias: String::new(),
            cert_aliases: vec![],
            default_metadata: SigningMetadata::default(),
        });
    }
}

enum ProfileAction {
    None,
    Save,
    Delete(String),
}

fn show_profile_editor(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    if state.edit_profile.is_none() {
        ui.label(RichText::new(lang.get("profile.select_or_new")).weak().italics());
        return;
    }

    let is_new = state.selected_profile.is_none();
    ui.label(RichText::new(if is_new {
        lang.get("profile.create")
    } else {
        lang.get("profile.edit")
    }).strong());
    ui.add_space(4.0);

    // Collect alias list before taking the profile borrow
    let aliases: Vec<String> = state.vault.certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.alias.clone())
        .collect();

    let profile = state.edit_profile.as_mut().unwrap();

    egui::Grid::new("profile_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(lang.get("profile.name"));
        ui.add(egui::TextEdit::singleline(&mut profile.name).desired_width(200.0));
        ui.end_row();

        ui.label(lang.get("profile.cert_alias"));
        egui::ComboBox::from_id_salt("profile_cert_combo")
            .selected_text(if profile.cert_alias.is_empty() {
                lang.get("profile.choose_cert").to_string()
            } else {
                profile.cert_alias.clone()
            })
            .show_ui(ui, |ui| {
                for alias in &aliases {
                    ui.selectable_value(&mut profile.cert_alias, alias.clone(), alias.as_str());
                }
            });
        ui.end_row();
    });

    ui.add_space(6.0);
    ui.label(RichText::new(lang.get("profile.cert_aliases")).small().weak());
    ui.label(RichText::new(lang.get("profile.cert_aliases_hint")).small().weak().italics());

    let profile = state.edit_profile.as_mut().unwrap();
    let cert_aliases_snapshot = profile.cert_aliases.clone();
    let mut to_remove_alias: Option<usize> = None;
    for (i, alias) in cert_aliases_snapshot.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(RichText::new(alias).small().monospace());
            if ui.small_button("✗").clicked() {
                to_remove_alias = Some(i);
            }
        });
    }
    if let Some(i) = to_remove_alias {
        profile.cert_aliases.remove(i);
    }

    // Combo to add a cert not already in the list
    let available: Vec<String> = aliases.iter()
        .filter(|a| **a != profile.cert_alias && !profile.cert_aliases.contains(*a))
        .cloned()
        .collect();
    if !available.is_empty() {
        let mut chosen = String::new();
        egui::ComboBox::from_id_salt("profile_extra_cert")
            .selected_text(lang.get("profile.cert_alias_add").to_string())
            .width(200.0)
            .show_ui(ui, |ui| {
                for alias in &available {
                    if ui.selectable_label(false, alias.as_str()).clicked() {
                        chosen = alias.clone();
                    }
                }
            });
        if !chosen.is_empty() {
            profile.cert_aliases.push(chosen);
        }
    }

    ui.add_space(8.0);
    ui.label(RichText::new(lang.get("profile.default_metadata")).strong());
    ui.add_space(4.0);

    egui::Grid::new("meta_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(lang.get("meta.version"));
        ui.add(egui::TextEdit::singleline(&mut profile.default_metadata.version).desired_width(200.0));
        ui.end_row();

        ui.label(lang.get("meta.author"));
        ui.add(egui::TextEdit::singleline(&mut profile.default_metadata.author).desired_width(200.0));
        ui.end_row();

        ui.label(lang.get("meta.description"));
        ui.add(egui::TextEdit::singleline(&mut profile.default_metadata.description).desired_width(200.0));
        ui.end_row();

        ui.label(lang.get("meta.build_date"));
        ui.add(egui::TextEdit::singleline(&mut profile.default_metadata.build_date).desired_width(200.0));
        ui.end_row();

        ui.label(lang.get("meta.source_url"));
        ui.add(egui::TextEdit::singleline(&mut profile.default_metadata.source_url).desired_width(200.0));
        ui.end_row();
    });

    ui.add_space(8.0);
    ui.label(RichText::new(lang.get("meta.custom_fields")).strong());
    ui.add_space(4.0);

    let keys: Vec<_> = profile.default_metadata.custom.keys().cloned().collect();
    let mut to_remove: Option<String> = None;
    for k in &keys {
        ui.horizontal(|ui| {
            ui.label(RichText::new(k).monospace().small());
            if let Some(v) = profile.default_metadata.custom.get_mut(k.as_str()) {
                ui.add(egui::TextEdit::singleline(v).desired_width(160.0));
            }
            if ui.small_button("✗").clicked() {
                to_remove = Some(k.clone());
            }
        });
    }
    if let Some(k) = to_remove {
        profile.default_metadata.custom.remove(&k);
    }

    let ck = state.custom_key_input.clone();
    let cv = state.custom_val_input.clone();
    let profile = state.edit_profile.as_mut().unwrap();
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut state.custom_key_input)
            .hint_text(lang.get("meta.custom_key"))
            .desired_width(120.0));
        ui.add(egui::TextEdit::singleline(&mut state.custom_val_input)
            .hint_text(lang.get("meta.custom_value"))
            .desired_width(120.0));
        if ui.button("+").clicked() && !ck.is_empty() {
            profile.default_metadata.custom.insert(ck, cv);
            state.custom_key_input.clear();
            state.custom_val_input.clear();
        }
    });

    ui.add_space(8.0);

    // Determine action without a closure borrow conflict
    let mut action = ProfileAction::None;
    let selected_id = state.selected_profile.clone();
    let profile_name = state.edit_profile.as_ref().map(|p| p.name.clone()).unwrap_or_default();

    ui.horizontal(|ui| {
        if ui.button(lang.get("profile.btn_save")).clicked() {
            action = ProfileAction::Save;
        }
        if let Some(ref id) = selected_id {
            if ui.button(RichText::new(format!("🗑 {}", lang.get("profile.delete")))
                .color(theme::RED_DANGER))
                .clicked()
            {
                action = ProfileAction::Delete(id.clone());
            }
        }
    });

    // Execute the action after releasing borrows
    match action {
        ProfileAction::Save => {
            if profile_name.is_empty() {
                state.status_msg = Some((lang.get("profile.name_required").to_string(), theme::RED));
            } else if let Some(p) = state.edit_profile.clone() {
                let is_new_profile = state.selected_profile.is_none();
                let id = p.id.clone();
                match state.vault.add_profile(p) {
                    Ok(()) => {
                        state.status_msg = Some((lang.get("profile.saved_ok").to_string(), theme::GREEN));
                        state.selected_profile = Some(id);
                        state.audit.append(crate::audit::AuditEntry::new(
                            if is_new_profile {
                                crate::audit::AuditAction::ProfileCreate
                            } else {
                                crate::audit::AuditAction::ProfileEdit
                            },
                            "operator".into(), None, None, None, None, true,
                        )).ok();
                    }
                    Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                }
            }
        }
        ProfileAction::Delete(id) => {
            let _ = state.vault.remove_profile(&id);
            state.selected_profile = None;
            state.edit_profile = None;
            state.status_msg = Some((lang.get("profile.deleted_ok").to_string(), theme::GREEN));
            state.audit.append(crate::audit::AuditEntry::new(
                crate::audit::AuditAction::ProfileDelete,
                "operator".into(), None, None, None, None, true,
            )).ok();
        }
        ProfileAction::None => {}
    }
}
