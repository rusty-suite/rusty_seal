use egui::{RichText, Ui};
use std::path::PathBuf;
use walkdir::WalkDir;

use crate::app::AppState;
use crate::signing::{sign_file, sig_path_for, write_sig_file};
use crate::ui::theme;
use crate::vault::types::SigningMetadata;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    if state.vault.is_locked() {
        ui.label(RichText::new(format!("🔒 {}", lang.get("common.vault_locked"))).color(theme::YELLOW));
        return;
    }

    ui.heading(RichText::new(lang.get("sign.title")).size(18.0).strong());
    ui.separator();
    ui.add_space(4.0);

    ui.columns(2, |cols| {
        cols[0].group(|ui| {
            show_file_selector(ui, state);
        });
        cols[1].group(|ui| {
            show_sign_config(ui, state);
        });
    });
}

fn show_file_selector(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();
    ui.label(RichText::new(lang.get("sign.files")).strong());
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        if ui.button(lang.get("sign.add_files")).clicked() {
            if let Some(files) = rfd::FileDialog::new().pick_files() {
                for f in files {
                    if !state.sign_files.contains(&f) {
                        state.sign_files.push(f);
                    }
                }
            }
        }
        if ui.button(lang.get("sign.add_dir")).clicked() {
            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                let filter = state.sign_filter.to_lowercase();
                for entry in WalkDir::new(&dir)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                {
                    let path = entry.path().to_path_buf();
                    let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                    if filter.is_empty() || name.contains(&filter) {
                        if !state.sign_files.contains(&path) {
                            state.sign_files.push(path);
                        }
                    }
                }
            }
        }
        if ui.button(lang.get("sign.clear")).clicked() {
            state.sign_files.clear();
        }
    });

    ui.horizontal(|ui| {
        ui.label(RichText::new(lang.get("sign.filter")).weak().small());
        ui.add(egui::TextEdit::singleline(&mut state.sign_filter)
            .hint_text("*.exe, *.dll ...")
            .desired_width(150.0));
    });

    ui.add_space(4.0);

    egui::ScrollArea::vertical().id_salt("sign_files_scroll").max_height(220.0).show(ui, |ui| {
        let mut to_remove: Option<usize> = None;
        for (i, path) in state.sign_files.iter().enumerate() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("📄 {}", name)).small());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("✗").clicked() {
                        to_remove = Some(i);
                    }
                });
            });
        }
        if let Some(i) = to_remove {
            state.sign_files.remove(i);
        }
    });

    ui.add_space(4.0);
    ui.label(RichText::new(format!("{} {}", state.sign_files.len(), lang.get("sign.files_count"))).weak().small());
}

fn show_sign_config(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.label(RichText::new(lang.get("sign.config")).strong());
    ui.add_space(4.0);

    // Profile selector
    let profiles: Vec<_> = state.vault.profiles()
        .unwrap_or_default()
        .into_iter()
        .cloned()
        .collect();

    ui.horizontal(|ui| {
        ui.label(lang.get("sign.profile"));
        egui::ComboBox::from_id_salt("sign_profile_combo")
            .selected_text(state.sign_selected_profile.clone().unwrap_or_else(|| lang.get("sign.no_profile").to_string()))
            .show_ui(ui, |ui| {
                if ui.selectable_value(&mut state.sign_selected_profile, None, lang.get("sign.no_profile")).clicked() {
                    state.sign_meta = SigningMetadata::default();
                }
                for p in &profiles {
                    if ui.selectable_value(
                        &mut state.sign_selected_profile,
                        Some(p.id.clone()),
                        &p.name,
                    ).clicked() {
                        state.sign_meta = p.default_metadata.clone();
                        state.sign_cert_alias = p.cert_alias.clone();
                    }
                }
            });
    });

    ui.add_space(4.0);

    // Certificate selector
    let certs: Vec<_> = state.vault.certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.alias.clone())
        .collect();

    ui.horizontal(|ui| {
        ui.label(lang.get("sign.certificate"));
        egui::ComboBox::from_id_salt("sign_cert_combo")
            .selected_text(if state.sign_cert_alias.is_empty() {
                lang.get("sign.choose_cert").to_string()
            } else {
                state.sign_cert_alias.clone()
            })
            .show_ui(ui, |ui| {
                for alias in &certs {
                    ui.selectable_value(&mut state.sign_cert_alias, alias.clone(), alias.as_str());
                }
            });
    });

    ui.add_space(8.0);
    ui.label(RichText::new(lang.get("sign.metadata")).strong());
    ui.add_space(4.0);

    egui::Grid::new("sign_meta_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(lang.get("meta.version"));
        ui.add(egui::TextEdit::singleline(&mut state.sign_meta.version).desired_width(180.0));
        ui.end_row();

        ui.label(lang.get("meta.author"));
        ui.add(egui::TextEdit::singleline(&mut state.sign_meta.author).desired_width(180.0));
        ui.end_row();

        ui.label(lang.get("meta.description"));
        ui.add(egui::TextEdit::singleline(&mut state.sign_meta.description).desired_width(180.0));
        ui.end_row();

        ui.label(lang.get("meta.build_date"));
        ui.add(egui::TextEdit::singleline(&mut state.sign_meta.build_date).desired_width(180.0));
        ui.end_row();

        ui.label(lang.get("meta.source_url"));
        ui.add(egui::TextEdit::singleline(&mut state.sign_meta.source_url).desired_width(180.0));
        ui.end_row();
    });

    ui.add_space(4.0);

    let keys: Vec<_> = state.sign_meta.custom.keys().cloned().collect();
    let mut to_remove: Option<String> = None;
    for k in &keys {
        ui.horizontal(|ui| {
            ui.label(RichText::new(k).monospace().small());
            if let Some(v) = state.sign_meta.custom.get_mut(k.as_str()) {
                ui.add(egui::TextEdit::singleline(v).desired_width(140.0));
            }
            if ui.small_button("✗").clicked() {
                to_remove = Some(k.clone());
            }
        });
    }
    if let Some(k) = to_remove {
        state.sign_meta.custom.remove(&k);
    }

    ui.add_space(8.0);

    let can_sign = !state.sign_files.is_empty() && !state.sign_cert_alias.is_empty();

    if ui.add_enabled(can_sign, egui::Button::new(RichText::new(lang.get("sign.btn_sign")).strong())).clicked() {
        do_sign_all(state);
    }

    if !can_sign {
        ui.label(RichText::new(lang.get("sign.need_files_cert")).small().weak());
    }
}

fn do_sign_all(state: &mut AppState) {
    let lang = state.lang.clone();
    let alias = state.sign_cert_alias.clone();
    let meta = state.sign_meta.clone();
    let files = state.sign_files.clone();

    let cert = match state.vault.get_cert(&alias).cloned() {
        Ok(c) => c,
        Err(e) => {
            state.status_msg = Some((e.to_string(), theme::RED));
            return;
        }
    };

    let mut ok_count = 0usize;
    let mut err_msgs = vec![];

    for file_path in &files {
        match sign_file(file_path, &cert, meta.clone()) {
            Ok(sig) => {
                let sig_path = sig_path_for(file_path);
                match std::fs::write(&sig_path, sig.to_json_pretty()) {
                    Ok(()) => {
                        ok_count += 1;
                        state.audit.append(crate::audit::AuditEntry::new(
                            crate::audit::AuditAction::Sign,
                            "operator".into(),
                            Some(sig.file_hash.clone()),
                            Some(sig.file_name.clone()),
                            Some(alias.clone()),
                            None,
                            true,
                        )).ok();
                    }
                    Err(e) => err_msgs.push(format!("{}: {}", file_path.display(), e)),
                }
            }
            Err(e) => {
                err_msgs.push(format!("{}: {}", file_path.display(), e));
                state.audit.append(crate::audit::AuditEntry::new(
                    crate::audit::AuditAction::Sign,
                    "operator".into(),
                    None,
                    Some(file_path.file_name().unwrap_or_default().to_string_lossy().to_string()),
                    Some(alias.clone()),
                    Some(e.to_string()),
                    false,
                )).ok();
            }
        }
    }

    if err_msgs.is_empty() {
        state.status_msg = Some((
            format!("{} {} {}", lang.get("sign.signed_ok_prefix"), ok_count, lang.get("sign.signed_ok_suffix")),
            theme::GREEN,
        ));
    } else {
        state.status_msg = Some((
            format!("{}/{} signed. Errors: {}", ok_count, files.len(), err_msgs.join("; ")),
            theme::YELLOW,
        ));
    }
}
