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

    show_compat_warning(ui, &state.sign_files, &state.sign_cert_alias.clone(), state);
}

fn show_compat_warning(ui: &mut Ui, files: &[PathBuf], cert_alias: &str, state: &crate::app::AppState) {
    let lang = &state.lang;

    let pe_count = files.iter().filter(|p| is_pe_file(p)).count();
    if pe_count > 0 {
        ui.add_space(6.0);
        ui.label(
            RichText::new(lang.get("sign.compat_pe_warn"))
                .small()
                .color(crate::ui::theme::YELLOW),
        );
    }

    let ps1_count = files.iter()
        .filter(|p| crate::signing::authenticode::is_authenticode_target(p))
        .count();

    if ps1_count > 0 {
        ui.add_space(4.0);
        if !cert_alias.is_empty() {
            let is_ed25519 = state.vault.get_cert(cert_alias)
                .ok()
                .map(|c| c.algorithm == crate::vault::types::KeyAlgorithm::Ed25519)
                .unwrap_or(false);

            if is_ed25519 {
                ui.label(
                    RichText::new(lang.get("sign.compat_ps1_ed25519_warn"))
                        .small()
                        .color(crate::ui::theme::RED),
                );
            } else {
                ui.label(
                    RichText::new(lang.get("sign.compat_ps1_info"))
                        .small()
                        .color(crate::ui::theme::GREEN_SOFT),
                );
            }
        }
    }
}

fn is_pe_file(path: &std::path::Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .as_deref(),
        Some("exe" | "dll" | "sys" | "ocx" | "drv" | "efi" | "msi" | "msp" | "msu" | "scr")
    )
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
                        let alt_aliases = p.cert_aliases.clone();
                        crate::ui::quick_sign_panel::try_auto_switch_cert(state, &alt_aliases);
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
                    if ui.selectable_value(&mut state.sign_cert_alias, alias.clone(), alias.as_str()).clicked() {
                        state.quick_sign_errors.clear();
                    }
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

    // Compatibility check — shown immediately when cert/files change
    crate::ui::quick_sign_panel::show_compat_block(ui, state, &lang, false);

    let can_sign = !state.sign_files.is_empty() && !state.sign_cert_alias.is_empty();

    ui.add_space(4.0);
    ui.separator();
    ui.add_space(4.0);

    // Copy mode toggle
    ui.horizontal(|ui| {
        ui.selectable_value(&mut state.sign_create_copy, false, lang.get("sign.output_mode_inplace"));
        ui.selectable_value(&mut state.sign_create_copy, true,
            format!("{} ({}{}…)", lang.get("sign.output_mode_copy"),
                lang.get("sign.signed_copy_prefix"), " "));
    });

    // Output options (summary, configured in Settings)
    let out_label = match &state.sign_output_dir {
        None => lang.get("sign.output_same_dir").to_string(),
        Some(d) => d.to_string_lossy().to_string(),
    };
    ui.horizontal(|ui| {
        ui.label(RichText::new(lang.get("sign.output_dir_label")).weak().small());
        ui.label(RichText::new(&out_label).small().monospace());
    });
    if !state.sign_create_copy {
        let overwrite_label = if state.sign_overwrite_sig {
            lang.get("sign.overwrite_sig")
        } else {
            lang.get("sign.skip_existing")
        };
        ui.label(RichText::new(overwrite_label).weak().small());
    }

    ui.add_space(8.0);

    if ui.add_enabled(can_sign, egui::Button::new(RichText::new(lang.get("sign.btn_sign")).strong())).clicked() {
        do_sign_all(state);
    }

    if !can_sign {
        ui.label(RichText::new(lang.get("sign.need_files_cert")).small().weak());
    }

    // Persistent inline error display
    if !state.quick_sign_errors.is_empty() {
        ui.add_space(6.0);
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(60, 20, 20))
            .inner_margin(egui::Margin::same(6.0))
            .rounding(4.0)
            .show(ui, |ui| {
                for err in &state.quick_sign_errors.clone() {
                    ui.label(RichText::new(format!("✗ {}", err)).small().color(theme::RED));
                }
            });
    }
}

fn sig_output_path(file_path: &std::path::Path, out_dir: &Option<std::path::PathBuf>) -> std::path::PathBuf {
    match out_dir {
        None => sig_path_for(file_path),
        Some(dir) => {
            let mut name = file_path.file_name().unwrap_or_default().to_os_string();
            name.push(".sig");
            dir.join(name)
        }
    }
}

/// Runs the actual signing loop.
/// Returns (signed, skipped, errors, signed_pairs) where signed_pairs is
/// a list of (source_file, output_sig_file) for successfully signed files.
pub fn perform_sign(state: &mut AppState) -> (usize, usize, Vec<String>, Vec<(std::path::PathBuf, std::path::PathBuf)>) {
    let alias = state.sign_cert_alias.clone();
    let meta = state.sign_meta.clone();
    let files = state.sign_files.clone();
    let out_dir = state.sign_output_dir.clone();
    let overwrite = state.sign_overwrite_sig;
    let create_copy = state.sign_create_copy;
    let copy_prefix = state.lang.get("sign.signed_copy_prefix").to_string();

    let cert = match state.vault.get_cert(&alias).cloned() {
        Ok(c) => c,
        Err(e) => return (0, 0, vec![e.to_string()], vec![]),
    };

    let mut ok_count = 0usize;
    let mut skipped_count = 0usize;
    let mut err_msgs = vec![];
    let mut signed_pairs: Vec<(std::path::PathBuf, std::path::PathBuf)> = vec![];

    for file_path in &files {
        // When copy mode is on, create a prefixed copy first and sign that
        let target_path = if create_copy {
            let fname = file_path.file_name().unwrap_or_default().to_string_lossy();
            let copy_name = format!("{} {}", copy_prefix, fname);
            let dest_dir = match &out_dir {
                Some(d) => d.clone(),
                None => file_path.parent().unwrap_or(std::path::Path::new(".")).to_path_buf(),
            };
            let dest = dest_dir.join(&copy_name);
            if let Err(e) = std::fs::copy(file_path, &dest) {
                err_msgs.push(format!("{}: {}", file_path.display(), e));
                continue;
            }
            dest
        } else {
            file_path.clone()
        };

        // PowerShell scripts → Authenticode (signature embedded in file)
        if crate::signing::authenticode::is_authenticode_target(&target_path) {
            match crate::signing::authenticode::sign_script(&target_path, &cert) {
                Ok(()) => {
                    ok_count += 1;
                    // Write a metadata sidecar alongside the signed PS1 (hash covers the signed file)
                    let meta_sig_path = sig_path_for(&target_path);
                    let file_hash = if let Ok(sig) = sign_file(&target_path, &cert, meta.clone()) {
                        let hash = sig.file_hash.clone();
                        std::fs::write(&meta_sig_path, sig.to_json_pretty()).ok();
                        hash
                    } else {
                        String::new()
                    };
                    signed_pairs.push((target_path.clone(), target_path.clone()));
                    state.audit.append(crate::audit::AuditEntry::new(
                        crate::audit::AuditAction::Sign,
                        "operator".into(),
                        if file_hash.is_empty() { None } else { Some(file_hash) },
                        Some(target_path.file_name().unwrap_or_default().to_string_lossy().to_string()),
                        Some(alias.clone()),
                        None,
                        true,
                    )).ok();
                }
                Err(e) => {
                    err_msgs.push(format!("{}: {}", file_path.display(), e));
                    // Clean up the copy on failure
                    if create_copy { std::fs::remove_file(&target_path).ok(); }
                    state.audit.append(crate::audit::AuditEntry::new(
                        crate::audit::AuditAction::Sign,
                        "operator".into(),
                        None,
                        Some(target_path.file_name().unwrap_or_default().to_string_lossy().to_string()),
                        Some(alias.clone()),
                        Some(e.to_string()),
                        false,
                    )).ok();
                }
            }
            continue;
        }

        // All other files → JSON sidecar
        // In copy mode the .sig always goes next to the copy; otherwise use out_dir logic
        let sig_path = if create_copy {
            sig_path_for(&target_path)
        } else {
            sig_output_path(file_path, &out_dir)
        };

        if sig_path.exists() && !overwrite && !create_copy {
            skipped_count += 1;
            continue;
        }

        match sign_file(&target_path, &cert, meta.clone()) {
            Ok(sig) => {
                match std::fs::write(&sig_path, sig.to_json_pretty()) {
                    Ok(()) => {
                        ok_count += 1;
                        signed_pairs.push((target_path.clone(), sig_path));
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
                    Err(e) => {
                        err_msgs.push(format!("{}: {}", file_path.display(), e));
                        if create_copy { std::fs::remove_file(&target_path).ok(); }
                    }
                }
            }
            Err(e) => {
                err_msgs.push(format!("{}: {}", file_path.display(), e));
                if create_copy { std::fs::remove_file(&target_path).ok(); }
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

    (ok_count, skipped_count, err_msgs, signed_pairs)
}

fn do_sign_all(state: &mut AppState) {
    let lang = state.lang.clone();
    state.quick_sign_errors.clear();
    let (ok_count, skipped_count, err_msgs, _) = perform_sign(state);

    let mut msg = format!("{} {} {}",
        lang.get("sign.signed_ok_prefix"), ok_count, lang.get("sign.signed_ok_suffix"));
    if skipped_count > 0 {
        msg.push_str(&format!(", {} {}", skipped_count, lang.get("sign.skipped")));
    }

    if err_msgs.is_empty() {
        state.status_msg = Some((msg, theme::GREEN));
    } else {
        // Store errors for inline display AND show in status bar
        state.quick_sign_errors = err_msgs.clone();
        state.status_msg = Some((
            format!("{} — {} erreur(s)", msg, err_msgs.len()),
            theme::RED,
        ));
    }
}
