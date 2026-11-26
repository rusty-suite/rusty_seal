use egui::{RichText, Ui};
use std::path::PathBuf;
use walkdir::WalkDir;

use crate::app::AppState;
use crate::signing::run_sign_job;
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
    // Handle background sign result (SignPanel context only)
    if matches!(state.bg_sign_result.as_ref(), Some((crate::app::BgSignContext::SignPanel, _))) {
        let (_, result) = state.bg_sign_result.take().unwrap();
        let lang = state.lang.clone();
        let mut msg = format!("{} {} {}",
            lang.get("sign.signed_ok_prefix"), result.ok_count, lang.get("sign.signed_ok_suffix"));
        if result.skipped > 0 {
            msg.push_str(&format!(", {} {}", result.skipped, lang.get("sign.skipped")));
        }
        if result.errors.is_empty() {
            state.status_msg = Some((msg, theme::GREEN));
        } else {
            state.quick_sign_errors = result.errors;
            state.status_msg = Some((
                lang.fmt("sign.with_errors", &[("msg", &msg), ("n", &state.quick_sign_errors.len().to_string())]),
                theme::RED,
            ));
        }
    }

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

    let signing_in_progress = state.bg_sign.as_ref()
        .map(|b| b.context == crate::app::BgSignContext::SignPanel)
        .unwrap_or(false);

    if signing_in_progress {
        let bg = state.bg_sign.as_ref().unwrap();
        let current = bg.progress.load(std::sync::atomic::Ordering::Relaxed);
        let total = bg.total;
        let frac = if total > 0 { current as f32 / total as f32 } else { 0.0 };
        ui.add(egui::ProgressBar::new(frac).animate(true).desired_width(250.0)
            .text(format!("{} / {}", current, total)));
    } else if ui.add_enabled(can_sign, egui::Button::new(RichText::new(lang.get("sign.btn_sign")).strong())).clicked() {
        start_sign_bg(state, crate::app::BgSignContext::SignPanel);
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

/// Spawns a background sign thread and stores the task handle in `state.bg_sign`.
pub fn start_sign_bg(state: &mut AppState, context: crate::app::BgSignContext) {
    let alias = state.sign_cert_alias.clone();
    let cert = match state.vault.get_cert(&alias).cloned() {
        Ok(c) => c,
        Err(e) => {
            state.quick_sign_errors = vec![e.localized(&state.lang)];
            return;
        }
    };
    let files = state.sign_files.clone();
    let meta = state.sign_meta.clone();
    let out_dir = state.sign_output_dir.clone();
    let overwrite = state.sign_overwrite_sig;
    let create_copy = state.sign_create_copy;
    let copy_prefix = state.lang.get("sign.signed_copy_prefix").to_string();
    let total = files.len();

    let progress = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let progress_clone = progress.clone();
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let result = run_sign_job(&files, &cert, meta, &out_dir, overwrite, create_copy, &copy_prefix, &progress_clone);
        tx.send(result).ok();
    });

    state.quick_sign_errors.clear();
    state.bg_sign = Some(crate::app::BgSign { rx, progress, total, context });
}
