use egui::{RichText, Ui};
use crate::app::AppState;
use crate::ui::theme;
use crate::vault::types::SigningMetadata;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.add_space(16.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(520.0);

        ui.heading(
            RichText::new(format!("🔏  {}", lang.get("common.quick_sign_title")))
                .size(22.0)
                .strong()
                .color(theme::GREEN_SOFT),
        );
        ui.add_space(20.0);

        if let Some((signed, skipped)) = state.quick_sign_done {
            show_done(ui, state, signed, skipped);
            return;
        }

        show_files(ui, state);
        ui.add_space(12.0);

        if state.vault.is_locked() {
            show_unlock_step(ui, state);
        } else {
            show_profile_step(ui, state);
        }
    });
}

fn show_files(ui: &mut Ui, state: &AppState) {
    let lang = state.lang.clone();
    let n = state.sign_files.len();

    ui.group(|ui| {
        ui.label(
            RichText::new(format!("{}  ({})", lang.get("sign.files"), n))
                .strong()
                .small(),
        );
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_salt("qs_files_scroll")
            .max_height(130.0)
            .show(ui, |ui| {
                for f in &state.sign_files {
                    let name = f.file_name().unwrap_or_default().to_string_lossy();
                    let dir = f
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("📄 {}", name)).small().strong());
                        ui.label(RichText::new(dir).small().weak());
                    });
                }
            });

        let pe_count = state.sign_files.iter().filter(|p| is_pe_file(p)).count();
        if pe_count > 0 {
            ui.add_space(4.0);
            ui.label(
                RichText::new(lang.get("sign.compat_pe_warn"))
                    .small()
                    .color(theme::YELLOW),
            );
        }
    });
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

fn show_unlock_step(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.group(|ui| {
        let vault_name = state
            .vault_registry
            .get(state.active_vault_idx)
            .map(|r| r.name.as_str())
            .unwrap_or("Vault");

        ui.horizontal(|ui| {
            ui.label(RichText::new(lang.get("vault.title")).weak().small());
            ui.label(RichText::new(vault_name).strong().small());
            ui.label(
                RichText::new(format!("  🔒 {}", lang.get("vault.locked")))
                    .color(theme::YELLOW)
                    .small(),
            );
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new(lang.get("vault.password")).small());
            let resp = ui.add(
                egui::TextEdit::singleline(&mut state.pw_input)
                    .password(true)
                    .desired_width(280.0)
                    .hint_text(lang.get("vault.password")),
            );
            // Allow Enter key to unlock
            let enter_pressed = resp.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter));

            let do_unlock = enter_pressed
                || ui
                    .add_enabled(
                        !state.pw_input.is_empty(),
                        egui::Button::new(
                            RichText::new(lang.get("vault.btn_unlock")).strong(),
                        ),
                    )
                    .clicked();

            if do_unlock && !state.pw_input.is_empty() {
                let pw = state.pw_input.clone();
                let keyfile_data = state.keyfile_path.as_ref().and_then(|p| std::fs::read(p).ok());
                match state.vault.unlock(&pw, keyfile_data.as_deref()) {
                    Ok(()) => {
                        state.pw_input.clear();
                        state.status_msg =
                            Some((lang.get("vault.unlocked_ok").to_string(), theme::GREEN));
                    }
                    Err(e) => {
                        state.status_msg = Some((e.to_string(), theme::RED));
                    }
                }
            }
        });
    });
}

fn show_profile_step(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.group(|ui| {
        ui.label(
            RichText::new(format!("✅  {}", lang.get("vault.unlocked")))
                .color(theme::GREEN_SOFT)
                .small(),
        );
        ui.add_space(10.0);

        // Profile selector
        let profiles: Vec<_> = state
            .vault
            .profiles()
            .unwrap_or_default()
            .into_iter()
            .cloned()
            .collect();

        ui.horizontal(|ui| {
            ui.label(RichText::new(lang.get("sign.profile")).small());

            let selected_label = state
                .sign_selected_profile
                .as_deref()
                .and_then(|id| profiles.iter().find(|p| p.id == id).map(|p| p.name.as_str()))
                .unwrap_or_else(|| lang.get("sign.no_profile"));

            egui::ComboBox::from_id_salt("qs_profile_combo")
                .selected_text(selected_label)
                .width(280.0)
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_value(
                            &mut state.sign_selected_profile,
                            None,
                            lang.get("sign.no_profile"),
                        )
                        .clicked()
                    {
                        state.sign_meta = SigningMetadata::default();
                        state.sign_cert_alias.clear();
                    }
                    for p in &profiles {
                        if ui
                            .selectable_value(
                                &mut state.sign_selected_profile,
                                Some(p.id.clone()),
                                &p.name,
                            )
                            .clicked()
                        {
                            state.sign_meta = p.default_metadata.clone();
                            state.sign_cert_alias = p.cert_alias.clone();
                        }
                    }
                });
        });

        // If no cert set via profile, show direct cert selector
        if state.sign_cert_alias.is_empty() {
            let certs: Vec<_> = state
                .vault
                .certificates()
                .unwrap_or_default()
                .iter()
                .map(|c| c.alias.clone())
                .collect();

            ui.horizontal(|ui| {
                ui.label(RichText::new(lang.get("sign.certificate")).small());
                egui::ComboBox::from_id_salt("qs_cert_combo")
                    .selected_text(if state.sign_cert_alias.is_empty() {
                        lang.get("sign.choose_cert").to_string()
                    } else {
                        state.sign_cert_alias.clone()
                    })
                    .width(280.0)
                    .show_ui(ui, |ui| {
                        for alias in &certs {
                            ui.selectable_value(
                                &mut state.sign_cert_alias,
                                alias.clone(),
                                alias.as_str(),
                            );
                        }
                    });
            });
        }

        ui.add_space(16.0);

        let can_sign =
            !state.sign_files.is_empty() && !state.sign_cert_alias.is_empty();

        ui.horizontal(|ui| {
            if ui
                .button(RichText::new(lang.get("common.no")).color(theme::GRAY))
                .clicked()
            {
                state.close_requested = true;
            }

            ui.add_space(20.0);

            if ui
                .add_enabled(
                    can_sign,
                    egui::Button::new(
                        RichText::new(format!("✓  {}", lang.get("sign.btn_sign")))
                            .strong()
                            .color(theme::GREEN_SOFT),
                    ),
                )
                .clicked()
            {
                let (signed, skipped, errs, paths) =
                    crate::ui::sign_panel::perform_sign(state);
                if errs.is_empty() || signed > 0 {
                    // Only advance to done screen if at least one file was signed
                    state.quick_sign_done = Some((signed, skipped));
                    state.quick_sign_signed_paths = paths;
                }
                if !errs.is_empty() {
                    state.status_msg = Some((errs.join("; "), theme::RED));
                }
            }

            if !can_sign {
                ui.label(
                    RichText::new(lang.get("sign.need_files_cert"))
                        .small()
                        .weak(),
                );
            }
        });
    });
}

fn show_done(ui: &mut Ui, state: &mut AppState, signed: usize, skipped: usize) {
    let lang = state.lang.clone();

    ui.add_space(12.0);

    // Success headline
    ui.label(
        RichText::new(format!(
            "✅  {} {} {}",
            lang.get("sign.signed_ok_prefix"),
            signed,
            lang.get("sign.signed_ok_suffix")
        ))
        .size(18.0)
        .strong()
        .color(theme::GREEN_SOFT),
    );

    if skipped > 0 {
        ui.add_space(2.0);
        ui.label(
            RichText::new(format!("{} {}", skipped, lang.get("sign.skipped")))
                .color(theme::GRAY)
                .small(),
        );
    }

    ui.add_space(12.0);

    // Output location
    let out_label = match &state.sign_output_dir {
        None => lang.get("sign.output_same_dir").to_string(),
        Some(d) => d.to_string_lossy().into_owned(),
    };
    ui.horizontal(|ui| {
        ui.label(RichText::new("📁").small());
        ui.label(RichText::new(lang.get("sign.output_dir_label")).weak().small());
        ui.label(RichText::new(&out_label).small().monospace());
    });

    // Per-file results
    ui.add_space(6.0);
    let pairs = state.quick_sign_signed_paths.clone();
    egui::ScrollArea::vertical()
        .id_salt("qs_done_scroll")
        .max_height(140.0)
        .show(ui, |ui| {
            for (src, sig) in &pairs {
                ui.horizontal(|ui| {
                    if src == sig {
                        // Authenticode: signature embedded in the file itself
                        ui.label(RichText::new("✏").small());
                        ui.label(
                            RichText::new(format!("{} [Authenticode]", sig.to_string_lossy()))
                                .small()
                                .monospace()
                                .color(theme::GREEN_SOFT),
                        );
                    } else {
                        // JSON sidecar
                        ui.label(RichText::new("📄").small());
                        ui.label(
                            RichText::new(sig.to_string_lossy().as_ref())
                                .small()
                                .monospace()
                                .color(theme::GREEN_SOFT),
                        );
                    }
                });
            }
        });

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(8.0);

    // Action buttons
    ui.horizontal(|ui| {
        if ui
            .button(RichText::new(format!("🏠  {}", lang.get("common.open_app"))).strong())
            .clicked()
        {
            state.quick_sign_mode = false;
        }

        ui.add_space(8.0);

        // Open containing folder in Explorer
        if let Some((_, sig)) = state.quick_sign_signed_paths.first() {
            if let Some(dir) = sig.parent() {
                let dir = dir.to_path_buf();
                if ui
                    .button(RichText::new(lang.get("common.open_folder")))
                    .clicked()
                {
                    #[cfg(target_os = "windows")]
                    std::process::Command::new("explorer")
                        .arg(&dir)
                        .spawn()
                        .ok();
                }
            }
        }

        ui.add_space(8.0);

        if ui
            .button(RichText::new(lang.get("common.close")))
            .clicked()
        {
            state.close_requested = true;
        }
    });
}
