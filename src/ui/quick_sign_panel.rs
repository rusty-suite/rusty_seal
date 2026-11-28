use egui::{RichText, Ui};
use crate::app::AppState;
use crate::ui::theme;
use crate::vault::types::SigningMetadata;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    // Handle background sign result (QuickSign context only)
    if matches!(state.bg_sign_result.as_ref(), Some((crate::app::BgSignContext::QuickSign, _))) {
        let (_, result) = state.bg_sign_result.take().unwrap();
        if result.ok_count > 0 || result.skipped > 0 {
            state.quick_sign_done = Some((result.ok_count, result.skipped));
            state.quick_sign_signed_paths = result.pairs;
        }
        if !result.errors.is_empty() {
            state.quick_sign_errors = result.errors;
        }
    }

    // Handle background cert gen result (QuickSignInline context only)
    if matches!(state.bg_cert_result.as_ref(), Some((crate::app::BgCertContext::QuickSignInline, _))) {
        let (_, result) = state.bg_cert_result.take().unwrap();
        match result {
            Ok(entry) => {
                let alias = entry.alias.clone();
                match state.vault.add_certificate(entry) {
                    Ok(()) => {
                        let profile_id = state.sign_selected_profile.clone();
                        state.sign_cert_alias = alias.clone();
                        state.sign_profile_before_compat_change = None;
                        state.quick_sign_errors.clear();
                        state.quick_sign_show_create_cert = false;
                        state.new_cert = crate::app::NewCertForm::default();
                        state.status_msg = Some((lang.get("cert.created_ok").to_string(), theme::GREEN));
                        if let Some(pid) = profile_id {
                            state.quick_sign_offer_add_cert_to_profile = Some((alias, pid));
                        }
                    }
                    Err(e) => state.status_msg = Some((e.localized(&state.lang), theme::RED)),
                }
            }
            Err(e) => state.status_msg = Some((e.localized(&state.lang), theme::RED)),
        }
    }

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
                        ui.label(rusty_ui::icons::rich(rusty_ui::icons::FILE, 14.0).color(rusty_ui::tokens::TEXT_SECONDARY));
                        ui.label(RichText::new(name.as_ref()).small().strong());
                        // Dossier coupé avec « … » s'il est trop long, complet en infobulle (charte, 05).
                        ui.add(egui::Label::new(RichText::new(&dir).small().weak()).truncate()).on_hover_text(&dir);
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
                        state.status_msg = Some((e.localized(&state.lang), theme::RED));
                    }
                }
            }
        });
    });
}

fn show_profile_step(ui: &mut Ui, state: &mut AppState) {
    if state.quick_sign_show_create_cert {
        ui.group(|ui| {
            show_inline_cert_create(ui, state);
        });
        return;
    }

    let lang = state.lang.clone();

    // Offer to add a newly-created cert to the active profile's compatible list
    if let Some((cert_alias, profile_id)) = state.quick_sign_offer_add_cert_to_profile.clone() {
        let profile_name = state.vault.profiles().unwrap_or_default()
            .iter()
            .find(|p| p.id == profile_id)
            .map(|p| p.name.clone());

        if let Some(pname) = profile_name {
            ui.group(|ui| {
                egui::Frame::new()
                    .fill(rusty_ui::tokens::SUCCESS_BG)
                    .inner_margin(egui::Margin::same(8))
                    .corner_radius(rusty_ui::theme::radius(rusty_ui::tokens::RADIUS_LG))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(format!("💡  {}",
                                lang.get("sign.compat_add_to_profile")
                                    .replace("{cert}", &cert_alias)
                                    .replace("{profile}", &pname)
                            ))
                            .small()
                            .color(theme::GREEN_SOFT),
                        );
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.button(RichText::new(lang.get("sign.compat_add_yes")).strong()).clicked() {
                                let pid = profile_id.clone();
                                let calias = cert_alias.clone();
                                // Clone the profile out before the mutable add_profile call
                                let existing: Option<crate::vault::types::Profile> = state.vault.profiles()
                                    .unwrap_or_default()
                                    .into_iter()
                                    .find(|p| p.id == pid)
                                    .cloned();
                                if let Some(mut p) = existing {
                                    p.cert_aliases.push(calias);
                                    state.vault.add_profile(p).ok();
                                }
                                state.quick_sign_offer_add_cert_to_profile = None;
                            }
                            ui.add_space(6.0);
                            if ui.button(lang.get("sign.compat_add_later")).clicked() {
                                state.quick_sign_offer_add_cert_to_profile = None;
                            }
                        });
                    });
            });
            ui.add_space(6.0);
        } else {
            // Profile no longer exists
            state.quick_sign_offer_add_cert_to_profile = None;
        }
    }

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

        // Pre-compute per-profile compatibility badges (outside the ComboBox closure to avoid borrow conflicts)
        let has_ps1 = state.sign_files.iter().any(|p| crate::signing::authenticode::is_authenticode_target(p));
        let profile_labels: Vec<String> = profiles.iter().map(|p| {
            if !has_ps1 {
                return p.name.clone();
            }
            let primary_ok = state.vault.get_cert(&p.cert_alias).ok()
                .map(|c| c.algorithm != crate::vault::types::KeyAlgorithm::Ed25519)
                .unwrap_or(true);
            if primary_ok {
                format!("✓ {}", p.name)
            } else {
                let has_compat_alt = p.cert_aliases.iter().any(|a| {
                    state.vault.get_cert(a).ok()
                        .map(|c| c.algorithm != crate::vault::types::KeyAlgorithm::Ed25519)
                        .unwrap_or(false)
                });
                if has_compat_alt {
                    format!("✓ {}", p.name)
                } else {
                    format!("⚠ {}", p.name)
                }
            }
        }).collect();

        ui.horizontal(|ui| {
            ui.label(RichText::new(lang.get("sign.profile")).small());

            let selected_label = state
                .sign_selected_profile
                .as_deref()
                .and_then(|id| {
                    profiles.iter().position(|p| p.id == id)
                        .map(|i| profile_labels[i].as_str())
                })
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
                        state.sign_profile_before_compat_change = None;
                    }
                    for (p, label) in profiles.iter().zip(profile_labels.iter()) {
                        if ui
                            .selectable_value(
                                &mut state.sign_selected_profile,
                                Some(p.id.clone()),
                                label.as_str(),
                            )
                            .clicked()
                        {
                            state.sign_meta = p.default_metadata.clone();
                            state.sign_cert_alias = p.cert_alias.clone();
                            state.quick_sign_errors.clear();
                            state.sign_profile_before_compat_change = None;
                            let alt_aliases = p.cert_aliases.clone();
                            try_auto_switch_cert(state, &alt_aliases);
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
                    .selected_text(lang.get("sign.choose_cert").to_string())
                    .width(280.0)
                    .show_ui(ui, |ui| {
                        for alias in &certs {
                            if ui.selectable_value(
                                &mut state.sign_cert_alias,
                                alias.clone(),
                                alias.as_str(),
                            ).clicked() {
                                state.quick_sign_errors.clear();
                            }
                        }
                    });
            });
        }

        // ── Compatibility check (shown immediately on selection) ─────────
        show_compat_block(ui, state, &lang, true);

        ui.add_space(8.0);

        // Copy mode toggle
        ui.horizontal(|ui| {
            ui.selectable_value(&mut state.sign_create_copy, false, lang.get("sign.output_mode_inplace"));
            ui.selectable_value(&mut state.sign_create_copy, true,
                format!("{} ({}…)", lang.get("sign.output_mode_copy"), lang.get("sign.signed_copy_prefix")));
        });

        ui.add_space(8.0);

        let can_sign =
            !state.sign_files.is_empty() && !state.sign_cert_alias.is_empty();

        let signing_in_progress = state.bg_sign.as_ref()
            .map(|b| b.context == crate::app::BgSignContext::QuickSign)
            .unwrap_or(false);

        if signing_in_progress {
            let bg = state.bg_sign.as_ref().unwrap();
            let current = bg.progress.load(std::sync::atomic::Ordering::Relaxed);
            let total = bg.total;
            let frac = if total > 0 { current as f32 / total as f32 } else { 0.0 };
            ui.add(egui::ProgressBar::new(frac).animate(true).desired_width(300.0)
                .text(format!("{} / {}", current, total)));
        } else {
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
                    state.quick_sign_errors.clear();
                    crate::ui::sign_panel::start_sign_bg(state, crate::app::BgSignContext::QuickSign);
                }

                if !can_sign {
                    ui.label(
                        RichText::new(lang.get("sign.need_files_cert"))
                            .small()
                            .weak(),
                    );
                }
            });
        }

        // Persistent error display — stays visible until the user changes selection
        if !state.quick_sign_errors.is_empty() {
            ui.add_space(8.0);
            egui::Frame::new()
                .fill(rusty_ui::tokens::DANGER_BG)
                .inner_margin(egui::Margin::same(8))
                .corner_radius(rusty_ui::theme::radius(rusty_ui::tokens::RADIUS_LG))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(lang.get("sign.failed_title"))
                            .strong()
                            .color(theme::RED),
                    );
                    for err in &state.quick_sign_errors.clone() {
                        ui.label(RichText::new(format!("• {}", err)).small().color(theme::RED));
                    }
                });
        }
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

    // Per-file results — grouped by signature type
    ui.add_space(6.0);
    let pairs = state.quick_sign_signed_paths.clone();
    let authenticode: Vec<_> = pairs.iter().filter(|(s, d)| s == d).collect();
    let sidecar: Vec<_> = pairs.iter().filter(|(s, d)| s != d).collect();

    egui::ScrollArea::vertical()
        .id_salt("qs_done_scroll")
        .max_height(160.0)
        .show(ui, |ui| {
            if !authenticode.is_empty() {
                ui.label(RichText::new(lang.get("sign.done_authenticode")).small().weak().strong());
                for (_, sig) in &authenticode {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("✏").small());
                        ui.label(
                            RichText::new(sig.file_name().unwrap_or_default().to_string_lossy().as_ref())
                                .small()
                                .monospace()
                                .color(theme::GREEN_SOFT),
                        );
                    });
                }
                if !sidecar.is_empty() {
                    ui.add_space(4.0);
                }
            }
            if !sidecar.is_empty() {
                ui.label(RichText::new(lang.get("sign.done_sidecar")).small().weak().strong());
                for (_, sig) in &sidecar {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("📄").small());
                        ui.label(
                            RichText::new(sig.file_name().unwrap_or_default().to_string_lossy().as_ref())
                                .small()
                                .monospace()
                                .color(theme::GREEN_SOFT),
                        );
                    });
                }
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
                    // Opens the folder in the system file manager.
                    #[cfg(target_os = "windows")]
                    let program = "explorer";
                    #[cfg(target_os = "macos")]
                    let program = "open";
                    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
                    let program = "xdg-open";
                    std::process::Command::new(program).arg(&dir).spawn().ok();
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

/// Detects cert/file incompatibility and shows an actionable warning block.
/// Also handles the "create similar profile" offer when a compatible cert is chosen.
/// `in_quick_sign`: if true, "create cert" button opens the main app on Certs tab.
pub fn show_compat_block(ui: &mut Ui, state: &mut AppState, lang: &crate::i18n::Lang, in_quick_sign: bool) {
    use crate::signing::authenticode::is_authenticode_target;
    use crate::vault::types::KeyAlgorithm;

    let has_ps1 = state.sign_files.iter().any(|p| is_authenticode_target(p));
    if !has_ps1 || state.sign_cert_alias.is_empty() {
        return;
    }

    let algo = state.vault.get_cert(&state.sign_cert_alias)
        .ok()
        .map(|c| c.algorithm.clone());

    let is_ed25519 = matches!(algo, Some(KeyAlgorithm::Ed25519));

    if is_ed25519 {
        // Remember which profile was active when incompatibility appeared
        if state.sign_profile_before_compat_change.is_none() {
            state.sign_profile_before_compat_change = Some(
                state.sign_selected_profile.clone().unwrap_or_else(|| "__none__".into())
            );
        }

        ui.add_space(6.0);
        egui::Frame::new()
            .fill(rusty_ui::tokens::WARNING_BG)
            .inner_margin(egui::Margin::same(8))
            .corner_radius(rusty_ui::theme::radius(rusty_ui::tokens::RADIUS_LG))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!("⚠  {}", lang.get("sign.compat_title")))
                        .strong()
                        .color(theme::YELLOW),
                );
                ui.label(
                    RichText::new(lang.get("sign.compat_ps1_ed25519_warn"))
                        .small()
                        .color(theme::YELLOW),
                );

                // Live list of compatible certs — updates as soon as a new cert is created
                let compat_certs: Vec<String> = state.vault.certificates()
                    .unwrap_or_default()
                    .iter()
                    .filter(|c| c.algorithm != KeyAlgorithm::Ed25519)
                    .map(|c| c.alias.clone())
                    .collect();
                if !compat_certs.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new(lang.get("sign.compat_use_existing")).small().weak());
                    ui.horizontal_wrapped(|ui| {
                        for alias in &compat_certs {
                            if ui.button(RichText::new(alias).small()).clicked() {
                                state.sign_cert_alias = alias.clone();
                                state.sign_profile_before_compat_change = None;
                                state.quick_sign_errors.clear();
                                state.quick_sign_show_create_cert = false;
                            }
                        }
                    });
                }

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new(lang.get("sign.compat_action_create_cert")).strong()).clicked() {
                        if in_quick_sign {
                            state.new_cert = crate::app::NewCertForm {
                                alias: "RSA Code Signing".into(),
                                algorithm: crate::vault::types::KeyAlgorithm::Rsa2048,
                                common_name: "Code Signing".into(),
                                org: String::new(),
                                country: "US".into(),
                                email: String::new(),
                                valid_days: 365,
                            };
                            state.quick_sign_show_create_cert = true;
                        } else {
                            state.new_cert = crate::app::NewCertForm {
                                alias: "RSA Code Signing".into(),
                                algorithm: crate::vault::types::KeyAlgorithm::Rsa2048,
                                common_name: "Code Signing".into(),
                                org: String::new(),
                                country: "US".into(),
                                email: String::new(),
                                valid_days: 365,
                            };
                            state.pending_tab_switch = Some(crate::app::Tab::Certificates);
                        }
                    }
                    ui.add_space(6.0);
                    if ui.button(lang.get("sign.compat_action_choose_cert")).clicked() {
                        state.sign_cert_alias.clear();
                        state.sign_selected_profile = None;
                        state.quick_sign_errors.clear();
                        state.quick_sign_show_create_cert = false;
                    }
                });
            });
    } else {
        // Compatible cert selected — offer to duplicate the previous profile if one was remembered
        if let Some(prev_id) = state.sign_profile_before_compat_change.clone() {
            if prev_id != "__none__" {
                let profile_name = state.vault.profiles().unwrap_or_default()
                    .iter()
                    .find(|p| p.id == prev_id)
                    .map(|p| p.name.clone());

                if let Some(name) = profile_name {
                    let new_cert = state.sign_cert_alias.clone();
                    ui.add_space(6.0);
                    egui::Frame::new()
                        .fill(rusty_ui::tokens::SUCCESS_BG)
                        .inner_margin(egui::Margin::same(8))
                        .corner_radius(rusty_ui::theme::radius(rusty_ui::tokens::RADIUS_LG))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "💡  {}",
                                    lang.get("sign.compat_profile_offer")
                                        .replace("{name}", &name)
                                        .replace("{cert}", &new_cert)
                                ))
                                .small()
                                .color(theme::GREEN_SOFT),
                            );
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui.button(RichText::new(lang.get("sign.compat_profile_create")).strong()).clicked() {
                                    create_profile_copy(state, &prev_id, &new_cert);
                                }
                                ui.add_space(6.0);
                                if ui.button(lang.get("sign.compat_profile_skip")).clicked() {
                                    state.sign_profile_before_compat_change = None;
                                }
                            });
                        });
                } else {
                    // Profile no longer exists — clear the tracker
                    state.sign_profile_before_compat_change = None;
                }
            } else {
                state.sign_profile_before_compat_change = None;
            }
        }
    }
}

/// When PS1 files are selected and the primary cert is Ed25519, try to auto-switch
/// to the first compatible (non-Ed25519) cert in the provided alt list.
pub fn try_auto_switch_cert(state: &mut AppState, alt_aliases: &[String]) {
    if alt_aliases.is_empty() {
        return;
    }
    let has_ps1 = state.sign_files.iter()
        .any(|f| crate::signing::authenticode::is_authenticode_target(f));
    if !has_ps1 {
        return;
    }
    let primary_is_ed25519 = state.vault.get_cert(&state.sign_cert_alias).ok()
        .map(|c| c.algorithm == crate::vault::types::KeyAlgorithm::Ed25519)
        .unwrap_or(false);
    if !primary_is_ed25519 {
        return;
    }
    for alt in alt_aliases {
        let is_compat = state.vault.get_cert(alt).ok()
            .map(|c| c.algorithm != crate::vault::types::KeyAlgorithm::Ed25519)
            .unwrap_or(false);
        if is_compat {
            state.sign_cert_alias = alt.clone();
            return;
        }
    }
}

fn show_inline_cert_create(ui: &mut Ui, state: &mut AppState) {
    use crate::cert::CertBuilder;
    use crate::vault::types::KeyAlgorithm;
    let lang = state.lang.clone();

    let cert_gen_in_progress = state.bg_cert_gen.as_ref()
        .map(|b| b.context == crate::app::BgCertContext::QuickSignInline)
        .unwrap_or(false);

    ui.label(
        RichText::new(lang.get("sign.compat_inline_title"))
            .strong()
            .color(theme::GREEN_SOFT),
    );
    ui.add_space(8.0);

    let algo_options = [
        KeyAlgorithm::Rsa2048,
        KeyAlgorithm::Rsa4096,
        KeyAlgorithm::EcdsaP256,
        KeyAlgorithm::EcdsaP384,
    ];

    if state.new_cert.algorithm == KeyAlgorithm::Ed25519 {
        state.new_cert.algorithm = KeyAlgorithm::Rsa2048;
    }

    egui::Grid::new("qs_inline_cert_grid")
        .num_columns(2)
        .spacing([8.0, 4.0])
        .show(ui, |ui| {
            ui.label(RichText::new(lang.get("cert.alias")).small());
            ui.add(
                egui::TextEdit::singleline(&mut state.new_cert.alias)
                    .desired_width(220.0)
                    .hint_text("RSA Code Signing"),
            );
            ui.end_row();

            ui.label(RichText::new(lang.get("cert.cn")).small());
            ui.add(
                egui::TextEdit::singleline(&mut state.new_cert.common_name)
                    .desired_width(220.0)
                    .hint_text("Code Signing"),
            );
            ui.end_row();

            ui.label(RichText::new(lang.get("cert.algorithm")).small());
            egui::ComboBox::from_id_salt("qs_inline_algo")
                .selected_text(state.new_cert.algorithm.to_string())
                .width(140.0)
                .show_ui(ui, |ui| {
                    for a in &algo_options {
                        ui.selectable_value(&mut state.new_cert.algorithm, a.clone(), a.to_string());
                    }
                });
            ui.end_row();

            ui.label(RichText::new(lang.get("cert.valid_days")).small());
            ui.add(egui::DragValue::new(&mut state.new_cert.valid_days).range(1..=3650));
            ui.end_row();
        });

    ui.add_space(8.0);

    if cert_gen_in_progress {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new(state.bg_cert_gen.as_ref().map(|b| b.label.as_str()).unwrap_or("")).small().weak());
        });
    } else {
        ui.horizontal(|ui| {
            let can_create = !state.new_cert.alias.is_empty() && !state.new_cert.common_name.is_empty();
            if ui.add_enabled(
                can_create,
                egui::Button::new(
                    RichText::new(lang.get("sign.compat_inline_create"))
                        .strong()
                        .color(theme::GREEN_SOFT),
                ),
            ).clicked() {
                let builder = CertBuilder {
                    alias: state.new_cert.alias.clone(),
                    algorithm: state.new_cert.algorithm.clone(),
                    common_name: state.new_cert.common_name.clone(),
                    org: state.new_cert.org.clone(),
                    country: state.new_cert.country.clone(),
                    email: state.new_cert.email.clone(),
                    valid_days: state.new_cert.valid_days,
                };
                let is_rsa = matches!(state.new_cert.algorithm, KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096);
                if is_rsa {
                    let (tx, rx) = std::sync::mpsc::channel();
                    let label = format!("{} {}...", lang.get("cert.btn_create"), state.new_cert.algorithm);
                    std::thread::spawn(move || { tx.send(builder.build()).ok(); });
                    state.bg_cert_gen = Some(crate::app::BgCertGen {
                        rx, label, context: crate::app::BgCertContext::QuickSignInline,
                    });
                } else {
                    match builder.build() {
                        Ok(entry) => {
                            let alias = entry.alias.clone();
                            match state.vault.add_certificate(entry) {
                                Ok(()) => {
                                    let profile_id = state.sign_selected_profile.clone();
                                    state.sign_cert_alias = alias.clone();
                                    state.sign_profile_before_compat_change = None;
                                    state.quick_sign_errors.clear();
                                    state.quick_sign_show_create_cert = false;
                                    state.new_cert = crate::app::NewCertForm::default();
                                    state.status_msg = Some((lang.get("cert.created_ok").to_string(), theme::GREEN));
                                    if let Some(pid) = profile_id {
                                        state.quick_sign_offer_add_cert_to_profile = Some((alias, pid));
                                    }
                                }
                                Err(e) => state.status_msg = Some((e.localized(&state.lang), theme::RED)),
                            }
                        }
                        Err(e) => state.status_msg = Some((e.localized(&state.lang), theme::RED)),
                    }
                }
            }
            ui.add_space(8.0);
            if ui.button(lang.get("sign.compat_inline_cancel")).clicked() {
                state.quick_sign_show_create_cert = false;
                state.new_cert = crate::app::NewCertForm::default();
            }
        });
    }
}

fn create_profile_copy(state: &mut AppState, source_id: &str, new_cert_alias: &str) {
    let old = state.vault.profiles().unwrap_or_default()
        .iter()
        .find(|p| p.id == source_id)
        .cloned();

    if let Some(old_profile) = old {
        let new_id = uuid::Uuid::new_v4().to_string();
        let new_profile = crate::vault::types::Profile {
            id: new_id.clone(),
            name: format!("{} ({})", old_profile.name, new_cert_alias),
            cert_alias: new_cert_alias.to_string(),
            cert_aliases: vec![],
            default_metadata: old_profile.default_metadata.clone(),
        };
        if state.vault.add_profile(new_profile).is_ok() {
            state.sign_selected_profile = Some(new_id);
            state.sign_cert_alias = new_cert_alias.to_string();
            state.sign_profile_before_compat_change = None;
            state.quick_sign_errors.clear();
            state.status_msg = Some((
                state.lang.get("sign.compat_profile_created").to_string(),
                theme::GREEN,
            ));
        }
    }
}
