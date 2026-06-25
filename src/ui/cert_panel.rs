use egui::{RichText, Ui};
use crate::app::AppState;
use crate::cert::{CertBuilder, import_pem, import_der};
use crate::vault::types::{CertEntry, CertHistory, KeyAlgorithm};
use crate::ui::theme;
use chrono::Utc;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    if state.vault.is_locked() {
        ui.label(RichText::new(format!("🔒 {}", lang.get("common.vault_locked"))).color(theme::YELLOW));
        return;
    }

    ui.heading(RichText::new(lang.get("cert.title")).size(18.0).strong());
    ui.separator();
    ui.add_space(4.0);

    ui.columns(2, |cols| {
        cols[0].group(|ui| {
            show_cert_list(ui, state);
        });
        cols[1].group(|ui| {
            show_cert_actions(ui, state);
        });
    });
}

fn show_cert_list(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();
    ui.label(RichText::new(lang.get("cert.list")).strong());
    ui.add_space(4.0);

    let certs: Vec<_> = state.vault.certificates()
        .unwrap_or_default()
        .into_iter()
        .cloned()
        .collect();

    if certs.is_empty() {
        ui.label(RichText::new(lang.get("cert.none")).weak().italics());
        return;
    }

    let now = Utc::now();

    egui::ScrollArea::vertical().id_salt("cert_list").show(ui, |ui| {
        for cert in &certs {
            let selected = state.selected_cert.as_deref() == Some(cert.alias.as_str());
            let days_left = cert.expires_at
                .map(|e| (e - now).num_days())
                .unwrap_or(9999);
            let exp_color = if days_left < 0 {
                theme::RED
            } else {
                theme::expiry_color(days_left as u64)
            };

            ui.horizontal(|ui| {
                let label = RichText::new(format!("📄 {}", cert.alias))
                    .strong()
                    .color(if selected { theme::GREEN_SOFT } else { egui::Color32::WHITE });

                if ui.selectable_label(selected, label).clicked() {
                    state.selected_cert = Some(cert.alias.clone());
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let exp_label = if days_left < 0 {
                        "EXPIRED".to_string()
                    } else {
                        format!("{}d", days_left)
                    };
                    ui.label(RichText::new(exp_label).small().color(exp_color));
                    ui.label(RichText::new(cert.algorithm.to_string()).small().weak());
                });
            });
        }
    });
}

fn show_cert_actions(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    if let Some(alias) = state.selected_cert.clone() {
        if let Ok(cert) = state.vault.get_cert(&alias).cloned() {
            show_cert_detail(ui, state, &cert);
            return;
        }
    }

    egui::CollapsingHeader::new(RichText::new(lang.get("cert.create_new")).strong())
        .default_open(true)
        .show(ui, |ui| {
            show_create_form(ui, state);
        });

    ui.add_space(8.0);

    egui::CollapsingHeader::new(RichText::new(lang.get("cert.import")).strong())
        .show(ui, |ui| {
            show_import_form(ui, state);
        });
}

fn show_cert_detail(ui: &mut Ui, state: &mut AppState, cert: &CertEntry) {
    let lang = state.lang.clone();
    let now = Utc::now();

    ui.label(RichText::new(format!("📄 {}", cert.alias)).size(16.0).strong());
    ui.add_space(4.0);

    egui::Grid::new("cert_detail_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(RichText::new(lang.get("cert.cn")).weak());
        ui.label(&cert.subject_cn);
        ui.end_row();

        if !cert.subject_email.is_empty() {
            ui.label(RichText::new(lang.get("cert.email")).weak());
            ui.label(&cert.subject_email);
            ui.end_row();
        }

        ui.label(RichText::new(lang.get("cert.algorithm")).weak());
        ui.label(cert.algorithm.to_string());
        ui.end_row();

        ui.label(RichText::new(lang.get("cert.created")).weak());
        ui.label(cert.created_at.format("%Y-%m-%d").to_string());
        ui.end_row();

        if let Some(exp) = cert.expires_at {
            let days = (exp - now).num_days();
            ui.label(RichText::new(lang.get("cert.expires")).weak());
            let exp_col = if days < 0 { theme::RED } else { theme::expiry_color(days as u64) };
            ui.label(RichText::new(exp.format("%Y-%m-%d").to_string()).color(exp_col));
            ui.end_row();
        }

        ui.label(RichText::new(lang.get("cert.fingerprint")).weak());
        ui.label(RichText::new(&cert.fingerprint).small().monospace());
        ui.end_row();

        let has_key = !cert.private_key_pkcs8_der_b64.is_empty();
        ui.label(RichText::new(lang.get("cert.private_key")).weak());
        ui.label(if has_key {
            RichText::new("✓ present").color(theme::GREEN)
        } else {
            RichText::new("✗ not stored").color(theme::GRAY)
        });
        ui.end_row();
    });

    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui.button(lang.get("cert.export_pem")).clicked() {
            if let Some(dest) = rfd::FileDialog::new()
                .set_file_name(format!("{}.crt.pem", cert.alias))
                .add_filter("PEM", &["pem", "crt"])
                .save_file()
            {
                match std::fs::write(&dest, &cert.certificate_pem) {
                    Ok(()) => state.status_msg = Some((lang.get("cert.exported_ok").to_string(), theme::GREEN)),
                    Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                }
            }
        }

        if ui.button(lang.get("cert.export_der")).clicked() {
            if let Ok(der) = crate::cert::export_public_der(cert) {
                if let Some(dest) = rfd::FileDialog::new()
                    .set_file_name(format!("{}.cer", cert.alias))
                    .add_filter("DER", &["cer", "der"])
                    .save_file()
                {
                    match std::fs::write(&dest, &der) {
                        Ok(()) => state.status_msg = Some((lang.get("cert.exported_ok").to_string(), theme::GREEN)),
                        Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                    }
                }
            }
        }
    });

    ui.add_space(4.0);

    if ui.button(RichText::new(lang.get("cert.back")).weak()).clicked() {
        state.selected_cert = None;
    }

    ui.add_space(4.0);

    let alias_clone = cert.alias.clone();
    if ui.button(RichText::new(format!("🗑 {}", lang.get("cert.delete")))
        .color(theme::RED_DANGER))
        .clicked()
    {
        state.confirm_delete_cert = Some(alias_clone);
    }

    if let Some(ref alias_to_del) = state.confirm_delete_cert.clone() {
        egui::Window::new(lang.get("common.confirm"))
            .resizable(false)
            .collapsible(false)
            .show(ui.ctx(), |ui| {
                ui.label(format!("{} '{}'?", lang.get("cert.confirm_delete"), alias_to_del));
                ui.horizontal(|ui| {
                    if ui.button(RichText::new(lang.get("common.yes")).color(theme::RED_DANGER)).clicked() {
                        let _ = state.vault.remove_certificate(alias_to_del);
                        state.selected_cert = None;
                        state.confirm_delete_cert = None;
                        state.audit.append(crate::audit::AuditEntry::new(
                            crate::audit::AuditAction::CertDelete,
                            "operator".into(), None, None,
                            Some(alias_to_del.clone()), None, true,
                        )).ok();
                    }
                    if ui.button(lang.get("common.no")).clicked() {
                        state.confirm_delete_cert = None;
                    }
                });
            });
    }

    if !cert.history.is_empty() {
        ui.add_space(8.0);
        ui.collapsing(lang.get("cert.history"), |ui| {
            for h in &cert.history {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(h.replaced_at.format("%Y-%m-%d").to_string()).small().weak());
                    ui.label(RichText::new(&h.reason).small());
                });
            }
        });
    }
}

fn show_create_form(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    egui::Grid::new("cert_create_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(lang.get("cert.alias"));
        ui.add(egui::TextEdit::singleline(&mut state.new_cert.alias).desired_width(180.0));
        ui.end_row();

        ui.label(lang.get("cert.cn"));
        ui.add(egui::TextEdit::singleline(&mut state.new_cert.common_name).desired_width(180.0));
        ui.end_row();

        ui.label(lang.get("cert.org"));
        ui.add(egui::TextEdit::singleline(&mut state.new_cert.org).desired_width(180.0));
        ui.end_row();

        ui.label(lang.get("cert.country"));
        ui.add(egui::TextEdit::singleline(&mut state.new_cert.country).desired_width(50.0));
        ui.end_row();

        ui.label(lang.get("cert.email"));
        ui.add(egui::TextEdit::singleline(&mut state.new_cert.email)
            .desired_width(180.0)
            .hint_text("user@example.com"));
        ui.end_row();

        ui.label(lang.get("cert.valid_days"));
        ui.add(egui::DragValue::new(&mut state.new_cert.valid_days).range(1..=3650));
        ui.end_row();

        ui.label(lang.get("cert.algorithm"));
        egui::ComboBox::from_id_salt("algo_combo")
            .selected_text(state.new_cert.algorithm.to_string())
            .show_ui(ui, |ui| {
                let algos = [
                    KeyAlgorithm::Ed25519,
                    KeyAlgorithm::EcdsaP256,
                    KeyAlgorithm::EcdsaP384,
                    KeyAlgorithm::Rsa2048,
                    KeyAlgorithm::Rsa4096,
                ];
                for a in algos {
                    ui.selectable_value(&mut state.new_cert.algorithm, a.clone(), a.to_string());
                }
            });
        ui.end_row();
    });

    ui.add_space(4.0);
    if ui.button(lang.get("cert.btn_create")).clicked() {
        if state.new_cert.alias.is_empty() || state.new_cert.common_name.is_empty() {
            state.status_msg = Some((lang.get("cert.fields_required").to_string(), theme::RED));
        } else {
            let builder = CertBuilder {
                alias: state.new_cert.alias.clone(),
                algorithm: state.new_cert.algorithm.clone(),
                common_name: state.new_cert.common_name.clone(),
                org: state.new_cert.org.clone(),
                country: state.new_cert.country.clone(),
                email: state.new_cert.email.clone(),
                valid_days: state.new_cert.valid_days,
            };
            match builder.build() {
                Ok(entry) => {
                    let alias = entry.alias.clone();
                    match state.vault.add_certificate(entry) {
                        Ok(()) => {
                            state.status_msg = Some((lang.get("cert.created_ok").to_string(), theme::GREEN));
                            state.selected_cert = Some(alias.clone());
                            state.new_cert = crate::app::NewCertForm::default();
                            state.audit.append(crate::audit::AuditEntry::new(
                                crate::audit::AuditAction::CertCreate,
                                "operator".into(), None, None, Some(alias), None, true,
                            )).ok();
                        }
                        Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                    }
                }
                Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
            }
        }
    }
}

fn show_import_form(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.horizontal(|ui| {
        ui.label(lang.get("cert.import_alias"));
        ui.add(egui::TextEdit::singleline(&mut state.import_cert_alias).desired_width(180.0));
    });

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        if ui.button(lang.get("cert.import_pem_btn")).clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .add_filter("PEM", &["pem", "crt", "cer"])
                .pick_file()
            {
                let cert_pem = std::fs::read_to_string(&p).unwrap_or_default();
                let alias = if state.import_cert_alias.is_empty() {
                    p.file_stem().unwrap_or_default().to_string_lossy().to_string()
                } else {
                    state.import_cert_alias.clone()
                };
                match import_pem(alias.clone(), &cert_pem, None) {
                    Ok(entry) => {
                        let _ = state.vault.add_certificate(entry);
                        state.status_msg = Some((lang.get("cert.imported_ok").to_string(), theme::GREEN));
                        state.import_cert_alias.clear();
                        state.audit.append(crate::audit::AuditEntry::new(
                            crate::audit::AuditAction::CertImport,
                            "operator".into(), None, None, Some(alias), None, true,
                        )).ok();
                    }
                    Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                }
            }
        }

        if ui.button(lang.get("cert.import_der_btn")).clicked() {
            if let Some(p) = rfd::FileDialog::new()
                .add_filter("DER", &["cer", "der"])
                .pick_file()
            {
                let der_bytes = std::fs::read(&p).unwrap_or_default();
                let alias = if state.import_cert_alias.is_empty() {
                    p.file_stem().unwrap_or_default().to_string_lossy().to_string()
                } else {
                    state.import_cert_alias.clone()
                };
                match import_der(alias.clone(), &der_bytes, None) {
                    Ok(entry) => {
                        let _ = state.vault.add_certificate(entry);
                        state.status_msg = Some((lang.get("cert.imported_ok").to_string(), theme::GREEN));
                        state.import_cert_alias.clear();
                        state.audit.append(crate::audit::AuditEntry::new(
                            crate::audit::AuditAction::CertImport,
                            "operator".into(), None, None, Some(alias), None, true,
                        )).ok();
                    }
                    Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                }
            }
        }
    });

    ui.add_space(4.0);
    ui.label(RichText::new(lang.get("cert.import_note")).small().weak());
}
