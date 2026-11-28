use egui::{RichText, Ui};
use std::path::PathBuf;

use crate::app::AppState;
use crate::signing::{verify_authenticode, verify_signature, VerifyResult};
use crate::ui::theme;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.heading(RichText::new(lang.get("verify.title")).size(18.0).strong());
    ui.separator();
    ui.add_space(4.0);

    let is_authenticode_file = state.verify_binary.as_ref()
        .map(|p| crate::signing::authenticode::is_authenticode_target(p))
        .unwrap_or(false);

    egui::Grid::new("verify_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(lang.get("verify.binary"));
        ui.horizontal(|ui| {
            let label = state.verify_binary.as_ref()
                .map(|p: &PathBuf| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
                .unwrap_or_else(|| lang.get("verify.none").to_string());
            ui.label(RichText::new(&label).monospace().small());
            if ui.button(rusty_ui::icons::rich(rusty_ui::icons::phosphor::FOLDER_OPEN, 16.0)).clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    // Auto-clear previous result on new file selection
                    state.verify_result = None;
                    let sig_candidate = crate::signing::sig_path_for(&p);
                    if sig_candidate.exists() {
                        state.verify_sig = Some(sig_candidate);
                    } else {
                        state.verify_sig = None;
                    }
                    state.verify_binary = Some(p);
                }
            }
        });
        ui.end_row();

        if !is_authenticode_file {
            ui.label(lang.get("verify.sig_file"));
            ui.horizontal(|ui| {
                let label = state.verify_sig.as_ref()
                    .map(|p: &PathBuf| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
                    .unwrap_or_else(|| lang.get("verify.none").to_string());
                ui.label(RichText::new(&label).monospace().small());
                if ui.button(rusty_ui::icons::rich(rusty_ui::icons::phosphor::FOLDER_OPEN, 16.0)).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Signature", &["sig"])
                        .pick_file()
                    {
                        state.verify_sig = Some(p);
                        state.verify_result = None;
                    }
                }
            });
            ui.end_row();
        } else {
            ui.label("");
            ui.label(RichText::new(lang.get("verify.no_sig_file_needed")).small().weak());
            ui.end_row();
        }
    });

    ui.add_space(8.0);

    let can_verify = state.verify_binary.is_some()
        && (is_authenticode_file || state.verify_sig.is_some());

    if ui.add_enabled(can_verify, egui::Button::new(RichText::new(lang.get("verify.btn_verify")).strong())).clicked() {
        do_verify(state, is_authenticode_file);
    }

    ui.add_space(8.0);

    if state.verify_result.is_some() {
        let result = state.verify_result.take().unwrap();
        show_verify_result(ui, state, &result);
        state.verify_result = Some(result);
    }
}

fn do_verify(state: &mut AppState, is_authenticode: bool) {
    let Some(binary) = state.verify_binary.clone() else { return };

    if is_authenticode {
        match verify_authenticode(&binary) {
            Ok(result) => {
                let is_valid = result.is_valid();
                state.audit.append(crate::audit::AuditEntry::new(
                    crate::audit::AuditAction::Verify,
                    "operator".into(),
                    None,
                    Some(binary.file_name().unwrap_or_default().to_string_lossy().to_string()),
                    None,
                    Some(result.message()),
                    is_valid,
                )).ok();
                state.verify_result = Some(result);
            }
            Err(e) => {
                state.status_msg = Some((e.localized(&state.lang), theme::RED));
            }
        }
        return;
    }

    let Some(sig_path) = state.verify_sig.clone() else { return };

    match verify_signature(&binary, &sig_path) {
        Ok(result) => {
            let is_valid = result.is_valid();
            state.audit.append(crate::audit::AuditEntry::new(
                crate::audit::AuditAction::Verify,
                "operator".into(),
                None,
                Some(binary.file_name().unwrap_or_default().to_string_lossy().to_string()),
                None,
                Some(result.message()),
                is_valid,
            )).ok();
            state.verify_result = Some(result);
        }
        Err(e) => {
            state.status_msg = Some((e.localized(&state.lang), theme::RED));
        }
    }
}

fn show_verify_result(ui: &mut Ui, state: &mut AppState, result: &VerifyResult) {
    let lang = state.lang.clone();

    egui::ScrollArea::vertical()
        .id_salt("verify_result_scroll")
        .max_height(400.0)
        .show(ui, |ui| {
            match result {
                VerifyResult::Valid(sig) => {
                    ui.group(|ui| {
                        ui.label(RichText::new(format!("{}", lang.get("verify.valid"))).color(theme::GREEN).strong().size(16.0));
                        ui.add_space(4.0);

                        egui::Grid::new("verify_detail_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                            ui.label(RichText::new(lang.get("verify.cert_alias")).weak());
                            ui.label(&sig.cert_alias);
                            ui.end_row();

                            ui.label(RichText::new(lang.get("verify.algorithm")).weak());
                            ui.label(&sig.algorithm);
                            ui.end_row();

                            ui.label(RichText::new(lang.get("verify.signed_at")).weak());
                            ui.label(sig.signed_at.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                            ui.end_row();

                            ui.label(RichText::new(lang.get("verify.file_hash")).weak());
                            ui.label(RichText::new(&sig.file_hash).monospace().small());
                            ui.end_row();

                            ui.label(RichText::new(lang.get("verify.cert_fingerprint")).weak());
                            ui.label(RichText::new(&sig.cert_fingerprint).monospace().small());
                            ui.end_row();
                        });

                        let meta = &sig.metadata;
                        let has_meta = !meta.version.is_empty()
                            || !meta.author.is_empty()
                            || !meta.description.is_empty()
                            || !meta.build_date.is_empty()
                            || !meta.source_url.is_empty()
                            || !meta.custom.is_empty();

                        if has_meta {
                            ui.add_space(4.0);
                            ui.label(RichText::new(lang.get("verify.metadata")).strong());
                            ui.add_space(2.0);

                            egui::Grid::new("verify_meta_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                                if !meta.version.is_empty() {
                                    ui.label(RichText::new(lang.get("meta.version")).weak());
                                    ui.label(&meta.version);
                                    ui.end_row();
                                }
                                if !meta.author.is_empty() {
                                    ui.label(RichText::new(lang.get("meta.author")).weak());
                                    ui.label(&meta.author);
                                    ui.end_row();
                                }
                                if !meta.description.is_empty() {
                                    ui.label(RichText::new(lang.get("meta.description")).weak());
                                    ui.label(&meta.description);
                                    ui.end_row();
                                }
                                if !meta.build_date.is_empty() {
                                    ui.label(RichText::new(lang.get("meta.build_date")).weak());
                                    ui.label(&meta.build_date);
                                    ui.end_row();
                                }
                                if !meta.source_url.is_empty() {
                                    ui.label(RichText::new(lang.get("meta.source_url")).weak());
                                    ui.label(&meta.source_url);
                                    ui.end_row();
                                }
                                for (k, v) in &meta.custom {
                                    ui.label(RichText::new(k).weak().monospace());
                                    ui.label(v);
                                    ui.end_row();
                                }
                            });
                        }
                    });
                }

                VerifyResult::AuthenticodeValid { subject, timestamp } => {
                    ui.group(|ui| {
                        ui.label(RichText::new(format!("{}", lang.get("verify.valid"))).color(theme::GREEN).strong().size(16.0));
                        ui.label(RichText::new(lang.get("verify.authenticode_info")).small().weak());
                        ui.add_space(4.0);

                        egui::Grid::new("verify_auth_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                            if !subject.is_empty() {
                                ui.label(RichText::new(lang.get("verify.authenticode_signer")).weak());
                                ui.label(RichText::new(subject).small().monospace());
                                ui.end_row();
                            }
                            if !timestamp.is_empty() {
                                ui.label(RichText::new(lang.get("verify.authenticode_timestamp")).weak());
                                ui.label(RichText::new(timestamp).small().monospace());
                                ui.end_row();
                            }
                        });
                    });
                }

                VerifyResult::AuthenticodeInvalid { status, subject } => {
                    ui.group(|ui| {
                        ui.label(RichText::new(format!("{}", lang.get("verify.invalid_sig"))).color(theme::RED).strong().size(16.0));
                        ui.label(RichText::new(lang.get("verify.authenticode_info")).small().weak());
                        ui.add_space(4.0);

                        egui::Grid::new("verify_auth_invalid_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                            ui.label(RichText::new(lang.get("verify.status_label")).weak());
                            ui.label(RichText::new(status).color(theme::RED).small());
                            ui.end_row();
                            if !subject.is_empty() {
                                ui.label(RichText::new(lang.get("verify.authenticode_signer")).weak());
                                ui.label(RichText::new(subject).small().monospace());
                                ui.end_row();
                            }
                        });
                    });
                }

                VerifyResult::FileMismatch { expected, actual } => {
                    ui.group(|ui| {
                        ui.label(RichText::new(format!("{}", lang.get("verify.file_mismatch"))).color(theme::RED).strong().size(16.0));
                        ui.add_space(4.0);
                        egui::Grid::new("mismatch_grid").num_columns(2).show(ui, |ui| {
                            ui.label(RichText::new(lang.get("verify.expected")).weak());
                            ui.label(RichText::new(expected).monospace().small());
                            ui.end_row();
                            ui.label(RichText::new(lang.get("verify.actual")).weak());
                            ui.label(RichText::new(actual).monospace().small());
                            ui.end_row();
                        });
                    });
                }

                VerifyResult::InvalidSignature(msg) => {
                    ui.group(|ui| {
                        ui.label(RichText::new(format!("{}", lang.get("verify.invalid_sig"))).color(theme::RED).strong().size(16.0));
                        ui.add_space(4.0);
                        ui.label(RichText::new(msg).small().color(theme::RED));
                    });
                }
            }
        });
}
