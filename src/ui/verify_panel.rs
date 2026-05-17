use egui::{RichText, Ui};
use std::path::PathBuf;

use crate::app::AppState;
use crate::signing::{verify_signature, VerifyResult};
use crate::ui::theme;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.heading(RichText::new(lang.get("verify.title")).size(18.0).strong());
    ui.separator();
    ui.add_space(4.0);

    egui::Grid::new("verify_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        ui.label(lang.get("verify.binary"));
        ui.horizontal(|ui| {
            let label = state.verify_binary.as_ref()
                .map(|p: &PathBuf| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
                .unwrap_or_else(|| lang.get("verify.none").to_string());
            ui.label(RichText::new(&label).monospace().small());
            if ui.button("📁").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    state.verify_binary = Some(p.clone());
                    let sig_candidate = crate::signing::sig_path_for(&p);
                    if sig_candidate.exists() {
                        state.verify_sig = Some(sig_candidate);
                    }
                }
            }
        });
        ui.end_row();

        ui.label(lang.get("verify.sig_file"));
        ui.horizontal(|ui| {
            let label = state.verify_sig.as_ref()
                .map(|p: &PathBuf| p.file_name().unwrap_or_default().to_string_lossy().into_owned())
                .unwrap_or_else(|| lang.get("verify.none").to_string());
            ui.label(RichText::new(&label).monospace().small());
            if ui.button("📁").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("Signature", &["sig"])
                    .pick_file()
                {
                    state.verify_sig = Some(p);
                }
            }
        });
        ui.end_row();
    });

    ui.add_space(8.0);

    let can_verify = state.verify_binary.is_some() && state.verify_sig.is_some();
    if ui.add_enabled(can_verify, egui::Button::new(RichText::new(lang.get("verify.btn_verify")).strong())).clicked() {
        do_verify(state);
    }

    ui.add_space(8.0);

    if state.verify_result.is_some() {
        let result = state.verify_result.take().unwrap();
        show_verify_result(ui, state, &result);
        state.verify_result = Some(result);
    }
}

fn do_verify(state: &mut AppState) {
    let lang = state.lang.clone();
    let Some(binary) = state.verify_binary.clone() else { return };
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
            state.status_msg = Some((e.to_string(), theme::RED));
        }
    }
}

fn show_verify_result(ui: &mut Ui, state: &mut AppState, result: &VerifyResult) {
    let lang = state.lang.clone();

    match result {
        VerifyResult::Valid(sig) => {
            ui.group(|ui| {
                ui.label(RichText::new(format!("✓ {}", lang.get("verify.valid"))).color(theme::GREEN).strong().size(16.0));
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

                ui.add_space(4.0);
                ui.label(RichText::new(lang.get("verify.metadata")).strong());
                ui.add_space(2.0);

                egui::Grid::new("verify_meta_grid").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
                    let meta = &sig.metadata;
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
            });
        }
        VerifyResult::FileMismatch { expected, actual } => {
            ui.group(|ui| {
                ui.label(RichText::new(format!("✗ {}", lang.get("verify.file_mismatch"))).color(theme::RED).strong().size(16.0));
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
                ui.label(RichText::new(format!("✗ {}", lang.get("verify.invalid_sig"))).color(theme::RED).strong().size(16.0));
                ui.add_space(4.0);
                ui.label(RichText::new(msg).small().color(theme::RED));
            });
        }
    }
}
