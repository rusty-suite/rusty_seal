use egui::{RichText, Ui};
use crate::app::AppState;
use crate::audit::AuditAction;
use crate::ui::theme;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.heading(RichText::new(lang.get("audit.title")).size(18.0).strong());
    ui.separator();
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label(RichText::new(lang.get("audit.filter")).weak());
        ui.add(egui::TextEdit::singleline(&mut state.audit_filter).desired_width(180.0));
        if ui.button(lang.get("audit.export_json")).clicked() {
            if let Some(dest) = rfd::FileDialog::new()
                .set_file_name("audit_log.json")
                .add_filter("JSON", &["json"])
                .save_file()
            {
                let json = state.audit.export_json();
                match std::fs::write(&dest, json) {
                    Ok(()) => state.status_msg = Some((lang.get("audit.exported_ok").to_string(), theme::GREEN)),
                    Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                }
            }
        }
        if ui.button(lang.get("audit.export_csv")).clicked() {
            if let Some(dest) = rfd::FileDialog::new()
                .set_file_name("audit_log.csv")
                .add_filter("CSV", &["csv"])
                .save_file()
            {
                match state.audit.export_csv() {
                    Ok(csv) => match std::fs::write(&dest, csv) {
                        Ok(()) => state.status_msg = Some((lang.get("audit.exported_ok").to_string(), theme::GREEN)),
                        Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                    },
                    Err(e) => state.status_msg = Some((e.to_string(), theme::RED)),
                }
            }
        }
    });

    ui.add_space(8.0);

    let filter = state.audit_filter.to_lowercase();
    let entries: Vec<_> = state.audit.entries().iter()
        .filter(|e| {
            if filter.is_empty() { return true; }
            e.action.to_string().contains(&filter)
                || e.operator.to_lowercase().contains(&filter)
                || e.cert_alias.as_deref().unwrap_or("").to_lowercase().contains(&filter)
                || e.file_name.as_deref().unwrap_or("").to_lowercase().contains(&filter)
                || e.details.as_deref().unwrap_or("").to_lowercase().contains(&filter)
        })
        .cloned()
        .collect();

    ui.label(RichText::new(format!("{} {}", entries.len(), lang.get("audit.entries"))).weak().small());
    ui.add_space(4.0);

    egui::ScrollArea::vertical().id_salt("audit_scroll").show(ui, |ui| {
        egui::Grid::new("audit_grid")
            .num_columns(6)
            .striped(true)
            .spacing([8.0, 2.0])
            .show(ui, |ui| {
                // Header
                ui.label(RichText::new(lang.get("audit.col_time")).strong().small());
                ui.label(RichText::new(lang.get("audit.col_action")).strong().small());
                ui.label(RichText::new(lang.get("audit.col_file")).strong().small());
                ui.label(RichText::new(lang.get("audit.col_cert")).strong().small());
                ui.label(RichText::new(lang.get("audit.col_result")).strong().small());
                ui.label(RichText::new(lang.get("audit.col_integrity")).strong().small());
                ui.end_row();

                for entry in entries.iter().rev() {
                    let time = entry.timestamp.format("%m-%d %H:%M:%S").to_string();
                    ui.label(RichText::new(&time).monospace().small());
                    ui.label(RichText::new(entry.action.to_string()).small());
                    ui.label(RichText::new(entry.file_name.as_deref().unwrap_or("—")).small());
                    ui.label(RichText::new(entry.cert_alias.as_deref().unwrap_or("—")).small());

                    if entry.success {
                        ui.label(RichText::new("✓").color(theme::GREEN).small());
                    } else {
                        ui.label(RichText::new("✗").color(theme::RED).small());
                    }

                    if entry.verify_integrity() {
                        ui.label(RichText::new("ok").color(theme::GREEN).small());
                    } else {
                        ui.label(RichText::new("TAMPERED").color(theme::RED).strong().small());
                    }

                    ui.end_row();
                }
            });
    });
}
