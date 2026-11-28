use egui::{RichText, Ui};
use crate::app::AppState;
#[cfg(target_os = "windows")] // couleurs du menu contextuel, propre à Windows
use crate::ui::theme;

pub fn show(ui: &mut Ui, state: &mut AppState) {
    let lang = state.lang.clone();

    ui.heading(RichText::new(lang.get("settings.title")).size(18.0).strong());
    ui.separator();
    ui.add_space(8.0);

    // ── Sign output ─────────────────────────────────────────────────────────
    ui.group(|ui| {
        ui.label(RichText::new(lang.get("settings.sign_output")).strong());
        ui.add_space(4.0);

        ui.label(RichText::new(lang.get("settings.sign_output_mode")).weak().small());
        ui.horizontal(|ui| {
            let same = state.sign_output_dir.is_none();
            if ui.radio(same, lang.get("sign.output_same_dir")).clicked() {
                state.sign_output_dir = None;
            }
            if ui.radio(!same, lang.get("sign.output_custom_dir")).clicked() {
                if state.sign_output_dir.is_none() {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        state.sign_output_dir = Some(d);
                    }
                }
            }
        });

        if let Some(ref dir) = state.sign_output_dir.clone() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(dir.to_string_lossy().to_string()).small().monospace());
                if ui.small_button("📁").on_hover_text(lang.get("sign.output_pick")).clicked() {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        state.sign_output_dir = Some(d);
                    }
                }
                if ui.small_button("✗").clicked() {
                    state.sign_output_dir = None;
                }
            });
        }

        ui.add_space(4.0);
        ui.label(RichText::new(lang.get("settings.sign_overwrite")).weak().small());
        ui.horizontal(|ui| {
            if ui.radio(state.sign_overwrite_sig, lang.get("sign.overwrite_sig")).clicked() {
                state.sign_overwrite_sig = true;
            }
            if ui.radio(!state.sign_overwrite_sig, lang.get("sign.skip_existing")).clicked() {
                state.sign_overwrite_sig = false;
            }
        });
    });

    ui.add_space(8.0);

    // ── Windows context menu ────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    {
        ui.group(|ui| {
            ui.label(RichText::new(lang.get("settings.context_menu")).strong());
            ui.add_space(4.0);
            ui.label(RichText::new(lang.get("settings.context_menu_note")).weak().small());
            ui.add_space(6.0);

            let registered = is_context_menu_registered();
            let status_text = if registered {
                lang.get("settings.context_menu_registered")
            } else {
                lang.get("settings.context_menu_not_registered")
            };
            let status_color = if registered { theme::GREEN } else { theme::GRAY };

            ui.horizontal(|ui| {
                ui.label(RichText::new(lang.get("settings.context_menu_status")).weak());
                ui.label(RichText::new(status_text).color(status_color).strong());
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(lang.get("settings.context_menu_register")).clicked() {
                    if let Ok(exe) = std::env::current_exe() {
                        register_context_menu(&exe, lang.get("settings.context_menu_label"));
                        state.status_msg = Some((
                            lang.get("settings.context_menu_registered").to_string(),
                            theme::GREEN,
                        ));
                    }
                }
                if registered && ui.button(
                    RichText::new(lang.get("settings.context_menu_unregister")).color(theme::YELLOW)
                ).clicked() {
                    unregister_context_menu();
                    state.status_msg = Some((
                        lang.get("settings.context_menu_not_registered").to_string(),
                        theme::GRAY,
                    ));
                }
            });
        });
    }
}

#[cfg(target_os = "windows")]
fn is_context_menu_registered() -> bool {
    std::process::Command::new("reg")
        .args(["query", r"HKCU\Software\Classes\*\shell\RustySeal"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
/// Adds the Explorer context-menu entry; `label` is in the user language.
fn register_context_menu(exe: &std::path::Path, label: &str) {
    let exe_str = exe.to_string_lossy();
    let cmd = format!("\"{}\" --sign \"%1\"", exe_str);
    std::process::Command::new("reg")
        .args(["add", r"HKCU\Software\Classes\*\shell\RustySeal",
               "/ve", "/d", label, "/f"])
        .output().ok();
    std::process::Command::new("reg")
        .args(["add", r"HKCU\Software\Classes\*\shell\RustySeal",
               "/v", "Icon", "/d", exe_str.as_ref(), "/f"])
        .output().ok();
    std::process::Command::new("reg")
        .args(["add", r"HKCU\Software\Classes\*\shell\RustySeal\command",
               "/ve", "/d", &cmd, "/f"])
        .output().ok();
}

#[cfg(target_os = "windows")]
fn unregister_context_menu() {
    std::process::Command::new("reg")
        .args(["delete", r"HKCU\Software\Classes\*\shell\RustySeal", "/f"])
        .output().ok();
}
