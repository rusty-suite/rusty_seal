use std::path::PathBuf;

pub const APP_NAME: &str = "rusty-seal";
pub const SUITE_NAME: &str = "rusty-suite";

pub fn resolve_workdir() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let suite = PathBuf::from(&appdata).join(SUITE_NAME);
        if suite.exists() {
            let app_dir = suite.join(APP_NAME);
            let _ = std::fs::create_dir_all(&app_dir);
            return app_dir;
        }
    }

    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    let app_dir = base.join(APP_NAME);
    let _ = std::fs::create_dir_all(&app_dir);
    app_dir
}

pub fn lang_dir(workdir: &PathBuf) -> PathBuf {
    workdir.join("lang")
}
