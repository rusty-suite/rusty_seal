use std::collections::HashMap;
use std::path::{Path, PathBuf};

const BUNDLED_LANGS: &[(&str, &str)] = &[
    ("EN_en.default.toml", include_str!("../lang/EN_en.default.toml")),
    ("FR_fr.toml",         include_str!("../lang/FR_fr.toml")),
    ("DE_de.toml",         include_str!("../lang/DE_de.toml")),
    ("CH_de.toml",         include_str!("../lang/CH_de.toml")),
    ("CH_fr.toml",         include_str!("../lang/CH_fr.toml")),
    ("IT_it.toml",         include_str!("../lang/IT_it.toml")),
    ("CH_it.toml",         include_str!("../lang/CH_it.toml")),
];

fn ensure_bundled_languages(lang_dir: &Path) {
    for &(name, content) in BUNDLED_LANGS {
        let dest = lang_dir.join(name);
        if !dest.exists() {
            let _ = std::fs::write(dest, content);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Lang {
    strings: HashMap<String, String>,
}

impl Lang {
    pub fn get<'a>(&'a self, key: &'a str) -> &'a str {
        self.strings.get(key).map(|s| s.as_str()).unwrap_or(key)
    }

    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let table: toml::Value = toml::from_str(&content)?;
        let mut strings = HashMap::new();
        Self::flatten_toml(&table, String::new(), &mut strings);
        Ok(Self { strings })
    }

    pub fn flatten_toml(val: &toml::Value, prefix: String, out: &mut HashMap<String, String>) {
        match val {
            toml::Value::Table(t) => {
                for (k, v) in t {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{}.{}", prefix, k)
                    };
                    Self::flatten_toml(v, key, out);
                }
            }
            toml::Value::String(s) => {
                out.insert(prefix, s.clone());
            }
            other => {
                out.insert(prefix, other.to_string());
            }
        }
    }
}

pub fn load_lang(lang_dir: &PathBuf) -> Lang {
    ensure_bundled_languages(lang_dir);

    let locale = detect_locale();
    let candidates = build_candidates(&locale, lang_dir);

    for path in &candidates {
        if path.exists() {
            if let Ok(lang) = Lang::load_from_file(path) {
                return lang;
            }
        }
    }

    if let Some(default_path) = find_default(lang_dir) {
        if let Ok(lang) = Lang::load_from_file(&default_path) {
            return lang;
        }
    }

    try_download_default(lang_dir)
}

fn detect_locale() -> String {
    #[cfg(target_os = "windows")]
    {
        get_windows_locale()
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("LANG")
            .or_else(|_| std::env::var("LC_ALL"))
            .unwrap_or_else(|_| "en_US".to_string())
    }
}

#[cfg(target_os = "windows")]
fn get_windows_locale() -> String {
    use std::process::Command;
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[System.Globalization.CultureInfo]::CurrentCulture.Name",
        ])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().replace('-', "_"))
        .unwrap_or_else(|| "en_US".to_string())
}

fn build_candidates(locale: &str, lang_dir: &PathBuf) -> Vec<PathBuf> {
    let parts: Vec<&str> = locale.splitn(2, '_').collect();
    let mut candidates = vec![];

    if parts.len() == 2 {
        let country = parts[1].to_uppercase();
        let lang = parts[0].to_lowercase();
        candidates.push(lang_dir.join(format!("{}_{}.toml", country, lang)));
    }

    let lang = parts[0].to_lowercase();
    candidates.push(lang_dir.join(format!("EN_{}.toml", lang)));
    candidates
}

fn find_default(lang_dir: &PathBuf) -> Option<PathBuf> {
    std::fs::read_dir(lang_dir).ok()?.find_map(|entry| {
        let path = entry.ok()?.path();
        if path.extension()? == "toml"
            && path.to_string_lossy().contains(".default.")
        {
            Some(path)
        } else {
            None
        }
    })
}

fn try_download_default(lang_dir: &PathBuf) -> Lang {
    const URL: &str =
        "https://raw.githubusercontent.com/00MY00/rusty_seal/main/lang/EN_en.default.toml";

    let _ = std::fs::create_dir_all(lang_dir);
    let dest = lang_dir.join("EN_en.default.toml");

    if let Ok(resp) = ureq::get(URL).call() {
        if let Ok(text) = resp.into_string() {
            let _ = std::fs::write(&dest, &text);
            if let Ok(lang) = Lang::load_from_file(&dest) {
                return lang;
            }
        }
    }

    eprintln!(
        "Ce programme a besoin d'un accès internet pour télécharger ses ressources linguistiques."
    );
    Lang { strings: embedded_fallback() }
}

fn embedded_fallback() -> HashMap<String, String> {
    let raw = include_str!("../lang/EN_en.default.toml");
    let mut strings = HashMap::new();
    if let Ok(table) = toml::from_str::<toml::Value>(raw) {
        Lang::flatten_toml(&table, String::new(), &mut strings);
    }
    strings
}
