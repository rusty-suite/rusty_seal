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
    // Always overwrite — the binary is the source of truth for bundled translations.
    // This ensures lang keys added in a new build are always available.
    for &(name, content) in BUNDLED_LANGS {
        let _ = std::fs::write(lang_dir.join(name), content);
    }
}

#[derive(Debug, Clone)]
pub struct Lang {
    strings: HashMap<String, String>,
}

impl Lang {
    /// Translation of `key`: active language, then bundled English, then the
    /// key itself (free text such as an OS error message is returned as-is).
    pub fn get<'a>(&'a self, key: &'a str) -> &'a str {
        self.strings
            .get(key)
            .or_else(|| embedded_default().get(key))
            .map(|s| s.as_str())
            .unwrap_or(key)
    }

    /// Like [`Lang::get`], then replaces each `{name}` placeholder.
    pub fn fmt(&self, key: &str, args: &[(&str, &str)]) -> String {
        let mut s = self.get(key).to_string();
        for (name, value) in args {
            s = s.replace(&format!("{{{name}}}"), value);
        }
        s
    }

    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let table: toml::Value = toml::from_str(&content)?;
        let mut strings = HashMap::new();
        Self::flatten_toml(&table, String::new(), &mut strings);
        // A stale local copy is completed by the bundled version of the same file.
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            for (k, v) in bundled_strings(name) {
                strings.entry(k).or_insert(v);
            }
        }
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

/// File remembering the language chosen in the settings (next to `lang/`).
fn choice_file(lang_dir: &Path) -> PathBuf {
    lang_dir.parent().unwrap_or(lang_dir).join("lang_chosen.txt")
}

/// Remembers the language file chosen by the user for the next start.
pub fn save_choice(lang_dir: &Path, lang_file: &Path) {
    if let Some(name) = lang_file.file_name().and_then(|n| n.to_str()) {
        let _ = std::fs::write(choice_file(lang_dir), name);
    }
}

pub fn load_lang(lang_dir: &PathBuf) -> Lang {
    ensure_bundled_languages(lang_dir);

    // 1. Language explicitly chosen in the settings
    if let Ok(name) = std::fs::read_to_string(choice_file(lang_dir)) {
        let path = lang_dir.join(name.trim());
        if let Ok(lang) = Lang::load_from_file(&path) {
            return lang;
        }
    }

    // 2. System locale
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
        "https://raw.githubusercontent.com/rusty-suite/rusty_seal/main/lang/EN_en.default.toml";

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

    // Offline: the bundled English language is always available.
    Lang { strings: embedded_default().clone() }
}

/// Flattened strings of a bundled language file (empty if not bundled).
fn bundled_strings(file_name: &str) -> HashMap<String, String> {
    let mut strings = HashMap::new();
    if let Some((_, raw)) = BUNDLED_LANGS.iter().find(|(name, _)| *name == file_name) {
        if let Ok(table) = toml::from_str::<toml::Value>(raw) {
            Lang::flatten_toml(&table, String::new(), &mut strings);
        }
    }
    strings
}

/// Bundled English strings, parsed once: the universal fallback.
fn embedded_default() -> &'static HashMap<String, String> {
    static CACHE: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| bundled_strings("EN_en.default.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn keys(file: &str) -> BTreeSet<String> {
        bundled_strings(file).into_keys().collect()
    }

    /// Every bundled language defines exactly the keys of the English file.
    #[test]
    fn all_languages_have_the_same_keys() {
        let reference = keys("EN_en.default.toml");
        assert!(reference.len() > 100);
        for (file, _) in BUNDLED_LANGS {
            let k = keys(file);
            let missing: Vec<_> = reference.difference(&k).collect();
            let extra: Vec<_> = k.difference(&reference).collect();
            assert!(missing.is_empty() && extra.is_empty(), "{file}: missing {missing:?}, extra {extra:?}");
        }
    }

    /// Every key used in the code (get/fmt calls and `errors.*` details) exists.
    #[test]
    fn keys_used_in_code_exist() {
        let reference = keys("EN_en.default.toml");
        let mut missing = Vec::new();
        let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() { stack.push(path); continue; }
                let text = std::fs::read_to_string(&path).unwrap();
                for call in [".get(\"", ".fmt(\"", "(\"errors."] {
                    for part in text.split(call).skip(1) {
                        let raw = part.split('"').next().unwrap();
                        let key = if call == "(\"errors." { format!("errors.{raw}") } else { raw.to_string() };
                        let key = key.split('|').next().unwrap().to_string();
                        // `.get("…")` is also used on other maps: only check dotted keys.
                        if key.contains('.') && !key.ends_with('.') && !key.contains([' ', '{'])
                            && !reference.contains(&key)
                        {
                            missing.push(format!("{}: {key}", path.display()));
                        }
                    }
                }
            }
        }
        assert!(missing.is_empty(), "missing keys: {missing:#?}");
    }

    #[test]
    fn missing_key_falls_back_to_english_then_key() {
        let lang = Lang { strings: HashMap::new() };
        assert_eq!(lang.get("common.cancel"), "Cancel");
        assert_eq!(lang.get("free text"), "free text");
        assert_eq!(lang.fmt("vault.days_left", &[("n", "3")]), "— 3 days left");
    }

    #[test]
    fn errors_are_localized_with_parameter() {
        let lang = Lang { strings: HashMap::new() };
        let e = crate::error::AppError::Vault("errors.cert_not_found|demo".into());
        assert_eq!(e.localized(&lang), "Vault error: Certificate 'demo' not found");
        let raw = crate::error::AppError::Signing("timeout".into());
        assert_eq!(raw.localized(&lang), "Signing error: timeout");
    }
}
