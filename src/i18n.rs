//! Textes de Rusty Seal.
//!
//! Le chargement (packs intégrés, fichiers locaux, mise à jour depuis GitHub, repli sur
//! la version intégrée puis sur l'anglais) est fait par `rusty_core::lang` (charte
//! Rusty Suite, section 05). Ce module garde l'API utilisée par les panneaux :
//! `lang.get(clé)` et `lang.fmt(clé, variables)`, avec des clés « section.clé ».

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Packs de langue intégrés au binaire (nom de fichier historique pour l'anglais).
pub const PACKS: rusty_core::lang::Packs = &[
    ("EN_en", include_str!("../lang/EN_en.default.toml")),
    ("FR_fr", include_str!("../lang/FR_fr.toml")),
    ("CH_fr", include_str!("../lang/CH_fr.toml")),
    ("DE_de", include_str!("../lang/DE_de.toml")),
    ("CH_de", include_str!("../lang/CH_de.toml")),
    ("IT_it", include_str!("../lang/IT_it.toml")),
    ("CH_it", include_str!("../lang/CH_it.toml")),
];

/// Langue active. Clonage bon marché (table partagée).
#[derive(Debug, Clone)]
pub struct Lang {
    core: rusty_core::Lang,
    strings: Arc<HashMap<String, String>>,
}

impl Lang {
    /// Charge la langue `chosen` (stem, vide = langue du système).
    pub fn load(data_dir: &Path, chosen: &str) -> Self {
        Self::from_core(rusty_core::Lang::load(PACKS, data_dir, chosen))
    }

    fn from_core(core: rusty_core::Lang) -> Self {
        let strings = core.keys().map(|k| (k.clone(), core.t(k))).collect();
        Self { core, strings: Arc::new(strings) }
    }

    /// Texte d'une clé ; la clé elle-même si elle n'existe dans aucune couche.
    pub fn get<'a>(&'a self, key: &'a str) -> &'a str {
        self.strings.get(key).map(String::as_str).unwrap_or(key)
    }

    /// Texte avec variables nommées `{nom}`.
    pub fn fmt(&self, key: &str, args: &[(&str, &str)]) -> String {
        self.core.tf(key, args)
    }

    /// Langue du kit (textes communs `[kit]`, stem, code du bouton Langue).
    pub fn core(&self) -> &rusty_core::Lang {
        &self.core
    }
}

/// Ancien choix de langue (`lang_chosen.txt`, nom de fichier) converti en stem, pour
/// reprendre le choix des versions précédentes.
pub fn legacy_choice(workdir: &Path) -> Option<String> {
    let name = std::fs::read_to_string(workdir.join("lang_chosen.txt")).ok()?;
    let name = name.trim();
    let stem = name.strip_suffix(".default.toml").or_else(|| name.strip_suffix(".toml")).unwrap_or(name);
    (!stem.is_empty()).then(|| stem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn english() -> Lang {
        Lang::load(&std::env::temp_dir().join("rusty_seal_lang_test"), "EN_en")
    }

    /// Toutes les langues ont exactement les clés de l'anglais.
    #[test]
    fn all_languages_have_the_same_keys() {
        assert_eq!(rusty_core::lang::check_packs(PACKS), Vec::<String>::new());
    }

    /// Chaque clé utilisée dans le code (`get`, `fmt`, détails `errors.*`) existe.
    #[test]
    fn keys_used_in_code_exist() {
        let lang = english();
        let reference: BTreeSet<&String> = lang.strings.keys().collect();
        let mut missing = Vec::new();
        let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for call in [".get(\"", ".fmt(\"", "(\"errors."] {
                    for part in text.split(call).skip(1) {
                        let raw = part.split('"').next().unwrap();
                        let key = if call == "(\"errors." { format!("errors.{raw}") } else { raw.to_string() };
                        let key = key.split('|').next().unwrap().to_string();
                        // `.get("…")` sert aussi à d'autres tables : seules les clés pointées comptent.
                        if key.contains('.') && !key.ends_with('.') && !key.contains([' ', '{']) && !reference.contains(&key) {
                            missing.push(format!("{}: {key}", path.display()));
                        }
                    }
                }
            }
        }
        assert!(missing.is_empty(), "clés manquantes : {missing:#?}");
    }

    #[test]
    fn missing_key_falls_back_to_the_key() {
        let lang = english();
        assert_eq!(lang.get("common.cancel"), "Cancel");
        assert_eq!(lang.get("free text"), "free text");
        assert!(lang.fmt("vault.days_left", &[("n", "3")]).contains('3'));
    }

    #[test]
    fn errors_are_localized_with_parameter() {
        let lang = english();
        let e = crate::error::AppError::Vault("errors.cert_not_found|demo".into());
        assert_eq!(e.localized(&lang), "Vault error: Certificate 'demo' not found");
        let raw = crate::error::AppError::Signing("timeout".into());
        assert_eq!(raw.localized(&lang), "Signing error: timeout");
    }

    #[test]
    fn legacy_choice_is_converted() {
        let dir = std::env::temp_dir().join(format!("rusty_seal_legacy_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("lang_chosen.txt"), "CH_fr.toml\n").unwrap();
        assert_eq!(legacy_choice(&dir).as_deref(), Some("CH_fr"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
