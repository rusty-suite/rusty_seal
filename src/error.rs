use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Vault error: {0}")]
    Vault(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Audit error: {0}")]
    Audit(String),
}

impl AppError {
    /// Message for the UI, in the user language.
    ///
    /// The category is translated (`errors.<category>`). A detail that is a
    /// translation key (`errors.*`) is translated too; a parameter can be
    /// passed as `"errors.key|value"` and replaces `{0}`. Any other detail
    /// (e.g. an OS or library message) is shown unchanged.
    pub fn localized(&self, lang: &crate::i18n::Lang) -> String {
        let (category, detail) = match self {
            Self::Io(e)          => ("errors.io", e.to_string()),
            Self::Vault(d)       => ("errors.vault", d.clone()),
            Self::Crypto(d)      => ("errors.crypto", d.clone()),
            Self::Certificate(d) => ("errors.certificate", d.clone()),
            Self::Signing(d)     => ("errors.signing", d.clone()),
            Self::Serde(e)       => ("errors.serde", e.to_string()),
            Self::Audit(d)       => ("errors.audit", d.clone()),
        };
        let detail = match detail.split_once('|') {
            Some((key, arg)) if key.starts_with("errors.") => lang.get(key).replace("{0}", arg),
            _ => lang.get(&detail).to_string(),
        };
        format!("{}: {}", lang.get(category), detail)
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
