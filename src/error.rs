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

    #[error("Network error: {0}")]
    Network(String),

    #[error("Profile error: {0}")]
    Profile(String),

    #[error("Audit error: {0}")]
    Audit(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
