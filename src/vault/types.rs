use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa4096,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::EcdsaP256 => write!(f, "ECDSA P-256"),
            Self::EcdsaP384 => write!(f, "ECDSA P-384"),
            Self::Rsa2048 => write!(f, "RSA 2048"),
            Self::Rsa4096 => write!(f, "RSA 4096"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertHistory {
    pub replaced_at: DateTime<Utc>,
    pub old_fingerprint: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CertEntry {
    pub alias: String,
    pub algorithm: KeyAlgorithm,
    pub certificate_pem: String,
    pub private_key_pkcs8_der_b64: String,
    pub fingerprint: String,
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,
    #[zeroize(skip)]
    pub expires_at: Option<DateTime<Utc>>,
    pub subject_cn: String,
    #[serde(default)]
    pub subject_email: String,
    #[zeroize(skip)]
    pub history: Vec<CertHistory>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigningMetadata {
    pub version: String,
    pub author: String,
    pub description: String,
    pub build_date: String,
    pub source_url: String,
    pub custom: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub cert_alias: String,
    #[serde(default)]
    pub cert_aliases: Vec<String>,
    pub default_metadata: SigningMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub version: u32,
    pub certificates: HashMap<String, CertEntry>,
    pub profiles: HashMap<String, Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub auto_lock_minutes: u64,
    pub warn_expiry_days: Vec<u64>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 15,
            warn_expiry_days: vec![30, 7, 1],
        }
    }
}

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct UnlockedVaultKey(pub [u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    pub name: String,
    pub path: PathBuf,
}
