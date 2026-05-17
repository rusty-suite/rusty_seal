use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::vault::types::SigningMetadata;

pub const SIG_FILE_VERSION: u32 = 1;
pub const SIGNER_ID: &str = "rusty-seal";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureFile {
    pub version: u32,
    pub signer: String,
    pub algorithm: String,
    pub cert_alias: String,
    pub cert_fingerprint: String,
    pub file_hash: String,
    pub file_name: String,
    pub signed_at: DateTime<Utc>,
    pub metadata: SigningMetadata,
    pub signature_b64: String,
    pub certificate_pem: String,
}

impl SignatureFile {
    pub fn canonical_message(&self) -> Vec<u8> {
        let obj = serde_json::json!({
            "version": self.version,
            "algorithm": self.algorithm,
            "cert_fingerprint": self.cert_fingerprint,
            "file_hash": self.file_hash,
            "file_name": self.file_name,
            "signed_at": self.signed_at.to_rfc3339(),
            "metadata": self.metadata,
        });
        serde_json::to_vec(&obj).unwrap_or_default()
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn from_json(s: &str) -> crate::error::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}
