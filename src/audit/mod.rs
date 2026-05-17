use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};

type HmacSha256 = Hmac<Sha256>;

const AUDIT_HMAC_KEY: &[u8] = b"rusty-seal-audit-integrity-key-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditAction {
    VaultCreate,
    VaultUnlock,
    VaultLock,
    VaultExport,
    VaultImport,
    CertCreate,
    CertImport,
    CertDelete,
    CertReplace,
    ProfileCreate,
    ProfileEdit,
    ProfileDelete,
    Sign,
    Verify,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::VaultCreate => "vault.create",
            Self::VaultUnlock => "vault.unlock",
            Self::VaultLock => "vault.lock",
            Self::VaultExport => "vault.export",
            Self::VaultImport => "vault.import",
            Self::CertCreate => "cert.create",
            Self::CertImport => "cert.import",
            Self::CertDelete => "cert.delete",
            Self::CertReplace => "cert.replace",
            Self::ProfileCreate => "profile.create",
            Self::ProfileEdit => "profile.edit",
            Self::ProfileDelete => "profile.delete",
            Self::Sign => "sign",
            Self::Verify => "verify",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    pub operator: String,
    pub file_hash: Option<String>,
    pub file_name: Option<String>,
    pub cert_alias: Option<String>,
    pub details: Option<String>,
    pub success: bool,
    pub hmac: String,
}

impl AuditEntry {
    fn compute_hmac(
        id: &str,
        timestamp: &DateTime<Utc>,
        action: &AuditAction,
        operator: &str,
        file_hash: Option<&str>,
        cert_alias: Option<&str>,
        success: bool,
    ) -> String {
        let mut mac = HmacSha256::new_from_slice(AUDIT_HMAC_KEY).unwrap();
        mac.update(id.as_bytes());
        mac.update(timestamp.to_rfc3339().as_bytes());
        mac.update(action.to_string().as_bytes());
        mac.update(operator.as_bytes());
        mac.update(file_hash.unwrap_or("").as_bytes());
        mac.update(cert_alias.unwrap_or("").as_bytes());
        mac.update(if success { b"1" } else { b"0" });
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn new(
        action: AuditAction,
        operator: String,
        file_hash: Option<String>,
        file_name: Option<String>,
        cert_alias: Option<String>,
        details: Option<String>,
        success: bool,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let hmac = Self::compute_hmac(
            &id,
            &timestamp,
            &action,
            &operator,
            file_hash.as_deref(),
            cert_alias.as_deref(),
            success,
        );
        Self { id, timestamp, action, operator, file_hash, file_name, cert_alias, details, success, hmac }
    }

    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_hmac(
            &self.id,
            &self.timestamp,
            &self.action,
            &self.operator,
            self.file_hash.as_deref(),
            self.cert_alias.as_deref(),
            self.success,
        );
        expected == self.hmac
    }
}

pub struct AuditLog {
    path: PathBuf,
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn load(path: PathBuf) -> Self {
        let entries = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .map(|s| {
                    s.lines()
                        .filter_map(|l| serde_json::from_str::<AuditEntry>(l).ok())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![]
        };
        Self { path, entries }
    }

    pub fn append(&mut self, entry: AuditEntry) -> Result<()> {
        let line = serde_json::to_string(&entry)?;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", line)?;
        self.entries.push(entry);
        Ok(())
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self.entries).unwrap_or_default()
    }

    pub fn export_csv(&self) -> Result<String> {
        let mut wtr = csv::Writer::from_writer(vec![]);
        let csv_err = |e: csv::Error| AppError::Audit(e.to_string());
        wtr.write_record(&[
            "id", "timestamp", "action", "operator",
            "file_name", "file_hash", "cert_alias", "details", "success", "integrity_ok",
        ]).map_err(csv_err)?;
        for e in &self.entries {
            let success = if e.success { "true" } else { "false" };
            let integrity = if e.verify_integrity() { "ok" } else { "TAMPERED" };
            let timestamp = e.timestamp.to_rfc3339();
            let action = e.action.to_string();
            wtr.write_record(&[
                e.id.as_str(),
                timestamp.as_str(),
                action.as_str(),
                e.operator.as_str(),
                e.file_name.as_deref().unwrap_or(""),
                e.file_hash.as_deref().unwrap_or(""),
                e.cert_alias.as_deref().unwrap_or(""),
                e.details.as_deref().unwrap_or(""),
                success,
                integrity,
            ]).map_err(|e| AppError::Audit(e.to_string()))?;
        }
        let data = wtr.into_inner().map_err(|e| AppError::Audit(e.to_string()))?;
        Ok(String::from_utf8(data).unwrap_or_default())
    }
}
