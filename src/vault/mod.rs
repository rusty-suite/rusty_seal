pub mod crypto;
pub mod types;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::error::{AppError, Result};
use crypto::*;
use types::*;

pub struct Vault {
    pub path: PathBuf,
    data: Option<VaultData>,
    key: Option<VaultKey>,
    last_activity: Option<Instant>,
    pub config: VaultConfig,
}

impl Vault {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            data: None,
            key: None,
            last_activity: None,
            config: VaultConfig::default(),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.key.is_none()
    }

    pub fn is_open(&self) -> bool {
        !self.is_locked()
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn tick_auto_lock(&mut self) {
        if self.config.auto_lock_minutes == 0 {
            return;
        }
        if let Some(t) = self.last_activity {
            if t.elapsed().as_secs() >= self.config.auto_lock_minutes * 60 {
                self.lock();
            }
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Some(Instant::now());
    }

    pub fn lock(&mut self) {
        self.key = None;
        self.data = None;
        self.last_activity = None;
    }

    pub fn create(&mut self, password: &str, keyfile: Option<&[u8]>) -> Result<()> {
        let salt = random_salt();
        let key = derive_key(password.as_bytes(), &salt, keyfile)?;

        let data = VaultData {
            version: 1,
            certificates: Default::default(),
            profiles: Default::default(),
        };

        let payload = serde_json::to_vec(&data)?;
        let compressed = gz_compress(&payload)?;
        let (ct, nonce) = encrypt_aes_gcm(&compressed, &key)?;

        self.write_file(&salt, &nonce, &ct)?;

        self.data = Some(data);
        self.key = Some(key);
        self.last_activity = Some(Instant::now());
        Ok(())
    }

    pub fn unlock(&mut self, password: &str, keyfile: Option<&[u8]>) -> Result<()> {
        let (salt, nonce, ct) = self.read_file()?;
        let key = derive_key(password.as_bytes(), &salt, keyfile)?;
        let compressed = decrypt_aes_gcm(&ct, &key, &nonce)?;
        let payload = gz_decompress(&compressed)?;
        let data: VaultData = serde_json::from_slice(&payload)?;

        self.data = Some(data);
        self.key = Some(key);
        self.last_activity = Some(Instant::now());
        Ok(())
    }


    fn write_file(&self, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN], ct: &[u8]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = vec![];
        out.extend_from_slice(VAULT_MAGIC);
        out.push(VAULT_VERSION);
        out.extend_from_slice(salt);
        out.extend_from_slice(nonce);
        out.extend_from_slice(ct);
        std::fs::write(&self.path, &out)?;
        set_vault_permissions(&self.path);
        Ok(())
    }

    fn read_file(&self) -> Result<([u8; SALT_LEN], [u8; NONCE_LEN], Vec<u8>)> {
        let raw = std::fs::read(&self.path)
            .map_err(|_| AppError::Vault("Cannot read vault file".into()))?;

        let min_len = 4 + 1 + SALT_LEN + NONCE_LEN + 1;
        if raw.len() < min_len {
            return Err(AppError::Vault("Vault file corrupted or too small".into()));
        }
        if &raw[..4] != VAULT_MAGIC {
            return Err(AppError::Vault("Invalid vault file (bad magic)".into()));
        }
        let _version = raw[4];
        let offset = 5;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[offset..offset + SALT_LEN]);
        let offset = offset + SALT_LEN;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[offset..offset + NONCE_LEN]);
        let offset = offset + NONCE_LEN;
        let ct = raw[offset..].to_vec();

        Ok((salt, nonce, ct))
    }

    pub fn data(&self) -> Result<&VaultData> {
        self.data.as_ref().ok_or_else(|| AppError::Vault("Vault is locked".into()))
    }

    pub fn data_mut(&mut self) -> Result<&mut VaultData> {
        self.data.as_mut().ok_or_else(|| AppError::Vault("Vault is locked".into()))
    }

    pub fn add_certificate(&mut self, entry: CertEntry) -> Result<()> {
        let alias = entry.alias.clone();
        self.data_mut()?.certificates.insert(alias, entry);
        self.save_internal()
    }

    pub fn remove_certificate(&mut self, alias: &str) -> Result<()> {
        self.data_mut()?.certificates.remove(alias);
        self.save_internal()
    }

    pub fn add_profile(&mut self, profile: Profile) -> Result<()> {
        let id = profile.id.clone();
        self.data_mut()?.profiles.insert(id, profile);
        self.save_internal()
    }

    pub fn remove_profile(&mut self, id: &str) -> Result<()> {
        self.data_mut()?.profiles.remove(id);
        self.save_internal()
    }

    pub fn certificates(&self) -> Result<Vec<&CertEntry>> {
        Ok(self.data()?.certificates.values().collect())
    }

    pub fn profiles(&self) -> Result<Vec<&Profile>> {
        Ok(self.data()?.profiles.values().collect())
    }

    pub fn get_cert(&self, alias: &str) -> Result<&CertEntry> {
        self.data()?
            .certificates
            .get(alias)
            .ok_or_else(|| AppError::Vault(format!("Certificate '{}' not found", alias)))
    }

    fn save_internal(&mut self) -> Result<()> {
        let key = self.key.as_ref().ok_or_else(|| AppError::Vault("Vault locked".into()))?;
        let data = self.data.as_ref().ok_or_else(|| AppError::Vault("No data".into()))?;

        let payload = serde_json::to_vec(data)?;
        let compressed = gz_compress(&payload)?;

        let (orig_salt, _, _) = self.read_file().unwrap_or_else(|_| {
            let s = crypto::random_salt();
            let n = crypto::random_nonce();
            (s, n, vec![])
        });

        let (ct, nonce) = encrypt_aes_gcm(&compressed, key)?;
        self.write_file(&orig_salt, &nonce, &ct)?;
        self.touch();
        Ok(())
    }

    pub fn expiring_certs(&self, warn_days: &[u64]) -> Vec<(&CertEntry, u64)> {
        let now = chrono::Utc::now();
        let max_days = warn_days.iter().max().copied().unwrap_or(30);
        let Ok(data) = self.data() else { return vec![] };

        data.certificates
            .values()
            .filter_map(|c| {
                let exp = c.expires_at?;
                let days = (exp - now).num_days();
                if days >= 0 && days as u64 <= max_days {
                    Some((c, days as u64))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn export_encrypted(&self, dest: &Path, password: &str) -> Result<()> {
        if self.is_locked() {
            return Err(AppError::Vault("Unlock vault before exporting".into()));
        }
        let raw = std::fs::read(&self.path)?;
        let salt = random_salt();
        let key = derive_key(password.as_bytes(), &salt, None)?;
        let (ct, nonce) = encrypt_aes_gcm(&raw, &key)?;

        let mut out = vec![];
        out.extend_from_slice(b"RSVX"); // export magic
        out.push(1u8);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);

        std::fs::write(dest, &out)?;
        Ok(())
    }

    pub fn import_encrypted(src: &Path, dest_vault_path: &Path, password: &str) -> Result<()> {
        let raw = std::fs::read(src)?;
        if raw.len() < 5 + SALT_LEN + NONCE_LEN {
            return Err(AppError::Vault("Invalid export file".into()));
        }
        if &raw[..4] != b"RSVX" {
            return Err(AppError::Vault("Not a rusty-seal vault export".into()));
        }
        let offset = 5;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[offset..offset + SALT_LEN]);
        let offset = offset + SALT_LEN;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&raw[offset..offset + NONCE_LEN]);
        let offset = offset + NONCE_LEN;
        let ct = &raw[offset..];

        let key = derive_key(password.as_bytes(), &salt, None)?;
        let vault_bytes = decrypt_aes_gcm(ct, &key, &nonce)?;

        if let Some(parent) = dest_vault_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dest_vault_path, &vault_bytes)?;
        set_vault_permissions(dest_vault_path);
        Ok(())
    }

    pub fn delete_file(&self) -> Result<()> {
        std::fs::remove_file(&self.path)?;
        Ok(())
    }

    pub fn change_password(&mut self, _old_pw: &str, new_pw: &str, keyfile: Option<&[u8]>) -> Result<()> {
        if self.is_locked() {
            return Err(AppError::Vault("Vault is locked".into()));
        }
        let data = self.data.clone().ok_or_else(|| AppError::Vault("No data".into()))?;

        let salt = crypto::random_salt();
        let new_key = derive_key(new_pw.as_bytes(), &salt, keyfile)?;

        let payload = serde_json::to_vec(&data)?;
        let compressed = gz_compress(&payload)?;
        let (ct, nonce) = encrypt_aes_gcm(&compressed, &new_key)?;
        self.write_file(&salt, &nonce, &ct)?;
        self.key = Some(new_key);
        Ok(())
    }
}

fn gz_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

fn gz_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut dec = GzDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(target_os = "windows")]
fn set_vault_permissions(_path: &Path) {
    // On Windows, ideally use DACL — skipped for portability
}

#[cfg(not(target_os = "windows"))]
fn set_vault_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
