use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use argon2::{Argon2, Params};
use rand::RngCore;
use zeroize::Zeroize;
use crate::error::{AppError, Result};

pub const VAULT_MAGIC: &[u8; 4] = b"RSVC";
pub const VAULT_VERSION: u8 = 1;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct VaultKey(pub [u8; KEY_LEN]);

pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], keyfile: Option<&[u8]>) -> Result<VaultKey> {
    let mut input = password.to_vec();
    if let Some(kf) = keyfile {
        for (b, kfb) in input.iter_mut().zip(kf.iter().cycle()) {
            *b ^= kfb;
        }
        if input.len() < kf.len() {
            input.extend_from_slice(&kf[input.len()..]);
        }
    }

    let params = Params::new(65536, 3, 4, Some(KEY_LEN))
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(&input, salt, &mut key)
        .map_err(|e| AppError::Crypto(e.to_string()))?;

    input.zeroize();
    Ok(VaultKey(key))
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt_aes_gcm(data: &[u8], key: &VaultKey) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let nonce_bytes = random_nonce();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, data)
        .map_err(|e| AppError::Crypto(e.to_string()))?;
    Ok((ct, nonce_bytes))
}

pub fn decrypt_aes_gcm(ct: &[u8], key: &VaultKey, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ct)
        .map_err(|_| AppError::Crypto("Decryption failed — wrong password or corrupted vault".into()))
}
