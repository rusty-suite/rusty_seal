pub mod format;
pub mod authenticode;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use pem::parse as pem_parse;
use ring::signature::{self, UnparsedPublicKey};
use sha2::{Sha256, Digest};
use std::path::Path;

use crate::error::{AppError, Result};
use crate::vault::types::{CertEntry, KeyAlgorithm, SigningMetadata};
use format::*;

pub fn hash_file(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    let mut h = Sha256::new();
    h.update(&data);
    let digest = h.finalize();
    Ok(format!("SHA256:{}", hex::encode(digest)))
}

pub fn sign_file(
    file_path: &Path,
    cert: &CertEntry,
    metadata: SigningMetadata,
) -> Result<SignatureFile> {
    if cert.certificate_pem.is_empty() {
        return Err(AppError::Signing(format!("errors.cert_no_pem|{}", cert.alias)));
    }

    let file_hash = hash_file(file_path)?;
    let file_name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let signed_at = chrono::Utc::now();

    let mut sig_file = SignatureFile {
        version: SIG_FILE_VERSION,
        signer: SIGNER_ID.into(),
        algorithm: cert.algorithm.to_string(),
        cert_alias: cert.alias.clone(),
        cert_fingerprint: cert.fingerprint.clone(),
        file_hash,
        file_name,
        signed_at,
        metadata,
        signature_b64: String::new(),
        certificate_pem: cert.certificate_pem.clone(),
    };

    let message = sig_file.canonical_message();
    let sig_bytes = do_sign(&message, cert)?;
    sig_file.signature_b64 = B64.encode(&sig_bytes);

    Ok(sig_file)
}

pub fn verify_authenticode(file_path: &Path) -> Result<VerifyResult> {
    let (is_valid, status, subject, timestamp) = authenticode::verify_script(file_path)?;
    if is_valid {
        Ok(VerifyResult::AuthenticodeValid { subject, timestamp })
    } else {
        Ok(VerifyResult::AuthenticodeInvalid { status, subject })
    }
}

pub fn verify_signature(file_path: &Path, sig_path: &Path) -> Result<VerifyResult> {
    let json = std::fs::read_to_string(sig_path)?;
    let sig_file = SignatureFile::from_json(&json)?;

    let actual_hash = hash_file(file_path)?;
    if actual_hash != sig_file.file_hash {
        return Ok(VerifyResult::FileMismatch {
            expected: sig_file.file_hash.clone(),
            actual: actual_hash,
        });
    }

    let message = sig_file.canonical_message();
    let sig_bytes = B64.decode(&sig_file.signature_b64)
        .map_err(|e| AppError::Signing(e.to_string()))?;

    match do_verify(&message, &sig_bytes, &sig_file.certificate_pem, &sig_file.algorithm) {
        Ok(()) => Ok(VerifyResult::Valid(sig_file)),
        Err(e) => Ok(VerifyResult::InvalidSignature(e.to_string())),
    }
}

#[derive(Debug)]
pub enum VerifyResult {
    Valid(SignatureFile),
    FileMismatch { expected: String, actual: String },
    InvalidSignature(String),
    AuthenticodeValid { subject: String, timestamp: String },
    AuthenticodeInvalid { status: String, subject: String },
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_) | Self::AuthenticodeValid { .. })
    }

    pub fn message(&self) -> String {
        match self {
            Self::Valid(_) => "Signature valid".into(),
            Self::FileMismatch { expected, actual } => {
                format!("File hash mismatch\nExpected: {}\nActual: {}", expected, actual)
            }
            Self::InvalidSignature(e) => format!("Invalid signature: {}", e),
            Self::AuthenticodeValid { subject, .. } => format!("Authenticode valid - {}", subject),
            Self::AuthenticodeInvalid { status, .. } => format!("Authenticode invalid: {}", status),
        }
    }
}

fn do_sign(message: &[u8], cert: &CertEntry) -> Result<Vec<u8>> {
    if cert.private_key_pkcs8_der_b64.is_empty() {
        return Err(AppError::Signing("errors.no_private_key".into()));
    }

    let key_der = B64.decode(&cert.private_key_pkcs8_der_b64)
        .map_err(|e| AppError::Signing(format!("Key decode: {}", e)))?;

    let rng = ring::rand::SystemRandom::new();

    match cert.algorithm {
        KeyAlgorithm::Ed25519 => {
            let kp = signature::Ed25519KeyPair::from_pkcs8(&key_der)
                .map_err(|e| AppError::Signing(format!("Ed25519 key: {:?}", e)))?;
            Ok(kp.sign(message).as_ref().to_vec())
        }
        KeyAlgorithm::EcdsaP256 => {
            let kp = signature::EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &key_der,
                &rng,
            )
            .map_err(|e| AppError::Signing(format!("ECDSA P-256 key: {:?}", e)))?;
            let sig = kp.sign(&rng, message)
                .map_err(|e| AppError::Signing(format!("ECDSA sign: {:?}", e)))?;
            Ok(sig.as_ref().to_vec())
        }
        KeyAlgorithm::EcdsaP384 => {
            let kp = signature::EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                &key_der,
                &rng,
            )
            .map_err(|e| AppError::Signing(format!("ECDSA P-384 key: {:?}", e)))?;
            let sig = kp.sign(&rng, message)
                .map_err(|e| AppError::Signing(format!("ECDSA sign: {:?}", e)))?;
            Ok(sig.as_ref().to_vec())
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            let kp = signature::RsaKeyPair::from_pkcs8(&key_der)
                .map_err(|e| AppError::Signing(format!("RSA key: {:?}", e)))?;
            let mut sig_buf = vec![0u8; kp.public().modulus_len()];
            kp.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut sig_buf)
                .map_err(|e| AppError::Signing(format!("RSA sign: {:?}", e)))?;
            Ok(sig_buf)
        }
    }
}

fn do_verify(message: &[u8], sig: &[u8], cert_pem: &str, algorithm: &str) -> Result<()> {
    use x509_parser::prelude::*;

    if cert_pem.is_empty() {
        return Err(AppError::Signing("errors.sig_no_cert".into()));
    }

    let pem_obj = pem_parse(cert_pem)
        .map_err(|e| AppError::Signing(format!("Cert PEM parse error: {}", e)))?;
    let (_, cert) = X509Certificate::from_der(pem_obj.contents())
        .map_err(|e| AppError::Signing(format!("X.509 parse error: {:?}", e)))?;

    let spki = cert.public_key();
    // ring 0.17: Ed25519 and ECDSA expect the raw key bytes from the BitString,
    // not the full SubjectPublicKeyInfo (SPKI).  RSA expects the full SPKI.
    let key_bytes = spki.subject_public_key.data.as_ref();
    let spki_bytes = spki.raw;

    match algorithm {
        "Ed25519" => {
            let pk = UnparsedPublicKey::new(&signature::ED25519, key_bytes);
            pk.verify(message, sig)
                .map_err(|_| AppError::Signing("Ed25519 verification failed".into()))
        }
        "ECDSA P-256" => {
            let pk = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key_bytes);
            pk.verify(message, sig)
                .map_err(|_| AppError::Signing("ECDSA P-256 verification failed".into()))
        }
        "ECDSA P-384" => {
            let pk = UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, key_bytes);
            pk.verify(message, sig)
                .map_err(|_| AppError::Signing("ECDSA P-384 verification failed".into()))
        }
        "RSA 2048" | "RSA 4096" => {
            let pk = UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                spki_bytes,
            );
            pk.verify(message, sig)
                .map_err(|_| AppError::Signing("RSA verification failed".into()))
        }
        _ => Err(AppError::Signing(format!("Unknown algorithm: {}", algorithm))),
    }
}

/// Result produced by `run_sign_job` - returned across thread boundary.
pub struct SignJobResult {
    pub ok_count: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
    pub pairs: Vec<(std::path::PathBuf, std::path::PathBuf)>,
    pub audit_entries: Vec<crate::audit::AuditEntry>,
}

/// Pure signing loop - all inputs passed by value/reference, no AppState access.
/// Designed to run inside a background thread.  `progress` is incremented once per file.
pub fn run_sign_job(
    files: &[std::path::PathBuf],
    cert: &CertEntry,
    meta: SigningMetadata,
    out_dir: &Option<std::path::PathBuf>,
    overwrite: bool,
    create_copy: bool,
    copy_prefix: &str,
    progress: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> SignJobResult {
    use std::sync::atomic::Ordering;
    let alias = cert.alias.clone();
    let mut ok_count = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<String> = vec![];
    let mut pairs: Vec<(std::path::PathBuf, std::path::PathBuf)> = vec![];
    let mut audit_entries: Vec<crate::audit::AuditEntry> = vec![];

    for file_path in files {
        let target_path = if create_copy {
            let fname = file_path.file_name().unwrap_or_default().to_string_lossy();
            let copy_name = format!("{} {}", copy_prefix, fname);
            let dest_dir = match out_dir {
                Some(d) => d.clone(),
                None => file_path.parent().unwrap_or(std::path::Path::new(".")).to_path_buf(),
            };
            let dest = dest_dir.join(&copy_name);
            if let Err(e) = std::fs::copy(file_path, &dest) {
                errors.push(format!("{}: {}", file_path.display(), e));
                progress.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            dest
        } else {
            file_path.clone()
        };

        if authenticode::is_authenticode_target(&target_path) {
            match authenticode::sign_script(&target_path, cert) {
                Ok(()) => {
                    ok_count += 1;
                    pairs.push((target_path.clone(), target_path.clone()));
                    audit_entries.push(crate::audit::AuditEntry::new(
                        crate::audit::AuditAction::Sign,
                        "operator".into(),
                        None,
                        Some(target_path.file_name().unwrap_or_default().to_string_lossy().to_string()),
                        Some(alias.clone()),
                        None,
                        true,
                    ));
                }
                Err(e) => {
                    errors.push(format!("{}: {}", file_path.display(), e));
                    if create_copy { std::fs::remove_file(&target_path).ok(); }
                    audit_entries.push(crate::audit::AuditEntry::new(
                        crate::audit::AuditAction::Sign,
                        "operator".into(),
                        None,
                        Some(target_path.file_name().unwrap_or_default().to_string_lossy().to_string()),
                        Some(alias.clone()),
                        Some(e.to_string()),
                        false,
                    ));
                }
            }
            progress.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let sig_path = if create_copy {
            sig_path_for(&target_path)
        } else {
            match out_dir {
                None => sig_path_for(file_path),
                Some(dir) => {
                    let mut name = file_path.file_name().unwrap_or_default().to_os_string();
                    name.push(".sig");
                    dir.join(name)
                }
            }
        };

        if sig_path.exists() && !overwrite && !create_copy {
            skipped += 1;
            progress.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        match sign_file(&target_path, cert, meta.clone()) {
            Ok(sig) => {
                let json = sig.to_json_pretty();
                if json.is_empty() {
                    errors.push(format!("{}: signature serialization failed", file_path.display()));
                    if create_copy { std::fs::remove_file(&target_path).ok(); }
                } else {
                    match std::fs::write(&sig_path, &json) {
                        Ok(()) => {
                            ok_count += 1;
                            pairs.push((target_path.clone(), sig_path));
                            audit_entries.push(crate::audit::AuditEntry::new(
                                crate::audit::AuditAction::Sign,
                                "operator".into(),
                                Some(sig.file_hash.clone()),
                                Some(sig.file_name.clone()),
                                Some(alias.clone()),
                                None,
                                true,
                            ));
                        }
                        Err(e) => {
                            errors.push(format!("{}: {}", file_path.display(), e));
                            if create_copy { std::fs::remove_file(&target_path).ok(); }
                        }
                    }
                }
            }
            Err(e) => {
                errors.push(format!("{}: {}", file_path.display(), e));
                if create_copy { std::fs::remove_file(&target_path).ok(); }
                audit_entries.push(crate::audit::AuditEntry::new(
                    crate::audit::AuditAction::Sign,
                    "operator".into(),
                    None,
                    Some(file_path.file_name().unwrap_or_default().to_string_lossy().to_string()),
                    Some(alias.clone()),
                    Some(e.to_string()),
                    false,
                ));
            }
        }
        progress.fetch_add(1, Ordering::Relaxed);
    }

    SignJobResult { ok_count, skipped, errors, pairs, audit_entries }
}

pub fn sig_path_for(file_path: &Path) -> std::path::PathBuf {
    let name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    file_path.with_file_name(format!("{}.sig", name))
}
