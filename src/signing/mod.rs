pub mod format;

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

pub fn verify_sig_bytes(sig_json: &str, file_data: &[u8]) -> Result<VerifyResult> {
    let sig_file = SignatureFile::from_json(sig_json)?;

    let mut h = Sha256::new();
    h.update(file_data);
    let actual_hash = format!("SHA256:{}", hex::encode(h.finalize()));

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
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    pub fn message(&self) -> String {
        match self {
            Self::Valid(_) => "Signature valid".into(),
            Self::FileMismatch { expected, actual } => {
                format!("File hash mismatch\nExpected: {}\nActual: {}", expected, actual)
            }
            Self::InvalidSignature(e) => format!("Invalid signature: {}", e),
        }
    }
}

fn do_sign(message: &[u8], cert: &CertEntry) -> Result<Vec<u8>> {
    if cert.private_key_pkcs8_der_b64.is_empty() {
        return Err(AppError::Signing("No private key available for this certificate".into()));
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

    let pem_obj = pem_parse(cert_pem)
        .map_err(|e| AppError::Signing(format!("Cert PEM: {}", e)))?;
    let (_, cert) = X509Certificate::from_der(pem_obj.contents())
        .map_err(|e| AppError::Signing(format!("Cert parse: {:?}", e)))?;

    let pub_key_der = cert.public_key().raw;

    match algorithm {
        "Ed25519" => {
            let pk = UnparsedPublicKey::new(&signature::ED25519, pub_key_der);
            pk.verify(message, sig)
                .map_err(|_| AppError::Signing("Ed25519 verification failed".into()))
        }
        "ECDSA P-256" => {
            let pk = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, pub_key_der);
            pk.verify(message, sig)
                .map_err(|_| AppError::Signing("ECDSA P-256 verification failed".into()))
        }
        "ECDSA P-384" => {
            let pk = UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, pub_key_der);
            pk.verify(message, sig)
                .map_err(|_| AppError::Signing("ECDSA P-384 verification failed".into()))
        }
        "RSA 2048" | "RSA 4096" => {
            let pk = UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                pub_key_der,
            );
            pk.verify(message, sig)
                .map_err(|_| AppError::Signing("RSA verification failed".into()))
        }
        _ => Err(AppError::Signing(format!("Unknown algorithm: {}", algorithm))),
    }
}

pub fn write_sig_file(file_path: &Path, sig: &format::SignatureFile) -> Result<()> {
    let sig_path = file_path.with_extension(
        format!("{}.sig", file_path.extension().unwrap_or_default().to_string_lossy())
    );
    let sig_path = if file_path.extension().is_some() {
        sig_path
    } else {
        file_path.with_extension("sig")
    };
    std::fs::write(&sig_path, sig.to_json_pretty())?;
    Ok(())
}

pub fn sig_path_for(file_path: &Path) -> std::path::PathBuf {
    let name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    file_path.with_file_name(format!("{}.sig", name))
}
