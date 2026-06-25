use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use pem::{parse as pem_parse, parse_many as pem_parse_many, encode as pem_encode, Pem};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    PKCS_ED25519, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256,
};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use sha2::{Sha256, Digest};
use time::OffsetDateTime;

use crate::error::{AppError, Result};
use crate::vault::types::{CertEntry, KeyAlgorithm};

pub struct CertBuilder {
    pub alias: String,
    pub algorithm: KeyAlgorithm,
    pub common_name: String,
    pub org: String,
    pub country: String,
    pub valid_days: u32,
}

impl Default for CertBuilder {
    fn default() -> Self {
        Self {
            alias: String::new(),
            algorithm: KeyAlgorithm::Ed25519,
            common_name: String::new(),
            org: String::new(),
            country: "US".into(),
            valid_days: 365,
        }
    }
}

impl CertBuilder {
    pub fn build(self) -> Result<CertEntry> {
        // ring (utilisé par rcgen) ne sait pas générer des clés RSA.
        // Pour RSA on génère via le crate `rsa` puis on charge le PKCS#8 DER dans rcgen.
        let key_pair = match self.algorithm {
            KeyAlgorithm::Rsa2048 => generate_rsa_keypair(2048)?,
            KeyAlgorithm::Rsa4096 => generate_rsa_keypair(4096)?,
            KeyAlgorithm::Ed25519 => {
                KeyPair::generate_for(&PKCS_ED25519)
                    .map_err(|e| AppError::Certificate(format!("Key generation: {}", e)))?
            }
            KeyAlgorithm::EcdsaP256 => {
                KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                    .map_err(|e| AppError::Certificate(format!("Key generation: {}", e)))?
            }
            KeyAlgorithm::EcdsaP384 => {
                KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
                    .map_err(|e| AppError::Certificate(format!("Key generation: {}", e)))?
            }
        };

        let mut params = CertificateParams::default();
        // Add Code Signing EKU so certs can be used for Windows Authenticode
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, self.common_name.clone());
        if !self.org.is_empty() {
            dn.push(DnType::OrganizationName, self.org.clone());
        }
        if !self.country.is_empty() {
            dn.push(DnType::CountryName, self.country.clone());
        }
        params.distinguished_name = dn;

        let now = Utc::now();
        let exp = now + Duration::days(self.valid_days as i64);

        params.not_before = chrono_to_offset(now);
        params.not_after = chrono_to_offset(exp);

        let cert = params.self_signed(&key_pair)
            .map_err(|e| AppError::Certificate(e.to_string()))?;

        let cert_pem = cert.pem();
        let key_der = key_pair.serialize_der();
        let fingerprint = cert_fingerprint(&cert_pem)?;

        Ok(CertEntry {
            alias: self.alias,
            algorithm: self.algorithm,
            certificate_pem: cert_pem,
            private_key_pkcs8_der_b64: B64.encode(&key_der),
            fingerprint,
            created_at: now,
            expires_at: Some(exp),
            subject_cn: self.common_name,
            history: vec![],
        })
    }
}

fn chrono_to_offset(dt: DateTime<Utc>) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(dt.timestamp())
        .unwrap_or(OffsetDateTime::now_utc())
}

/// Génère une paire de clés RSA via le crate `rsa` (ring ne supporte pas
/// la génération RSA) et la charge dans rcgen via PKCS#8 DER.
fn generate_rsa_keypair(bits: usize) -> Result<KeyPair> {
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| AppError::Certificate(format!("RSA {}-bit generation: {}", bits, e)))?;

    // Exporté en PKCS#8 PEM puis rechargé dans rcgen
    // (ring — backend de rcgen — ne génère pas de clés RSA)
    let pem_str = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| AppError::Certificate(format!("RSA PKCS#8 PEM: {}", e)))?;

    KeyPair::from_pkcs8_pem_and_sign_algo(&pem_str, &PKCS_RSA_SHA256)
        .map_err(|e| AppError::Certificate(format!("rcgen key import: {}", e)))
}

pub fn import_pem(alias: String, pem_text: &str, private_key_pem: Option<&str>) -> Result<CertEntry> {
    let cert_pem = extract_cert_pem(pem_text)?;
    let fingerprint = cert_fingerprint(&cert_pem)?;
    let (subject_cn, expires_at, algorithm) = parse_cert_info(&cert_pem)?;

    let private_key_pkcs8_der_b64 = if let Some(key_pem) = private_key_pem {
        let pem_obj = pem::parse(key_pem)
            .map_err(|e| AppError::Certificate(format!("Invalid private key PEM: {}", e)))?;
        B64.encode(pem_obj.contents())
    } else {
        // Try extracting from the same PEM text if it contains a PRIVATE KEY block
        extract_key_from_pem(pem_text).unwrap_or_default()
    };

    Ok(CertEntry {
        alias,
        algorithm,
        certificate_pem: cert_pem,
        private_key_pkcs8_der_b64,
        fingerprint,
        created_at: Utc::now(),
        expires_at,
        subject_cn,
        history: vec![],
    })
}

pub fn import_der(alias: String, der_bytes: &[u8], private_key_der: Option<&[u8]>) -> Result<CertEntry> {
    let pem_text = pem_encode(&Pem::new("CERTIFICATE", der_bytes.to_vec()));
    let key_pem = private_key_der.map(|d| {
        pem_encode(&Pem::new("PRIVATE KEY", d.to_vec()))
    });
    import_pem(alias, &pem_text, key_pem.as_deref())
}

fn extract_cert_pem(pem_text: &str) -> Result<String> {
    let pems = pem_parse_many(pem_text)
        .map_err(|e| AppError::Certificate(e.to_string()))?;
    for pem_obj in pems {
        if pem_obj.tag() == "CERTIFICATE" {
            return Ok(pem_encode(&pem_obj));
        }
    }
    Err(AppError::Certificate("No CERTIFICATE block found in PEM".into()))
}

fn extract_key_from_pem(pem_text: &str) -> Option<String> {
    let pems = pem_parse_many(pem_text).ok()?;
    for pem_obj in pems {
        let tag = pem_obj.tag();
        if tag == "PRIVATE KEY" || tag == "RSA PRIVATE KEY" || tag == "EC PRIVATE KEY" {
            return Some(B64.encode(pem_obj.contents()));
        }
    }
    None
}

pub fn cert_fingerprint(cert_pem: &str) -> Result<String> {
    let pem_obj = pem_parse(cert_pem)
        .map_err(|e| AppError::Certificate(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(pem_obj.contents());
    let hash = hasher.finalize();
    let hex_parts: Vec<String> = hash.iter().map(|b| format!("{:02X}", b)).collect();
    Ok(format!("SHA256:{}", hex_parts.join(":")))
}

fn parse_cert_info(cert_pem: &str) -> Result<(String, Option<DateTime<Utc>>, KeyAlgorithm)> {
    use x509_parser::prelude::*;

    let pem_obj = pem_parse(cert_pem)
        .map_err(|e| AppError::Certificate(e.to_string()))?;
    let (_, cert) = X509Certificate::from_der(pem_obj.contents())
        .map_err(|e| AppError::Certificate(format!("X.509 parse: {:?}", e)))?;

    let cn = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let expires = {
        let ts = cert.validity().not_after.timestamp();
        DateTime::from_timestamp(ts, 0)
    };

    let algorithm = detect_algorithm(&cert);
    Ok((cn, expires, algorithm))
}

fn detect_algorithm(cert: &x509_parser::certificate::X509Certificate) -> KeyAlgorithm {
    let oid = cert.public_key().algorithm.algorithm.to_string();
    match oid.as_str() {
        "1.3.101.112" => KeyAlgorithm::Ed25519,
        "1.2.840.10045.2.1" => KeyAlgorithm::EcdsaP256,
        "1.2.840.113549.1.1.1" => KeyAlgorithm::Rsa2048,
        _ => KeyAlgorithm::Ed25519,
    }
}

pub fn export_public_pem(entry: &CertEntry) -> String {
    entry.certificate_pem.clone()
}

pub fn export_public_der(entry: &CertEntry) -> Result<Vec<u8>> {
    let pem_obj = pem_parse(&entry.certificate_pem)
        .map_err(|e| AppError::Certificate(e.to_string()))?;
    Ok(pem_obj.into_contents())
}
