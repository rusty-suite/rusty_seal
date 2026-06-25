use std::path::Path;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use pem::parse as pem_parse;

use crate::error::{AppError, Result};
use crate::vault::types::{CertEntry, KeyAlgorithm};

/// Returns true if this file should be signed with Authenticode (embedded), not sidecar.
pub fn is_authenticode_target(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .as_deref(),
        Some("ps1" | "psm1" | "psd1")
    )
}

/// Validates that the cert+algorithm combination is compatible with Windows Authenticode.
pub fn check_authenticode_compat(cert: &CertEntry) -> Result<()> {
    if cert.algorithm == KeyAlgorithm::Ed25519 {
        return Err(AppError::Signing(
            "Ed25519 is not supported by Windows Authenticode. \
             Use RSA 2048/4096 or ECDSA P-256/P-384 for script signing."
                .into(),
        ));
    }
    if cert.private_key_pkcs8_der_b64.is_empty() {
        return Err(AppError::Signing("No private key available".into()));
    }
    if !has_code_signing_eku(cert)? {
        return Err(AppError::Signing(
            "This certificate does not have the Code Signing EKU (1.3.6.1.5.5.7.3.3). \
             Recreate the certificate — new certificates include this EKU automatically."
                .into(),
        ));
    }
    Ok(())
}

/// Signs a PowerShell script file using Windows Authenticode via PowerShell.
/// The signature is embedded directly in the script file (in-place).
#[cfg(target_os = "windows")]
pub fn sign_script(file_path: &Path, cert: &CertEntry) -> Result<()> {
    check_authenticode_compat(cert)?;

    let pfx_bytes = build_pfx(cert)?;

    // Write PFX to a temp file to avoid command-line length limits
    let pfx_path = std::env::temp_dir().join(format!(
        "rseal_{}.pfx",
        uuid::Uuid::new_v4().simple()
    ));

    std::fs::write(&pfx_path, &pfx_bytes)
        .map_err(|e| AppError::Signing(format!("Temp file: {}", e)))?;

    let result = run_powershell_sign(file_path, &pfx_path);

    std::fs::remove_file(&pfx_path).ok();

    result
}

#[cfg(not(target_os = "windows"))]
pub fn sign_script(_file_path: &Path, _cert: &CertEntry) -> Result<()> {
    Err(AppError::Signing(
        "Authenticode signing is only supported on Windows".into(),
    ))
}

#[cfg(target_os = "windows")]
fn run_powershell_sign(file_path: &Path, pfx_path: &Path) -> Result<()> {
    let file_str = file_path.to_string_lossy().replace('\'', "''");
    let pfx_str = pfx_path.to_string_lossy().replace('\'', "''");

    let ps = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $pfxBytes = [System.IO.File]::ReadAllBytes('{pfx}')\n\
         $secPw = ConvertTo-SecureString 'rseal' -AsPlainText -Force\n\
         $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet\n\
         $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxBytes, $secPw, $flags)\n\
         $result = Set-AuthenticodeSignature -FilePath '{file}' -Certificate $cert -HashAlgorithm SHA256\n\
         Write-Output $result.Status",
        pfx = pfx_str,
        file = file_str
    );

    let output = std::process::Command::new("powershell")
        .args(["-NonInteractive", "-NoProfile", "-Command", &ps])
        .output()
        .map_err(|e| AppError::Signing(format!("PowerShell unavailable: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Signing(format!(
            "Authenticode signing failed: {}",
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_string();

    match stdout.as_str() {
        // Valid = cert is trusted, UnknownError = self-signed (not in trusted store).
        // Both mean the signature WAS embedded in the file — that's what we want.
        "Valid" | "UnknownError" => Ok(()),
        "NotSupportedFileFormat" => Err(AppError::Signing(
            "File format not supported for Authenticode".into(),
        )),
        other if other.is_empty() => Ok(()),
        other => Err(AppError::Signing(format!("Authenticode status: {}", other))),
    }
}

fn build_pfx(cert: &CertEntry) -> Result<Vec<u8>> {
    let key_der = B64.decode(&cert.private_key_pkcs8_der_b64)
        .map_err(|e| AppError::Signing(format!("Key decode: {}", e)))?;

    let cert_der = pem_parse(&cert.certificate_pem)
        .map_err(|e| AppError::Signing(format!("Cert PEM: {}", e)))?
        .into_contents();

    let pfx = p12::PFX::new(&cert_der, &key_der, None, "rseal", &cert.alias)
        .ok_or_else(|| AppError::Signing("Failed to build PFX from certificate".into()))?;

    Ok(pfx.to_der())
}

fn has_code_signing_eku(cert: &CertEntry) -> Result<bool> {
    use x509_parser::prelude::*;
    use x509_parser::extensions::ParsedExtension;

    if cert.certificate_pem.is_empty() {
        return Ok(false);
    }

    let pem_obj = pem_parse(&cert.certificate_pem)
        .map_err(|e| AppError::Signing(format!("Cert PEM: {}", e)))?;
    let (_, x509) = X509Certificate::from_der(pem_obj.contents())
        .map_err(|e| AppError::Signing(format!("X.509 parse: {:?}", e)))?;

    let mut found_eku = false;
    for ext in x509.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            found_eku = true;
            if eku.code_signing || eku.any {
                return Ok(true);
            }
        }
    }

    // No EKU extension = unrestricted (treat as compatible)
    Ok(!found_eku)
}
