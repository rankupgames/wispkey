/*
 * Author: Miguel A. Lopez
 * Company: RankUp Games LLC
 * Project: WispKey
 * Description: In-vault CA signing -- issues X.509 leaf certificates from a
 *              CA private key held in the vault without ever returning that key.
 * Created: 2026-08-25
 * Last Modified: 2026-08-25
 */

use std::net::IpAddr;

use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, RsaKeySize, SanType,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, X509Certificate};

const DEFAULT_VALIDITY_DAYS: u32 = 365;
const MAX_VALIDITY_DAYS: u32 = 3650;
const MAX_COMMON_NAME_LEN: usize = 64;
const MAX_SAN_COUNT: usize = 64;
const MAX_SAN_LEN: usize = 253;

/// Leaf key algorithm requested when WispKey generates the keypair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeafKeyType {
    #[default]
    EcP256,
    EcP384,
    Rsa2048,
    Rsa4096,
}

impl LeafKeyType {
    pub fn parse(value: &str) -> Result<Self, PkiError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ec-p256" | "p256" | "ecdsa-p256" => Ok(Self::EcP256),
            "ec-p384" | "p384" | "ecdsa-p384" => Ok(Self::EcP384),
            "rsa-2048" | "rsa2048" => Ok(Self::Rsa2048),
            "rsa-4096" | "rsa4096" => Ok(Self::Rsa4096),
            other => Err(PkiError::InvalidInput(format!(
                "unsupported key_type '{other}'. Use ec-p256, ec-p384, rsa-2048, or rsa-4096"
            ))),
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcP256 => "ec-p256",
            Self::EcP384 => "ec-p384",
            Self::Rsa2048 => "rsa-2048",
            Self::Rsa4096 => "rsa-4096",
        }
    }
}

/// Inputs for issuing a leaf certificate from in-vault CA material.
pub struct IssueCertRequest<'a> {
    pub ca_pem: &'a str,
    pub ca_cert_pem: Option<&'a str>,
    pub common_name: Option<&'a str>,
    pub san: &'a [String],
    pub validity_days: Option<u32>,
    pub key_type: Option<LeafKeyType>,
    pub csr_pem: Option<&'a str>,
}

/// Issued leaf material. The CA private key is never included.
#[derive(Debug)]
pub struct IssuedCertificate {
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub common_name: String,
    pub san: Vec<String>,
    pub validity_days: u32,
    pub key_type: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_hex: String,
    pub source: &'static str,
}

/// Errors from CA parsing, request validation, or certificate issuance.
#[derive(Debug, Error)]
pub enum PkiError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    InvalidCaMaterial(String),
    #[error("{0}")]
    IssueFailed(String),
}

/// Issues an X.509 v3 leaf certificate using CA material that stays in-process.
pub fn issue_certificate(request: IssueCertRequest<'_>) -> Result<IssuedCertificate, PkiError> {
    let validity_days = request.validity_days.unwrap_or(DEFAULT_VALIDITY_DAYS);
    validate_validity_days(validity_days)?;

    let (issuer, ca_not_after) = load_issuer(request.ca_pem, request.ca_cert_pem)?;
    let window = validity_window(validity_days);
    if window.not_after > ca_not_after {
        return Err(PkiError::InvalidInput(
            "validity_days extends past the CA certificate expiration".into(),
        ));
    }

    if let Some(csr_pem) = request.csr_pem {
        return issue_from_csr(
            &issuer,
            csr_pem,
            request.common_name,
            request.san,
            validity_days,
            window,
        );
    }

    let common_name =
        normalize_common_name(request.common_name.ok_or_else(|| {
            PkiError::InvalidInput("missing required argument: common_name".into())
        })?)?;
    let sans = resolve_sans(common_name, request.san)?;
    let key_type = request.key_type.unwrap_or_default();
    let leaf_key = generate_leaf_key(key_type)?;
    let params = leaf_params(
        common_name,
        &sans,
        window.not_before,
        window.not_after,
        key_type,
    )?;
    let cert = params.signed_by(&leaf_key, &issuer).map_err(|error| {
        PkiError::IssueFailed(format!("failed to sign leaf certificate: {error}"))
    })?;

    finish_issued(
        cert.pem(),
        Some(leaf_key.serialize_pem()),
        IssuedMeta {
            common_name,
            san: sans,
            validity_days,
            key_type: key_type.as_str().to_string(),
            window,
            source: "generated",
        },
    )
}

fn issue_from_csr(
    issuer: &Issuer<'_, KeyPair>,
    csr_pem: &str,
    common_name: Option<&str>,
    san: &[String],
    validity_days: u32,
    window: ValidityWindow,
) -> Result<IssuedCertificate, PkiError> {
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|error| PkiError::InvalidInput(format!("invalid CSR PEM: {error}")))?;

    let resolved_cn = match common_name {
        Some(value) => normalize_common_name(value)?.to_string(),
        None => csr_common_name(&csr.params).ok_or_else(|| {
            PkiError::InvalidInput(
                "CSR has no common name; pass common_name to set the leaf subject".into(),
            )
        })?,
    };

    let sans = if san.is_empty() {
        let existing = csr_sans(&csr.params);
        if existing.is_empty() {
            resolve_sans(&resolved_cn, &[])?
        } else {
            existing
        }
    } else {
        resolve_sans(&resolved_cn, san)?
    };

    csr.params.distinguished_name = distinguished_name(&resolved_cn);
    apply_leaf_extensions(
        &mut csr.params,
        &sans,
        window.not_before,
        window.not_after,
        None,
    )?;

    let key_type = detect_csr_key_type(&csr);
    let cert = csr
        .signed_by(issuer)
        .map_err(|error| PkiError::IssueFailed(format!("failed to sign CSR: {error}")))?;

    finish_issued(
        cert.pem(),
        None,
        IssuedMeta {
            common_name: &resolved_cn,
            san: sans,
            validity_days,
            key_type,
            window,
            source: "csr",
        },
    )
}

struct IssuedMeta<'a> {
    common_name: &'a str,
    san: Vec<String>,
    validity_days: u32,
    key_type: String,
    window: ValidityWindow,
    source: &'static str,
}

fn finish_issued(
    certificate_pem: String,
    private_key_pem: Option<String>,
    meta: IssuedMeta<'_>,
) -> Result<IssuedCertificate, PkiError> {
    let serial_hex = parse_serial_hex(&certificate_pem)?;
    if !certificate_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(PkiError::IssueFailed(
            "issued certificate was not valid PEM".into(),
        ));
    }

    Ok(IssuedCertificate {
        certificate_pem,
        private_key_pem,
        common_name: meta.common_name.to_string(),
        san: meta.san,
        validity_days: meta.validity_days,
        key_type: meta.key_type,
        not_before: rfc3339(meta.window.not_before.min(meta.window.now)),
        not_after: rfc3339(meta.window.not_after),
        serial_hex,
        source: meta.source,
    })
}

fn load_issuer(
    ca_pem: &str,
    ca_cert_override: Option<&str>,
) -> Result<(Issuer<'static, KeyPair>, OffsetDateTime), PkiError> {
    let blocks = split_pem_blocks(ca_pem);
    if blocks.is_empty() {
        return Err(PkiError::InvalidCaMaterial(
            "CA credential is not PEM; store the CA private key (and optionally the CA certificate) as a PEM bundle".into(),
        ));
    }

    let key_pem = blocks
        .iter()
        .find(|block| is_private_key_block(block))
        .cloned()
        .ok_or_else(|| {
            PkiError::InvalidCaMaterial(
                "CA credential does not contain a private key PEM block".into(),
            )
        })?;
    let bundled_cert = blocks
        .iter()
        .find(|block| is_certificate_block(block))
        .cloned();
    let cert_pem = ca_cert_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or(bundled_cert)
        .ok_or_else(|| {
            PkiError::InvalidCaMaterial(
                "CA certificate is required. Include it in the credential PEM bundle or pass ca_cert".into(),
            )
        })?;

    let ca_not_after = validate_ca_certificate(&cert_pem)?;
    let normalized_key = normalize_private_key_pem(&key_pem)?;
    let key_pair = KeyPair::from_pem(&normalized_key).map_err(|error| {
        PkiError::InvalidCaMaterial(format!(
            "CA private key is not a supported PEM key (PKCS#8, PKCS#1, or SEC1): {error}"
        ))
    })?;
    ensure_key_matches_certificate(&cert_pem, &key_pair)?;

    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair).map_err(|error| {
        PkiError::InvalidCaMaterial(format!("failed to load CA issuer: {error}"))
    })?;
    Ok((issuer, ca_not_after))
}

fn validate_ca_certificate(cert_pem: &str) -> Result<OffsetDateTime, PkiError> {
    let der = pem_der(cert_pem, "CERTIFICATE")?;
    let certificate = X509Certificate::from_der(&der)
        .map_err(|error| PkiError::InvalidCaMaterial(format!("invalid CA certificate: {error}")))?
        .1;

    match certificate.basic_constraints() {
        Ok(Some(extension)) if extension.value.ca => {}
        Ok(Some(_)) => {
            return Err(PkiError::InvalidCaMaterial(
                "supplied certificate is not a CA (Basic Constraints CA:FALSE)".into(),
            ));
        }
        Ok(None) => {
            return Err(PkiError::InvalidCaMaterial(
                "CA certificate must include Basic Constraints CA:TRUE".into(),
            ));
        }
        Err(error) => {
            return Err(PkiError::InvalidCaMaterial(format!(
                "failed to parse CA Basic Constraints: {error}"
            )));
        }
    }

    if let Ok(Some(extension)) = certificate.key_usage()
        && !extension.value.key_cert_sign()
    {
        return Err(PkiError::InvalidCaMaterial(
            "CA certificate Key Usage does not allow certificate signing".into(),
        ));
    }

    let not_after = certificate.validity().not_after.to_datetime();
    if not_after <= OffsetDateTime::now_utc() {
        return Err(PkiError::InvalidCaMaterial(
            "CA certificate is expired".into(),
        ));
    }

    Ok(not_after)
}

fn ensure_key_matches_certificate(cert_pem: &str, key_pair: &KeyPair) -> Result<(), PkiError> {
    let der = pem_der(cert_pem, "CERTIFICATE")?;
    let certificate = X509Certificate::from_der(&der)
        .map_err(|error| PkiError::InvalidCaMaterial(format!("invalid CA certificate: {error}")))?
        .1;
    let cert_raw = certificate.public_key().subject_public_key.data.as_ref();
    let key_raw = key_pair.public_key_raw();
    if cert_raw != key_raw {
        return Err(PkiError::InvalidCaMaterial(
            "CA private key does not match the CA certificate public key".into(),
        ));
    }
    Ok(())
}

fn normalize_private_key_pem(pem: &str) -> Result<String, PkiError> {
    let label = pem_label(pem).unwrap_or_default();
    match label.as_str() {
        "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => Ok(pem.to_string()),
        other => Err(PkiError::InvalidCaMaterial(format!(
            "unsupported private key PEM label '{other}'"
        ))),
    }
}

fn generate_leaf_key(key_type: LeafKeyType) -> Result<KeyPair, PkiError> {
    match key_type {
        LeafKeyType::EcP256 => {
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|error| {
                PkiError::IssueFailed(format!("failed to generate P-256 key: {error}"))
            })
        }
        LeafKeyType::EcP384 => {
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).map_err(|error| {
                PkiError::IssueFailed(format!("failed to generate P-384 key: {error}"))
            })
        }
        LeafKeyType::Rsa2048 => {
            KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, RsaKeySize::_2048).map_err(|error| {
                PkiError::IssueFailed(format!("failed to generate RSA-2048 key: {error}"))
            })
        }
        LeafKeyType::Rsa4096 => {
            KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, RsaKeySize::_4096).map_err(|error| {
                PkiError::IssueFailed(format!("failed to generate RSA-4096 key: {error}"))
            })
        }
    }
}

fn leaf_params(
    common_name: &str,
    sans: &[String],
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    key_type: LeafKeyType,
) -> Result<CertificateParams, PkiError> {
    let mut params = CertificateParams::new(Vec::new()).map_err(|error| {
        PkiError::IssueFailed(format!("failed to build certificate params: {error}"))
    })?;
    params.distinguished_name = distinguished_name(common_name);
    apply_leaf_extensions(&mut params, sans, not_before, not_after, Some(key_type))?;
    Ok(params)
}

fn apply_leaf_extensions(
    params: &mut CertificateParams,
    sans: &[String],
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    key_type: Option<LeafKeyType>,
) -> Result<(), PkiError> {
    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.not_before = not_before;
    params.not_after = not_after;
    params.key_usages.clear();
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    match key_type {
        Some(LeafKeyType::Rsa2048 | LeafKeyType::Rsa4096) => {
            params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        }
        Some(LeafKeyType::EcP256 | LeafKeyType::EcP384) => {
            params.key_usages.push(KeyUsagePurpose::KeyAgreement);
        }
        None => {
            params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
            params.key_usages.push(KeyUsagePurpose::KeyAgreement);
        }
    }
    params.extended_key_usages.clear();
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params.subject_alt_names = sans
        .iter()
        .map(|name| parse_san(name))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

fn parse_san(value: &str) -> Result<SanType, PkiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_SAN_LEN {
        return Err(PkiError::InvalidInput(format!(
            "SAN '{trimmed}' must be 1..{MAX_SAN_LEN} characters"
        )));
    }
    if trimmed.chars().any(|ch| ch.is_control() || ch == '\0') {
        return Err(PkiError::InvalidInput(
            "SAN names cannot contain control characters".into(),
        ));
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SanType::IpAddress(ip));
    }
    let ia5 = Ia5String::try_from(trimmed).map_err(|_| {
        PkiError::InvalidInput(format!(
            "SAN '{trimmed}' is not a valid DNS name or IP address"
        ))
    })?;
    Ok(SanType::DnsName(ia5))
}

fn resolve_sans(common_name: &str, sans: &[String]) -> Result<Vec<String>, PkiError> {
    if sans.len() > MAX_SAN_COUNT {
        return Err(PkiError::InvalidInput(format!(
            "at most {MAX_SAN_COUNT} SANs are allowed"
        )));
    }

    let mut resolved = Vec::new();
    for san in sans {
        let trimmed = san.trim();
        if trimmed.is_empty() {
            return Err(PkiError::InvalidInput("SAN entries cannot be empty".into()));
        }
        let _ = parse_san(trimmed)?;
        if !resolved.iter().any(|existing| existing == trimmed) {
            resolved.push(trimmed.to_string());
        }
    }

    if resolved.is_empty() {
        if parse_san(common_name).is_ok() {
            resolved.push(common_name.to_string());
        } else {
            return Err(PkiError::InvalidInput(
                "at least one SAN is required when common_name is not a DNS name or IP address"
                    .into(),
            ));
        }
    }

    Ok(resolved)
}

fn normalize_common_name(value: &str) -> Result<&str, PkiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PkiError::InvalidInput("common_name cannot be empty".into()));
    }
    if trimmed.len() > MAX_COMMON_NAME_LEN {
        return Err(PkiError::InvalidInput(format!(
            "common_name cannot exceed {MAX_COMMON_NAME_LEN} characters"
        )));
    }
    if trimmed.chars().any(|ch| ch.is_control() || ch == '\0') {
        return Err(PkiError::InvalidInput(
            "common_name cannot contain control characters".into(),
        ));
    }
    Ok(trimmed)
}

fn validate_validity_days(days: u32) -> Result<(), PkiError> {
    if days == 0 || days > MAX_VALIDITY_DAYS {
        return Err(PkiError::InvalidInput(format!(
            "validity_days must be between 1 and {MAX_VALIDITY_DAYS}"
        )));
    }
    Ok(())
}

struct ValidityWindow {
    now: OffsetDateTime,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

fn validity_window(validity_days: u32) -> ValidityWindow {
    let now = OffsetDateTime::now_utc();
    ValidityWindow {
        now,
        not_before: now - Duration::minutes(1),
        not_after: now + Duration::days(i64::from(validity_days)),
    }
}

fn csr_common_name(params: &CertificateParams) -> Option<String> {
    params
        .distinguished_name
        .iter()
        .find(|(kind, _)| **kind == DnType::CommonName)
        .map(|(_, value)| dn_value_text(value))
}

fn csr_sans(params: &CertificateParams) -> Vec<String> {
    params
        .subject_alt_names
        .iter()
        .map(san_to_string)
        .filter(|name| !name.is_empty())
        .collect()
}

fn san_to_string(san: &SanType) -> String {
    match san {
        SanType::DnsName(name) => name.as_str().to_string(),
        SanType::IpAddress(ip) => ip.to_string(),
        SanType::Rfc822Name(name) => name.as_str().to_string(),
        SanType::URI(uri) => uri.as_str().to_string(),
        SanType::OtherName(_) => String::new(),
        _ => String::new(),
    }
}

fn dn_value_text(value: &DnValue) -> String {
    match value {
        DnValue::Utf8String(text) => text.clone(),
        DnValue::PrintableString(text) => text.to_string(),
        DnValue::Ia5String(text) => text.to_string(),
        DnValue::TeletexString(text) => text.to_string(),
        DnValue::BmpString(_) | DnValue::UniversalString(_) => String::new(),
        _ => String::new(),
    }
}

fn detect_csr_key_type(csr: &CertificateSigningRequestParams) -> String {
    let alg = csr.public_key.algorithm();
    if alg == &rcgen::PKCS_ECDSA_P256_SHA256 {
        "ec-p256".into()
    } else if alg == &rcgen::PKCS_ECDSA_P384_SHA384 {
        "ec-p384".into()
    } else if alg == &rcgen::PKCS_RSA_SHA256
        || alg == &rcgen::PKCS_RSA_SHA384
        || alg == &rcgen::PKCS_RSA_SHA512
    {
        "rsa".into()
    } else {
        "unknown".into()
    }
}

fn parse_serial_hex(certificate_pem: &str) -> Result<String, PkiError> {
    let der = pem_der(certificate_pem, "CERTIFICATE")?;
    let certificate = X509Certificate::from_der(&der)
        .map_err(|error| {
            PkiError::IssueFailed(format!("failed to parse issued certificate: {error}"))
        })?
        .1;
    Ok(certificate
        .raw_serial()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| value.to_string())
}

fn split_pem_blocks(input: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut in_block = false;
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN ") {
            in_block = true;
            current.clear();
            current.push_str(trimmed);
            current.push('\n');
        } else if in_block {
            current.push_str(trimmed);
            current.push('\n');
            if trimmed.starts_with("-----END ") {
                blocks.push(current.clone());
                in_block = false;
            }
        }
    }
    blocks
}

fn pem_label(pem: &str) -> Option<String> {
    pem.lines().find_map(|line| {
        line.trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
            .map(str::to_string)
    })
}

fn is_private_key_block(block: &str) -> bool {
    matches!(
        pem_label(block).as_deref(),
        Some("PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY")
    )
}

fn is_certificate_block(block: &str) -> bool {
    pem_label(block).as_deref() == Some("CERTIFICATE")
}

fn pem_der(pem: &str, expected_label: &str) -> Result<Vec<u8>, PkiError> {
    let block = split_pem_blocks(pem)
        .into_iter()
        .find(|candidate| pem_label(candidate).as_deref() == Some(expected_label))
        .ok_or_else(|| {
            PkiError::InvalidCaMaterial(format!("missing {expected_label} PEM block"))
        })?;
    let body = block
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|error| PkiError::InvalidCaMaterial(format!("invalid PEM base64: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa};

    fn test_ca(is_ca: bool, key_cert_sign: bool) -> (String, String, String) {
        test_ca_with_validity(is_ca, key_cert_sign, None)
    }

    fn test_ca_with_validity(
        is_ca: bool,
        key_cert_sign: bool,
        not_after: Option<OffsetDateTime>,
    ) -> (String, String, String) {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "WispKey Test CA");
        params.is_ca = if is_ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::NoCa
        };
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        if key_cert_sign {
            params.key_usages.push(KeyUsagePurpose::KeyCertSign);
            params.key_usages.push(KeyUsagePurpose::CrlSign);
        }
        if let Some(not_after) = not_after {
            params.not_before = not_after - Duration::days(2);
            params.not_after = not_after;
        }
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let key_pem = key.serialize_pem();
        let cert_pem = cert.pem();
        let bundle = format!("{cert_pem}{key_pem}");
        (bundle, cert_pem, key_pem)
    }

    fn issue_ok(ca_pem: &str, cn: &str, san: &[&str], key_type: LeafKeyType) -> IssuedCertificate {
        issue_certificate(IssueCertRequest {
            ca_pem,
            ca_cert_pem: None,
            common_name: Some(cn),
            san: &san
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
            validity_days: Some(30),
            key_type: Some(key_type),
            csr_pem: None,
        })
        .unwrap()
    }

    #[test]
    fn issues_ec_p256_leaf_signed_by_ca() {
        let (bundle, cert_pem, key_pem) = test_ca(true, true);
        let issued = issue_ok(
            &bundle,
            "blackbox-exporter",
            &["blackbox.internal"],
            LeafKeyType::EcP256,
        );

        assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));
        let leaf_key = issued.private_key_pem.expect("generated key");
        assert!(leaf_key.contains("BEGIN PRIVATE KEY"));
        assert!(!issued.certificate_pem.contains(key_pem.trim()));
        assert!(!leaf_key.contains(key_pem.trim()));
        assert_eq!(issued.common_name, "blackbox-exporter");
        assert_eq!(issued.san, vec!["blackbox.internal".to_string()]);
        assert_eq!(issued.source, "generated");
        assert_eq!(issued.key_type, "ec-p256");
        assert!(!issued.serial_hex.is_empty());

        let leaf_der = pem_der(&issued.certificate_pem, "CERTIFICATE").unwrap();
        let ca_der = pem_der(&cert_pem, "CERTIFICATE").unwrap();
        let leaf = X509Certificate::from_der(&leaf_der).unwrap().1;
        let ca = X509Certificate::from_der(&ca_der).unwrap().1;
        leaf.verify_signature(Some(ca.public_key())).unwrap();
        assert_eq!(
            leaf.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "blackbox-exporter"
        );
    }

    #[test]
    fn issues_rsa_2048_leaf() {
        let (bundle, cert_pem, _) = test_ca(true, true);
        let issued = issue_ok(&bundle, "rsa-leaf.internal", &[], LeafKeyType::Rsa2048);
        assert_eq!(issued.key_type, "rsa-2048");
        let leaf_der = pem_der(&issued.certificate_pem, "CERTIFICATE").unwrap();
        let ca_der = pem_der(&cert_pem, "CERTIFICATE").unwrap();
        X509Certificate::from_der(&leaf_der)
            .unwrap()
            .1
            .verify_signature(Some(
                X509Certificate::from_der(&ca_der).unwrap().1.public_key(),
            ))
            .unwrap();
    }

    #[test]
    fn signs_csr_without_returning_a_key() {
        let (bundle, _, key_pem) = test_ca(true, true);
        let mut params = CertificateParams::new(vec!["csr.internal".into()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "csr-leaf");
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = params.serialize_request(&leaf_key).unwrap();

        let issued = issue_certificate(IssueCertRequest {
            ca_pem: &bundle,
            ca_cert_pem: None,
            common_name: None,
            san: &[],
            validity_days: Some(14),
            key_type: None,
            csr_pem: Some(&csr.pem().unwrap()),
        })
        .unwrap();

        assert!(issued.private_key_pem.is_none());
        assert_eq!(issued.source, "csr");
        assert_eq!(issued.common_name, "csr-leaf");
        assert!(issued.san.contains(&"csr.internal".to_string()));
        assert!(!issued.certificate_pem.contains(key_pem.trim()));
    }

    #[test]
    fn accepts_key_only_credential_with_separate_ca_cert() {
        let (_, cert_pem, key_pem) = test_ca(true, true);
        let issued = issue_certificate(IssueCertRequest {
            ca_pem: &key_pem,
            ca_cert_pem: Some(&cert_pem),
            common_name: Some("svc.internal"),
            san: &[],
            validity_days: Some(7),
            key_type: Some(LeafKeyType::EcP256),
            csr_pem: None,
        })
        .unwrap();
        assert_eq!(issued.common_name, "svc.internal");
        assert_eq!(issued.san, vec!["svc.internal".to_string()]);
    }

    #[test]
    fn rejects_missing_ca_certificate() {
        let (_, _, key_pem) = test_ca(true, true);
        let error = issue_certificate(IssueCertRequest {
            ca_pem: &key_pem,
            ca_cert_pem: None,
            common_name: Some("svc"),
            san: &["svc.internal".into()],
            validity_days: Some(7),
            key_type: None,
            csr_pem: None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("CA certificate is required"));
    }

    #[test]
    fn rejects_end_entity_used_as_ca() {
        let (bundle, _, _) = test_ca(false, false);
        let error = issue_certificate(IssueCertRequest {
            ca_pem: &bundle,
            ca_cert_pem: None,
            common_name: Some("svc.internal"),
            san: &[],
            validity_days: Some(7),
            key_type: None,
            csr_pem: None,
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("not a CA")
                || error.to_string().contains("Basic Constraints"),
            "{error}"
        );
    }

    #[test]
    fn rejects_mismatched_ca_key() {
        let (_, cert_pem, _) = test_ca(true, true);
        let (_, _, other_key) = test_ca(true, true);
        let error = issue_certificate(IssueCertRequest {
            ca_pem: &other_key,
            ca_cert_pem: Some(&cert_pem),
            common_name: Some("svc.internal"),
            san: &[],
            validity_days: Some(7),
            key_type: None,
            csr_pem: None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn rejects_invalid_validity_and_key_type() {
        assert!(LeafKeyType::parse("dsa").is_err());
        assert!(validate_validity_days(0).is_err());
        assert!(validate_validity_days(3651).is_err());
        assert!(normalize_common_name("").is_err());
        assert!(normalize_common_name(&"n".repeat(65)).is_err());
    }

    #[test]
    fn parses_ip_sans() {
        let san = parse_san("127.0.0.1").unwrap();
        assert!(matches!(san, SanType::IpAddress(IpAddr::V4(_))));
        let (bundle, _, _) = test_ca(true, true);
        let issued = issue_ok(&bundle, "localhost", &["127.0.0.1"], LeafKeyType::EcP256);
        assert_eq!(issued.san, vec!["127.0.0.1".to_string()]);
    }

    #[test]
    fn rejects_expired_ca_and_leaf_past_ca_expiry() {
        let expired = OffsetDateTime::now_utc() - Duration::days(1);
        let (bundle, _, _) = test_ca_with_validity(true, true, Some(expired));
        let error = issue_certificate(IssueCertRequest {
            ca_pem: &bundle,
            ca_cert_pem: None,
            common_name: Some("svc.internal"),
            san: &[],
            validity_days: Some(7),
            key_type: None,
            csr_pem: None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("expired"), "{error}");

        let soon = OffsetDateTime::now_utc() + Duration::days(3);
        let (short_ca, _, _) = test_ca_with_validity(true, true, Some(soon));
        let error = issue_certificate(IssueCertRequest {
            ca_pem: &short_ca,
            ca_cert_pem: None,
            common_name: Some("svc.internal"),
            san: &[],
            validity_days: Some(30),
            key_type: None,
            csr_pem: None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("extends past the CA"), "{error}");
    }
}
