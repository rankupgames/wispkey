//! Strict, secret-free configuration preflight for the first cross-node operation slice.
//! Parsing does not authenticate a requester or contact a destination.

use std::collections::HashSet;
use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_CATALOG_BYTES: usize = 64 * 1024;
const MAX_OPERATIONS: usize = 32;
const MAX_FIELD_BYTES: usize = 255;

#[derive(Clone, Serialize)]
pub struct Catalog {
    pub version: u32,
    pub operations: Vec<Operation>,
}

#[derive(Clone, Serialize)]
pub struct Operation {
    pub id: String,
    pub project_id: String,
    pub credential_id: String,
    pub requester_principal: String,
    pub environment_id: String,
    pub target_id: String,
    pub expires_at: DateTime<Utc>,
    pub max_grant_seconds: u32,
    pub max_runtime_seconds: u32,
    pub connect_timeout_seconds: u32,
    pub max_concurrency: u32,
    pub kind: OperationKind,
}

#[derive(Clone, Serialize)]
pub enum OperationKind {
    SshHelper(SshTarget),
    KubernetesSecret(super::environment::KubernetesTarget),
    PostgresPassword(super::postgres::PostgresTarget),
}

#[derive(Clone, Serialize)]
pub struct SshTarget {
    pub address: IpAddr,
    pub port: u16,
    pub account: String,
    pub host_key_algorithm: String,
    pub host_key_sha256: String,
    pub helper_path: String,
    pub identity_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    version: u32,
    operation: Vec<RawOperation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOperation {
    id: String,
    kind: String,
    project_id: String,
    credential_id: String,
    requester_principal: String,
    environment_id: String,
    target_id: String,
    expires_at: String,
    max_grant_seconds: u32,
    max_runtime_seconds: u32,
    connect_timeout_seconds: u32,
    max_concurrency: u32,
    ssh: Option<RawSshTarget>,
    kubernetes: Option<super::environment::KubernetesTarget>,
    postgres: Option<super::postgres::PostgresTarget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSshTarget {
    address: String,
    port: u16,
    account: String,
    host_key_algorithm: String,
    host_key_sha256: String,
    helper_path: String,
    identity_file: String,
}

/// Parses bounded v1 preflight or v2 runtime catalogs. Errors never contain input text.
pub fn parse_catalog(raw: &str) -> Result<Catalog, &'static str> {
    if raw.len() > MAX_CATALOG_BYTES {
        return Err("catalog too large");
    }
    if raw.bytes().any(|byte| {
        !byte.is_ascii() || (byte.is_ascii_control() && !matches!(byte, b'\r' | b'\n' | b'\t'))
    }) {
        return Err("invalid catalog");
    }
    let parsed: RawCatalog = toml::from_str(raw).map_err(|_| "invalid catalog")?;
    if !matches!(parsed.version, 1 | 2) {
        return Err("unsupported catalog version");
    }
    if parsed.operation.is_empty() || parsed.operation.len() > MAX_OPERATIONS {
        return Err("invalid operation count");
    }

    let mut seen = HashSet::with_capacity(parsed.operation.len());
    let mut operations = Vec::with_capacity(parsed.operation.len());
    for operation in parsed.operation {
        if !valid_slug(&operation.id) || !seen.insert(operation.id.clone()) {
            return Err("invalid operation id");
        }
        if operation.kind != "ssh-helper"
            && !(parsed.version == 2
                && matches!(
                    operation.kind.as_str(),
                    "kubernetes-secret" | "postgres-password"
                ))
        {
            return Err("unsupported operation kind");
        }
        if operation.project_id != "default" && !canonical_uuid(&operation.project_id) {
            return Err("invalid project id");
        }
        if !canonical_uuid(&operation.credential_id) {
            return Err("invalid credential id");
        }
        let instance_principal = operation
            .requester_principal
            .strip_prefix("instance:")
            .is_some_and(canonical_uuid);
        if (parsed.version == 1 && !valid_principal(&operation.requester_principal))
            || (parsed.version == 2 && !instance_principal)
        {
            return Err("invalid requester principal");
        }
        if !valid_slug(&operation.environment_id) || !valid_slug(&operation.target_id) {
            return Err("invalid target scope");
        }
        let expires_at = DateTime::parse_from_rfc3339(&operation.expires_at)
            .map_err(|_| "invalid expiry")?
            .with_timezone(&Utc);
        if expires_at.to_rfc3339_opts(SecondsFormat::Secs, true) != operation.expires_at
            || expires_at <= Utc::now()
        {
            return Err("invalid expiry");
        }
        if !(1..=300).contains(&operation.max_grant_seconds)
            || !(1..=60).contains(&operation.max_runtime_seconds)
            || !(1..=30).contains(&operation.connect_timeout_seconds)
            || operation.connect_timeout_seconds > operation.max_runtime_seconds
            || operation.max_concurrency != 1
        {
            return Err("invalid operation bounds");
        }
        let kind = match (
            operation.kind.as_str(),
            operation.ssh,
            operation.kubernetes,
            operation.postgres,
        ) {
            ("ssh-helper", Some(ssh), None, None) => {
                OperationKind::SshHelper(parse_ssh_target(ssh)?)
            }
            ("kubernetes-secret", None, Some(target), None) if parsed.version == 2 => {
                target.validate()?;
                if target.environment_id != operation.environment_id
                    || target.provider_credential_id == operation.credential_id
                {
                    return Err("invalid environment credential scope");
                }
                OperationKind::KubernetesSecret(target)
            }
            ("postgres-password", None, None, Some(target)) if parsed.version == 2 => {
                target.validate()?;
                if target.environment_id != operation.environment_id
                    || target.provider_credential_id == operation.credential_id
                    || target.previous_credential_id == operation.credential_id
                {
                    return Err("invalid database credential scope");
                }
                OperationKind::PostgresPassword(target)
            }
            _ => return Err("invalid operation target"),
        };
        operations.push(Operation {
            id: operation.id,
            project_id: operation.project_id,
            credential_id: operation.credential_id,
            requester_principal: operation.requester_principal,
            environment_id: operation.environment_id,
            target_id: operation.target_id,
            expires_at,
            max_grant_seconds: operation.max_grant_seconds,
            max_runtime_seconds: operation.max_runtime_seconds,
            connect_timeout_seconds: operation.connect_timeout_seconds,
            max_concurrency: operation.max_concurrency,
            kind,
        });
    }
    Ok(Catalog {
        version: parsed.version,
        operations,
    })
}

fn parse_ssh_target(raw: RawSshTarget) -> Result<SshTarget, &'static str> {
    if !bounded_ascii(&raw.address) || raw.address.contains('%') || raw.port == 0 {
        return Err("invalid ssh destination");
    }
    let address = raw
        .address
        .parse::<IpAddr>()
        .map_err(|_| "invalid ssh destination")?;
    if address.to_string() != raw.address
        || address.is_unspecified()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(v4) if v4 == std::net::Ipv4Addr::BROADCAST)
    {
        return Err("invalid ssh destination");
    }
    if !valid_account(&raw.account) {
        return Err("invalid ssh account");
    }
    if raw.host_key_algorithm != "ssh-ed25519" {
        return Err("invalid host key algorithm");
    }
    let Some(fingerprint) = raw.host_key_sha256.strip_prefix("SHA256:") else {
        return Err("invalid host key fingerprint");
    };
    let decoded = STANDARD_NO_PAD
        .decode(fingerprint)
        .map_err(|_| "invalid host key fingerprint")?;
    if decoded.len() != 32 || STANDARD_NO_PAD.encode(decoded) != fingerprint {
        return Err("invalid host key fingerprint");
    }
    if !valid_helper_path(&raw.helper_path) {
        return Err("invalid helper path");
    }
    if !valid_identity_path(&raw.identity_file) {
        return Err("invalid identity file path");
    }
    Ok(SshTarget {
        address,
        port: raw.port,
        account: raw.account,
        host_key_algorithm: raw.host_key_algorithm,
        host_key_sha256: raw.host_key_sha256,
        helper_path: raw.helper_path,
        identity_file: raw.identity_file,
    })
}

fn bounded_ascii(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FIELD_BYTES
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_slug(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn canonical_uuid(value: &str) -> bool {
    bounded_ascii(value)
        && Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn valid_principal(value: &str) -> bool {
    if !bounded_ascii(value) {
        return false;
    }
    if let Some(uid) = value.strip_prefix("unix-uid:") {
        return !uid.is_empty()
            && (uid == "0" || !uid.starts_with('0'))
            && uid.bytes().all(|byte| byte.is_ascii_digit())
            && uid.parse::<u32>().is_ok();
    }
    if let Some(sid) = value.strip_prefix("windows-sid:S-1-") {
        let parts: Vec<_> = sid.split('-').collect();
        if !(2..=16).contains(&parts.len()) {
            return false;
        }
        let canonical_number = |part: &str| {
            !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        };
        return canonical_number(parts[0])
            && parts[0]
                .parse::<u64>()
                .is_ok_and(|authority| authority < (1_u64 << 48))
            && parts[1..]
                .iter()
                .all(|part| canonical_number(part) && part.parse::<u32>().is_ok());
    }
    false
}

fn valid_account(value: &str) -> bool {
    value != "root"
        && value.len() <= 32
        && value
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first == b'_')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn valid_helper_path(value: &str) -> bool {
    valid_absolute_path(value, false)
}

fn valid_identity_path(value: &str) -> bool {
    if valid_absolute_path(value, true) {
        return true;
    }
    // Windows OpenSSH accepts forward slashes. Reject ambiguous relative,
    // UNC/device, backslash, and alternate-data-stream path forms.
    let bytes = value.as_bytes();
    if !bounded_ascii(value)
        || bytes.len() < 4
        || !bytes[0].is_ascii_uppercase()
        || bytes[1] != b':'
        || bytes[2] != b'/'
    {
        return false;
    }
    valid_path_segments(&value[3..], true)
}

fn valid_absolute_path(value: &str, identity: bool) -> bool {
    if !bounded_ascii(value) || !value.starts_with('/') || value == "/" {
        return false;
    }
    valid_path_segments(&value[1..], identity)
}

fn valid_path_segments(path: &str, identity: bool) -> bool {
    path.split('/').all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-')
                    || (identity && byte == b'.')
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> String {
        format!(
            r#"version = 1
[[operation]]
id = "maintenance"
kind = "ssh-helper"
project_id = "default"
credential_id = "00000000-0000-4000-8000-000000000001"
requester_principal = "unix-uid:1000"
environment_id = "dev-one"
target_id = "node-one"
expires_at = "2099-01-01T00:00:00Z"
max_grant_seconds = 300
max_runtime_seconds = 60
connect_timeout_seconds = 30
max_concurrency = 1
[operation.ssh]
address = "192.0.2.1"
port = 22
account = "restricted"
host_key_algorithm = "ssh-ed25519"
host_key_sha256 = "SHA256:{}"
helper_path = "/usr/local/libexec/wispkey-helper"
identity_file = "/home/runner/.ssh/restricted_key"
"#,
            STANDARD_NO_PAD.encode([0x5au8; 32])
        )
    }

    fn replace(raw: &str, from: &str, to: &str) -> String {
        assert!(raw.contains(from));
        raw.replacen(from, to, 1)
    }

    #[test]
    fn accepts_one_bounded_ssh_helper() {
        let catalog = parse_catalog(&valid()).unwrap();
        assert_eq!(catalog.operations.len(), 1);
        assert!(matches!(
            catalog.operations[0].kind,
            OperationKind::SshHelper(_)
        ));
    }

    #[test]
    fn runtime_catalog_requires_canonical_enrolled_instance() {
        let raw = valid().replace("version = 1", "version = 2").replace(
            "unix-uid:1000",
            "instance:5af05c13-1c0a-4394-a7a3-7f457ff74a40",
        );
        assert_eq!(parse_catalog(&raw).unwrap().version, 2);
        for bad in [
            "instance:nil",
            "instance:00000000-0000-0000-0000-000000000000",
            "unix-uid:1000",
            "agent:worker",
        ] {
            assert!(
                parse_catalog(&raw.replace("instance:5af05c13-1c0a-4394-a7a3-7f457ff74a40", bad))
                    .is_err()
            );
        }
    }

    #[test]
    fn denies_unknown_or_unsupported_surfaces() {
        let valid = valid();
        for bad in [
            replace(&valid, "version = 1", "version = 2"),
            replace(
                &valid,
                "kind = \"ssh-helper\"",
                "kind = \"kubernetes-secret\"",
            ),
            replace(
                &valid,
                "kind = \"ssh-helper\"",
                "kind = \"ssh-helper\"\ncommand = \"sh -c secret\"",
            ),
            replace(
                &valid,
                "[operation.ssh]",
                "password_channel = \"env\"\n[operation.ssh]",
            ),
            replace(
                &valid,
                "port = 22",
                "port = 22\nproxy_jump = \"other-host\"",
            ),
            replace(&valid, "port = 22", "port = 22\naskpass = true"),
            replace(
                &valid,
                "port = 22",
                "port = 22\nknown_hosts = \"/tmp/attacker\"",
            ),
            replace(&valid, "version = 1", "version = 1\nextra = \"secret\""),
            format!("{valid}# nonascii ☃\n"),
            format!("{valid}# control \u{0000}\n"),
        ] {
            assert!(parse_catalog(&bad).is_err());
        }
    }

    #[test]
    fn denies_scope_identity_and_expiry_substitution() {
        let valid = valid();
        for bad in [
            replace(&valid, "unix-uid:1000", "agent-supplied"),
            replace(&valid, "unix-uid:1000", "unix-uid:01000"),
            replace(&valid, "unix-uid:1000", "windows-sid:S-1-5-x"),
            replace(&valid, "dev-one", "dev_☃"),
            replace(&valid, "node-one", "node-one\nother"),
            replace(&valid, "2099-01-01T00:00:00Z", "2020-01-01T00:00:00Z"),
            replace(&valid, "2099-01-01T00:00:00Z", "2099-01-01T00:00:00+01:00"),
            replace(&valid, "00000000-0000-4000-8000-000000000001", "missing"),
            replace(
                &valid,
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-0000-0000-000000000000",
            ),
            replace(
                &valid,
                "project_id = \"default\"",
                "project_id = \"00000000-0000-0000-0000-000000000000\"",
            ),
        ] {
            assert!(parse_catalog(&bad).is_err());
        }
    }

    #[test]
    fn accepts_windows_sid_principal_syntax() {
        let raw = replace(&valid(), "unix-uid:1000", "windows-sid:S-1-5-21-42");
        assert!(parse_catalog(&raw).is_ok());
        let max_authority = replace(
            &valid(),
            "unix-uid:1000",
            "windows-sid:S-1-281474976710655-42",
        );
        assert!(parse_catalog(&max_authority).is_ok());
        let too_large_authority = replace(
            &valid(),
            "unix-uid:1000",
            "windows-sid:S-1-281474976710656-42",
        );
        assert!(parse_catalog(&too_large_authority).is_err());
        let many_subauthorities = format!("windows-sid:S-1-5{}", "-1".repeat(16));
        assert!(parse_catalog(&replace(&valid(), "unix-uid:1000", &many_subauthorities)).is_err());
    }

    #[test]
    fn accepts_canonical_windows_identity_file_path() {
        let raw = replace(
            &valid(),
            "/home/runner/.ssh/restricted_key",
            "C:/Users/runner/.ssh/restricted_key",
        );
        assert!(parse_catalog(&raw).is_ok());
        for path in [
            "C:relative/key",
            "c:/Users/runner/key",
            "C:/Users/../key",
            "C:/Users/runner/key:ads",
            "C:/Users/runner\\key",
            "\\\\server\\share\\key",
            "C:/",
        ] {
            let bad = replace(&valid(), "/home/runner/.ssh/restricted_key", path);
            assert!(parse_catalog(&bad).is_err(), "accepted unsafe path form");
        }
    }

    #[test]
    fn denies_ssh_aliases_keys_and_untrusted_paths() {
        let valid = valid();
        for bad in [
            replace(&valid, "192.0.2.1", "example.invalid"),
            replace(&valid, "192.0.2.1", "192.0.2.01"),
            replace(&valid, "192.0.2.1", "fe80::1%eth0"),
            replace(&valid, "192.0.2.1", "0.0.0.0"),
            replace(&valid, "192.0.2.1", "224.0.0.1"),
            replace(&valid, "192.0.2.1", "255.255.255.255"),
            replace(&valid, "port = 22", "port = 0"),
            replace(&valid, "account = \"restricted\"", "account = \"root\""),
            replace(&valid, "restricted", "root;id"),
            replace(&valid, "ssh-ed25519", "ssh-rsa"),
            replace(&valid, "SHA256:", "MD5:"),
            replace(&valid, "SHA256:", "SHA256:abc"),
            replace(
                &valid,
                "/usr/local/libexec/wispkey-helper",
                "/usr/../bin/sh",
            ),
            replace(
                &valid,
                "/usr/local/libexec/wispkey-helper",
                "/tmp/helper.sh",
            ),
            replace(&valid, "/home/runner/.ssh/restricted_key", "../key"),
        ] {
            assert!(parse_catalog(&bad).is_err());
        }
    }

    #[test]
    fn denies_unbounded_limits_duplicates_and_oversize() {
        let valid = valid();
        let block = valid.trim_start_matches("version = 1\n");
        let mut too_many = String::from("version = 1\n");
        for index in 0..=MAX_OPERATIONS {
            too_many.push_str(&replace(
                block,
                "id = \"maintenance\"",
                &format!("id = \"maintenance-{index}\""),
            ));
        }
        for bad in [
            replace(&valid, "max_grant_seconds = 300", "max_grant_seconds = 301"),
            replace(
                &valid,
                "max_runtime_seconds = 60",
                "max_runtime_seconds = 0",
            ),
            replace(
                &valid,
                "connect_timeout_seconds = 30",
                "connect_timeout_seconds = 31",
            ),
            replace(&valid, "max_concurrency = 1", "max_concurrency = 2"),
            replace(
                &valid,
                "max_runtime_seconds = 60",
                "max_runtime_seconds = 10",
            ),
            format!("{valid}{}", valid.trim_start_matches("version = 1\n")),
            too_many,
            format!("{valid}{}", "#".repeat(MAX_CATALOG_BYTES)),
        ] {
            assert!(parse_catalog(&bad).is_err());
        }
    }

    #[test]
    fn errors_do_not_reflect_input() {
        let raw = replace(&valid(), "port = 22", "port = \"secret-canary\"");
        let error = parse_catalog(&raw).err().unwrap();
        assert!(!error.contains("secret-canary"));
    }
}
