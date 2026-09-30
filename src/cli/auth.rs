use std::fs::File;
use std::io::Read;

use chrono::{DateTime, Utc};

use crate::core::auth::{AuthBundle, AuthRegistration, ProviderExpiry};
use crate::core::{self, Vault};

use super::shared::{json_output, print_json};

const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;

pub struct AuthRegisterArgs<'a> {
    pub name: &'a str,
    pub project: &'a str,
    pub provider: &'a str,
    pub account: &'a str,
    pub origins: Vec<String>,
    pub provider_expiry: &'a str,
    pub use_until: Option<&'a str>,
}

/// Opt in an existing credential without reading or displaying its secret.
pub fn handle_auth_register(args: AuthRegisterArgs<'_>) {
    let provider_expiry = match args.provider_expiry {
        "unknown" => ProviderExpiry::Unknown,
        "non-expiring" => ProviderExpiry::NonExpiring,
        value => ProviderExpiry::ExpiresAt {
            at: parse_timestamp(value, "provider-expiry"),
        },
    };
    let use_until = args
        .use_until
        .map(|value| parse_timestamp(value, "use-until"));
    if provider_expiry == ProviderExpiry::Unknown && use_until.is_none() {
        fail::<(), _>("unknown provider expiry requires a finite --use-until timestamp");
    }
    let vault = open_vault();
    let auth = vault
        .register_auth(
            args.project,
            args.name,
            AuthRegistration {
                provider: args.provider.to_string(),
                account: args.account.to_string(),
                origins: args.origins,
                provider_expiry,
                use_until,
            },
        )
        .unwrap_or_else(fail);
    if json_output() {
        print_json(serde_json::json!({
            "ok": true,
            "name": args.name,
            "project": args.project,
            "auth": auth,
        }));
    } else {
        println!("Auth registered for '{}' in '{}'.", args.name, args.project);
        println!("Auth ID:  {}", auth.id);
        println!("Revision: {}", auth.revision);
    }
}

/// Inventory includes unregistered legacy credentials, but never their tokens.
pub fn handle_auth_list(project: Option<&str>) {
    let project = project
        .map(str::to_owned)
        .unwrap_or_else(core::resolve_active_project);
    let inventory = open_vault()
        .list_auth_inventory(&project)
        .unwrap_or_else(fail);
    if json_output() {
        print_json(serde_json::json!({ "project": project, "credentials": inventory }));
    } else if inventory.is_empty() {
        println!("No credentials stored in '{project}'.");
    } else {
        println!(
            "{:<24} {:<20} {:<16} AUTH ID",
            "NAME", "PARTITION", "STATUS"
        );
        for item in inventory {
            let (status, id) = match &item.auth {
                Some(auth) if auth.revoked_at.is_some() => ("revoked", auth.id.as_str()),
                Some(auth) => ("registered", auth.id.as_str()),
                None => ("unregistered", "-"),
            };
            println!(
                "{:<24} {:<20} {:<16} {}",
                item.name, item.partition, status, id
            );
        }
    }
}

pub fn handle_auth_revoke(name: &str, project: &str) {
    open_vault().revoke_auth(project, name).unwrap_or_else(fail);
    if json_output() {
        print_json(serde_json::json!({ "ok": true, "name": name, "project": project }));
    } else {
        println!("Auth revoked for '{name}' in '{project}'.");
    }
}

pub fn handle_auth_bundle_set(path: &str) {
    let file = File::open(path).unwrap_or_else(fail);
    let mut input = Vec::new();
    file.take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut input)
        .unwrap_or_else(fail);
    if input.len() as u64 > MAX_BUNDLE_BYTES {
        fail::<(), _>("auth bundle JSON exceeds the 1 MiB limit");
    }
    // Parse errors can echo untrusted input. Keep the diagnostic metadata-only.
    let bundle: AuthBundle = serde_json::from_slice(&input).unwrap_or_else(|_| {
        fail("invalid auth bundle JSON; provide only name, project, partition, account, and named alternatives with auth_id/revision/role members")
    });
    open_vault().set_auth_bundle(&bundle).unwrap_or_else(fail);
    if json_output() {
        print_json(serde_json::json!({ "ok": true, "bundle": bundle }));
    } else {
        println!("Auth bundle '{}' saved.", bundle.name);
    }
}

pub fn handle_auth_bundle_list(project: &str, partition: &str) {
    let bundles = open_vault()
        .list_auth_bundles(project, partition)
        .unwrap_or_else(fail);
    if json_output() {
        print_json(serde_json::json!({
            "project": project,
            "partition": partition,
            "bundles": bundles,
        }));
    } else if bundles.is_empty() {
        println!("No auth bundles stored in '{project}/{partition}'.");
    } else {
        // Full metadata makes pinned revisions and required-together members inspectable.
        for bundle in bundles {
            print_json(serde_json::to_value(bundle).expect("auth bundle must serialize"));
        }
    }
}

pub fn handle_auth_bundle_resolve(
    name: &str,
    project: &str,
    partition: &str,
    account: &str,
    alternative: &str,
    origin: &str,
) {
    // Resolve the complete selected alternative before printing any token.
    let members = open_vault()
        .resolve_auth_bundle(project, partition, name, account, alternative, origin)
        .unwrap_or_else(fail);
    if json_output() {
        print_json(serde_json::json!({
            "name": name,
            "project": project,
            "partition": partition,
            "alternative": alternative,
            "members": members,
        }));
    } else {
        for member in members {
            println!("{}\t{}", member.role, member.wisp_token);
        }
    }
}

fn open_vault() -> Vault {
    Vault::open_with_session().unwrap_or_else(fail)
}

fn parse_timestamp(value: &str, flag: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or_else(|_| {
            fail(format!(
                "--{flag} must be an RFC3339 timestamp with a timezone"
            ))
        })
}

fn fail<T, E: std::fmt::Display>(error: E) -> T {
    eprintln!("Error: {error}");
    std::process::exit(1);
}
