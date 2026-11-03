use crate::audit;
use crate::core::access_ring::AccessRing;
use crate::core::{self, AddCredentialRequest, CredentialType, Vault};
use crate::migrate;

use super::shared::{credential_json, json_output, print_json, prompt_password_confirm};

pub struct AddCredentialArgs<'a> {
    pub name: &'a str,
    pub type_str: &'a str,
    pub description: Option<&'a str>,
    pub value: Option<&'a str>,
    pub hosts: Option<&'a str>,
    pub tags: Option<&'a str>,
    pub header_name: Option<&'a str>,
    pub param_name: Option<&'a str>,
    pub partition: Option<&'a str>,
    pub project: Option<&'a str>,
    pub ring: Option<&'a str>,
}

fn parse_ring_or_exit(value: &str) -> AccessRing {
    AccessRing::parse(value).unwrap_or_else(|| {
        eprintln!("Error: access ring must be routine, restricted or critical");
        std::process::exit(1);
    })
}

pub async fn handle_add(args: AddCredentialArgs<'_>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let credential_type = match CredentialType::from_str_with_params(
        args.type_str,
        args.header_name,
        args.param_name,
    ) {
        Ok(CredentialType::WebsiteLogin) => {
            eprintln!(
                "Error: website_login credentials must be created with `wispkey login generate`"
            );
            std::process::exit(1);
        }
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let ring = args.ring.map(parse_ring_or_exit);

    let resolved_value = match args.value {
        Some(v) => v.to_string(),
        None => {
            let entered = prompt_password_confirm("Enter secret value: ", "Confirm secret value: ");
            match entered {
                Some(v) => v,
                None => {
                    eprintln!("Error: values did not match");
                    std::process::exit(1);
                }
            }
        }
    };

    let active_project = args
        .project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);

    let added = vault.add_classified_credential(
        AddCredentialRequest {
            name: args.name,
            credential_type,
            value: &resolved_value,
            description: args.description,
            hosts: args.hosts,
            tags: args.tags,
            partition: args.partition,
            project: args.project,
            origin: None,
            lifecycle_state: None,
            review_at: None,
        },
        ring,
    );
    match added {
        Ok(cred) => {
            audit::log_event(
                vault.db(),
                "CredentialAdded",
                Some(args.name),
                Some(&cred.wisp_token),
                None,
                None,
                None,
                None,
                false,
                None,
                Some(&active_project),
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "credential": credential_json(&cred),
                    "project": active_project,
                }));
                return;
            }
            println!("Credential '{}' added.", args.name);
            println!("Wisp token: {}", cred.wisp_token);
            println!();
            println!(
                "Use this token in API calls. The proxy will swap it for the real credential."
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Lists credentials for a partition, the active or named project, or all projects.
pub async fn handle_list(partition: Option<&str>, project: Option<&str>, all_projects: bool) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let list_result = if let Some(partition_name) = partition {
        let active = project
            .map(String::from)
            .unwrap_or_else(core::resolve_active_project);
        vault.list_credentials_in_partition_for_project(&active, partition_name)
    } else if all_projects {
        vault.list_credentials()
    } else {
        let active = project
            .map(String::from)
            .unwrap_or_else(core::resolve_active_project);
        vault.list_credentials_in_project(&active)
    };

    match list_result {
        Ok(credentials) => {
            if json_output() {
                let active = project
                    .map(String::from)
                    .unwrap_or_else(core::resolve_active_project);
                let list: Vec<serde_json::Value> =
                    credentials.iter().map(credential_json).collect();
                print_json(serde_json::json!({
                    "credentials": list,
                    "project": if all_projects { serde_json::Value::String("*".to_string()) } else { serde_json::Value::String(active) },
                    "all_projects": all_projects,
                    "partition": partition,
                }));
                return;
            }
            if credentials.is_empty() {
                let active = core::resolve_active_project();
                if !all_projects {
                    println!(
                        "No credentials in project '{}'. Use --all-projects to see all.",
                        active
                    );
                } else {
                    println!("No credentials stored.");
                }
                println!(
                    "Add one with: wispkey add \"name\" --type bearer_token --value \"secret\""
                );
                return;
            }

            println!(
                "{:<24} {:<16} {:<30} {:<20} TAGS",
                "NAME", "TYPE", "DESCRIPTION", "CREATED"
            );
            println!("{}", "-".repeat(102));
            for cred in &credentials {
                let tags = if cred.tags.is_empty() {
                    String::new()
                } else {
                    cred.tags.join(", ")
                };
                let desc = if cred.description.len() > 28 {
                    format!("{}..", &cred.description[..28])
                } else {
                    cred.description.clone()
                };
                println!(
                    "{:<24} {:<16} {:<30} {:<20} {}",
                    cred.name,
                    cred.credential_type.display_name(),
                    desc,
                    cred.created_at.format("%Y-%m-%d %H:%M"),
                    tags
                );
            }
            println!();
            println!("{} credential(s)", credentials.len());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Prints metadata for a credential, optionally including its wisp token.
pub async fn handle_get(name: &str, show_token: bool) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match vault.get_credential(name) {
        Ok(cred) => {
            if json_output() {
                let mut value = credential_json(&cred);
                if !show_token && let Some(object) = value.as_object_mut() {
                    object.remove("wisp_token");
                }
                print_json(serde_json::json!({ "credential": value }));
                return;
            }
            println!("Name:       {}", cred.name);
            if !cred.description.is_empty() {
                println!("Desc:       {}", cred.description);
            }
            println!("Type:       {}", cred.credential_type.display_name());
            if show_token {
                println!("Wisp Token: {}", cred.wisp_token);
            }
            if !cred.hosts.is_empty() {
                println!("Hosts:      {}", cred.hosts.join(", "));
            }
            if !cred.tags.is_empty() {
                println!("Tags:       {}", cred.tags.join(", "));
            }
            if !cred.origin.is_empty() {
                println!("Origin:     {}", cred.origin);
            }
            if cred.credential_type == crate::core::CredentialType::WebsiteLogin {
                println!("Lifecycle:  {}", cred.lifecycle_state);
                if let Some(review_at) = cred.review_at {
                    println!("Review at:  {}", review_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }
            }
            println!(
                "Created:    {}",
                cred.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "Updated:    {}",
                cred.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            if let Some(last_used) = cred.last_used_at {
                println!("Last Used:  {}", last_used.format("%Y-%m-%d %H:%M:%S UTC"));
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Removes a credential from the vault by name.
pub async fn handle_remove(name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match vault.remove_credential(name) {
        Ok(()) => {
            audit::log_event(
                vault.db(),
                "CredentialRemoved",
                Some(name),
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "deleted": name,
                }));
                return;
            }
            println!("Credential '{}' removed.", name);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Rotates the wisp token for the named credential.
pub async fn handle_rotate(name: &str) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match vault.rotate_wisp_token(name) {
        Ok(new_token) => {
            audit::log_event(
                vault.db(),
                "CredentialRotated",
                Some(name),
                Some(&new_token),
                None,
                None,
                None,
                None,
                false,
                None,
                None,
            );
            if json_output() {
                print_json(serde_json::json!({
                    "ok": true,
                    "credential": name,
                    "wisp_token": new_token,
                }));
                return;
            }
            println!("Wisp token rotated for '{}'.", name);
            println!("New token: {}", new_token);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Shows or sets an access ring. Broadening needs the owner password typed at an
/// interactive terminal; `WISPKEY_PASSWORD` and a cached unlock never count.
pub fn handle_ring(name: &str, project: Option<&str>, set: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let project = project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);
    let current = vault
        .access_ring_in_project(&project, name)
        .unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });
    let Some(requested) = set.map(parse_ring_or_exit) else {
        if json_output() {
            print_json(serde_json::json!({
                "credential": name,
                "project": project,
                "access_ring": current.as_str(),
            }));
        } else {
            println!("{}", current.as_str());
        }
        return;
    };
    let password = if requested < current {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            eprintln!("Error: broadening an access ring requires an interactive terminal");
            std::process::exit(1);
        }
        let entered = rpassword::prompt_password("Owner approval - enter vault password: ")
            .unwrap_or_else(|_| {
                eprintln!("Error: owner approval unavailable");
                std::process::exit(1);
            });
        Some(zeroize::Zeroizing::new(entered))
    } else {
        None
    };
    let previous = vault
        .set_access_ring(
            &project,
            name,
            requested,
            password.as_deref().map(String::as_str),
        )
        .unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        });
    if json_output() {
        print_json(serde_json::json!({
            "ok": true,
            "credential": name,
            "project": project,
            "access_ring": requested.as_str(),
            "previous": previous.as_str(),
        }));
        return;
    }
    println!(
        "Access ring for '{}': {} (was {}).",
        name,
        requested.as_str(),
        previous.as_str()
    );
}

pub async fn handle_import(
    path: &str,
    prefix: Option<&str>,
    partition: Option<&str>,
    project: Option<&str>,
) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match migrate::import_env_file(&vault, path, prefix, partition, project) {
        Ok(results) => {
            if json_output() {
                print_json(serde_json::json!({
                    "imported": results.imported,
                    "skipped": results.skipped,
                    "errors": results.errors,
                    "output_path": results.output_path,
                    "project": project,
                    "partition": partition,
                }));
                return;
            }
            println!("Import complete:");
            println!("  Imported:  {}", results.imported);
            println!("  Skipped:   {}", results.skipped);
            if results.errors > 0 {
                println!("  Errors:    {}", results.errors);
            }
            if !results.output_path.is_empty() {
                println!();
                println!("Wisp token .env written to: {}", results.output_path);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
