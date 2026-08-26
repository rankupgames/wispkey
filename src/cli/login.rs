use chrono::{Duration, Utc};

use crate::audit;
use crate::core::{
    self, GenerateWebsiteLoginRequest, LIFECYCLE_ACTIVE, LIFECYCLE_ARCHIVED, LIFECYCLE_PENDING,
    Vault,
};

use super::shared::{credential_json, json_output, print_json};

pub struct GenerateLoginArgs<'a> {
    pub name: &'a str,
    pub username: &'a str,
    pub url: &'a str,
    pub project: Option<&'a str>,
    pub partition: Option<&'a str>,
    pub review_after: Option<&'a str>,
    pub length: Option<usize>,
    pub no_symbols: bool,
}

pub async fn handle_generate(args: GenerateLoginArgs<'_>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let review_at = match args.review_after {
        Some("none") => None,
        Some(value) => match parse_duration(value).and_then(|duration| {
            Utc::now()
                .checked_add_signed(duration)
                .ok_or_else(|| "review-after is too large".to_string())
        }) {
            Ok(review_at) => Some(review_at),
            Err(error) => {
                eprintln!("Error: {error}");
                std::process::exit(1);
            }
        },
        None => Some(Utc::now() + Duration::days(180)),
    };

    let active_project = args
        .project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);

    match vault.generate_website_login(GenerateWebsiteLoginRequest {
        name: args.name,
        username: args.username,
        url: args.url,
        project: args.project,
        partition: args.partition,
        review_at,
        length: args.length,
        symbols: !args.no_symbols,
    }) {
        Ok(cred) => {
            audit::log_event(
                vault.db(),
                "WebsiteLoginCreated",
                Some(args.name),
                Some(&cred.wisp_token),
                Some(&cred.origin),
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
                    "username": args.username,
                    "project": active_project,
                }));
                return;
            }
            println!("Website login '{}' saved.", args.name);
            println!("Origin:     {}", cred.origin);
            println!("Username:   {}", args.username);
            println!("Lifecycle:  {}", cred.lifecycle_state);
            if let Some(review_at) = cred.review_at {
                println!("Review at:  {}", review_at.format("%Y-%m-%d %H:%M:%S UTC"));
            }
            println!();
            println!("The generated password was stored in the vault and is not printed.");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

pub async fn handle_archive(name: &str, project: Option<&str>) {
    set_lifecycle(name, LIFECYCLE_ARCHIVED, "WebsiteLoginArchived", project).await;
}

pub async fn handle_restore(name: &str, project: Option<&str>) {
    set_lifecycle(name, LIFECYCLE_PENDING, "WebsiteLoginRestored", project).await;
}

pub async fn handle_activate(name: &str, project: Option<&str>) {
    set_lifecycle(name, LIFECYCLE_ACTIVE, "WebsiteLoginActivated", project).await;
}

pub async fn handle_list(project: Option<&str>, all_projects: bool, due: bool) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let result = if due {
        let scoped = resolve_project(project);
        vault.list_due_website_logins(if all_projects {
            None
        } else {
            Some(scoped.as_str())
        })
    } else if all_projects {
        vault.list_credentials()
    } else {
        vault.list_credentials_in_project(&resolve_project(project))
    };

    match result {
        Ok(credentials) => {
            let logins: Vec<_> = credentials
                .into_iter()
                .filter(|credential| {
                    credential.credential_type == core::CredentialType::WebsiteLogin
                })
                .collect();
            if json_output() {
                let list: Vec<serde_json::Value> = logins.iter().map(credential_json).collect();
                print_json(serde_json::json!({
                    "logins": list,
                    "due": due,
                    "project": if all_projects { serde_json::Value::String("*".into()) } else { serde_json::Value::String(resolve_project(project)) },
                }));
                return;
            }
            if logins.is_empty() {
                if due {
                    println!("No website logins are due for review.");
                } else {
                    println!("No website logins stored.");
                }
                return;
            }
            println!("{:<24} {:<12} {:<40} REVIEW", "NAME", "LIFECYCLE", "ORIGIN");
            println!("{}", "-".repeat(90));
            for login in &logins {
                let review = login
                    .review_at
                    .map(|value| value.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<24} {:<12} {:<40} {}",
                    login.name, login.lifecycle_state, login.origin, review
                );
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn set_lifecycle(name: &str, lifecycle: &str, event: &str, project: Option<&str>) {
    let vault = match Vault::open_with_session() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    let active_project = resolve_project(project);
    match vault.set_credential_lifecycle(name, lifecycle, project) {
        Ok(cred) => {
            audit::log_event(
                vault.db(),
                event,
                Some(name),
                Some(&cred.wisp_token),
                Some(&cred.origin),
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
            println!("Website login '{}' is now {}.", name, cred.lifecycle_state);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn resolve_project(project: Option<&str>) -> String {
    project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project)
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("review-after must not be empty".into());
    }
    let (digits, unit) = value.split_at(
        value
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(value.len()),
    );
    let amount: i64 = digits
        .parse()
        .map_err(|_| "review-after must start with a number".to_string())?;
    if amount <= 0 {
        return Err("review-after must be positive".into());
    }
    let duration = match unit {
        "" | "d" => Duration::try_days(amount),
        "h" => Duration::try_hours(amount),
        "m" => Duration::try_minutes(amount),
        "s" => Duration::try_seconds(amount),
        _ => return Err("review-after unit must be one of s, m, h, or d".into()),
    };
    duration.ok_or_else(|| "review-after is too large".into())
}
