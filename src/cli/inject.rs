use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::audit;
use crate::core::{self, Vault};
use crate::secure_files;

use super::exec::open_unlocked_vault;

pub struct InjectArgs<'a> {
    pub input: &'a str,
    pub output: Option<&'a str>,
    pub project: Option<&'a str>,
    pub stdout: bool,
}

pub async fn handle_inject(args: InjectArgs<'_>) {
    if args.output.is_none() && !args.stdout {
        eprintln!("Error: provide -o <outfile> or pass --stdout to write plaintext to stdout");
        std::process::exit(1);
    }
    if args.output.is_some() && args.stdout {
        eprintln!("Error: choose either -o <outfile> or --stdout");
        std::process::exit(1);
    }

    let template = read_template(args.input);
    let project = args
        .project
        .map(String::from)
        .unwrap_or_else(core::resolve_active_project);
    let vault = open_unlocked_vault();
    let (rendered, credential_names) = render_template(&template, &vault, &project);

    let destination = if args.stdout {
        let mut stdout = io::stdout().lock();
        if let Err(e) = stdout.write_all(rendered.as_bytes()) {
            eprintln!("Error: failed to write rendered template to stdout: {}", e);
            std::process::exit(1);
        }
        "stdout".to_string()
    } else {
        let output = args.output.expect("validated output path");
        if let Err(e) = secure_files::write_private(Path::new(output), rendered.as_bytes()) {
            eprintln!("Error: failed to write rendered template {}: {}", output, e);
            std::process::exit(1);
        }
        output.to_string()
    };

    audit_credential_inject(&vault, &credential_names, &destination, &project);
}

fn read_template(input: &str) -> String {
    if input == "-" {
        let mut template = String::new();
        if let Err(e) = io::stdin().read_to_string(&mut template) {
            eprintln!("Error: failed to read template from stdin: {}", e);
            std::process::exit(1);
        }
        return template;
    }

    match fs::read_to_string(input) {
        Ok(template) => template,
        Err(e) => {
            eprintln!("Error: failed to read template {}: {}", input, e);
            std::process::exit(1);
        }
    }
}

fn render_template(template: &str, vault: &Vault, project: &str) -> (String, Vec<String>) {
    let mut rendered = String::with_capacity(template.len());
    let mut credential_names = Vec::new();
    let mut rest = template;

    while let Some(start) = rest.find("{{") {
        rendered.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find("}}") else {
            if after_start.contains("cred:") {
                eprintln!("Error: malformed credential reference in template");
                std::process::exit(1);
            }
            rendered.push_str(&rest[start..]);
            return (rendered, credential_names);
        };

        let expression = &after_start[..end];
        let trimmed = expression.trim();
        if let Some(name) = trimmed.strip_prefix("cred:") {
            let name = name.trim();
            if name.is_empty()
                || name
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch == '{' || ch == '}')
            {
                eprintln!("Error: malformed credential reference in template");
                std::process::exit(1);
            }
            let secret = match vault.decrypt_credential_value_in_project(project, name) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            rendered.push_str(&secret);
            credential_names.push(name.to_string());
        } else if trimmed.starts_with("cred") {
            eprintln!("Error: malformed credential reference in template");
            std::process::exit(1);
        } else {
            rendered.push_str("{{");
            rendered.push_str(expression);
            rendered.push_str("}}");
        }

        rest = &after_start[end + 2..];
    }

    rendered.push_str(rest);
    (rendered, credential_names)
}

fn audit_credential_inject(
    vault: &Vault,
    credential_names: &[String],
    destination: &str,
    project: &str,
) {
    let credentials = credential_names.join(",");
    audit::log_event(
        vault.db(),
        "CredentialInject",
        Some(&credentials),
        None,
        None,
        Some(destination),
        Some("inject"),
        None,
        false,
        None,
        Some(project),
    );
}
