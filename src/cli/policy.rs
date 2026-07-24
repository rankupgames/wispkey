pub async fn handle_policy_list() {
    let config = crate::policy::load_policies_from_disk();
    if config.policy.is_empty() {
        println!("No policies configured.");
        println!("Run `wispkey policy init` to create a template policies.toml");
        return;
    }
    println!(
        "{} policies loaded from {}",
        config.policy.len(),
        crate::policy::policies_path().display()
    );
    println!();
    for policy in &config.policy {
        println!("  [{}]", policy.name);
        if let Some(ref cred) = policy.credential {
            println!("    credential: {}", cred);
        }
        if let Some(ref agent) = policy.agent {
            println!("    agent: {}", agent);
        }
        if !policy.allowed_methods.is_empty() {
            println!("    allowed_methods: {}", policy.allowed_methods.join(", "));
        }
        if !policy.allowed_hosts.is_empty() {
            println!("    allowed_hosts: {}", policy.allowed_hosts.join(", "));
        }
        if !policy.denied_hosts.is_empty() {
            println!("    denied_hosts: {}", policy.denied_hosts.join(", "));
        }
        if !policy.denied_paths.is_empty() {
            println!("    denied_paths: {}", policy.denied_paths.join(", "));
        }
        if !policy.allowed_paths.is_empty() {
            println!("    allowed_paths: {}", policy.allowed_paths.join(", "));
        }
        if let Some(ref rl) = policy.rate_limit {
            println!("    rate_limit: {}", rl);
        }
        if let Some(ref tw) = policy.time_window {
            println!("    time_window: {}", tw);
        }
        if policy.deny {
            println!("    deny: true");
        }
        println!();
    }
}

/// Writes a commented `policies.toml` template when the file does not exist.
pub async fn handle_policy_init() {
    let path = crate::policy::policies_path();
    if path.exists() {
        println!("Policies file already exists at {}", path.display());
        return;
    }
    let template = r#"# WispKey Policy Configuration
# Each [[policy]] block defines an access rule evaluated on every proxied request.
# Policies are evaluated in order; the first match that denies wins.

# Example: restrict production AWS credentials to GET-only
# [[policy]]
# name = "restrict-aws-prod"
# credential = "aws-prod"
# allowed_methods = ["GET"]
# denied_paths = ["/admin*", "/delete*"]
# rate_limit = "10/minute"

# Example: block all access to a credential
# [[policy]]
# name = "block-deprecated"
# credential = "old-api-key"
# deny = true

# Example: time-windowed access
# [[policy]]
# name = "business-hours-only"
# credential = "billing-api"
# time_window = "09:00-17:00"
"#;
    std::fs::write(&path, template).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {}", path.display(), e);
        std::process::exit(1);
    });
    println!("Created policies template at {}", path.display());
}

/// Parses `policies.toml` and reports success or TOML validation errors.
pub async fn handle_policy_check() {
    let path = crate::policy::policies_path();
    if !path.exists() {
        eprintln!("No policies file at {}", path.display());
        eprintln!("Run `wispkey policy init` to create one.");
        std::process::exit(1);
    }
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {}", path.display(), e);
        std::process::exit(1);
    });
    match toml::from_str::<crate::policy::PolicyConfig>(&content) {
        Ok(config) => match crate::policy::validate_policy_config(&config) {
            Ok(()) => {
                println!(
                    "OK -- {} policies parsed from {}",
                    config.policy.len(),
                    path.display()
                );
                for policy in &config.policy {
                    println!("  [{}] ok", policy.name);
                }
            }
            Err(error) => {
                eprintln!("INVALID -- {}", error);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("INVALID -- parse error in {}", path.display());
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
