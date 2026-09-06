use std::io::{self, Read};
use std::sync::OnceLock;

use regex::Regex;

const MAX_HOOK_INPUT_BYTES: usize = 64 * 1024;
const BEFORE_SHELL_EXECUTION: &str = "beforeShellExecution";

const EMPTY_INPUT_USER_MESSAGE: &str = "WispKey blocked: shell hook input was empty.";
const EMPTY_INPUT_AGENT_MESSAGE: &str =
    "beforeShellExecution could not inspect an empty hook payload, so it failed closed.";
const INVALID_INPUT_USER_MESSAGE: &str = "WispKey blocked: shell hook command could not be parsed.";
const INVALID_INPUT_AGENT_MESSAGE: &str =
    "beforeShellExecution did not receive a command field, so it failed closed.";
const OVERSIZED_INPUT_USER_MESSAGE: &str = "WispKey blocked: shell hook input was too large.";
const OVERSIZED_INPUT_AGENT_MESSAGE: &str =
    "beforeShellExecution received an oversized hook payload, so it failed closed.";
const ENV_PRINT_USER_MESSAGE: &str =
    "WispKey blocked: command would print a secret environment variable.";
const ENV_PRINT_AGENT_MESSAGE: &str = "beforeShellExecution blocked this command because it would print a secret environment variable to stdout, exposing it in the conversation. Use WispKey to manage secrets safely. Run 'wispkey list' to see stored credentials, or use wisp tokens through the proxy instead of raw env vars.";
const ENV_EXPORT_USER_MESSAGE: &str =
    "WispKey blocked: setting a secret env var directly. Use 'wispkey add' instead.";
const ENV_EXPORT_AGENT_MESSAGE: &str = "beforeShellExecution blocked this export because it sets a secret environment variable with a real value. Store it in WispKey instead: run 'wispkey add <name> --type bearer_token --value-file -' and use the wisp token.";
const PROTECTED_ENV_NAMES: &[&str] = &[
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "STRIPE_SECRET_KEY",
    "DATABASE_URL",
    "DISCORD_TOKEN",
    "SLACK_TOKEN",
];

#[derive(Debug, Clone, Copy)]
enum DenyReason {
    EmptyInput,
    InvalidInput,
    OversizedInput,
    Secret(&'static str),
    EnvironmentPrint,
    EnvironmentExport,
}

enum HookDecision {
    Allow,
    Deny(DenyReason),
}

struct SecretPattern {
    regex: Regex,
    description: &'static str,
}

struct GuardPatterns {
    wisp_token: Regex,
    secret: Vec<SecretPattern>,
    environment_print: Regex,
    environment_export: Regex,
}

pub async fn handle_guard_shell() {
    let decision = evaluate_shell_hook(io::stdin().lock());
    println!("{}", decision.json());
}

fn evaluate_shell_hook<R: Read>(reader: R) -> HookDecision {
    let input = match read_bounded_input(reader) {
        Ok(input) => input,
        Err(reason) => return HookDecision::Deny(reason),
    };

    let raw_input = match std::str::from_utf8(&input) {
        Ok(input) => input,
        Err(_) => return HookDecision::Deny(DenyReason::InvalidInput),
    };
    let hook_input = match serde_json::from_slice::<serde_json::Value>(&input) {
        Ok(input) => input,
        Err(_) => return HookDecision::Deny(DenyReason::InvalidInput),
    };

    let Some(hook_input) = hook_input.as_object() else {
        return HookDecision::Deny(DenyReason::InvalidInput);
    };

    if hook_input
        .get("hook_event_name")
        .is_some_and(|event| event.as_str() != Some(BEFORE_SHELL_EXECUTION))
    {
        return HookDecision::Deny(DenyReason::InvalidInput);
    }

    let Some(command) = hook_input
        .get("command")
        .and_then(serde_json::Value::as_str)
        .filter(|command| !command.trim().is_empty())
    else {
        return HookDecision::Deny(DenyReason::InvalidInput);
    };

    evaluate_command(command, raw_input)
}

fn read_bounded_input<R: Read>(reader: R) -> Result<Vec<u8>, DenyReason> {
    let mut input = Vec::new();
    let read_result = reader
        .take((MAX_HOOK_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input);
    if read_result.is_err() {
        return Err(DenyReason::InvalidInput);
    }

    if input.is_empty() || input.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err(DenyReason::EmptyInput);
    }
    if input.len() > MAX_HOOK_INPUT_BYTES {
        return Err(DenyReason::OversizedInput);
    }
    Ok(input)
}

fn evaluate_command(command: &str, raw_input: &str) -> HookDecision {
    let patterns = guard_patterns();
    let scrubbed_command = patterns.wisp_token.replace_all(command, "[wisp-token]");
    let scrubbed_payload = patterns.wisp_token.replace_all(raw_input, "[wisp-token]");
    let scan_text = format!("{scrubbed_command}\n{scrubbed_payload}");

    if let Some(description) = patterns
        .secret
        .iter()
        .find(|pattern| pattern.regex.is_match(&scan_text))
        .map(|pattern| pattern.description)
    {
        return HookDecision::Deny(DenyReason::Secret(description));
    }

    if patterns.environment_print.is_match(command) {
        return HookDecision::Deny(DenyReason::EnvironmentPrint);
    }

    if patterns
        .environment_export
        .captures_iter(command)
        .any(|capture| {
            let value = capture.name("value").map_or("", |value| value.as_str());
            !is_safe_wisp_export(value, &patterns.wisp_token)
        })
    {
        return HookDecision::Deny(DenyReason::EnvironmentExport);
    }

    HookDecision::Allow
}

fn is_safe_wisp_export(value: &str, wisp_token: &Regex) -> bool {
    let value = value.trim();
    let value = value.trim_matches(|character| matches!(character, '"' | '\''));

    wisp_token
        .find(value)
        .is_some_and(|matched| matched.as_str() == value)
}

fn guard_patterns() -> &'static GuardPatterns {
    static PATTERNS: OnceLock<GuardPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        // WispKey-generated and env-sideload tokens use lowercase alphanumerics and underscores.
        let wisp_token = Regex::new(r"\bwk_[a-z0-9_]+\b").expect("static wisp token regex");
        let secret = vec![
            SecretPattern {
                regex: Regex::new(r"sk-[a-zA-Z0-9]{20,}").expect("static secret regex"),
                description: "OpenAI API key (sk-...)",
            },
            SecretPattern {
                regex: Regex::new(r"ghp_[a-zA-Z0-9]{36}").expect("static secret regex"),
                description: "GitHub personal access token (ghp_...)",
            },
            SecretPattern {
                regex: Regex::new(r"ghs_[a-zA-Z0-9]{36}").expect("static secret regex"),
                description: "GitHub app token (ghs_...)",
            },
            SecretPattern {
                regex: Regex::new(r"AKIA[A-Z0-9]{16}").expect("static secret regex"),
                description: "AWS access key (AKIA...)",
            },
            SecretPattern {
                regex: Regex::new(r"xox[bp]-[0-9]+-").expect("static secret regex"),
                description: "Slack token (xox...)",
            },
            SecretPattern {
                regex: Regex::new(r"sk_(test|live)_[a-zA-Z0-9]{24,}")
                    .expect("static secret regex"),
                description: "Stripe secret key (sk_...)",
            },
            SecretPattern {
                regex: Regex::new(r"Bearer [a-zA-Z0-9._-]{40,}")
                    .expect("static secret regex"),
                description: "Bearer token (40+ chars)",
            },
            SecretPattern {
                regex: Regex::new(
                    r#"(-H|--header|Authorization:|X-API-Key:)[[:space:]]*['"]?[a-zA-Z0-9+/=._-]{40,}"#,
                )
                .expect("static secret regex"),
                description: "possible secret in HTTP header (40+ char value)",
            },
        ];
        let protected_names = PROTECTED_ENV_NAMES.join("|");
        // Cover the common variable-reference forms without pretending to parse a shell.
        let unix_environment_reference = format!(
            r"\$(?:{protected_names})|\$\x7b(?:{protected_names})\x7d"
        );
        let powershell_environment_reference = format!(r"\$env:(?:{protected_names})");
        let cmd_environment_reference = format!(r"%(?:{protected_names})%");
        let environment_print = Regex::new(&format!(
            r"(?ix)\b(?:echo|printf|cat|write-output|write-host)\b[^\n;|&]*(?:{unix_environment_reference}|{powershell_environment_reference}|{cmd_environment_reference})"
        ))
        .expect("static environment regex");
        let environment_export = Regex::new(&format!(
            r#"(?ix)(?:\bexport\s+(?:{protected_names})\s*=\s*|\$env:(?:{protected_names})\s*=\s*|\bset\s+['"]?(?:{protected_names})\s*=\s*)(?P<value>[^\n;&|]*)"#
        ))
        .expect("static environment regex");

        GuardPatterns {
            wisp_token,
            secret,
            environment_print,
            environment_export,
        }
    })
}

impl HookDecision {
    fn json(self) -> serde_json::Value {
        match self {
            Self::Allow => serde_json::json!({"permission": "allow"}),
            Self::Deny(reason) => {
                let (user_message, agent_message) = reason.messages();
                serde_json::json!({
                    "permission": "deny",
                    "user_message": user_message,
                    "agent_message": agent_message,
                })
            }
        }
    }
}

impl DenyReason {
    fn messages(self) -> (String, String) {
        match self {
            Self::EmptyInput => (
                EMPTY_INPUT_USER_MESSAGE.to_string(),
                EMPTY_INPUT_AGENT_MESSAGE.to_string(),
            ),
            Self::InvalidInput => (
                INVALID_INPUT_USER_MESSAGE.to_string(),
                INVALID_INPUT_AGENT_MESSAGE.to_string(),
            ),
            Self::OversizedInput => (
                OVERSIZED_INPUT_USER_MESSAGE.to_string(),
                OVERSIZED_INPUT_AGENT_MESSAGE.to_string(),
            ),
            Self::Secret(description) => (
                format!(
                    "WispKey blocked: detected {description} in shell command. Use a wisp token instead."
                ),
                format!(
                    "beforeShellExecution blocked this command because it contains what appears to be a real secret ({description}). Use WispKey wisp tokens instead of real credentials. Run 'wispkey list' to see available tokens, or 'wispkey get <name> --show-token' to get a specific wisp token. For HTTP requests, route through HTTP_PROXY=http://localhost:7700. For HTTPS token substitution, use reverse-proxy mode with the X-Target-Url header."
                ),
            ),
            Self::EnvironmentPrint => (
                ENV_PRINT_USER_MESSAGE.to_string(),
                ENV_PRINT_AGENT_MESSAGE.to_string(),
            ),
            Self::EnvironmentExport => (
                ENV_EXPORT_USER_MESSAGE.to_string(),
                ENV_EXPORT_AGENT_MESSAGE.to_string(),
            ),
        }
    }
}
