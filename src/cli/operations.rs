use std::path::Path;

use crate::{core::Vault, operations};

use super::shared::{json_output, print_json};

pub fn handle_operation_identity() {
    match operations::current_principal() {
        Ok(principal) => {
            if json_output() {
                print_json(serde_json::json!({
                    "principal": principal,
                    "source": "operating_system",
                    "scope": "local_os_account"
                }));
            } else {
                println!("{principal}");
            }
        }
        Err(error) => fail(error),
    }
}

pub fn handle_operation_check(config: Option<&Path>, operation: Option<&str>) {
    let default_path = Vault::vault_dir().join("operations.toml");
    match operations::check(config.unwrap_or(&default_path), operation) {
        Ok(report) => {
            if json_output() {
                print_json(serde_json::to_value(report).expect("fixed preflight schema"));
            } else {
                println!(
                    "Catalog metadata and file permissions are valid for {} operation(s).",
                    report.checked_operations
                );
                println!("Catalog revision: {}", report.catalog_revision);
                println!(
                    "Preflight only: credentials and live targets are unverified; execution requires separate owner approval and requester authentication."
                );
            }
        }
        Err(error) => fail(error),
    }
}

fn fail(error: &'static str) -> ! {
    if json_output() {
        print_json(serde_json::json!({
            "configuration_valid": false,
            "error": error,
            "execution_available": false,
        }));
    } else {
        eprintln!("Operation failed: {error}");
    }
    std::process::exit(1)
}

pub fn handle_operation_authorize(operation: &str, seconds: u32) {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        fail("owner approval requires an interactive terminal");
    }
    let vault = Vault::open_with_session()
        .unwrap_or_else(|_| fail("a finite unlocked session is required"));
    let (_, reviewed) =
        operations::runtime::load_operation(&operations::runtime::catalog_path(), operation)
            .unwrap_or_else(|e| fail(e));
    if seconds == 0 || seconds > reviewed.max_grant_seconds {
        fail("invalid grant lifetime");
    }
    eprintln!(
        "Approve operation {} for instance {}: target {}, environment {}, credential {}, at most {} seconds.",
        reviewed.operation,
        reviewed.requester_instance_id,
        reviewed.target,
        reviewed.environment,
        reviewed.credential_id,
        seconds
    );
    // The shared password helper deliberately accepts env input; authorization does not.
    let password = zeroize::Zeroizing::new(
        rpassword::prompt_password("Owner approval - enter vault password: ")
            .unwrap_or_else(|_| fail("owner approval unavailable")),
    );
    vault
        .verify_operation_owner_password(&password)
        .unwrap_or_else(|error| fail(error));
    let status = operations::runtime::authorize(
        &vault,
        operation,
        seconds,
        Some(&reviewed.catalog_revision),
    )
    .unwrap_or_else(|error| fail(error));
    print_json(serde_json::json!(status));
}

pub fn handle_operation_status(grant: Option<&str>, attempt: Option<&str>) {
    use crate::core::operation_grants as grants;
    let vault = Vault::open_with_session().unwrap_or_else(|_| fail("session unavailable"));
    let value = match (grant, attempt) {
        (Some(id), None) => {
            serde_json::json!(grants::owner_grant_status(&vault, id).unwrap_or_else(|e| fail(e)))
        }
        (None, Some(id)) => {
            serde_json::json!(grants::owner_attempt_status(&vault, id).unwrap_or_else(|e| fail(e)))
        }
        _ => fail("select one grant or attempt"),
    };
    print_json(value);
}

pub fn handle_operation_cancel(grant: Option<&str>, attempt: Option<&str>) {
    use crate::core::operation_grants as grants;
    let vault = Vault::open_with_session().unwrap_or_else(|_| fail("session unavailable"));
    let value = match (grant, attempt) {
        (Some(id), None) => {
            serde_json::json!(grants::cancel_grant(&vault, id).unwrap_or_else(|e| fail(e)))
        }
        (None, Some(id)) => {
            serde_json::json!(grants::request_cancel(&vault, id).unwrap_or_else(|e| fail(e)))
        }
        _ => fail("select one grant or attempt"),
    };
    print_json(value);
}

pub fn handle_operation_reconcile(attempt: &str) {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        fail("owner reconciliation requires an interactive terminal");
    }
    let vault = Vault::open_with_session().unwrap_or_else(|_| fail("session unavailable"));
    let pending = crate::core::operation_grants::owner_attempt_status(&vault, attempt)
        .unwrap_or_else(|e| fail(e));
    eprintln!(
        "Reconcile attempt {} for target {}. Verify the destination has stopped this attempt before releasing its concurrency reservation. Its outcome will remain unknown.",
        pending.attempt_id, pending.target
    );
    let password = zeroize::Zeroizing::new(
        rpassword::prompt_password("Confirm target checked - enter vault password: ")
            .unwrap_or_else(|_| fail("owner reconciliation unavailable")),
    );
    vault
        .verify_operation_owner_password(&password)
        .unwrap_or_else(|e| fail(e));
    let status = crate::core::operation_grants::reconcile_attempt(&vault, attempt)
        .unwrap_or_else(|e| fail(e));
    print_json(serde_json::json!(status));
}

pub fn handle_operation_audit(limit: usize) {
    let vault = Vault::open_with_session().unwrap_or_else(|_| fail("session unavailable"));
    let rows =
        crate::core::operation_grants::owner_audit(&vault, limit).unwrap_or_else(|e| fail(e));
    print_json(serde_json::json!(rows));
}

pub async fn handle_operation_execute(grant: &str, identity_file: &Path, proxy: Option<&str>) {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RequesterCredentials {
        instance_id: String,
        instance_secret: String,
    }
    if !uuid::Uuid::parse_str(grant).is_ok_and(|id| !id.is_nil() && id.to_string() == grant) {
        fail("invalid grant reference");
    }
    let identity_raw = zeroize::Zeroizing::new(
        operations::read_private_identity(identity_file).unwrap_or_else(|e| fail(e)),
    );
    let mut identity: RequesterCredentials = serde_json::from_str(&identity_raw)
        .unwrap_or_else(|_| fail("invalid instance identity file"));
    let secret = zeroize::Zeroizing::new(std::mem::take(&mut identity.instance_secret));
    let address = proxy
        .map(str::to_owned)
        .unwrap_or_else(crate::proxy::lifecycle::proxy_address_or_default);
    let mut base = url::Url::parse(&address).unwrap_or_else(|_| fail("invalid proxy address"));
    let local = base
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    if !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || (base.scheme() != "https" && !(base.scheme() == "http" && local))
    {
        fail("operation client requires HTTPS or literal loopback HTTP");
    }
    base.set_path(&format!("/api/operations/grants/{grant}/execute"));
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(65))
        .build()
        .unwrap_or_else(|_| fail("operation client unavailable"));
    let mut response = client
        .post(base)
        .header("x-wispkey-instance-id", &identity.instance_id)
        .header("x-wispkey-instance-secret", secret.as_str())
        .send()
        .await
        .unwrap_or_else(|_| {
            fail("operation outcome unknown; inspect grant status before retrying")
        });
    let success = response.status().is_success();
    if !success {
        fail("operation request denied or failed; inspect grant status");
    }
    if response.content_length().is_some_and(|n| n > 8192) {
        fail("invalid operation response");
    }
    // Decode only the allowlisted status schema; raw provider/transport bytes never print.
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .unwrap_or_else(|_| fail("operation response unavailable"))
    {
        if chunk.len() > 8192 - bytes.len() {
            fail("invalid operation response");
        }
        bytes.extend_from_slice(&chunk);
    }
    let status: crate::core::operation_grants::AttemptStatus =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| fail("invalid operation response"));
    let uuid = |value: &str| {
        uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
    };
    let slug = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if status.grant_id != grant
        || !uuid(&status.attempt_id)
        || !uuid(&status.credential_ref)
        || !slug(&status.operation)
        || !slug(&status.target)
        || !slug(&status.environment)
        || status.hard_deadline > status.expires_at
        || status.exit_code.is_some_and(|code| code < 0)
    {
        fail("invalid operation response");
    }
    print_json(serde_json::json!(status));
}
