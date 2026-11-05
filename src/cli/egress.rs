use crate::audit;
use crate::core::Vault;

/// Record intent before owner plaintext can leave the process. An attempted
/// event does not assert that a child started or an output write completed.
pub(super) fn require_attempt(
    vault: &Vault,
    event_type: &str,
    credentials: &str,
    program: Option<&str>,
    destination: Option<&str>,
    operation: &str,
    project: &str,
) {
    if audit::try_log_event(
        vault.db(),
        event_type,
        Some(credentials),
        None,
        program,
        destination,
        Some(operation),
        None,
        false,
        None,
        Some(project),
    )
    .is_err()
    {
        eprintln!("Error: cannot record owner egress attempt; no secret released");
        std::process::exit(1);
    }
}
