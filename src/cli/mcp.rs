use crate::core::Vault;
use crate::mcp;

pub async fn handle_mcp_serve() {
    if Vault::open_with_session().is_err()
        && let Ok(password) = std::env::var("WISPKEY_PASSWORD")
    {
        match Vault::open() {
            Ok(mut vault) => {
                if let Err(e) = vault.unlock(&password) {
                    eprintln!(
                        "Warning: auto-unlock via WISPKEY_PASSWORD failed: {}. Continuing with locked vault and env sideloads only.",
                        e
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: vault unavailable for auto-unlock: {}. Continuing with env sideloads only.",
                    e
                );
            }
        }
    }

    if let Err(e) = mcp::run_mcp_server().await {
        eprintln!("MCP server error: {}", e);
        std::process::exit(1);
    }
}
