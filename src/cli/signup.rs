use super::shared::{json_output, print_json};
use crate::core::{
    Vault, VaultError,
    signup::{ProfileSelection, SignupIdentity},
};
use std::io::Read;
use zeroize::Zeroizing;

/// Input is read only from an owner file or stdin, never argv or MCP.
pub fn handle_signup(
    action: &str,
    project: &str,
    partition: &str,
    name: Option<&str>,
    id: Option<&str>,
    revision: Option<&str>,
    input: Option<&str>,
) {
    let result = (|| -> crate::core::Result<serde_json::Value> {
        let vault = Vault::open_with_session()?;
        if action == "list" {
            return Ok(
                serde_json::json!({"profiles": vault.list_signup_profiles(project,partition)?}),
            );
        }
        let selection = ProfileSelection {
            id: id.unwrap_or(""),
            revision: revision.unwrap_or(""),
            project,
            partition,
            use_username: false,
        };
        if action == "remove" {
            vault.remove_signup_profile(selection)?;
            return Ok(serde_json::json!({"ok": true}));
        }
        let path = input.ok_or(VaultError::AuthRejected("identity file required"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        let mut reader: Box<dyn Read> = if path == "-" {
            Box::new(std::io::stdin())
        } else {
            Box::new(std::fs::File::open(path)?)
        };
        reader.by_ref().take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(VaultError::AuthRejected("identity input too large"));
        }
        let identity: SignupIdentity = serde_json::from_slice(&bytes)
            .map_err(|_| VaultError::AuthRejected("invalid signup identity JSON"))?;
        let profile = if action == "create" {
            vault.create_signup_profile(project, partition, name.unwrap_or(""), identity)?
        } else {
            vault.update_signup_profile(selection, identity)?
        };
        Ok(serde_json::json!({"profile": profile}))
    })();
    match result {
        Ok(value) => {
            if json_output() {
                print_json(value);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("metadata JSON")
                );
            }
        }
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
}
