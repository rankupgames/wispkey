use super::shared::{json_output, print_json};
use crate::core::{ExistingLoginInput, ExistingLoginMode, MAX_EXISTING_LOGIN_INPUT_BYTES, Vault};
use std::io::{IsTerminal, Read};
use zeroize::Zeroizing;

type InputResult = Result<ExistingLoginInput, &'static str>;
fn read_stdin(reader: impl Read) -> InputResult {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_EXISTING_LOGIN_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read login input")?;
    if bytes.is_empty() || bytes.len() > MAX_EXISTING_LOGIN_INPUT_BYTES {
        return Err("login input is empty or exceeds 131072 bytes");
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "login input must contain exactly username and password strings")
}
fn confirmed(
    prompt: &mut impl FnMut(&str) -> std::io::Result<String>,
    first: &str,
    again: &str,
    max: usize,
) -> Result<Zeroizing<String>, &'static str> {
    let value = Zeroizing::new(prompt(first).map_err(|_| "login input cancelled or unavailable")?);
    if value.is_empty() || value.len() > max {
        return Err("login input is empty or exceeds field limit");
    }
    let confirm =
        Zeroizing::new(prompt(again).map_err(|_| "login input cancelled or unavailable")?);
    if *value != *confirm {
        return Err("login input confirmation did not match");
    }
    Ok(value)
}
fn read_confirmed(mut prompt: impl FnMut(&str) -> std::io::Result<String>) -> InputResult {
    let mut username = confirmed(
        &mut prompt,
        "Enter existing username (hidden): ",
        "Confirm username (hidden): ",
        1024,
    )?;
    let mut password = confirmed(
        &mut prompt,
        "Enter existing password (hidden): ",
        "Confirm password (hidden): ",
        16384,
    )?;
    ExistingLoginInput::new(
        std::mem::take(&mut *username),
        std::mem::take(&mut *password),
    )
    .map_err(|_| "invalid login fields")
}
pub fn handle_existing_login(
    name: &str,
    project: &str,
    partition: &str,
    origin: &str,
    stdin: bool,
    mode: ExistingLoginMode,
) {
    let result = (|| -> Result<(), &'static str> {
        let vault =
            Vault::open_with_session().map_err(|_| "valid unlocked owner session required")?;
        let prepared = vault
            .prepare_existing_login(project, partition, name, origin, mode)
            .map_err(
                |_| "login target unavailable, duplicate, ineligible, or outside selected scope",
            )?;
        eprintln!(
            "Ready for existing login input; no provider verification or password generation occurs."
        );
        let input = if stdin {
            if std::io::stdin().is_terminal() {
                return Err("--stdin requires a pipe; use hidden prompts in a terminal");
            }
            read_stdin(std::io::stdin().lock())
        } else {
            if !std::io::stdin().is_terminal() {
                return Err("hidden input requires a terminal; use --stdin for a pipe");
            }
            read_confirmed(|message| rpassword::prompt_password(message))
        }?;
        prepared.commit(&input).map_err(|_| "login write rejected: invalid input, changed vault/session, or unavailable authorization; start again")
    })();
    match result {
        Ok(()) if json_output() => print_json(serde_json::json!({"ok":true})),
        Ok(()) => {
            println!("Existing login saved locally; provider authentication has not been verified.")
        }
        Err(message) => {
            eprintln!("Error: {message}");
            std::process::exit(1);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_bounded_input_and_hidden_confirmation() {
        for data in [
            &b""[..],
            &b"\xff"[..],
            br#"{"username":"x","password":"x","extra":true}"#,
            br#"{"username":"x","username":"y","password":"x"}"#,
            br#"{"username":"x"}"#,
            br#"{"username":123,"password":"x"}"#,
        ] {
            assert!(read_stdin(data).is_err());
        }
        assert!(read_stdin(&vec![b'x'; MAX_EXISTING_LOGIN_INPUT_BYTES + 1][..]).is_err());
        assert!(read_stdin(&br#"{"username":"synthetic","password":"synthetic"}"#[..]).is_ok());
        assert!(read_confirmed(|_| Ok("synthetic".into())).is_ok());
        for failure_at in 1..=4 {
            for kind in [
                std::io::ErrorKind::Interrupted,
                std::io::ErrorKind::UnexpectedEof,
            ] {
                let mut calls = 0;
                assert!(
                    read_confirmed(|_| {
                        calls += 1;
                        if calls == failure_at {
                            Err(kind.into())
                        } else {
                            Ok("synthetic".into())
                        }
                    })
                    .is_err()
                );
            }
        }
        let mut calls = 0;
        assert!(
            read_confirmed(|_| {
                calls += 1;
                Ok(calls.to_string())
            })
            .is_err()
        );
        assert!(read_confirmed(|_| Ok(String::new())).is_err());
        for (user, password) in [(" ", "x"), ("x", ""), ("x\0", "x"), ("x", "x\n")] {
            assert!(ExistingLoginInput::new(user.into(), password.into()).is_err());
        }
        assert!(ExistingLoginInput::new("x".repeat(1025), "x".into()).is_err());
        assert!(ExistingLoginInput::new("x".into(), "x".repeat(16385)).is_err());
    }
}
