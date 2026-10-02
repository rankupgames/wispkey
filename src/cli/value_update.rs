use std::io::{IsTerminal, Read};
use zeroize::Zeroizing;

use super::shared::{json_output, print_json};
use crate::core::{MAX_REPLACEMENT_VALUE_BYTES, Vault};

type InputResult = Result<Zeroizing<String>, &'static str>;

fn read_stdin(reader: impl Read) -> InputResult {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_REPLACEMENT_VALUE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read replacement input")?;
    if bytes.is_empty() || bytes.len() > MAX_REPLACEMENT_VALUE_BYTES {
        return Err("replacement input is empty or exceeds 1048576 bytes");
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "replacement input must be UTF-8")?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn read_confirmed(mut prompt: impl FnMut(&str) -> std::io::Result<String>) -> InputResult {
    let first = Zeroizing::new(
        prompt("Enter complete replacement value: ")
            .map_err(|_| "replacement input cancelled or unavailable")?,
    );
    if first.is_empty() || first.len() > MAX_REPLACEMENT_VALUE_BYTES {
        return Err("replacement input is empty or exceeds 1048576 bytes");
    }
    let confirmation = Zeroizing::new(
        prompt("Confirm complete replacement value: ")
            .map_err(|_| "replacement input cancelled or unavailable")?,
    );
    if *first != *confirmation {
        return Err("replacement values did not match");
    }
    Ok(first)
}

pub fn handle_replace_value(name: &str, project: &str, partition: &str, stdin: bool) {
    let result = (|| -> Result<(), String> {
        let vault =
            Vault::open_with_session().map_err(|_| "valid unlocked owner session required")?;
        let prepared = vault
            .prepare_value_update(project, partition, name)
            .map_err(|_| "replacement target unavailable, ineligible, or outside selected scope")?;
        eprintln!("Ready for complete replacement value; this does not edit a password field.");
        let value = if stdin {
            if std::io::stdin().is_terminal() {
                return Err("--stdin requires a pipe; use the hidden prompt in a terminal".into());
            }
            read_stdin(std::io::stdin().lock())
        } else {
            if !std::io::stdin().is_terminal() {
                return Err("hidden input requires a terminal; use --stdin for a pipe".into());
            }
            read_confirmed(|message| rpassword::prompt_password(message))
        }
        .map_err(str::to_owned)?;
        prepared.commit(&value).map_err(|_| "replacement rejected: invalid value, changed vault/session, or unavailable authorization; retry from the beginning")?;
        Ok(())
    })();
    match result {
        Ok(()) if json_output() => print_json(serde_json::json!({"ok": true})),
        Ok(()) => println!("Credential value replaced; identity and metadata preserved."),
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_input_is_bounded_and_exact() {
        assert_eq!(&**read_stdin("value\n".as_bytes()).unwrap(), "value\n");
        assert!(read_stdin(&b""[..]).is_err());
        assert!(read_stdin(&b"\xff"[..]).is_err());
        assert!(read_stdin(&vec![b'x'; MAX_REPLACEMENT_VALUE_BYTES + 1][..]).is_err());
        assert!(read_stdin(&vec![b'x'; MAX_REPLACEMENT_VALUE_BYTES][..]).is_ok());
    }
    #[test]
    fn replacement_prompt_cancellation_eof_and_mismatch_are_errors() {
        for kind in [
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            assert!(read_confirmed(|_| Err(kind.into())).is_err());
            let mut calls = 0;
            assert!(
                read_confirmed(|_| {
                    calls += 1;
                    if calls == 1 {
                        Ok("synthetic".into())
                    } else {
                        Err(kind.into())
                    }
                })
                .is_err()
            );
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
        assert!(read_confirmed(|_| Ok("synthetic".into())).is_ok());
    }
}
