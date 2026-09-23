//! Browser-native transport. This is the only browser path that returns plaintext,
//! over the browser's private native-messaging pipe after per-fill OS verification.
use std::collections::HashSet;
use std::io::{self, Read, Write};

use serde_json::{Value, json};

use crate::core::{Vault, browser, parse_https_origin};

mod consent;

const MAX_MESSAGE: usize = 16 * 1024;

fn read_message(input: &mut impl Read) -> io::Result<Option<Value>> {
    let mut length = [0; 4];
    if input.read(&mut length[..1])? == 0 {
        return Ok(None);
    }
    input.read_exact(&mut length[1..])?;
    let size = u32::from_ne_bytes(length) as usize;
    if size == 0 || size > MAX_MESSAGE {
        return Err(io::Error::other("invalid native message size"));
    }
    let mut bytes = vec![0; size];
    input.read_exact(&mut bytes)?;
    let message =
        serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid native message"))?;
    Ok(Some(message))
}

fn write_message(output: &mut impl Write, message: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(message).map_err(|_| io::Error::other("invalid response"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("native response too large"));
    }
    output.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    output.write_all(&bytes)?;
    output.flush()
}

fn field<'a>(message: &'a Value, key: &str) -> browser::Result<&'a str> {
    message
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .ok_or("invalid native request")
}

fn handle(message: &Value, released: &mut HashSet<String>) -> browser::Result<Value> {
    let method = field(message, "method")?;
    let vault =
        Vault::open_with_session().map_err(|_| "unlock WispKey before using browser handoff")?;
    match method {
        "pending" => {
            let origin = field(message, "origin")?;
            if parse_https_origin(origin).ok().as_deref() != Some(origin) {
                return Err("an exact HTTPS origin is required");
            }
            Ok(
                json!({ "requests": browser::pending(&vault, origin)?, "approval_available": cfg!(windows) }),
            )
        }
        "deny" => {
            browser::deny(&vault, field(message, "request_id")?)?;
            Ok(json!({ "status": "denied" }))
        }
        "fill" => {
            let request = browser::status(&vault, field(message, "request_id")?)?;
            if request.status != "pending" || request.origin != field(message, "origin")? {
                return Err("request expired, already decided or origin mismatch");
            }
            // Close the vault while the user decides; do not hold a DB transaction
            // or an unlocked session across the potentially long approval prompt.
            drop(vault);
            if !consent::verify(&request)? {
                let vault = Vault::open().map_err(|_| "vault unavailable")?;
                browser::deny(&vault, &request.request_id)?;
                return Err("user denied browser fill");
            }
            let vault = Vault::open_with_session()
                .map_err(|_| "vault locked during approval; unlock and retry")?;
            let login = browser::release(&vault, &request)?;
            released.insert(request.request_id.clone());
            Ok(
                json!({ "request_id": request.request_id, "origin": request.origin, "login": login }),
            )
        }
        "complete" => {
            let id = field(message, "request_id")?;
            if !released.contains(id) {
                return Err("request was not released on this connection");
            }
            let completed = message
                .get("completed")
                .and_then(Value::as_bool)
                .ok_or("completion status is required")?;
            browser::finish(&vault, id, completed)?;
            released.remove(id);
            Ok(json!({ "status": if completed { "completed" } else { "failed" } }))
        }
        _ => Err("unsupported native method"),
    }
}

/// Dedicated binary entry point. Never initialize logging or echo input/errors.
pub fn run() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut released = HashSet::new();
    let result = (|| {
        while let Some(message) = read_message(&mut input)? {
            let response = match handle(&message, &mut released) {
                Ok(result) => json!({ "ok": true, "result": result }),
                Err(error) => json!({ "ok": false, "error": error }),
            };
            write_message(&mut output, &response)?;
        }
        Ok(())
    })();
    if let Ok(vault) = Vault::open() {
        for id in released {
            let _ = browser::finish(&vault, &id, false);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_handles_unicode_eof_and_truncation() {
        let mut bytes = Vec::new();
        let value = json!({"method": "pending", "origin": "https://example.com", "text": "é"});
        write_message(&mut bytes, &value).unwrap();
        assert_eq!(read_message(&mut bytes.as_slice()).unwrap(), Some(value));
        assert!(read_message(&mut &bytes[..bytes.len() - 1]).is_err());
        assert!(read_message(&mut &bytes[..2]).is_err());
        assert!(read_message(&mut &[][..]).unwrap().is_none());
    }

    #[test]
    fn framing_rejects_oversized_or_invalid_input_without_echoing_it() {
        assert!(read_message(&mut &(MAX_MESSAGE as u32 + 1).to_ne_bytes()[..]).is_err());
        let bytes = [3_u32.to_ne_bytes().as_slice(), b"bad"].concat();
        assert_eq!(
            read_message(&mut bytes.as_slice()).unwrap_err().to_string(),
            "invalid native message"
        );
    }
}
