//! Renderer trust boundary. Only native token copy may request an opaque token.

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::owner_client::{OwnerClient, clear_json, failure};
use crate::popout::{Anchor, Popout};

const MAX_RENDERER_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(super) struct RendererBridge {
    clipboard: Option<arboard::Clipboard>,
}

// This type is private to the native bridge; it is not an owner IPC contract.
enum HostCommand {
    CloseWindow,
    ResizeWindow(Option<f64>),
    ChooseImportFiles,
    ChooseImportDirectory,
    ClipboardImport(Value),
    CopyToken(Value),
    Owner(Value),
    Unavailable,
}

impl RendererBridge {
    pub(super) fn release_clipboard(&mut self) {
        self.clipboard.take();
    }

    /// Returns true only when the renderer requests destruction of this popout.
    pub(super) fn handle_request(
        &mut self,
        dialog: &mut Popout,
        owner: &OwnerClient,
        body: &str,
        anchor: Option<Anchor>,
    ) -> bool {
        let Some((id, command)) = decode(body) else {
            return false;
        };
        match command {
            HostCommand::CloseWindow => return true,
            HostCommand::ResizeWindow(height) => {
                match height.filter(|height| height.is_finite() && *height > 0.0) {
                    Some(height) => {
                        dialog.resize(height, anchor);
                        deliver(dialog, &id, &json!({"ok":true,"result":{"resized":true}}));
                    }
                    None => deliver(
                        dialog,
                        &id,
                        &failure("invalid_input", "window height is invalid"),
                    ),
                }
            }
            HostCommand::ChooseImportFiles | HostCommand::ChooseImportDirectory => {
                let paths = dialog
                    .choose_import_paths(matches!(command, HostCommand::ChooseImportDirectory));
                deliver(
                    dialog,
                    &id,
                    &json!({"ok":true,"result":{"cancelled":paths.is_none(),"paths":paths.unwrap_or_default()}}),
                );
                dialog.focus();
            }
            HostCommand::ClipboardImport(mut params) => {
                let result = clipboard_mut(&mut self.clipboard)
                    .and_then(|clipboard| {
                        clipboard.get_text().map(Zeroizing::new).map_err(|_| {
                            failure("clipboard_unavailable", "clipboard text is unavailable")
                        })
                    })
                    .and_then(|content| clipboard_preview(&content, &params));
                clear_json(&mut params);
                match result {
                    Ok(preview) => queue(
                        dialog,
                        owner,
                        &id,
                        json!({"id":id, "method":"import_preview", "params":preview}),
                        false,
                    ),
                    Err(error) => deliver(dialog, &id, &error),
                }
            }
            HostCommand::CopyToken(request) => queue(dialog, owner, &id, request, true),
            HostCommand::Owner(request) => queue(dialog, owner, &id, request, false),
            HostCommand::Unavailable => deliver(
                dialog,
                &id,
                &failure("invalid_input", "desktop action is unavailable"),
            ),
        }
        false
    }

    /// Replaces native token results before any response reaches the renderer.
    pub(super) fn respond(
        &mut self,
        dialog: Option<&Popout>,
        id: &Value,
        mut response: Value,
        copy_token: bool,
        activity: u64,
    ) {
        if let Some(dialog) = dialog {
            if copy_token && response["ok"] == true {
                copy_token_response(
                    &mut response,
                    &mut self.clipboard,
                    activity == dialog.activity(),
                );
            }
            deliver(dialog, id, &response);
        }
        clear_json(&mut response);
    }
}

fn decode(body: &str) -> Option<(Value, HostCommand)> {
    if body.len() > MAX_RENDERER_BYTES {
        return None;
    }
    let mut request = serde_json::from_str::<Value>(body).ok()?;
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let command = match method {
        "close_window" => HostCommand::CloseWindow,
        "resize_window" => HostCommand::ResizeWindow(request["params"]["height"].as_f64()),
        "choose_import_files" => HostCommand::ChooseImportFiles,
        "choose_import_directory" => HostCommand::ChooseImportDirectory,
        "clipboard_import" => HostCommand::ClipboardImport(request["params"].take()),
        "copy_token" => {
            request["method"] = json!("get_token");
            return Some((id, HostCommand::CopyToken(request)));
        }
        method if owner_method_allowed(method) => return Some((id, HostCommand::Owner(request))),
        _ => HostCommand::Unavailable,
    };
    clear_json(&mut request);
    Some((id, command))
}

fn queue(dialog: &Popout, owner: &OwnerClient, id: &Value, request: Value, copy_token: bool) {
    if !owner.queue(dialog.id(), request, copy_token, dialog.activity()) {
        deliver(dialog, id, &failure("busy", "desktop is busy; try again"));
    }
}

fn clipboard_mut(
    clipboard: &mut Option<arboard::Clipboard>,
) -> Result<&mut arboard::Clipboard, Value> {
    if clipboard.is_none() {
        *clipboard = Some(
            arboard::Clipboard::new()
                .map_err(|_| failure("clipboard_unavailable", "clipboard is unavailable"))?,
        );
    }
    clipboard
        .as_mut()
        .ok_or_else(|| failure("clipboard_unavailable", "clipboard is unavailable"))
}

fn copy_token_response(
    response: &mut Value,
    clipboard: &mut Option<arboard::Clipboard>,
    active: bool,
) {
    let copied = if !active {
        Err(failure("cancelled", "token copy was cancelled"))
    } else {
        response["result"]["token"]
            .as_str()
            .filter(|token| token.starts_with("wk_"))
            .ok_or_else(|| failure("invalid_response", "credential token is unavailable"))
            .and_then(|token| {
                clipboard_mut(clipboard)?
                    .set_text(token.to_owned())
                    .map_err(|_| failure("clipboard_unavailable", "could not copy the token"))
            })
    };
    clear_json(response);
    *response = copied.map_or_else(
        |error| error,
        |_| json!({"ok":true,"result":{"copied":true}}),
    );
}

fn clipboard_preview(content: &str, params: &Value) -> Result<Value, Value> {
    if content.trim().is_empty() {
        return Err(failure("invalid_input", "clipboard is empty"));
    }
    if content.len() > 1024 * 1024 {
        return Err(failure(
            "limit_exceeded",
            "clipboard exceeds the import limit",
        ));
    }
    let format = if content.trim_start().starts_with('{') {
        "json"
    } else if content.lines().any(|line| {
        line.trim_start()
            .split_once('=')
            .is_some_and(|(key, value)| {
                let key = key
                    .trim()
                    .strip_prefix("export ")
                    .unwrap_or(key.trim())
                    .trim();
                !key.is_empty()
                    && !value.is_empty()
                    && !value.starts_with('=')
                    && key.bytes().enumerate().all(|(index, ch)| {
                        ch == b'_' || ch.is_ascii_alphabetic() || (index > 0 && ch.is_ascii_digit())
                    })
            })
    }) {
        "env"
    } else {
        "secret"
    };
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty());
    if format == "secret" && name.is_none() {
        return Err(failure("clipboard_name_required", "Name this credential"));
    }
    Ok(
        json!({"source":{"kind":"clipboard", "content":content, "format":format, "name":name}, "project":params.get("project"), "environment":params.get("environment")}),
    )
}

fn owner_method_allowed(method: &str) -> bool {
    matches!(
        method,
        "status"
            | "initialize"
            | "unlock"
            | "lock"
            | "list_credentials"
            | "list_projects"
            | "list_partitions"
            | "create_project"
            | "create_partition"
            | "add_credential"
            | "add_template"
            | "generate_login"
            | "rotate_credential"
            | "remove_credential"
            | "import_preview"
            | "import_review"
            | "import_commit"
            | "import_cancel"
            | "get_settings"
            | "set_settings"
    )
}

fn deliver(dialog: &Popout, id: &Value, response: &Value) {
    dialog.evaluate_script(&format!("window.__wispkeyResolve?.({id},{response});"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obsolete_token_copy_never_opens_the_clipboard_or_retains_the_token() {
        let mut clipboard = None;
        let mut response = json!({"ok":true,"result":{"token":"wk_synthetic_token"}});
        copy_token_response(&mut response, &mut clipboard, false);
        assert!(clipboard.is_none());
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "cancelled");
        assert!(!response.to_string().contains("wk_synthetic_token"));
    }

    #[test]
    fn clipboard_preview_requires_a_name_for_one_value_and_never_guesses_a_secret_as_env() {
        let value = "fixture-value==";
        assert_eq!(
            clipboard_preview(value, &json!({"project":"default"})).unwrap_err()["error"]["code"],
            "clipboard_name_required"
        );
        let preview = clipboard_preview(
            value,
            &json!({"project":"default","name":"clipboard-fixture"}),
        )
        .unwrap();
        assert_eq!(preview["source"]["format"], "secret");
        assert_eq!(preview["source"]["name"], "clipboard-fixture");
        assert_eq!(
            clipboard_preview("QUJDRA==", &json!({"project":"default"})).unwrap_err()["error"]["code"],
            "clipboard_name_required"
        );
        assert_eq!(
            clipboard_preview("FIXTURE_KEY=value", &json!({"project":"default"})).unwrap()["source"]
                ["format"],
            "env"
        );
        assert_eq!(
            clipboard_preview("{\"FIXTURE_KEY\":\"value\"}", &json!({"project":"default"}))
                .unwrap()["source"]["format"],
            "json"
        );
    }

    #[test]
    fn renderer_cannot_call_raw_token_or_server_shutdown_methods() {
        assert!(!owner_method_allowed("get_token"));
        assert!(!owner_method_allowed("shutdown"));
        assert!(!owner_method_allowed("cloud_login"));
        assert!(owner_method_allowed("import_commit"));
        for method in ["get_token", "shutdown", "cloud_login"] {
            let (_, command) = decode(&json!({"method":method}).to_string()).unwrap();
            assert!(matches!(command, HostCommand::Unavailable));
        }
        let (_, command) =
            decode(r#"{"id":7,"method":"copy_token","params":{"name":"fixture"}}"#).unwrap();
        let HostCommand::CopyToken(mut request) = command else {
            panic!("token copy must stay native");
        };
        assert_eq!(request["method"], "get_token");
        assert_eq!(request["params"]["name"], "fixture");
        clear_json(&mut request);
        let (_, command) = decode(r#"{"method":"import_commit"}"#).unwrap();
        assert!(matches!(command, HostCommand::Owner(_)));
    }
}
