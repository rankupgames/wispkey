# Secure WispKey Tray GUI Design

Date: 2026-08-25
Issue: https://github.com/rankupgames/wispkey/issues/4

## Goal

Add an optional background tray application so an owner can add credentials through a native Svelte 5 dialog without using the terminal. The CLI remains the shared core. The tray is a desktop extension that talks to the vault through authenticated, current-user-only local IPC.

## Non-goals

- Changing proxy, MCP, or CLI credential semantics except adding lock, empty-value rejection, and atomic multi-add.
- Unauthenticated localhost HTTP forms.
- Passing secrets through argv, `--value`, or shell history.
- Showing plaintext credential values in the default list view.

## Architecture

```
[Svelte 5 webview] -- in-process IPC --> [wispkey-tray]
                                              |
                                              v
                                    owner Unix socket / named pipe
                                              |
                                              v
                         [wispkey tray --ipc-only | tray in-process server]
                                              |
                                              v
                                         Vault (SQLite)
```

- `wispkey` library exposes vault operations and the owner IPC protocol.
- `wispkey tray --ipc-only` serves IPC with no GUI (tests, headless desktop host).
- `wispkey-tray` optional binary shows the tray icon and Svelte dialogs, hosting or connecting to the same IPC.
- Closing a dialog does not quit the tray process. Quit does.

## Vault APIs

- `Vault::add_credential` rejects empty/whitespace names and values.
- `Vault::add_credentials_atomic(&[AddCredentialRequest])` inserts all rows in one `BEGIN IMMEDIATE` transaction. Any validation, duplicate, or insert failure rolls back every row.
- `Vault::lock()` clears the session store and drops the in-memory master key.
- OVH API template expands to three `api_key` credentials:
  - `{prefix}-application-key`
  - `{prefix}-application-secret`
  - `{prefix}-consumer-key`
  Duplicate names among the three or against the project fail before commit.

## Owner IPC

- Endpoint: owner-only Unix socket `owner.sock` under `WISPKEY_VAULT_PATH` / `~/.wispkey` on Unix; per-user named pipe on Windows.
- Discovery file `owner.json` is owner-only and contains pid, protocol version, and endpoint. It does not contain secrets.
- Unix connections must present the same UID as the server (`SO_PEERCRED`). Mismatched UID fails closed.
- Socket file mode is `0600`.
- JSON request/response. Methods: `status`, `unlock`, `lock`, `list_credentials`, `list_projects`, `list_partitions`, `add_credential`, `add_template`, `shutdown`.
- Responses return names, types, tags, hosts, wisp tokens, and project/partition metadata. They never return plaintext secret values.
- Tracing/logs redact `value`, `password`, and template secret fields. Notifications never include secrets.
- Locked vault, missing endpoint, malformed JSON, empty fields, duplicate names, and unauthorized peers fail closed.

## Tray UI

- Menu: lock/unlock status, Add credential, List credentials, Lock vault, Settings, Quit.
- Add credential dialog: name, type, value (masked), description, tags, hosts, project, partition.
- Compound path: OVH API template with three masked fields and a name prefix.
- Reveal and copy are explicit actions. Form secret state clears on save, cancel, lock, timeout, and failure.
- Settings include optional start-at-login.
- List view shows names and metadata only.

## Testing

Automated tests cover successful save, atomic rollback, invalid input, duplicate names, locked vault, IPC authorization, and secret-redaction boundaries. GUI is optional in CI; IPC and vault tests run on the default `cargo test` path.
