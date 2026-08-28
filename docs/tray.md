# WispKey Tray

The optional tray application is a desktop extension of the WispKey CLI. The CLI remains the shared core. The tray talks to the vault through authenticated, current-user-only owner IPC and never puts secrets on argv or in an unauthenticated localhost web form.

## Quick start

```bash
wispkey init
wispkey tray --ipc-only          # headless owner IPC for tests and desktop hosts
cargo build -p wispkey-tray      # optional GUI binary
wispkey-tray                     # tray icon + Svelte 5 dialogs
```

`wispkey tray` starts owner IPC. If `wispkey-tray` is on `PATH` or next to the CLI binary, it also launches the GUI.

Closing a dialog does not quit the tray. Use **Quit** in the tray menu.

Tray menu:

- Add credential
- List credentials
- Unlock vault
- Lock vault
- Open settings
- Quit

The tooltip shows locked or unlocked status. Secret fields are masked by default, with explicit reveal and copy actions. Idle timeout, save, cancel, lock, and failure clear secret form state.

## Owner IPC

The server listens on an owner-only Unix socket (`~/.wispkey/owner.sock`, or `$WISPKEY_VAULT_PATH/owner.sock`) and writes `owner.json` for discovery. Unix connections must present the same UID as the server. Socket and metadata files are mode `0600`.

Newline-delimited JSON methods:

- `status`, `unlock`, `lock`
- `list_credentials`, `list_projects`, `list_partitions`
- `add_credential`, `add_template`
- `get_settings`, `set_settings`
- `shutdown`

Responses include names and metadata only. They never include plaintext secret values. Known secret fields are redacted from logs.

## OVH API template

`add_template` with `template: "ovh_api"` creates three `api_key` credentials in one transaction:

- `{prefix}-application-key`
- `{prefix}-application-secret`
- `{prefix}-consumer-key`

If any name already exists or any field is empty, none of the three are saved.

## GUI build dependencies

The tray crate needs platform webview and tray libraries, for example on Debian/Ubuntu:

```bash
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev
cargo build -p wispkey-tray
```

Default `cargo test` does not build the GUI crate.
