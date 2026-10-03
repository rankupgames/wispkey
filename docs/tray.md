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
- Generate website login
- List credentials
- Unlock vault
- Lock vault
- Open settings
- Quit

The tooltip shows locked or unlocked status. Secret fields are masked by default, with explicit reveal and copy actions. Idle timeout, save, cancel, lock, and failure clear secret form state.

## Start-at-login platform limits

The Settings dialog stores the `start_at_login` preference in the owner-only
`tray.json` file. On Linux, saving it also creates or removes
`autostart/wispkey-tray.desktop` under the user's configuration directory.
On macOS and Windows, the preference is stored but no login-startup registration
is created. A successful save on those platforms does not enable autostart.

## Owner IPC

The server listens on an owner-only Unix socket (`~/.wispkey/owner.sock`, or `$WISPKEY_VAULT_PATH/owner.sock`) and writes `owner.json` for discovery. Unix connections must present the same UID as the server. Socket and metadata files are mode `0600`.

Newline-delimited JSON methods:

- `status`, `unlock`, `lock`
- `list_credentials`, `list_projects`, `list_partitions`
- `add_credential`, `add_template`, `generate_login`
- `get_settings`, `set_settings`
- `shutdown`

Responses include names and metadata only. They never include plaintext secret values. Known secret fields are redacted from logs.

`generate_login` accepts `name`, `username`, an HTTPS `url`, optional `project` /
`partition`, and `destination_confirmed: true`. It saves a strong unique password
without displaying it, sets lifecycle `pending`, and schedules a review in 180
days. The job application preset uses `career-ops` / `job-applications`; the
confirmed project and partition are created if needed. Use the
[browser handoff preview](browser-handoff.md) to approve a fill separately; owner
IPC has no browser-fill or password-reveal endpoint.

## OVH API template

`add_template` with `template: "ovh_api"` creates three `api_key` credentials in one transaction:

- `{prefix}-application-key`
- `{prefix}-application-secret`
- `{prefix}-consumer-key`

If any name already exists or any field is empty, none of the three are saved.

## GUI build dependencies

The tray crate needs platform webview and tray libraries, for example on Debian/Ubuntu:

```bash
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev libxdo-dev
cargo build -p wispkey-tray
```

Default `cargo test` does not build the GUI crate.

## IPC troubleshooting

Windows owner IPC calls bound connection, request-write, and response-read phases to five seconds each. Timeout messages identify the phase and prior phase durations without request contents. Server logs include request-handling duration and success status. If a launcher captures stderr, it must continuously drain the pipe; an unread log pipe can stall request handling. The integration harness drains logs while retaining at most 256 KiB, and tests log pressure and concurrent clients without automatic retries.

## Frontend build maintenance

The tray embeds `ui-dist/index.html`; it must boot without a dev server or
separate JavaScript/CSS downloads. Use Node.js 24 LTS (CI), or Node.js 22.12+,
and run `npm ci` followed by `npm run build` in `crates/wispkey-tray/ui`.
Commit the rebuilt HTML alongside source or toolchain changes. The browser
suite exercises the production bundle in Chromium and Firefox with synthetic
owner IPC, including an external-asset-blocked bootstrap check. Native webview
and human OS-consent acceptance still require the platform-specific checks.

The October 2026 frontend migration uses Vite 8.3.0, Svelte 5.57.1 and
`@sveltejs/vite-plugin-svelte` 7.3.1. Vite 8.3.1 is the newer registry stable
release, published September 24 at 12:26:19.940 UTC; it becomes eligible under
the development machine's seven-day npm release-age policy on October 1 at
12:26:19.940 UTC. The committed lockfile intentionally retains 8.3.0 until that
window has elapsed and a fresh tested update is prepared. No release-age or
peer-dependency checks are bypassed.

The [Vite 7 migration](https://v7.vite.dev/guide/migration) and
[Vite 8 migration](https://vite.dev/guide/migration) change bundlers and default
browser targets. Explicit compile targets preserve the previous Vite 6
JavaScript baseline (Chrome 87, Edge 88, Firefox 78, Safari 14), rather than
silently raising native webview requirements. This does not claim runtime
acceptance on every historical browser. `vite-plugin-singlefile` 2.3.3 supports
Vite 8's bundler and keeps assets inline; the artifact regression checks that
future plugin changes do not split them out.
