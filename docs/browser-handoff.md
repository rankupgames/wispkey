# Local browser login handoff (preview)

An agent can request a website login fill and poll its status without receiving
the username/password payload. A person opens the site in a **separate,
human-controlled browser profile**, reviews the request in the WispKey extension,
and verifies with Windows Hello. WispKey fills the form but never submits it.

This source-build preview targets Chrome, Edge and Firefox on Windows 11. Windows
Hello must be configured; there is no passwordless approval-button fallback.
macOS and Linux native hosts refuse fills until they have an OS approval backend.
The extension is not yet published in browser stores or included in release archives.

## Set up the human profile

Create a separate profile that your agent/browser automation cannot control.
Do not enable remote debugging in that profile, expose it to a browser-control
MCP server, or install the extension in the agent's profile. Native host
registration is per Windows user, **not** per browser profile; install the
extension only in the intended human profile.

From the repository root:

```powershell
cargo build --release --bin wispkey --bin wispkey-browser-host
npm --prefix browser-extension run build
$env:PATH = (Resolve-Path ./target/release).Path + [IO.Path]::PathSeparator + $env:PATH
```

Restart MCP clients with the updated CLI on their `PATH`; an already-running
server keeps its old tools. Keep the MCP command as `wispkey`, as in the normal
setup. The `PATH` change above applies only to this terminal and its child processes.

Chrome/Edge: enable developer mode at `chrome://extensions` or `edge://extensions`,
choose **Load unpacked**, and select `browser-extension/dist/chromium`. Copy its
extension ID and register that exact ID:

```powershell
./scripts/install-browser-host.ps1 -Browser Chrome -ExtensionId '<extension-id>'
# Or -Browser Edge with the ID from Edge.
```

Firefox: open `about:debugging#/runtime/this-firefox`, choose **Load Temporary
Add-on**, and select `browser-extension/dist/firefox/manifest.json`. Register it:

```powershell
./scripts/install-browser-host.ps1 -Browser Firefox
```

Firefox temporary add-ons disappear when Firefox restarts; reload the add-on for
each development session. A persistent release needs Mozilla signing. Chromium
unpacked IDs can change when the extension directory moves; register the new ID.

The installer uses `HKCU`, needs no administrator rights, and writes only a native
host manifest under `%LOCALAPPDATA%\WispKey\BrowserHost` plus the selected browser's
`NativeMessagingHosts\com.wispkey.browser` registry key. `-HostPath` can select a
different build. It does not install an extension or change a browser profile.
To uninstall, remove the extension, that browser's registry key, and its manifest
(`chrome.json`, `edge.json` or `firefox.json`). Rebuild/re-register after moving the binary.

## Generate, request, approve, fill

Unlock WispKey normally. Use **Generate website login** in the optional desktop
tray, or the existing `login generate` CLI / `wispkey_generate_login` MCP tool.
The desktop job application preset selects project `career-ops` and partition
`job-applications`. Confirm the destination before generating; missing projects
and partitions are created for this desktop flow. The login is
encrypted and saved as `pending` with a 180-day review reminder; its password
never enters the desktop form or its IPC response.

An agent then calls:

```json
{
  "name": "wispkey_request_browser_fill",
  "arguments": {
    "name": "acme-careers",
    "project": "career-ops",
    "origin": "https://careers.example.com",
    "requester": "career-ops-agent",
    "reason": "Create the application account I requested"
  }
}
```

The result contains only `request_id`. In the human profile, navigate to the
matching HTTPS page, open the extension, confirm that this is your human profile,
and select the request. Review the full origin, project/name, requester and reason
before approving with Windows Hello. Requester and reason are **unverified
agent-supplied labels**, not proof of identity. Denying a request never decrypts it.

The extension needs one visible username/email field and one password field in
the top-level form. It also supports two password fields when both explicitly
declare `autocomplete="new-password"`. Ambiguous forms, hidden/disabled fields,
iframes, OTP fields and forms with a different submission origin are refused.
There is no broad host permission, persistent content script, clipboard use,
automatic form submission, or external messaging endpoint.

```json
{
  "name": "wispkey_browser_fill_status",
  "arguments": { "request_id": "<id-from-request>" }
}
```

States: `pending`, `approved`, `denied`, `completed`, `failed`. `approved` means
OS verification succeeded and the payload was consumed once. `completed` is the
extension's report that it set the fields; it is **not** evidence of submission,
successful login, or account creation. Keep the site open while approving.
Reopen the extension to see the last local result if Windows Hello closed its popup.
Confirm account creation yourself, then use `wispkey login activate <name>`.

## Boundaries and recovery

- Requests last five minutes and bind the credential ID, project, exact HTTPS
  origin (including a non-default port) and credential revision. Deletion,
  replacement, edits, archival, expiry, denial, or prior consumption prevents
  disclosure. Concurrent consumers have at most one successful release.
- The host closes its vault before prompting and reopens the unlocked session
  afterward. Locking or session expiry during approval prevents release.
- Filling uses a one-use Port attached to the original top-level document. A
  navigation during approval disconnects it. Origin and form checks run again
  just before filling. Passwords are sent only through the browser's private
  native-messaging pipe and its document Port, never through MCP or owner IPC.
- Native messaging uses framed stdin/stdout as required by the browser protocol.
  `wispkey-browser-host` is a dedicated transport binary, not a reveal command or
  normal JSON CLI. Do not capture its transport output or enable payload logging.
- Request, approval, denial, completion and failure events contain metadata only.
  Approval fails closed if its audit write fails. Expiry is applied when requests
  are next accessed; terminal request metadata is retained for up to a day.
  Transient browser requests are omitted from encrypted backup/export bundles.
- A failed fill never deletes the saved credential. Fix the form/profile/session
  and request a fresh approval. Request IDs do not confer approval or allow replay.
- Separate profiles protect against accidental disclosure to browser automation;
  they are **not an OS security boundary**. The destination website necessarily
  sees the filled password. An agent with DOM access to that profile, malicious
  extensions, or code running as the same OS owner can read it. WispKey's existing
  owner-only `exec`/`run`/`inject` tools also permit intentional plaintext egress.
  Use OS-account/process isolation if your agent has unrestricted shell access.

## Verification

```powershell
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
npm --prefix browser-extension test
npm --prefix browser-extension run build
cd browser-extension
npm ci
npx playwright install chromium firefox
npm run test:browser
cd ..
npm --prefix crates/wispkey-tray/ui ci
npm --prefix crates/wispkey-tray/ui run build
cargo check -p wispkey-tray
```

Automated tests cover metadata-only MCP/native responses, framing, migration,
expiry, denial, credential changes, concurrent consumption, audit failure, origin
and form checks, and navigation during approval. Chromium and Firefox fixtures
exercise real DOM/layout and the popup with synthetic data and mocked extension
transport. They do not verify extension installation or bypass OS verification.
Before release, smoke-test both actual browser families in a disposable human
profile with synthetic logins: approve/cancel Windows Hello, navigate during
approval, lock the vault during approval, fill a login/signup form, verify no
submission, and inspect metadata-only request status. The real Windows Hello
prompt and browser extension installation require a human check.

Protocol references: [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging),
[Firefox native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging),
[Windows desktop user verification](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync).
