# Secure Tray GUI Implementation Record

Historical implementation record for the August 25, 2026 tray work. The local
tray and owner IPC are implemented; this file is not an outstanding task list.
See [current tray usage and platform limits](../../tray.md) for operation.
The original implementation plan remains in Git history.

## Implemented components

| Component | Source | Current behavior |
| --- | --- | --- |
| Vault and OVH template | `src/core/mod.rs`, `src/core/templates.rs` | Input validation, atomic credential addition and compound OVH saves. |
| Library and owner IPC | `src/lib.rs`, `src/owner_ipc/mod.rs`, `src/main.rs` | Local lock/unlock and authenticated owner IPC, including headless `wispkey tray --ipc-only`. |
| Optional tray | `crates/wispkey-tray/`, `crates/wispkey-tray/ui/` | Tray menu, credential/list/settings dialogs and masked secret input; closing a dialog does not quit. |
| Default build boundary | Root `Cargo.toml` | Workspace `default-members = ["."]` excludes the optional GUI from default tests. |

The start-at-login preference is stored on all supported platforms, but only
Linux registers/removes an autostart entry. Saving the setting on macOS or
Windows does not register the application to start at login.

## Global Constraints

- Secrets never enter argv, stdout/stderr, logs, telemetry, crash reports, or notifications.
- No unauthenticated localhost web form.
- Compound saves are atomic.
- Duplicate names fail explicitly.
- Default `cargo test` must pass without GUI system libraries.
- Existing CLI and proxy behavior stays intact except empty-value rejection and new lock/tray commands.


## Existing verification surfaces

Vault tests are in `src/core/tests.rs`; owner IPC unit/integration coverage is in
`src/owner_ipc/mod.rs` and `tests/owner_ipc.rs`. Current operating and security
guidance lives in `docs/tray.md`, `docs/security-model.md` and `AGENTS.md`.
This record does not claim a new test run or cross-platform autostart acceptance.
