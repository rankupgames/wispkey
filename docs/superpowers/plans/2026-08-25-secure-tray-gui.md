# Secure Tray GUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an optional WispKey tray that can securely add single and OVH-template credentials over authenticated local IPC.

**Architecture:** Keep CLI as the core binary. Expose a library with vault atomic writes plus owner IPC. Add `wispkey tray --ipc-only` for headless tests and a `wispkey-tray` crate with tray-icon plus Svelte 5 webview.

**Tech Stack:** Rust, rusqlite, tokio Unix sockets / Windows named pipes, Svelte 5, tray-icon, wry.

## Global Constraints

- Secrets never enter argv, stdout/stderr, logs, telemetry, crash reports, or notifications.
- No unauthenticated localhost web form.
- Compound saves are atomic.
- Duplicate names fail explicitly.
- Default `cargo test` must pass without GUI system libraries.
- Existing CLI and proxy behavior stays intact except empty-value rejection and new lock/tray commands.

---

### Task 1: Vault validation, atomic add, lock, OVH template

**Files:**
- Modify: `src/core/mod.rs`
- Modify: `src/core/session.rs`
- Create: `src/core/templates.rs`
- Test: `src/core/tests.rs`

- [ ] Write failing unit tests for empty value, atomic rollback, OVH expansion
- [ ] Implement validation, `add_credentials_atomic`, `lock`, OVH template
- [ ] Run `cargo test --lib core::tests` until green
- [ ] Commit

### Task 2: Library surface and owner IPC

**Files:**
- Create: `src/lib.rs`
- Create: `src/owner_ipc/mod.rs`
- Modify: `src/main.rs`
- Test: `src/owner_ipc/mod.rs` unit tests and `tests/owner_ipc.rs`

- [ ] Convert package to lib+bin
- [ ] Implement JSON IPC with same-user auth and redaction
- [ ] Add `wispkey lock` and `wispkey tray --ipc-only`
- [ ] Integration tests for save, rollback, locked vault, duplicate, unauthorized, redaction
- [ ] Commit

### Task 3: Optional tray GUI

**Files:**
- Create: `crates/wispkey-tray/`
- Create: Svelte 5 UI under `crates/wispkey-tray/ui`
- Modify: root `Cargo.toml` workspace `default-members = ["."]`

- [ ] Tray menu, add/list/settings dialogs, masked secrets, start-at-login setting
- [ ] Closing dialogs does not quit
- [ ] Commit

### Task 4: Docs and PR

**Files:** `README.md`, `AGENTS.md`, `docs/security-model.md`, `CHANGES.md`, `docs/tray.md`

- [ ] Document tray, IPC, OVH template, and security boundary
- [ ] `cargo fmt`, clippy, test
- [ ] Open PR
