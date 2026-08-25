# Headless Unlock And Boring Computer Smoke Tests

WispKey never accepts the vault master password as a command-line argument. Headless and Boring Computer verification should unlock the **host** vault through a remembered protector or an owner-only password file, then inject only `wk_*` tokens and instance identity into guests.

## Unlock Paths

1. **OS protector (preferred on macOS and Windows)** -- `wispkey unlock --remember` stores the derived vault key, not the password, in:
   - macOS Keychain
   - Windows Credential Manager
2. **Bounded local protector (Linux default and universal fallback)** -- when the OS store is unavailable or not compiled in, WispKey writes a machine-bound encrypted `session-protector` file next to the vault (`WISPKEY_PROTECTOR=auto` or `file`). Linux builds keep this file path so the binary does not require D-Bus or libsecret.
3. **Current session** -- `~/.wispkey/session` remains the short-lived unlocked state (default 30 minutes). Commands use this file; they do not re-read the master password.
4. **Owner-only password file** -- `wispkey unlock --password-file ~/.wispkey/master.pass` for first authorization or recovery. The file must be owner-only on Unix (mode `0600`).
5. **`WISPKEY_PASSWORD`** -- still supported for trusted local automation. Do not put it in guest environments, URLs, repository files, or process arguments.

`wispkey lock` revokes the current session immediately. `wispkey lock --forget` also deletes the remembered protector so later unlocks require the master password again.

## Timeouts And Revocation

| State | Default lifetime | Revoke |
|-------|------------------|--------|
| Unlocked session | 30 minutes (`--timeout`, `WISPKEY_SESSION_TIMEOUT`; `0` means no expiry) | `wispkey lock` |
| Remembered protector | 480 minutes (`--protector-timeout`, `WISPKEY_PROTECTOR_TIMEOUT`; `0` means until `--forget`) | `wispkey lock --forget` |

Expired sessions and protectors fail closed. `wispkey status` reports `session_active`, `session_expires_at`, `protector_available`, and `protector_backend`. Unlock, lock, remember, forget, and expiry write audit events (`VaultUnlocked`, `VaultLocked`, `ProtectorRemembered`, `ProtectorForgotten`, `SessionExpired`) without the password or raw credential values.

## Recovery When A Protector Is Unavailable

- **OS protector missing (no Keychain/Secret Service, CI, headless Linux):** unset `WISPKEY_PROTECTOR` or set `WISPKEY_PROTECTOR=file`, then `wispkey unlock --remember`. Or unlock once with `--password-file`.
- **`WISPKEY_PROTECTOR=os` and the platform store fails:** the error names the failure and tells you to use `file` or `--password-file`. WispKey does not prompt for a password over a non-TTY.
- **Remembered unlock expired or forgotten:** unlock again with `--password-file` or `WISPKEY_PASSWORD` on the host, optionally with `--remember`.
- **Local proxy down:** `wispkey serve` still requires an unlocked host session (or env sideloads). Unlock the host first; do not copy the master password into the guest.

## Boring Computer Browser Smoke Test

Run this on the **host** that owns the vault. Guests receive instance identity and wisp tokens only.

```bash
# 1. Authorize a bounded host session without putting the password in argv
export WISPKEY_PROTECTOR=auto
wispkey unlock --remember --timeout 30 --protector-timeout 480 \
  --password-file ~/.wispkey/master.pass

# 2. Confirm the host vault and proxy are ready
wispkey --format json status
wispkey serve --listen unix:/run/wispkey/proxy.sock

# 3. Enroll one approved ephemeral guest (scope to the credential it may use)
wispkey instance enroll bc-smoke-001 --credential openai-key

# 4. Launch the guest with instance id/secret and wk_* tokens only.
#    Do not export WISPKEY_PASSWORD, --password-file contents, or plaintext secrets
#    into the microVM. See docs/multi-instance-deployment.md for Firecracker vsock.

# 5. From the guest, authenticate the Boring control API through WispKey,
#    open one approved browser interaction, and capture evidence.

# 6. Clean up
#    stop/destroy the guest, then:
wispkey instance revoke bc-smoke-001
wispkey lock
```

Fail-closed checks to include in the same run:

- Locked vault (`wispkey lock` then `wispkey list`) returns a locked-session error.
- Expired session returns `session expired -- run \`wispkey unlock\``.
- `wispkey lock --forget` then `wispkey unlock` without a password fails.
- An instance using a credential outside its enrollment/approval scope returns `403 out_of_scope`.
