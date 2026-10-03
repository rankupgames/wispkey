# Owner-operated whole-value replacement

`replace-value` replaces an existing credential's **entire stored value**. It never
creates a missing record. Select the project, partition and credential explicitly:

```sh
wispkey replace-value example-api --project default --partition personal
```

The default is a hidden, confirmed terminal prompt. For trusted automation, feed
exact UTF-8 bytes through a pipe and add `--stdin`. No replacement value argument,
environment-variable fallback, or file option is accepted. `--stdin` refuses an
interactive terminal so typed input is not echoed accidentally. EOF without bytes,
cancellation, mismatched confirmation, invalid UTF-8, NUL and values over 1 MiB
fail without updating the credential. Stdin bytes are not trimmed: a trailing
newline is part of the value. Header-based credential types reject CR/LF;
`basic_auth` requires a complete nonempty `username:password` pair.

This is **not a password-field editor**. For example, an `api_key` containing a
JSON object is opaque to WispKey. The owner must supply the complete intended JSON,
including any username and other fields they want to retain. It does not infer,
merge, validate or patch an application-specific JSON schema. `website_login` has
a known structured payload and is rejected; it requires a separate structured
login editor. This command does not contact a provider or reset a password.

Only encrypted value and `updated_at` change. Record ID, Wisp token, type, project,
partition, hosts, tags, description, creation/use timestamps, origin, lifecycle,
review date, auth registration and bundle relationships remain intact. The new
owner-only interface is an explicit exception to the generic registered-credential
overwrite prohibition; MCP `wispkey_set` and other overwrite APIs retain their
existing behavior. Revoked, expired, inactive, or inconsistent auth registrations
are rejected, and this command never extends their deadlines or revives them.
Successful output is just a confirmation (`{"ok":true}` with `--format json`);
value and token are absent from output and the audit event.

Preserving the registry's provider and account fields preserves the owner's
assertion of identity. An opaque replacement cannot verify that the new secret
belongs to that provider or account; the owner must establish that separately.

## Concurrency and authorization

A valid, finite unlocked owner session is required. WispKey captures a
connection-bound update ticket **before** reading input. At commit it takes an
SQLite immediate transaction and rejects any intervening database commit, even
an unrelated write or a change that was subsequently reverted. A busy proxy may
therefore require retrying the command. The ticket is not an exported revision
and cannot be submitted on another connection. Nothing holds a database lock
while the owner is entering input.

The current session must still match, and auth eligibility is checked again
inside the transaction. Session save/lock operations and the final replacement
commit share a private `session.lock` file. Do not delete that lock file while
processes are running. Use this version for concurrently operating WispKey
processes: older binaries and direct filesystem writes do not participate in this
session lock protocol. Database writes from older clients still invalidate the
update ticket. Renames, moves, removals, token rotations, registry changes and
competing replacements all fail closed. Ciphertext update and the redacted audit
event commit together; audit failure rolls back the update.

This does not make every session-renewal path race-free. The pre-existing
`restore_or_refresh_session` path still loads and saves in separate lock intervals;
a concurrent lock can occur between them. That separate renewal race is unchanged
by this command.
