# Store an existing website login

Use the owner CLI to enter an existing account's username and password without generating a new password or changing anything at the provider:

```sh
wispkey login add-existing work-login --project work --partition personal \
  --origin https://login.example.com
```

The project and partition must already exist. The command refuses any same-named credential in the selected project, including one in a different partition. It never silently updates or creates scope containers. Username and password are each entered twice through hidden terminal prompts; neither has a command-line argument or environment-variable fallback.

To replace both fields of an existing `WebsiteLogin`:

```sh
wispkey login update-existing work-login --project work --partition personal \
  --origin https://login.example.com
```

This is a complete typed pair replacement, not a password-only patch. Enter the intended username again. The selected credential must already be a website login at that exact origin and partition. Updates preserve its ID, wisp token, type, origin, partition, description, hosts, tags, creation/last-use dates, lifecycle, review date and auth-registry/bundle relationships. Only encrypted value and update timestamp change. Unknown or malformed stored payload fields are refused instead of silently discarded. Generic credentials are never converted, and generic `replace-value`/MCP overwrite behavior is unchanged.

Both commands require an already-unlocked, finite owner session. Target, database-write generation and session identity are captured before input, with no database/session lock held during prompts. Any intervening database write (including unrelated writes or an ABA change), session lock/replacement/expiry, or authorization revocation/expiry rejects the write. Retry from the beginning after reviewing changes. Input, encryption and audit failures leave the transaction uncommitted. Cancellation, EOF and confirmation mismatch do not change the record.

For an owner-controlled pipe, explicitly select `--stdin` and send one UTF-8 JSON object with exactly two string fields, `username` and `password`. No file option, secret argument or environment lookup is added. Never put real secrets in an inline shell command, history, logs or a shared file. Input is capped at 128 KiB; the decoded username is at most 1,024 UTF-8 bytes and the password at most 16,384. Username must not be blank; password must not be empty; control characters are refused. Values are not trimmed or otherwise normalized. Unknown fields, duplicate keys and non-string values fail. Secret-bearing input buffers and decoded fields are zeroized on normal drop; this is not a promise to erase terminal, OS or allocator copies.

Output is a generic acknowledgement (`{"ok":true}` with global `--format json`), never the username, password, wisp token, stored payload or input-derived error detail. Audit events are metadata-only `WebsiteLoginStored` and `WebsiteLoginUpdated`, committed atomically with the record.

New records have an exact HTTPS origin, a matching host restriction, pending local lifecycle, no review date and no automatic auth registration. Pending is not a provider-authentication result. Updates retain the existing pending/active state; archived, revoked, expired or inconsistent registered records are refused. No server login, password reset, account activation or provider verification is performed.

The existing [browser handoff](browser-handoff.md) still requires real native owner approval and separate human submission. Saving a login does not bypass that boundary, publish a Cloud relay, verify the account, install an extension or configure a browser session. Use `login generate` only when a newly generated password is actually intended. No real vault, provider account or credential is needed by the disposable regression tests in `tests/existing_login.rs`.
