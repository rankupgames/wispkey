# Encrypted signup profiles

This is the reusable identity foundation for issue #43. A profile holds an email
and optional username encrypted with the local vault key. It is a separate record,
not a credential, wisp token, auth-registry account, or proxy capability. Profile
inventory contains only its ID, label, revision, project and partition. Use a
non-sensitive label; labels and scope names are metadata.

Profile management requires an unlocked owner vault. CLI creation and replacement
read JSON from `--identity-file PATH` or stdin (`--identity-file -`). Neither CLI
nor MCP returns the stored identity. There is deliberately no MCP identity-write
or plaintext-profile retrieval tool.

## Setup with synthetic data

Build with current stable Rust (minimum 1.94). On macOS, install the Command Line
Tools. If Xcode is selected but unavailable, use
`DEVELOPER_DIR=/Library/Developer/CommandLineTools` for Cargo. No native user
presence acceptance is implied by a successful Rust build.

Use a scratch vault for this example. Do not point a test suite at a personal vault.

```sh
export WISPKEY_VAULT_PATH="$(mktemp -d)"
export WISPKEY_PASSWORD='synthetic-test-password'
cargo build --locked
WK=./target/debug/wispkey
"$WK" init
printf '%s' '{"email":"synthetic@example.test","username":"synthetic-user"}' |
  "$WK" --format json signup-profile create work \
    --project default --partition personal --identity-file -
"$WK" --format json signup-profile list --project default --partition personal
```

For real identities, use an owner-controlled input file or pipe; never put them
in argv or an agent prompt. Protect and dispose of input files according to the
owner's normal secret handling. JSON permits only `email` and optional `username`.
Input is bounded to 4096 bytes. Empty identities, control characters, malformed
JSON, unknown fields and oversized input fail without echoing the input.

Take the ID and revision from the metadata response:

```sh
"$WK" --format json login generate example-login \
  --profile PROFILE_ID --profile-revision REVISION \
  --project default --partition personal --url https://signup.example.test
```

All four selectors are required. The login uses the email by default. Add
`--profile-username` to select the optional username instead; absence of a username
fails closed. The existing native-browser contract supports one identity slot.
Forms requiring *both* a distinct username and email remain unsupported and are
refused by the existing conservative mapping. This change does not expand mapping.

Profile resolution and the encrypted login insert share one SQLite write
transaction. Every successful generation produces a new random password and a
pending login. Duplicate login names, failed writes, invalid scope, deleted IDs
and stale revisions return no login or password. No fill is queued until a saved
login is separately requested through the existing approval flow.

```sh
"$WK" --format json signup-profile update PROFILE_ID --revision REVISION \
  --project default --partition personal --identity-file owner-input.json
"$WK" signup-profile remove PROFILE_ID --revision CURRENT_REVISION \
  --project default --partition personal
```

An update changes the revision. Deletion followed by recreation changes the ID.
Both invalidate old selections. Existing generated logins are independent saved
snapshots: profile edits/removal do not change their identity or password. Browser
denial, cancellation, navigation or failed signup leaves that pending login
recoverable and never marks the account active. Credential edits still invalidate
existing browser requests through the unchanged credential-revision checks.
Projects and partitions containing profiles cannot be deleted/reassigned through
the generic scope deletion path; remove the profiles explicitly first.

## Agent integration

`wispkey_signup_profile_list` requires explicit `project` and `partition` and returns
metadata only. `wispkey_generate_login` accepts `profile`, `profile_revision`,
`project`, `partition`, `name`, and `url`, with optional `profile_username: true`.
Exactly one of legacy inline `username` or `profile` is permitted. Responses omit
identity and password, including legacy generation responses. Legacy inline login
generation and already-saved logins remain supported. Owner IPC's existing inline
generator remains unchanged; there is no new native GUI profile selector here.

## Recovery and transport

Schema 15 adds the encrypted profile table. Opening schema 14 migrates the table
without changing existing credentials. Older binaries reject schema 15. Profile
payloads bind their ID, label, revision, project and partition inside encryption;
swapped ciphertext or changed metadata fails to resolve.

- Full-vault backup includes encrypted profile rows with credentials, uses backup
  format 3 when profiles exist, and restores the original IDs and revisions.
  Excluding credentials also excludes profiles. Conflicting merge rows fail closed.
- Project and partition export include profiles in authenticated version 3
  envelopes, encrypted under the bundle passphrase. Imports are atomic, preserve
  scope and IDs, and reject duplicates rather than silently skip profiles. Single
  credential export includes the saved login only; it does not share reusable
  profiles or create a live link back to one.
- Encrypted Cloud snapshots use version 3 for profile-bearing partitions, including
  an empty profile set after deletion. They preserve profile edits and deletion.
  The existing local hash guard detects edits during sync. Legacy snapshots cannot
  replace a partition that has profile history. Profile fields never enter relay
  metadata; they are inside the existing authenticated encrypted snapshot.
- Legacy profile-free project/partition bundles and v1/v2 snapshots remain readable.
  Older readers reject profile-bearing transport instead of silently dropping it.

## Regression suites

```sh
export WISPKEY_VAULT_PATH="$(mktemp -d)"
cargo test --locked --all-features --lib signup
cargo test --locked --all-features --test signup_profiles --test login
cargo test --locked --all-features --test cloud_sync signup_profiles
cargo test --locked --all-features --lib core::browser::tests
node --test browser-extension/tests/*.test.mjs
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

The profile unit suite covers ciphertext/metadata binding, stale selections,
profile edits and recreation, project/partition isolation, explicit identity
choice, fresh passwords, duplicate names, injected database failures, denial
recovery, encrypted sync round trips/deletion/conflicts, export/import, malformed
and old-format rejection, migration and legacy login generation. A two-connection
SQLite regression pauses the encrypted profile read and checks that competing
update/generate/remove operations cannot write before generation commits. Backup
recovery also checks that deleting the last profile retains the managed-history
marker and rejects legacy snapshots after restore. The integration
suite uses actual CLI/MCP subprocesses with synthetic temporary vaults to check
setup, file/stdin input, metadata-only outputs, structured-error and stored-audit
redaction, backup restoration, merge conflicts and exclusions. A synthetic HTTP
sync fixture additionally checks profile-only conflicts, edits, deletion and Cloud-account
isolation without contacting a live service. Existing
browser suites cover form mapping, navigation, exact origin, request expiry,
credential edits and single-use release.

## Acceptance still outstanding

This slice does **not** complete issue #43. Real macOS native-host installation and
OS user-presence approval remain separate acceptance work. The Cloud request/status
relay still needs its device/request binding and cancellation implementation and
acceptance. Local encrypted snapshot tests prove storage/transport preservation;
they do not prove live Cloud relay behavior. Browser fixtures do not prove real
OS presence or native-host installation. No deployment, live grant, account
submission, terms acceptance, or real-vault migration is part of this suite.
