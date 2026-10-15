# Development environments across Git worktrees

`wispkey env bind` selects a project and development partition once for a local
Git repository. Its registered worktrees reuse the same credential references.
Values are decrypted afresh for each `wispkey run` child, never copied into an
`.env` file. This is an owner-operated plaintext-egress tool, like explicit
`run --manifest`, not a sandbox for untrusted repository code.

## Bind once

Create the project/partition and selected credentials first. Use `--value-file`
for secret input. Every referenced credential must belong to the selected
project **and** partition.

```sh
wispkey partition create development --project example
wispkey add development-secret --project example --partition development \
  --type api_key --value-file /private/input
wispkey env bind --project example --environment development \
  --manifest wispkey.toml
```

Example `wispkey.toml`:

```toml
[env]
PAYLOAD_SECRET = "cred:development-secret"
PORT = "3000"
BROWSER_ORIGIN = "http://localhost:3000"
DATABASE_URL = "file:./local.db"

[worktree]
overrides = ["PORT", "BROWSER_ORIGIN", "DATABASE_URL"]
```

Use credential references for all secrets. Literal manifest settings and local
or CLI overrides are **nonsecret configuration**, and are not encrypted. The
binding snapshots references, defaults and the allowlist in an owner-only local
vault sidecar. Changes to the original manifest require an explicit rebind with
`--replace`; credential value updates are seen immediately on the next launch.
A second bind never replaces an existing binding without that flag.

Only `development`, `dev`, `local`, and `test` partitions are accepted. Production
is never inferred from branch names, active projects, environment variables or
filenames. Manual production use remains an explicit `run --manifest ...
--project ...` choice.

## Per-worktree settings

Create an optional `wispkey.local.toml` at each worktree root (add it to your
repository's ignore rules):

```toml
[env]
PORT = "3100"
BROWSER_ORIGIN = "http://localhost:3100"
DATABASE_URL = "file:./feature.db"
```

Launch from that worktree:

```sh
wispkey run -- npm run dev
wispkey run --env PORT=3200 --env BROWSER_ORIGIN=http://localhost:3200 -- npm run dev
```

Precedence: binding defaults, then the root's `wispkey.local.toml`, then repeated
CLI `--env NAME=VALUE` settings (last occurrence wins). These override inherited
parent-process values. Only names in the bound allowlist can be overridden, and
credential references cannot be replaced or introduced by overrides. Invalid
local settings are errors even if a CLI override would cover them. No unrelated
keys are imported automatically.

`--project` must match the bound project. `WISPKEY_PROJECT` and the active project
do not redirect a binding. An explicit `--manifest` bypasses automatic discovery
and uses existing manual project selection; combining it with `--env` is rejected.
Inside Git, a missing binding is an error, even if `wispkey.toml` exists: bind once
or pass `--manifest wispkey.toml` explicitly. Outside Git the historical local
`wispkey.toml` default remains supported.

## Identity, isolation and limits

Discovery uses Git's canonical common directory and registered worktree list,
not a remote URL or branch name. An untracked private UUID marker in the common
Git directory and its canonical location identify the repository to the local
vault. No machine-specific path is committed. Independent clones, even with the
same remote or a copied marker, do not inherit. Recreating a repository at the
same path without its marker does not inherit. Moving a checkout or restoring a
vault on another machine requires binding there again. Bindings are local state,
not part of encrypted vault backup/sync. Deleting a project/partition and creating
the same name again invalidates its binding. Missing, expired, revoked or
out-of-partition credentials stop launch; errors do not echo config values.

The child retains the caller's working directory: relative application paths
resolve there, never relative to the original manifest or main checkout. Launch
from the worktree root for a database at that root. By default bound DATABASE_URL
must be a relative `file:` or `sqlite:` URL, without parent traversal, authority,
query strings or encoded paths. Each worktree therefore gets its own database
path. Existing symlinks remain the owner's responsibility. For a deliberately
shared database (including network or credential-backed URLs), set
`allow_shared_database = true` in `[worktree]` and explicitly rebind. This may let
concurrent branches alter the same data and schema.

This feature does not copy database contents. Seed databases in a separate setup
operation using SQLite's consistent-backup mechanism. It also adds no automatic
plaintext export mode; existing explicit `inject` remains the materialization
boundary. Runtime launch writes no environment files or resolved secret copies.
As with existing `run`, the child can print its own environment; do not launch
untrusted commands or enable secret-printing diagnostics.
