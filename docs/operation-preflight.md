# Operation catalog preflight

`wispkey operation identity` identifies the local OS account. `wispkey operation
check` validates an owner-private catalog for that account without opening the
vault, reading SSH keys, connecting to a destination, or launching a child.
They are the first implementation of the [cross-node contract](cross-node-operations.md).

Version 1 remains preflight-only. Version 2 enables the separately authorized
[runtime commands](operation-runtime.md). Successful preflight means that the
configuration and private-file checks passed. It does not verify a credential's existence, a live host key,
SSH authentication, a remote helper, or an authorization grant.

## Identify the runner

```console
wispkey operation identity
wispkey --format json operation identity
```

The identifier is `unix-uid:<effective UID>` on Linux/macOS or
`windows-sid:<process account SID>` on Windows. It comes from the operating
system, not `USER`, `USERNAME`, or a caller-supplied requester label. Processes
sharing an OS account share this identifier. It is not an authenticated agent
identity and does not complete RUG-8 or confer permission to run an operation.

## Configure a catalog

The default path is `~/.wispkey/operations.toml`, or `operations.toml` inside
`WISPKEY_VAULT_PATH` when set. `--config` selects a different private file.
The catalog contains metadata only. Never put credential values in it.

The following example is syntactically valid for the illustrative Unix
principal. Replace the principal, UUIDs, expiry, target, key fingerprint and
paths with operator-reviewed metadata. The example fingerprint is synthetic;
preflight does not establish that a server owns the corresponding key.

```toml
version = 1

[[operation]]
id = "maintenance"
kind = "ssh-helper"
project_id = "default"
credential_id = "5af05c13-1c0a-4394-a7a3-7f457ff74a40"
requester_principal = "unix-uid:1000"
environment_id = "preview"
target_id = "worker"
expires_at = "2099-01-01T00:00:00Z"
max_grant_seconds = 300
max_runtime_seconds = 60
connect_timeout_seconds = 10
max_concurrency = 1

[operation.ssh]
address = "192.0.2.1"
port = 22
account = "maintenance"
host_key_algorithm = "ssh-ed25519"
host_key_sha256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
helper_path = "/usr/local/libexec/maintenance"
identity_file = "/approved/restricted-key"
```

On Windows, use the principal returned by `operation identity` and an absolute
identity path such as `C:/Users/runner/.ssh/restricted-key`. The key is neither
opened nor inspected by preflight.

The first schema accepts at most 32 SSH-helper operations in 64 KiB of ASCII
TOML. Unknown fields, empty catalogs, duplicate operation IDs and unsupported
versions/kinds fail. Identifiers use bounded lowercase ASCII slugs; project
and credential references use canonical, non-nil UUIDs, except the built-in
project ID `default`. Expiry must be future UTC in `YYYY-MM-DDTHH:MM:SSZ` form.

Grant limits are 1–300 seconds; runtime limits are 1–60 seconds. Connection
timeouts are 1–30 seconds and cannot exceed runtime. The initial concurrency
limit is exactly one. These are configuration checks, not active grant or
runtime enforcement.

SSH targets require a canonical literal IP address, nonzero port, restricted
non-root account, Ed25519 SHA-256 fingerprint, a fixed absolute POSIX helper
path without traversal, and an absolute identity-file path. DNS aliases,
unspecified/multicast addresses, command strings, proxy/jump settings,
password/env/askpass delivery and arbitrary extra fields are rejected. Docker
and Kubernetes catalogs are not accepted by this preflight version.

## Protect the file

On Linux/macOS, the catalog must belong to the effective user and have no
group/other permission bits (for example, mode `0600`). The reader uses
no-follow directory traversal and checks the opened file. It rejects symlink
components, including aliases such as `/tmp` on systems where `/tmp` is a link;
use the real path. It never changes file permissions itself.

On Windows, the opened file must belong to the process account. Its DACL may
grant access only to that account, SYSTEM and Administrators. Null DACLs,
unverifiable protection, and pathname reparse points are rejected. The
pathname check is a preflight observation, not a guarantee against a concurrent
parent-junction replacement; the file handle's owner and DACL are still checked.

To set an existing catalog to the current account only in PowerShell:

```powershell
$catalogPath = Join-Path $env:USERPROFILE '.wispkey\operations.toml'
$identity = wispkey --format json operation identity | ConvertFrom-Json
$sid = [System.Security.Principal.SecurityIdentifier]::new($identity.principal.Substring(12))
$catalogAcl = [System.Security.AccessControl.FileSecurity]::new()
$catalogAcl.SetOwner($sid)
$catalogAcl.SetAccessRuleProtection($true, $false)
$catalogAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
Set-Acl -LiteralPath $catalogPath -AclObject $catalogAcl
```

## Check the configuration

```console
wispkey operation check
wispkey --format json operation check --config /private/operations.toml --operation maintenance
```

Without `--operation`, every entry must match the current OS principal.
With it, the entire catalog is still parsed and validated; the selected entry
is checked against the current principal. An absent operation, expired entry,
principal mismatch, unsafe file or invalid catalog exits with status 1. Version 2
binds enrolled instance UUIDs instead of comparing the current OS principal;
preflight does not authenticate that instance.

JSON success reports `configuration_valid`, `checked_operations`, and a
`catalog_revision` computed from canonical validated metadata. Formatting and
comments do not affect the revision. It is a review reference, not a signature
or grant. `credential_verified`, `live_target_verified` and
`execution_authorized` and `requester_authenticated` are always `false`.
`execution_available` is `false` for version 1 and `true` for version 2, which
indicates an implemented runtime, not permission to execute. Runtime grant
bindings use a separate domain-separated digest that includes target CA/posture
bytes; the preflight review reference alone is not an authorization binding. Errors contain fixed
diagnostics, never catalog snippets, supplied operation names or input paths.
