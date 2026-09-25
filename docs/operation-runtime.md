# Scoped operation runtime

WispKey runs owner-approved operations for an authenticated enrolled instance.
It supports a fixed SSH helper, an update or removal of one Kubernetes Secret
key, and PostgreSQL application-password rotation. These are local executor
features; cloud sync is not involved. Installing a target helper, configuring a
database or cluster, and using real credentials remain destination-owner tasks.

## Approval and execution

Keep the vault, finite unlocked session and catalog on a trusted owner-controlled
runner. Workload agents must use a different account or machine: the local vault
owner can already decrypt credentials, so these commands cannot isolate a
malicious process running as that owner.

1. Enroll an instance using `wispkey instance enroll`. Its credential scopes for
   HTTP substitution do not grant operation access.
2. Install a private `operations.toml` in the vault directory. Start from the
   [preflight SSH example](operation-preflight.md), change `version` to `2`, and
   set `requester_principal = "instance:<enrolled UUID>"`. Review the actual
   credential ID, project, target and expiry. Version 1 remains preflight only.
3. Run `wispkey operation check`. This checks metadata and private files, not
   requester authentication, live target identity, or permission to execute.
4. On the trusted runner, run `wispkey operation authorize maintenance --seconds
   60`. Review the displayed scope and enter the vault password at the fresh
   interactive prompt. An unlocked session alone, `WISPKEY_PASSWORD`, a password
   file, or a management API token cannot issue a grant.
5. Give the agent the resulting grant ID. It runs:

   ```console
   wispkey operation execute --grant <grant-id> --identity-file /private/instance.json --proxy https://executor.example
   ```

The owner-private identity file is JSON containing only `instance_id` and
`instance_secret`. It must have the same ownership and permission protections
as the catalog. Provision it through a protected channel; never place its
secret in argv. The CLI accepts HTTPS or literal loopback HTTP, disables system
proxies and redirects, and never prints the identity file. WispKey's native
listener is HTTP; a remote HTTPS endpoint requires an owner-configured TLS
terminator/tunnel. Protect that transport and restrict access to the executor.

The operation API authenticates both instance headers on every request and
requires the current secret. An older secret in its proxy rotation grace period
does not authorize an operation. Instance rename cannot change its principal;
revocation, secret rotation, session lock/renewal, catalog/CA/posture changes,
credential replacement or grant expiry invalidates execution. Proxy agent
policies also now use the authenticated `instance:<UUID>` principal; labels
and caller-provided agent headers do not establish it.

## Grants, status and cancellation

The effective deadline is the earliest catalog, grant, finite session and
environment-posture expiry. Grants allow at most 300 seconds and executions at
most 60 seconds. One active attempt per named operation or target is allowed.
A SQL transaction consumes the grant and records its start before any credential
is released. A crash, lost response, cancel or timeout never makes it reusable.
Selected, provider and previous-password values each have a separate one-use
release recorded against their exact project, credential ID and revision.

```console
wispkey operation status --grant <grant-id>
wispkey operation status --attempt <attempt-id>
wispkey operation cancel --grant <unused-grant-id>
wispkey operation cancel --attempt <running-attempt-id>
wispkey operation audit --limit 100
```

Canceling an attempt requests bounded transport cancellation. It does not prove
that a remote mutation was undone. Uncertain results remain `outcome_unknown`;
do not automatically authorize a retry. A crashed attempt holds its concurrency
reservation. After its deadline, the owner checks the destination and uses
`wispkey operation reconcile --attempt <attempt-id>` with fresh interactive authentication
to release that reservation while preserving the unknown outcome.

Status contains typed IDs, scope, deadlines, fixed state, cancellation state and
a recorded child exit code when available. The audit has exactly eight fields:
`timestamp`, `requester`, `operation`, `target`, `environment`, `credential_ref`,
`expires_at`, `result`. No credential values, command output or provider bodies
are returned. Operation audit rows survive encrypted backup; live grants,
attempts and session authorization do not. Vault schema 13 migrates automatically.

Authenticated API routes are `GET /api/operations/grants/{id}` and
`GET /api/operations/attempts/{id}`, with `POST` to a grant's `/execute` or
`/cancel`, or an attempt's `/cancel`. They accept no execution arguments.
Management bearer tokens do not authorize these routes. Grant issuance and
reconciliation have no HTTP or MCP endpoint.

## Fixed SSH helper

The SSH target fields remain those in the version 1 example. The executor uses
a dedicated private SSH key and pins the server's Ed25519 fingerprint before releasing
the credential. It ignores OpenSSH config, agents, forwarding, jump hosts and
shell options. The SSH command is only the fixed helper path. See
[restricted helper installation and protocol](restricted-helper.md).

The helper passes the selected value to its one owner-configured program by
stdin, clears its environment, discards program output, bounds runtime, and
reserves attempt IDs durably to reject replay. Privileged deployment uses a
reviewed helper/account policy; no general sudo password is transferred.

## Kubernetes Secret adapter

Use `kind = "kubernetes-secret"` with the same common operation fields and this
target block. All identifiers below are illustrative; there are no default live
clusters or credentials.

```toml
[operation.kubernetes]
endpoint = "https://cluster.example:6443"
cluster_id = "preview-cluster"
context = "preview-context"
environment_id = "preview"
environment_owner = "platform-team"
consumer_id = "application"
issuer_id = "postgres"
namespace = "preview"
namespace_uid = "5af05c13-1c0a-4394-a7a3-7f457ff74a40"
secret_name = "application-db"
secret_uid = "5af05c13-1c0a-4394-a7a3-7f457ff74a41"
data_key = "password"
ca_file = "/private/cluster-ca.pem"
provider_credential_id = "5af05c13-1c0a-4394-a7a3-7f457ff74a42"
posture_file = "/private/cluster-posture.json"
posture_public_key = "<base64 without padding: 32-byte Ed25519 public key>"
encryption_config_revision = "reviewed-revision"
action = "deliver"
```

The provider credential is a separate bearer token in the selected project.
Provision it with only GET on the named namespace and GET/UPDATE on the named
precreated Secret, using `resourceNames`. It must not create/list/delete Secrets,
change workloads or access other environments. WispKey does not infer provider
permissions or Kubernetes encryption settings from an API success response.

The destination owner must verify permissions, consumer ownership and encryption
at rest, then sign short-lived posture evidence. `posture_file` contains exactly
`payload` and `signature`, both canonical base64 without padding. Sign the exact
decoded JSON payload with Ed25519. Payload fields are `endpoint`, `ca_sha256`
(SHA-256 of the exact CA PEM bytes, base64 without padding), `cluster_id`,
`context`, `environment_id`, `namespace_uid`, `secret_uid`, `environment_owner`,
`consumer_id`, `issuer_id`, `encryption_config_revision`, `issued_at` and
`expires_at`. Its lifetime is at most one hour, and all values must match the
catalog. The signing key stays with the destination owner, outside the executor.
Evidence is an owner attestation, not automatic discovery of cluster posture.

TLS trusts only the configured CA. The adapter validates live namespace and
Secret UIDs before releasing the selected value, then updates only the selected
key while preserving other data and using the existing resource version. The commit marker binds the catalog, destination and immutable credential revision.
A new owner-approved grant for that same revision can confirm an already matching
value without another PUT; uncertain operations are never retried automatically. It
does not create or delete a Secret, namespace, database or persistent volume.
An acknowledged Secret write returns `delivery_acknowledged`. The application
must separately reload and prove it uses the new credential. A separately
authorized `action = "revoke"` removes only that key and returns
`revocation_unverified`; removing delivery material cannot invalidate a value
already read by a consumer.

## PostgreSQL rotation and operational order

Use the [PostgreSQL issuer adapter](postgres-issuer.md) for `kind =
"postgres-password"`. Its separate grant changes one reviewed application's
password, verifies a fresh login with the new value, and requires an actual
invalid-password rejection for the previous value. Network failures are unknown
outcomes. Existing database sessions remain a separate operator concern.

Issuer rotation, Secret delivery, and consumer reload are separate steps with
separate authority. Schedule them with the application's outage/rollout policy;
this initial adapter does not promise an atomic or zero-downtime rollout.
Verify consumer reload and retained application data before declaring a rollout
complete. No real destination or application has been configured by this change.
