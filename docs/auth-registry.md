# Authentication registry and reusable bundles

This foundation adds opt-in lifecycle policy to existing encrypted credentials.
It does not obtain credentials, perform OAuth authorization/refresh, capture or
replay browser sessions, or run credentials in WispKey Cloud.

## Register an existing credential

First store a secret through the existing protected `--value-file` path. Register
only descriptive provider/account labels, not passwords, tokens, or personal
login information:

```sh
wispkey auth register example-api --project default \
  --provider example --account work \
  --origin https://api.example.com \
  --provider-expiry unknown --use-until 2026-12-01T00:00:00Z
wispkey --format json auth list --project default
wispkey auth revoke example-api --project default
```

Provider expiry is explicitly `unknown`, `non-expiring`, or an RFC 3339 timestamp.
`--use-until` is a separate local deadline. The earliest applicable deadline wins;
use at the exact deadline is rejected. Unknown provider expiry always requires a
local deadline. Every proxy use, bundle resolution, browser release, MCP certificate
issuance, and registered cross-node operation requires a finite local deadline.
Explicit owner-only `exec`, `run`, and `inject` may use a declared non-expiring
credential without a local deadline, while still honoring provider expiry and
revocation. No expiry state is inferred from the secret contents.

Registration can represent an already-expired credential for inventory/recovery.
Expiry blocks use; it never deletes recovery material. `review_at` remains advisory
and does not become an expiry deadline. Local revocation is terminal for that auth
identity: re-registering or synchronizing older live metadata cannot clear it.
Create a new credential for replacement secret material. Re-registration retains
the auth ID, changes its revision, and cannot change its provider/account identity.
It invalidates existing bundle references until the owner explicitly updates them.

Legacy credentials remain usable through their existing flows and appear with
`auth: null` in the new inventory. They have not been declared non-expiring or
migrated to the new delegated-auth policy. Register them explicitly to opt in.
Environment sideloads also remain outside this registry.

## Reusable bundles

These are metadata selectors, distinct from encrypted `.wkbundle` transfer files.
A bundle belongs to one explicit project, partition and account. It lists named
alternatives. Every member of the selected alternative is required together at
resolution; no other alternative or account is chosen automatically.

Use the portable auth IDs and revisions from `auth list` to write a small JSON
file. For example (replace the example UUIDs with the actual inventory values):

```json
{
  "name": "example-service",
  "project": "default",
  "partition": "personal",
  "account": "work",
  "alternatives": [
    {
      "name": "api",
      "members": [
        {
          "auth_id": "00000000-0000-4000-8000-000000000001",
          "revision": "00000000-0000-4000-8000-000000000002",
          "role": "api-token"
        }
      ]
    }
  ]
}
```

```sh
wispkey auth bundle set --file example-auth.json
wispkey auth bundle list --project default --partition personal
wispkey --format json auth bundle resolve example-service \
  --project default --partition personal --account work --alternative api \
  --origin https://api.example.com
```

Listing and registration output contain only metadata. Resolution returns opaque
`wk_*` member tokens, never raw secrets. Treat those tokens as reusable capabilities:
keep them out of logs and public output. If any member is missing, stale, expired,
revoked, archived, from a different scope/account, or disallows the requested
origin, resolution returns no tokens. Exact HTTPS origins include scheme, hostname
and port; paths, query strings and userinfo are not valid origins. A registry origin
can only narrow the existing credential host restriction.

A bundle grants no permission. Existing project, instance, host/path/method
policies, one-use operation grants and browser approvals still apply. Required-
together is a resolution contract; it does not force a client to send all returned
tokens in the same network request. Each member still has its own use policy.
Provider/account labels are owner declarations, not provider-verified identity or
proof of current token validity. A successful resolution does not prove the
upstream account or operation succeeded.

Deleting a referenced credential fails until its bundles are explicitly updated.
Registered credentials cannot be overwritten, moved between partitions, or moved
implicitly by deleting their partition/project. Replace them using a new credential
and reviewed bundle references instead of silently changing an identity.

## Enforcement and recovery

Schema v14 adds the registry and bundles. Registered ciphertext has a `wka1:`
storage marker. Older binaries cannot decode it, and newer binaries fail closed
when the marker and valid registry metadata do not agree. Do not downgrade a
managed vault to an older binary. This is compatibility protection, not protection
against a trusted vault owner deliberately editing their own database or code.

Expiry and revocation checks occur at actual secret-use/release helpers, not only
when listing or resolving a bundle. Proxy auth failures do not fall back to an
environment sideload. Operation grants bind the auth revision and recheck mutable
authority while an operation runs. Checks stop new mediated use; they cannot undo
bytes already sent to an approved process/provider.

Encrypted partition/project/single-credential exports and cloud snapshots preserve
registry policy. Portable auth IDs avoid accidental rebinding to same-named local
credentials. A single-credential export includes its own registration but no
bundles, and registered project/partition overrides are rejected. Auth-bearing
sharing payloads use a version-2 envelope inside authenticated encryption; old
readers reject them. Cloud snapshots use version 2 with an authenticated registry
and per-credential identity mapping. A partition that has used auth registration
stays version 2 even after its final registration is deleted.

Auth-bearing imports are atomic, reject conflicting credentials/identities, and
never leave a credential usable without its policy. Existing legacy sharing formats
remain readable. Cloud updates cannot drop restrictions on retained credentials,
clear a retained revocation, or remap a portable identity. Stale revisions may be
preserved for recovery, but remain unusable until explicitly rebound. Missing,
cross-partition or cross-account references are rejected. Full encrypted backups
include registry rows and markers; auth-related merge conflicts cannot be skipped.

Encrypted recovery/export can preserve expired or revoked material without
re-enabling use. Replacing a whole vault from an older backup or explicitly deleting
and recreating identities is a recovery operation, not a global revocation ledger:
review recovered policy before reconnecting consumers. Cloud stores encrypted
snapshots and does not execute credentials.

## Boundaries and next gates

Compatibility limit: existing `website_login` credentials with a non-default
HTTPS port cannot yet opt into the registry because their legacy host metadata
includes the port. Registration is rejected safely; no secret is released. Generic
API credential exact-origin/port checks are supported. Fixing that existing login
representation is a separate browser-login compatibility slice.

Local expiry/revocation does not revoke the provider token, sign out a remote
browser, or invalidate previously copied material. Provider-side revocation and
verification require separate provider integrations. Browser validity is distinct
from provider token expiry and WispKey's local deadline.

OAuth needs issuer/resource binding, PKCE, expiry-aware serialized refresh,
rotation ownership, and reconnect handling. Browser-session reuse needs explicit
account/site/destination consent, cookie-attribute preservation, a trusted execution
boundary and response handling. The current reverse proxy forwards upstream
response headers and bodies, so it is not a hidden browser-session broker. Neither
capability, nor universal provider compatibility, is implemented here.

Custom per-auth login notes are a separate next slice: encrypted human-authored
instructions, strict size limits, explicit owner-controlled access, and encrypted
round-trip coverage. Notes must stay separate from account identity, origin/scope
policy and approvals. They must never become executable instructions or policy
authority, and must not appear in default inventory/MCP metadata. This foundation
does not store login notes.

## Synthetic verification

`cargo test --test auth_registry --test auth_release` exercises CLI contracts and
actual proxy/process release denials. Core clock tests cover exact deadline
boundaries without sleeps. Sharing/cloud and backup tests cover legacy round trips,
authenticated format downgrade rejection, stable portable references, atomic
rollback, expired/revoked recovery, and stale-reference denial. Browser and operation
tests exercise their existing release boundaries. No production secret, real OAuth
grant, or browser-session extraction is needed.
