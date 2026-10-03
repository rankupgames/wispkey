---
name: wispkey-cloud-sync
description: WispKey optional encrypted partition sync, compatibility limits, and offline backup/sharing workflows. Use when the user asks about cloud backup, sync across devices, teams, organizations, or hosted WispKey.
---

# WispKey Cloud Sync

WispKey is a local-first credential firewall for AI agents. Local vault, proxy,
MCP, injection, and backup/sharing workflows work offline without an account.
Cloud is optional.

## Current State

The CLI implements `cloud login`, `status`, `push`, `pull`, `sync`, `resolve`, and
`recover`. Account-owned partition transfers require a compatible backend with
conditional revisions and encrypted payload download. The reviewed backend
migration must precede the Worker deployment; older unconditional backends are
incompatible. Follow [encrypted sync and recovery](../../../docs/cloud-sync.md)
and [Cloud sign-in](../../../docs/cloud-login.md), including their preview and
operator-verification limits. Do not infer production readiness from CLI support.

Sync encrypts the payload locally with a separate bundle passphrase; Cloud must
not receive that passphrase, plaintext credentials, or the user's master key.
Concurrent edits produce conflicts. Explicit `cloud resolve` preserves encrypted
recovery copies; never silently overwrite a changed remote revision. Authentication
expiry requires sign-in again; the CLI does not request refresh tokens.

Default builds do not include automatic/background synchronization or device
enrollment. Experimental builds offer a bounded owner-run
[foreground watch](../../../docs/foreground-sync-watch.md) after manual pairing.
Account sign-in, sync, or restored metadata does not grant credential execution.
Organization/account scope remains external to the local vault; full Cloud
organization administration and recipient-sharing flows are not implemented here.

## Offline backup and sharing

Partition, project, and single-credential bundles are encrypted and
passphrase-protected for sharing selected credentials. Use `wispkey backup` for
complete local disaster recovery, including policies, audits, instances and
sidecars; see [vault backup](../../../docs/vault-backup.md).

The bundle passphrase is separate from `WISPKEY_PASSWORD`. For trusted automation,
use `WISPKEY_BUNDLE_PASSPHRASE` or `--bundle-passphrase-file`. Transfer the bundle
and its passphrase through different channels. Use projects for products/repos
and partitions for environments; consistent names and tags keep the scope clear.
Account-owned sync is not team-sharing authorization.
