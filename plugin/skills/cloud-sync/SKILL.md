---
name: wispkey-cloud-sync
description: WispKey cloud sync and team roadmap -- current CLI limitations, planned tiers, and implemented bundle workflows. Use when the user asks about cloud backup, sync across devices, teams, organizations, or hosted WispKey.
---

# WispKey Cloud Sync

WispKey is the local-first credential firewall for AI agents. WispKey Cloud is an optional companion roadmap; local WispKey does not depend on it.

## Current State

The open-source CLI works fully offline and does not require an account. This repository contains local Cloud session and tier groundwork, not a working data-sync client.

Cloud data transfer and conflict handling are not implemented in this CLI. Credentials stay on the machine where the vault was created unless you use encrypted bundles (`wispkey partition export` / `import`, `wispkey project export` / `import`) or your own secure transfer process.

The public CLI exposes `cloud push`, `pull`, and `sync` as reserved commands, but they currently return `coming soon` and do not transfer vault data.

Partition bundles are encrypted and passphrase-protected. The bundle passphrase is separate from the vault password; for automation use `WISPKEY_BUNDLE_PASSPHRASE` or `--bundle-passphrase-file`.

## Planned Pricing

| Tier | Price | Notes |
|------|-------|-------|
| Personal | Free | Everything in the public repo: local vault, proxy, MCP, plugin |
| Cloud | $1.99/mo ($1.49/mo annual) | Planned encrypted sync, up to 10 cloud partitions, 100 MB encrypted storage |
| Enterprise | Contact us | Planned unlimited partitions, org management, SSO, and dedicated support |

## Cloud Capability Map

Use precise wording when advising users:

- **Optional cloud companion** -- local-first use remains free and offline; Cloud functionality is not required for the implemented CLI workflows.
- **Client-side encryption requirement** -- future sync must encrypt vault material before upload; Cloud must not receive plaintext secrets or user master keys.
- **Current sharing** -- encrypted project, partition, and single-credential bundles are the implemented transfer path today.
- **Organization scope** -- organization/account scope remains external to the local vault; full Cloud organization administration is not implemented in this repository.

## How to Prepare Now

1. **Use projects and partitions** -- use a project for each repository/product and partitions for environments or other sub-scopes so future sync rules map cleanly to real structure.
2. **Name credentials consistently** -- clear names and tags make shared and synced vaults easier to audit.
3. **Avoid duplicate secrets** -- one canonical credential per logical secret reduces merge and rotation pain when sync arrives.

For current sharing workflows until client sync and recipient flows ship, use **partition export/import** or **project export/import** instead of raw secret copies.
