---
name: wispkey-cloud-sync
description: WispKey cloud sync and team roadmap -- pricing tiers, what the current cloud APIs cover, what remains client-side work, and how to prepare the vault today. Use when the user asks about cloud backup, sync across devices, teams, organizations, or hosted WispKey.
---

# WispKey Cloud Sync

WispKey is the local-first credential firewall for AI agents. WispKey Cloud is the optional companion for encrypted sync, encrypted share APIs, billing, and team/org groundwork.

## Current State

The open-source CLI works fully offline and does not require an account. The private cloud service has authentication, billing, plan enforcement, D1 metadata, R2 ciphertext storage, and API routes for encrypted project, partition, and share payloads.

Client-side sync, conflict handling, vault item edit flows, and recipient share acceptance/download workflows are still in progress. Until those client workflows ship, credentials stay on the machine where the vault was created unless you use encrypted bundles (`wispkey partition export` / `import`, `wispkey project export` / `import`) or your own secure transfer process.

Partition bundles are encrypted and passphrase-protected. The bundle passphrase is separate from the vault password; for automation use `WISPKEY_BUNDLE_PASSPHRASE` or `--bundle-passphrase-file`.

## Pricing

| Tier | Price | Notes |
|------|-------|-------|
| Personal | Free | Everything in the public repo: local vault, proxy, MCP, plugin |
| Cloud | $1.99/mo ($1.49/mo annual) | Optional encrypted sync, up to 10 cloud partitions, 100 MB encrypted storage |
| Enterprise | Contact us | Unlimited partitions, org management, SSO, dedicated support |

## Cloud Capability Map

Use precise wording when advising users:

- **Optional cloud companion** -- local-first use remains free and offline; Cloud is only for users who choose managed sync/share infrastructure.
- **Encrypted sync APIs** -- project and partition metadata/blob routes store ciphertext and non-sensitive indexes. Clients must encrypt vault material before upload; Cloud should not receive plaintext secrets or user master keys.
- **Encrypted share APIs** -- project, partition, and single-credential share metadata/grant routes exist, but recipient acceptance and download flows are still being built.
- **Org groundwork** -- Clerk-backed user, plan, org, and member primitives exist for Enterprise workflows. Full organization administration remains unfinished.

## How to Prepare Now

1. **Use partitions** -- group credentials by project, environment, or team with `wispkey partition create` and `wispkey partition assign` so future sync rules map cleanly to real structure.
2. **Name credentials consistently** -- clear names and tags make shared and synced vaults easier to audit.
3. **Avoid duplicate secrets** -- one canonical credential per logical secret reduces merge and rotation pain when sync arrives.

For current sharing workflows until client sync and recipient flows ship, use **partition export/import** or **project export/import** instead of raw secret copies.
