---
name: wispkey-cloud-sync
description: Planned WispKey cloud sync and team features -- pricing tiers, what sync will provide, and how to prepare the vault today. Use when the user asks about cloud backup, sync across devices, teams, organizations, or hosted WispKey.
---

# WispKey Cloud Sync (Coming Soon)

Cloud sync is not available yet. This skill describes the planned offering so you can set expectations and prepare local vaults accordingly.

## Status

WispKey cloud sync is **coming soon**. Until it ships, credentials stay on the machine where the vault was created unless you use partition bundles (`wispkey partition export` / `import`) or your own secure transfer process.

## Planned Pricing

| Tier | Price | Audience |
|------|-------|----------|
| Pro | $1.99/month | Single-user encrypted sync across your devices |
| Team | $9.99/user/month | Multi-user workspaces with shared partitions and collaboration |

Exact feature boundaries may adjust at launch; use official WispKey announcements for the final matrix.

## What Cloud Sync Will Offer

When released, cloud sync is intended to provide:

- **Encrypted sync** -- vault data synchronized with encryption end-to-end appropriate to the product design; the service should not need plaintext secrets.
- **Team sharing** -- share partition-backed sets of credentials with invited members instead of exporting bundles for every change.
- **Organization management** -- central administration of members, partitions, and access policies suitable for small and growing teams.

## How to Prepare Now

1. **Use partitions** -- group credentials by project, environment, or team with `wispkey partition create` and `wispkey partition assign` so future sync rules map cleanly to real structure.
2. **Name credentials consistently** -- clear names and tags make shared and synced vaults easier to audit.
3. **Avoid duplicate secrets** -- one canonical credential per logical secret reduces merge and rotation pain when sync arrives.

For current sharing workflows until cloud sync launches, use **partition export/import** (see the partition-management skill).
