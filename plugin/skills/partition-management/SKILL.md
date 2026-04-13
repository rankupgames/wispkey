---
name: wispkey-partition-management
description: Organize WispKey credentials into partitions, assign secrets to groups, and export or import encrypted bundles for teams. Use when the user asks about partitions, grouping credentials, sharing vault subsets, onboarding, or bundle export/import.
---

# WispKey Partition Management

Partitions group credentials inside the vault. Use them to separate projects, environments, or teams without mixing unrelated secrets in one flat list.

## Creating a Partition

```bash
wispkey partition create "<name>" --description "Human-readable purpose"
```

Example:

```bash
wispkey partition create "acme-api" --description "ACME customer integration keys"
```

## Listing Partitions

```bash
wispkey partition list
```

Shows partition names and descriptions. Does not print secret values.

## Assigning Credentials to a Partition

Move an existing credential into a partition:

```bash
wispkey partition assign "<credential-name>" --to "<partition-name>"
```

Example:

```bash
wispkey partition assign "stripe-prod" --to "payments-team"
```

You can also place new credentials directly when adding them (see the credential-management skill: `wispkey add` with `--partition`).

## Deleting a Partition

```bash
wispkey partition delete "<name>"
```

Removes the partition. Any credentials that were in that partition are moved to the default **`personal`** partition (they are not deleted). The built-in `personal` partition itself cannot be deleted.

## Exporting a Bundle

Export one partition and its credentials to a portable encrypted bundle:

```bash
wispkey partition export "<partition-name>" -o export.wkbundle
```

Example:

```bash
wispkey partition export "onboarding-kit" -o ./handoff/onboarding-kit.wkbundle
```

The CLI prompts for a **bundle passphrase** (with confirmation on export). Share that passphrase with recipients through a different channel than the file. Share the bundle through secure channels only; treat it like any other secret-bearing artifact until imported.

## Importing a Bundle

```bash
wispkey partition import ./path/to/file.wkbundle
```

Unlock the vault if needed, then enter the **same bundle passphrase** used at export. The CLI prints counts for imported, skipped, and errored credentials. If the partition name already exists, it is reused; credentials whose names already exist in the vault are counted as **skipped** rather than overwritten.

## Use Cases

### Organizing by Project

Create a partition per product or repo, assign only the credentials that belong there, and use `wispkey list --partition "<name>"` during day-to-day work to stay scoped.

### Team Sharing

Export a partition bundle for teammates or contractors who need a defined subset of secrets. They import with `wispkey partition import` instead of receiving ad-hoc copies of raw keys.

### Onboarding

Prepare a standard partition (for example `new-hire-dev`) with non-production keys and documentation-oriented names, export once, and hand new developers a single bundle import step after vault setup.

## Related Commands

- `wispkey add` with `--partition` when creating credentials inside a partition
- `wispkey list --partition "<name>"` to list credentials in one partition
- Cloud sync (future): see the cloud-sync skill for planned multi-user and org workflows
