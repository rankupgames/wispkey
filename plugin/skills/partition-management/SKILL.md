---
name: wispkey-partition-management
description: Organize WispKey credentials into partitions, assign secrets to groups, and export or import encrypted bundles for teams. Use when the user asks about partitions, grouping credentials, sharing vault subsets, onboarding, or bundle export/import.
---

# WispKey Partition Management

Partitions group credentials inside a WispKey project. Use projects for repositories, products, or engagements; use partitions for environments or other sub-scopes inside that project.

## Creating a Partition

```bash
wispkey partition create "<name>" --description "Human-readable purpose" [--project "<project>"]
```

Example:

```bash
wispkey project create "acme-api" --description "ACME API credentials"
wispkey project use "acme-api"
wispkey partition create "production" --description "Production credentials"
```

Most partition operations use the active project. Select it with `wispkey project use <project>` before assigning, deleting, exporting, or importing by partition name.

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

Bundle passphrases are separate from the vault master password. `WISPKEY_PASSWORD` unlocks the vault only; it is not used for bundle export/import. New exports require a 12+ character bundle passphrase.

For non-interactive sharing workflows:
```bash
export WISPKEY_BUNDLE_PASSPHRASE="a-long-export-passphrase"
wispkey partition export "onboarding-kit" -o ./handoff/onboarding-kit.wkbundle

wispkey partition import ./handoff/onboarding-kit.wkbundle \
  --bundle-passphrase-file ~/.wispkey/onboarding-kit.bundle-passphrase
```

## Importing a Bundle

```bash
wispkey partition import ./path/to/file.wkbundle
```

Unlock the vault if needed, then enter the **same bundle passphrase** used at export. The CLI prints counts for imported, skipped, and errored credentials. If the partition name already exists, it is reused; credentials whose names already exist in the target project are counted as **skipped** rather than overwritten.

Credential names are unique per project, so duplicate detection happens inside the target project. The same credential name may exist in another project without blocking the import.

## Use Cases

### Organizing Environments

Create a WispKey project per product or repo, then create partitions such as `development`, `staging`, and `production`. Use `wispkey list --project "<project>" --partition "<environment>"` to stay scoped.

### Team Sharing

Export a partition bundle for teammates or contractors who need a defined subset of secrets. They import with `wispkey partition import` instead of receiving ad-hoc copies of raw keys.

### Onboarding

Prepare a standard partition (for example `new-hire-dev`) with non-production keys and documentation-oriented names, export once, and hand new developers a single bundle import step after vault setup.

## Related Commands

- `wispkey add` with `--partition` when creating credentials inside a partition
- `wispkey list --partition "<name>"` to list credentials in one partition
- Cloud sync commands are reserved but currently return `coming soon`; use encrypted project, partition, or credential bundles today
