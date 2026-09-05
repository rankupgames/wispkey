# Vault Backup And Restore

WispKey stores a complete operational backup as an encrypted `.wkbackup` archive. Project, partition, and credential bundles remain the sharing format. A vault backup is the disaster-recovery format: it includes credentials, projects, partitions, policies, audit history, instance identities and scopes, access requests, bootstrap metadata, and cloud sidecar files.

```bash
wispkey backup create --output vault.wkbackup
wispkey backup inspect vault.wkbackup
wispkey backup verify vault.wkbackup
wispkey backup restore vault.wkbackup --dry-run
wispkey backup restore vault.wkbackup --target /tmp/wispkey-restore-test
wispkey backup restore vault.wkbackup --replace
```

The backup passphrase is separate from the vault master password. Use `WISPKEY_BUNDLE_PASSPHRASE` or `--bundle-passphrase-file`. New backups require a 12+ character passphrase. Share the archive and passphrase through different channels.

Backup creation never replaces an existing output. It also refuses active vault paths such as `vault.db`, SQLite WAL/journal files, session/protector files, IPC files, and supported sidecars. Sharing bundle commands keep their existing output behavior.

## Format

The on-disk frame is the shared WispKey bundle frame used by `.wkbundle` and `.wkcred` files:

- Magic `WKVB`
- Version byte `1`
- 32-byte random salt
- AES-256-GCM ciphertext with a random 12-byte nonce prepended

The passphrase is stretched with Argon2id (`m=65536`, `t=3`, `p=4`) to a 256-bit key. Authentication is provided by AES-GCM. A SHA-256 integrity hash of the canonical JSON payload is stored inside the ciphertext and checked by `backup verify`.

Payload `format_version` is `1`. `source_schema_version` records the vault schema at export time (currently `11`). Restores from schema 6 through the current version insert known columns and apply SQLite defaults for newer columns. A backup from a newer WispKey is rejected.

### Included

| Item | Notes |
|------|-------|
| `vault_meta` | Schema version, created time, and the Argon2id master-password hash |
| `projects`, `partitions`, `credentials` | Original IDs, wisp tokens, and AES-GCM `encrypted_value` blobs |
| `audit_log` | Event history with token fingerprints, not reusable tokens |
| `instances`, `instance_scopes`, `access_requests` | Identity metadata and hashes only |
| `bootstrap_tokens` | Metadata and hashes only |
| `policies.toml` | Policy file when present |
| `cloud.json`, `cloud-manifests.json` | Cloud client config when present |
| `active_project` | Last `project use` selection |
| `audit-fingerprint.key` | Local audit HMAC key when present |

Use `--exclude` to omit groups. Parent excludes cascade: `projects` also drops partitions and credentials; `instances` also drops scopes and access requests. The recorded scope is part of inspect output.

### Excluded

| Item | Reason |
|------|--------|
| `session`, `session-device-seed`, `session-protector` | Machine-bound unlock material |
| `proxy.pid`, `proxy.json` | Live process state and management token |
| `owner.sock`, `owner.json` | Live owner IPC |
| Instance bearer secrets | Never stored; only Argon2id hashes exist |
| Bootstrap token secrets | Never stored; only Argon2id hashes exist |
| `WISPKEY_SIDELOAD_*` values | Process environment only |

## Inspect, Verify, And Dry Run

`inspect`, `verify`, and `restore --dry-run` decrypt the archive with the backup passphrase. They do not require an unlocked vault. Output never includes credential plaintext, `encrypted_value`, password hashes, instance secret hashes, bootstrap token hashes, wisp tokens, or cloud session tokens.

`verify` checks magic/version, AES-GCM authentication, the inner SHA-256 integrity hash, row counts, and schema compatibility. It does not modify the destination.

`restore --dry-run` reports the restore mode (`replace` or `merge`), row counts, database and sidecar conflicts, instances that would be marked for re-enrollment, and recovery limits. Merge planning opens the destination read-only, copies it into an in-memory SQLite database, and migrates only that copy. The destination is not changed by planning.

## Restore

Restore validates integrity and schema compatibility before writing. Replace writes go to a staging directory, then files are renamed into the destination. Merge sidecars are staged and created before the SQLite transaction commits; ordinary process I/O failures roll back both the database transaction and newly created sidecars. Failed operations retain `.wk-restore-*` staging when recovery is incomplete. SQLite and multiple file renames are not power-loss atomic.

| Destination | Behavior |
|-------------|----------|
| Empty `--target` path | Full replace. Creates `vault.db` and sidecars. |
| Current vault with `--replace` | Atomic replace of `vault.db` and restored sidecars. |
| Existing vault without `--replace` | Merge. Conflicts never overwrite. Default `--on-conflict fail`. |

Encrypted credential blobs stay wrapped with the original vault master key. Merge into a vault with a different `password_hash` is rejected; restore to an empty `--target` or pass `--replace`. After restore, unlock with the **original master password**. Session and protector files are not restored.

Conflicts (same id with different data, unique name/token collisions, sidecar collisions, or unavailable parent identities) require `--on-conflict skip` or `--replace`. Identical rows are treated as already present. With `--on-conflict skip`, dependent partitions, credentials, scopes, and access requests are skipped when their exact referenced parent ID is unavailable. WispKey never remaps a security relationship by matching a different ID with the same name.

### Instance re-enrollment

Restored instances keep their ids and scopes but cannot authenticate. Active instances are marked `needs_reenrollment` and their stored hashes are replaced so previous bearer secrets stop working. Mint a new secret without changing the instance id:

```bash
wispkey instance rotate-secret worker-acme-001
```

Restored bootstrap tokens are revoked. During a merge, only tokens inserted from the backup are revoked; existing destination tokens are not changed. Mint new tokens with `wispkey instance bootstrap create`.

## Recovery Limits

- **Lost master password.** Unrecoverable. The backup passphrase only unwraps the archive. Credential blobs remain encrypted with the original master key.
- **Lost backup passphrase.** The `.wkbackup` file is unreadable.
- **Lost or reset device.** Copied `session` or `session-protector` files will not unlock on another machine. Restore the backup, then `wispkey unlock` with the master password.
- **Corrupt `vault.db`.** Restore onto an empty `--target` or use `--replace`. Verify the archive first.
- **Partial backup.** Excluded tables and sidecars are not recreated. Inspect the recorded scope before restore.
- **Cross-file consistency.** Database rows are read in one SQLite transaction. Sidecars are read separately, so stop WispKey and quiesce vault-sidecar writers for a consistent backup.
- **Replace preflight.** Replace refuses stale `session`/protector files, SQLite `-wal`/`-shm`/journal files, live IPC files, and target sidecars omitted from the backup. Clear the stale state or use a complete backup; no live replacement promise is made for excluded files.
- **Interrupted restore.** Ordinary process failures are rolled back when possible. Power loss can occur between SQLite commit and filesystem durability, so verify the vault after an interruption. This feature does not promise crash-safe atomicity across SQLite and multiple files.
- **Instance and bootstrap secrets.** Never stored at rest. Restored workers must receive newly minted secrets.
- **Env sideloads.** `WISPKEY_SIDELOAD_*` values are not in the vault and are not in the backup.

Test a restore with `--dry-run` and a separate `--target` path before replacing a live vault.
