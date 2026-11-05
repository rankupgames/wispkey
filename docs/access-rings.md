# Access rings

An access ring is a local owner classification on one credential. It limits
which release paths may decrypt the credential. It does not replace any other
check. Project and partition scope, instance identity, host/origin/method
rules, auth registry lifecycle, release atomicity and policy still apply.

A ring is not identity, an account role or a billing tier. An account sign-in,
a device label or a caller-supplied value never changes a ring or grants a
release.

## Rings

| Ring | Meaning |
|------|---------|
| `routine` | Unattended release is allowed |
| `restricted` | Release needs a fresh owner approval |
| `critical` | No delegated execution or fill path exists |

A credential without a ring is unclassified. WispKey treats an unclassified or
unknown stored value as `restricted`. The vault records ring policy version `1`
in `vault_meta`. A missing or other policy version denies every release.

## Release paths

| Release path | Approval held | Allowed rings |
|--------------|---------------|---------------|
| Token proxy (forward and reverse mode) | Unattended | `routine` |
| MCP certificate issuance with a vault CA key | Unattended | `routine` |
| Webhook signature verification | Unattended | `routine` |
| Auth bundle resolution | Unattended | `routine` |
| Owner egress: `exec`, `run`, `inject`, worktree environments | Unattended | `routine` |
| Browser fill after Windows Hello or Touch ID | Owner approved | `routine`, `restricted` |
| One-use operation grant after the owner password | Owner approved | `routine`, `restricted` |

A cached unlock, a remembered protector or `WISPKEY_PASSWORD` is not a step-up.
Owner egress uses the session, so it is unattended. An owner approval counts
only when it binds the credential identity, its revision and a fresh check. A
ring change updates the credential revision, so earlier browser and operation
approvals for that credential become stale.

The proxy returns `403` with the ring reason and records a denial audit event.
The ring check runs before the project, instance scope and website-login
checks. Browser fill and operation grants show their existing error and hide
the ring reason.

`critical` has no delegated execution or fill path. Trusted-device presence does
not exist yet. Owner-local reads, encrypted export, Cloud push, backup and value
replacement retain the existing owner recovery and transfer boundary. Rings do
not protect a credential from the local account that can unlock the vault. A
process with that account's cached session and a bundle passphrase can export
and decrypt even a critical credential. These transfers add no ring step-up.

## Owner control

```bash
wispkey add "openai-key" --ring routine --type bearer_token \
  --value-file - --hosts "api.openai.com"
wispkey ring "openai-key"
wispkey ring "openai-key" --set critical
wispkey ring "openai-key" --set routine
```

- `add --ring` classifies a new row. The owner supplies the value in the same
  call, so no step-up is necessary.
- `ring --set` with a narrower ring needs no password.
- `ring --set` with a broader ring needs the vault password at an interactive
  terminal. `WISPKEY_PASSWORD` and piped input do not satisfy it.
- Broadening also requires a finite owner session. Unlock with a positive
  timeout before broadening if `WISPKEY_SESSION_TIMEOUT=0` was used.
- Setting the current ring again does nothing.
- The audit event records the credential name, project, previous ring and new
  ring. It records no value or token.

## Existing vaults

Schema 17 adds the ring column and the policy row. Migration sets no ring, so
every existing credential is unclassified (`restricted`). After the upgrade,
the proxy, MCP, webhook verification, auth bundle resolution and owner egress
deny these credentials until the owner runs `wispkey ring <name> --set routine`.

Only `add --ring` classifies a new row. `env attach`, `import`, MCP
`wispkey_set`, `login generate` and `login add-existing` create unclassified
rows. MCP cannot set or broaden a ring.

Env sideloads (`WISPKEY_SIDELOAD_<SLUG>`) have no vault row and no ring. They
are outside ring enforcement.

## Sharing, sync and backup

| Format | Ring behavior |
|--------|---------------|
| Project, partition and credential bundles | Version 4 carries rings. Older readers reject version 4. |
| Cloud partition sync | Snapshot version 4 carries rings. Older peers reject it, so mixed-version sync stops. |
| Vault backup | A ring requires source schema 17. An unknown ring value is malformed. |

- Exports carry the effective `restricted` ring for unclassified credentials,
  so an older reader cannot drop the default restriction. Unknown local policy
  versions block sharing and sync exports.
- An import or sync can keep or narrow the ring of an existing row. It cannot
  broaden it. Only the local owner control broadens a ring, so a broadening
  change from a peer stops until the local owner applies it.
- A new row from a bundle or sync keeps the transported ring. The bundle
  passphrase holder or sync peer chose that ring.
- A legacy snapshot without rings narrows `routine` rows to unclassified. It is
  rejected over `critical` rows.
- Nonempty project and partition bundles import atomically: overlapping names
  reject the whole import instead of skipping those rows.
- A backup restore with replace brings back the rings from the backup. A
  restore cannot reactivate delegated authority: restored instances need
  re-enrollment.

## Limits

- Device enrollment, trusted-device presence, signing-key custody and remote
  grants are not implemented. Critical delegated execution and fill remain denied.
- Rings apply to one local vault. They are not a cross-device or team policy.
- Owner recovery and transfer remain possible for every ring, including critical.
- A process that holds the vault password can create `routine` rows with
  `add --ring routine`.
