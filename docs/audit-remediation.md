# Protected legacy fallback audit remediation

Older `sideload-audit.jsonl` files can contain reusable `wk_*` capabilities.
Current readers redact recognized capabilities, and current writers store keyed
fingerprints. RUG-10 adds an explicit offline sanitized-copy workflow:

```sh
wispkey audit remediate-fallback \
  --input /private/snapshot/legacy.jsonl \
  --output /private/remediated/sideload-audit.jsonl
```

The source must be an offline snapshot: stop the old writer before making the
snapshot. Do not point this command at an actively appended log. The command
never changes the source, installs the output, touches a vault, accesses a
credential, or rotates a token. It works without an initialized or unlocked vault.

## Protection and failure behavior

- On Unix, the input must belong to the current owner, be owner-only, have one
  hard link, and be a regular file. A symbolic link in the final input path component is rejected and the opened
  descriptor identity is rechecked. Ancestor links are resolved normally. Input is bounded to 16 MiB, including during reading.
- On Unix, the output parent must already be an owner-owned, owner-only real directory.
  The new file is owner-only. Existing destinations, including links and the
  input itself, are never overwritten. Existing directory permissions are not changed. The final parent component
  cannot be a link; ancestor links are resolved normally. A verified directory
  descriptor pins output creation, and no path-based permission changes occur.
- On Windows, only ordinary local fixed-drive paths are supported. UNC/network,
  device/verbatim namespaces, drive-relative paths, alternate data streams,
  reserved device names and reparse points (including junctions) are rejected.
  Every source/output ancestor is opened with directory read/list access (needed
  to enforce sharing exclusions), without write/delete sharing, and checked
  for reparse points before opening its child. These handles remain alive through
  output completion, preventing directory renames and writable reparse changes.
  The source is opened without write/delete sharing, must have one hard link,
  and is bounded to 16 MiB. Its owner must be the current account and its DACL
  must pass the same conservative policy as private operation catalogs: grants
  only to that account, SYSTEM or Administrators; null/missing DACLs and unknown
  ACE types fail closed. The output parent must pass this ownership/ACL check too.
  The new file receives an explicit current-user owner and protected user-only
  DACL in the exclusive CREATE_NEW call, before any bytes are written. Its
  protection is checked on the returned handle. No existing ACL is changed.
  File contents are flushed; portable directory-fsync durability is not promised.
  Filesystems without these ACL/handle semantics fail closed; ordinary Windows
  path-length limits apply. Privileged OS administrators and same-account code
  are not isolation boundaries. Keep using offline snapshots.
- Other platforms without private-file verification refuse the command rather
  than making an unverified protection claim.
- UTF-8, JSONL records, and RFC3339 timestamps are validated before creating output.
  Any malformed nonblank record rejects the whole migration. Observed input length
  or modification-time changes also reject the snapshot. Errors report line
  numbers, never parser diagnostics, file paths, event contents, or raw tokens.
- Only the known fallback schema is written. Unknown fields and arbitrary source
  labels are discarded, all recognized string fields are capability-redacted,
  and the legacy `wisp_token` field is removed. A legacy token is not rehashed.
  Existing fingerprints survive only when there is no legacy token and their
  syntax is exactly `hmac-sha256:` plus 64 hex digits. This is syntax validation,
  not proof of fingerprint authenticity or log provenance.
- Reprocessing a sanitized copy produces the same event bytes. Reusing an output
  filename fails; this prevents accidental replacement of evidence. An I/O failure
  while writing or syncing can leave a partial protected copy; no success is reported.

Successful stdout is a JSON summary with `records_written`,
`legacy_token_fields_removed`, and `source_preserved`. It contains no event data.
Blank lines do not count as events. No audit event is added to a live sink.

## Operator follow-through

Review the sanitized copy under the same private-file controls. Keep the original
snapshot protected until your evidence retention decision is made. This operation
is not secure erasure and does not remove copies in backups, snapshots, or logs.
Rotate any capabilities that may have been exposed using the appropriate owner
workflow. Replacing a live sink, deleting retained evidence, and credential
rotation are separate explicit operator actions. If the original was already
read by another party, redaction cannot undo that exposure.

Remediation preserves audit metadata, not arbitrary secrets accidentally stored
inside a log. The redactor recognizes WispKey capability syntax; it is not a
general-purpose secret detector. Do not publish either original or remediated
files as public artifacts.

## Windows implementation references

The sharing, reparse and creation guarantees follow Microsoft's
[CreateFileW documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
Rejected namespaces and reserved filenames follow
[Windows naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
Windows-only tests use newly created synthetic fixtures for private creation,
ACL rejection, sharing/rename protection, junctions, hard links, malformed input
and competing output creation. Run these on Windows; Unix tests do not validate
Windows behavior.
