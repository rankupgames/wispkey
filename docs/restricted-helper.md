# Restricted SSH helper

`wispkey-operation-helper` is the destination-side companion for a named SSH operation. It accepts no flags, target, command, path, or environment override. The SSH account should be restricted to a forced invocation of this binary; the binary loads only `/etc/wispkey/helper.toml` and `/var/lib/wispkey-helper/attempts.db`.

Build it for the destination's Unix platform with `cargo build --release --bin
wispkey-operation-helper`. The destination owner installs the reviewed binary at
the catalog's helper path, owned by root and not writable by other accounts.

This guide is an installation template, not a live deployment. The destination owner must review the exact program, its privilege, and its effects before installing it. The fixed paths support one helper profile per destination host; use a separately isolated host for a distinct operation. The target program must make a repeated attempt ID safe to reconcile; this helper prevents a repeated ID from receiving a second credential, but cannot undo an action that the program already performed.

## Local policy and state

The root-owned `/etc/wispkey/helper.toml` has one fixed child program and static arguments:

```toml
version = 1
program = "/usr/local/libexec/wispkey-fixed-action"
args = []
```

The helper rejects unknown fields, relative programs, path traversal, control characters, and more than 16 static arguments. It does not accept an operation or command in its stdin messages. The program and every component of its path must be root-owned, free of symlinks, and not writable by group or others. The helper launches it with a cleared environment, private stdin, and discarded stdout and stderr. Configure the child program to read the credential from stdin and never echo or log it.

Prepare `/etc/wispkey/helper.toml` as root-owned mode `0600`. Prepare `/var/lib/wispkey-helper` as root-owned mode `0700` and precreate `attempts.db` as root-owned mode `0600`. The helper checks these properties at startup and fails closed when they differ. Its SQLite transaction reserves the attempt ID before it sends `ready`; the reservation persists across restarts. A duplicate attempt receives only `outcome_unknown` and never receives another credential. Back up and protect the state database with the same care as authorization state; deleting it removes replay protection.

For a restricted SSH account named `wispkey-ssh`, an OpenSSH `authorized_keys` entry can force the reviewed binary and disable interactive and forwarding features:

```text
restrict,command="/usr/bin/sudo -n /usr/local/libexec/wispkey-operation-helper" ssh-ed25519 AAAA... reviewed-operator-key
```

The corresponding sudoers rule must name only this exact binary with no arguments:

```text
wispkey-ssh ALL=(root) NOPASSWD: /usr/local/libexec/wispkey-operation-helper ""
```

The empty `""` argument list in sudoers forbids additional arguments; the helper binary also rejects them. Deny other login paths for that account, including password authentication and unreviewed authorized keys. The catalog's `helper_path` is `/usr/local/libexec/wispkey-operation-helper`; the forced command is the server-side authority. Do not grant the account a general shell or a broad sudo wildcard.

## Protocol and outcomes

SSH stdin carries one JSON line for each of `hello` and `deliver`. The non-secret `hello` includes `version: 1`, canonical `attempt_id`, `phase: "hello"`, `remaining_ms` (1–60000), and `deadline_unix_ms`. The helper checks both the monotonic remaining time and the UTC deadline, reserves the attempt, then writes a small `ready` JSON line. Only after the client verifies `ready` does it decrypt and send `deliver` with a base64-encoded `credential_b64`. Base64 is framing, not protection; SSH is the protected channel.

After the child exits, the helper writes only `version`, `attempt_id`, a fixed `outcome`, a bounded count, and `exit_code`. The exit code is `0` for success, `1` through `255` for a child that exits with failure, or `null` when the child was signaled, did not start, or its outcome is uncertain. The helper process itself exits `0` or `1`; that status is never presented as the child exit code. Child output is always discarded. A timeout, malformed delivery, lost acknowledgement, canceled channel, or crash may leave `outcome_unknown`; the caller must not automatically retry with a new grant. Cancellation closes stdin and kills the child process group where possible, but a privileged child may have already completed an external side effect. Keep clocks synchronized between the trusted runner and destination so the UTC deadline is meaningful. The runner also enforces its own earlier hard deadline.

The helper is Unix-only for execution. Windows builds return a fixed unsupported status until a Windows Job Object based termination path is implemented and tested.
