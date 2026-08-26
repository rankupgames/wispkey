# Multi-Instance Deployment

WispKey can serve untrusted ephemeral VMs and worker instances without giving them plaintext secrets. The host keeps the vault and proxy. Each instance receives only opaque `wk_*` tokens plus a per-instance identity, and WispKey swaps tokens for real credentials only at the proxy boundary.

This guide covers enrollment, scoped token injection, host-approved escalation, and cross-machine or VM proxy listeners.

## Model

The host is trusted. Instances are not.

Each instance enrolls with a stable id, a one-time 48-character secret, and optional scope selectors. The secret is shown once and stored only as an Argon2id hash. The instance authenticates every proxied request with:

```http
x-wispkey-instance-id: <instance-id>
x-wispkey-instance-secret: <instance-secret>
```

Scope selectors are ORed. A credential is in scope if it matches any selector:

- `--partition <name-or-id>`
- `--project <name>`
- `--credential <name>`
- `--tag <tag>`

Tag matching is exact, so tags such as `company:acme` are useful for tenant or customer grouping. Credential selectors resolve the name in the active project and persist that credential's exact ID. Approved access requests also bind to the exact credential ID, so same-named credentials in other projects remain out of scope. In-scope vault credentials work automatically; out-of-scope vault credentials fail closed, create a pending request, and require host approval before retry. Env-sideload tokens cannot be enrolled or approved and are denied for instance-authenticated requests.

## Host Workflow

Enroll an instance on the host:

```bash
wispkey instance enroll worker-acme-001 \
  --description "Firecracker worker for acme batch jobs" \
  --tag company:acme \
  --credential openai-key
```

The output includes the instance id and secret. Save the secret into the VM launch environment or metadata channel immediately; WispKey cannot show it again.

For automation, use `wispkey --format json instance enroll ...` and read the returned `id` and `secret` fields.

Manage instances and scope:

```bash
wispkey instance list
wispkey instance show worker-acme-001
wispkey instance scope add worker-acme-001 --partition customer-acme
wispkey instance scope remove worker-acme-001 --credential old-key
wispkey instance revoke worker-acme-001
```

Revocation keeps audit history and makes the original id/secret fail authentication.

## Fleet Self-Enrollment

For VM fleets, the host can mint a scoped bootstrap token instead of pre-enrolling every instance by hand. The token is a first-contact bearer credential: it is scoped, optional-TTL-limited, optional-use-limited, revocable, and stored only as an Argon2id hash.

Create a bootstrap token on the host:

```bash
wispkey instance bootstrap create \
  --description "Acme worker launch token" \
  --tag company:acme \
  --ttl 1h \
  --uses 50
```

The output includes the bootstrap token once. Pass it to the VM launcher through a protected launch channel. The VM can redeem it locally when the vault is available; prefer `--token-file` so the token is not exposed through shell history or process listings:

```bash
printf '%s' "$BOOTSTRAP_TOKEN" | wispkey instance join --token-file - --name worker-acme-001
```

For remote first contact through the proxy, call the join endpoint. It does not require a management token or existing instance identity because the VM has neither yet; the bootstrap token is the sole authenticator:

```bash
curl --unix-socket /run/wispkey/proxy.sock http://wispkey.local/api/instances/join \
  -H "Content-Type: application/json" \
  -d '{"bootstrap_token":"<bootstrap-token>","name":"worker-acme-001"}'
```

On success, WispKey returns the new instance `id`, one-time `secret`, and copied scopes. Bootstrap redemption is atomic/race-safe, so max-use limits are strictly enforced under concurrent joins. The VM then proceeds with the normal request flow using `x-wispkey-instance-id` and `x-wispkey-instance-secret`. Invalid, expired, exhausted, or revoked bootstrap tokens fail closed.

## Proxy Listeners

The default command is unchanged:

```bash
wispkey serve
```

By default, WispKey listens on loopback TCP at `127.0.0.1:7700` and does not require instance identity. This preserves the original trusted-local workflow.

For multi-instance deployments, add one or more listeners:

```bash
wispkey serve \
  --listen tcp://127.0.0.1:7700 \
  --listen unix:/run/wispkey/proxy.sock
```

Supported listener specs:

| Transport | Example | Default identity requirement |
|-----------|---------|------------------------------|
| Loopback TCP | `tcp://127.0.0.1:7700` | `false` |
| Non-loopback TCP | `tcp://192.168.4.20:7700` | `true` |
| Unix domain socket | `unix:/run/wispkey/proxy.sock` | `true` |
| Linux AF_VSOCK | `vsock://2:7700` | `true` |
| Firecracker UDS-backed vsock | `firecracker-vsock:/run/wispkey/worker.vsock:7700` | `true` |

Use `--require-identity` or `--no-require-identity` to override the default for all listeners in one `serve` invocation.

Use identity-required listeners for untrusted instances. TCP is best kept on loopback behind an SSH tunnel or on an encrypted host-only network. Per-instance authentication does not encrypt TCP, so do not send the instance bearer secret over an observable LAN or public network. Unix sockets and vsock are better fits for same-host VM-to-host proxying because they avoid exposing a general network port.

The Unix socket file is created with mode `0600`. If WispKey creates the parent directory, it hardens that directory; it does not chmod a pre-existing parent directory. This allows shared system directories such as `/run` to keep their existing ownership and mode.

Unix socket paths must be short because the OS stores them in a fixed-size field. macOS is commonly limited to about 104 bytes. Prefer `unix:/run/wispkey/proxy.sock`.

The `vsock://` listener is Linux-only, compiled behind the optional `vsock` feature, and uses host AF_VSOCK directly. Without that feature it returns a clear "vsock support not compiled in" error.

Firecracker does not expose guest connections through host AF_VSOCK. It maps guest AF_VSOCK port `P` to a host Unix socket named `<uds_path>_P`. Use `firecracker-vsock:` for Firecracker; it is UDS-backed and works in the default build on Unix hosts.

## Windows And Remote Servers

Windows clients use the TCP transport. The safest simple topology is to keep the WispKey host listener on loopback and carry it through OpenSSH, which is available on current Windows installations.

On the WispKey host:

```bash
wispkey serve --listen tcp://127.0.0.1:7700 --require-identity
```

On the remote Linux server, macOS machine, or Windows PowerShell session, open a local tunnel to the WispKey host:

```powershell
ssh -o KexAlgorithms=mlkem768x25519-sha256 `
  -o UpdateHostKeys=yes `
  -o ExitOnForwardFailure=yes `
  -N -L 17700:127.0.0.1:7700 wispkey-host
```

The explicit `KexAlgorithms` setting fails closed instead of falling back to a classical-only exchange. OpenSSH 9.9 added `mlkem768x25519-sha256`, and OpenSSH 10.0 made it the default. Check support with `ssh -Q kex`; if either endpoint lacks the algorithm, upgrade OpenSSH before relying on the tunnel for store-now-decrypt-later protection. Windows in-box OpenSSH can lag current releases, so follow Microsoft's supported [OpenSSH upgrade guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/upgrade-in-box-openssh-to-latest-openssh-release).

`UpdateHostKeys=yes` lets a trusted server advertise replacement host keys and helps ordinary host-key rotation. It is not a substitute for hybrid post-quantum key exchange, and current post-quantum SSH host-signature support remains version-dependent. See the [OpenSSH release notes](https://www.openssh.com/releasenotes.html).

The remote machine now reaches WispKey at `127.0.0.1:17700`. Send the enrolled instance id and secret on every request. For example in PowerShell:

```powershell
$env:WISPKEY_INSTANCE_ID = "inst_..."
$env:WISPKEY_INSTANCE_SECRET = "..."
$env:OPENAI_API_KEY = "wk_openai_prod_a7x9m2k4"

curl.exe http://127.0.0.1:17700 `
  -H "X-Target-Url: https://api.openai.com/v1/chat/completions" `
  -H "Authorization: Bearer $env:OPENAI_API_KEY" `
  -H "x-wispkey-instance-id: $env:WISPKEY_INSTANCE_ID" `
  -H "x-wispkey-instance-secret: $env:WISPKEY_INSTANCE_SECRET" `
  -H "Content-Type: application/json" `
  -d '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hello"}]}'
```

This tunnel keeps the instance bearer identity and request contents off the LAN. WispKey removes the identity headers before forwarding upstream. A direct non-loopback TCP listener automatically requires identity, but it still needs an encrypted private channel if other machines can observe that network.

## Automatic Instance Secret Rotation

Instance identities use 48 uniformly generated mixed-alphanumeric characters, approximately 286 bits of symmetric entropy. Quantum-resistant transport and secret rotation solve different problems: hybrid SSH key exchange protects captured traffic, while rotation limits how long a copied bearer secret remains useful.

Run this command from cron, a systemd timer, CI, launchd, or Windows Task Scheduler:

```bash
wispkey --format json instance rotate-secret worker-acme-001 --if-older-than 30d --grace 15m
```

The JSON response always includes `rotated`. When it is `false`, no secret changed and `secret` is `null`. When it is `true`, `secret` contains the new value exactly once. Send that value to the instance through the hybrid post-quantum tunnel or another protected deployment channel, update the remote secret store atomically, and do not retain scheduler stdout in logs.

The previous secret remains valid until the grace deadline so a failed deployment does not immediately strand the instance. Its first successful request with the new secret confirms rollout and retires the previous secret early. Use `--grace 0s` only when the consumer update is atomic with the rotation command.

The host stores only Argon2id hashes for both the current and grace-period secrets. Rotation uses a compare-and-swap update against the active instance, current hash, and rotation timestamp, so concurrent rotation or revocation fails closed rather than overwriting newer state.

## Instance Request Flow

Pass the instance identity and wisp tokens into the VM environment:

```bash
export WISPKEY_INSTANCE_ID='inst_...'
export WISPKEY_INSTANCE_SECRET='...'
export OPENAI_API_KEY='wk_openai_prod_a7x9m2k4'
```

For HTTP proxy mode over TCP:

```bash
export HTTP_PROXY=http://127.0.0.1:7700
export HTTPS_PROXY=http://127.0.0.1:7700
```

For HTTPS token substitution, use reverse proxy mode so WispKey can see and replace the token before the upstream TLS connection:

```bash
curl http://127.0.0.1:7700 \
  -H "X-Target-Url: https://api.openai.com/v1/chat/completions" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "x-wispkey-instance-id: $WISPKEY_INSTANCE_ID" \
  -H "x-wispkey-instance-secret: $WISPKEY_INSTANCE_SECRET" \
  -d '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hello"}]}'
```

For Unix socket deployments, connect the VM-side client to the mounted or forwarded socket path and send the same HTTP headers. The proxy strips instance auth headers before forwarding upstream.

## Out-of-Scope Escalation

In-scope token use injects the real credential and forwards the request. Out-of-scope token use does not forward the request. It returns:

```json
{
  "error": "out_of_scope",
  "credential": "billing-api",
  "instance": "worker-acme-001",
  "access_request": "req_...",
  "message": "access requested; awaiting host approval"
}
```

The pending request is idempotent for the same instance and credential. The host reviews and decides:

```bash
wispkey instance requests --pending
wispkey instance requests --instance worker-acme-001
wispkey instance approve req_...
wispkey instance deny req_...
```

After approval, the instance can retry the same request and WispKey treats the approved credential ID as an implicit scope.

## Firecracker / boring-computers Example

A practical Firecracker setup uses the host as the credential boundary:

1. The host runs WispKey with a UDS or vsock listener.
2. Each microVM is enrolled as a separate WispKey instance.
3. The launcher injects only the instance id, instance secret, and required `wk_*` tokens into the microVM environment.
4. The microVM routes egress through WispKey.
5. WispKey authenticates the instance, checks scope, applies credential host restrictions and policies, writes audit events, and swaps `wk_*` tokens for real secrets only at the proxy boundary.

Host setup with Firecracker's UDS-backed vsock bridge:

```bash
wispkey instance enroll bc-acme-build-001 \
  --tag company:acme \
  --partition customer-acme

wispkey serve --listen firecracker-vsock:/run/wispkey/bc-acme-build-001.vsock:7700
```

Configure the Firecracker VM with the same base socket path and a unique guest CID:

```json
{
  "vsock": {
    "guest_cid": 3,
    "uds_path": "/run/wispkey/bc-acme-build-001.vsock"
  }
}
```

WispKey binds `/run/wispkey/bc-acme-build-001.vsock_7700`. Inside the guest, connect AF_VSOCK to host CID `2`, port `7700`. Firecracker bridges that connection to WispKey's Unix socket. Use a unique base path and instance identity per microVM.

The repository integration coverage verifies scoped injection, out-of-scope denial, host approval and retry, revocation, and Firecracker socket naming with disposable vaults and synthetic credentials. A production deployment should still validate its own Firecracker, filesystem-permission, and network configuration.

The boring-computers launcher records the one-time enrollment output and starts the microVM with `WISPKEY_INSTANCE_ID`, `WISPKEY_INSTANCE_SECRET`, and only the `wk_*` tokens it should use. Generic hypervisors that expose host AF_VSOCK directly can instead use `vsock://<cid>:<port>` on Linux builds compiled with `--features vsock`.

Authorize the **host** vault before launching guests. Prefer `wispkey unlock --remember` (OS Keychain or a bounded local protector) or `wispkey unlock --password-file`; never pass the master password as a CLI argument or into the guest environment. `wispkey lock` ends the host session after cleanup. The full host-side sequence is in [`docs/headless-unlock.md`](headless-unlock.md).

The invariant is that the guest receives no plaintext secrets. A compromised microVM can use credentials already in its WispKey scope, but out-of-scope credentials fail closed and require a host approval step before retry.

Operationally, treat the instance secret as a bearer credential, rotate it with `instance rotate-secret`, prefer narrow selectors such as `--credential` or tenant tags, keep UDS paths short and host-owned, and keep using credential host restrictions and TOML policies. Instance scope is an additional gate, not a replacement for policy.
