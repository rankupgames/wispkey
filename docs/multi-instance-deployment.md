# Multi-Instance Deployment

WispKey can serve untrusted ephemeral VMs and worker instances without giving them plaintext secrets. The host keeps the vault and proxy. Each instance receives only opaque `wk_*` tokens plus a per-instance identity, and WispKey swaps tokens for real credentials only at the proxy boundary.

This guide covers stages 1-2 of multi-instance access: enrollment, scoped token injection, host-approved escalation, and multi-transport proxy listeners.

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

Tag matching is exact, so tags such as `company:acme` are useful for tenant or customer grouping. Approved access requests also act as implicit credential scope. In-scope credentials work automatically; out-of-scope credentials fail closed, create a pending request, and require host approval before retry.

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
| TCP | `tcp://127.0.0.1:7700` | `false` |
| Unix domain socket | `unix:/run/wispkey/proxy.sock` | `true` |
| vsock | `vsock://2:7700` | `true` |

Use `--require-identity` or `--no-require-identity` to override the default for all listeners in one `serve` invocation.

Use identity-required listeners for untrusted instances. TCP is best kept on loopback or a host-only network. Unix sockets and vsock are better fits for VM-to-host proxying because they avoid exposing a general network port.

The Unix socket file is created with mode `0600`. If WispKey creates the parent directory, it hardens that directory; it does not chmod a pre-existing parent directory. This allows shared system directories such as `/run` to keep their existing ownership and mode.

Unix socket paths must be short because the OS stores them in a fixed-size field. macOS is commonly limited to about 104 bytes. Prefer `unix:/run/wispkey/proxy.sock`.

Vsock is Linux-only and compiled behind the optional `vsock` feature. Without that feature, `vsock://...` listeners return a clear "vsock support not compiled in" error. The vsock path is intended for guest-to-host VM networking and is currently unverified on macOS.

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

After approval, the instance can retry the same request and WispKey treats the approved request as an implicit credential scope.

## Firecracker / boring-computers Example

A practical Firecracker setup uses the host as the credential boundary:

1. The host runs WispKey with a UDS or vsock listener.
2. Each microVM is enrolled as a separate WispKey instance.
3. The launcher injects only the instance id, instance secret, and required `wk_*` tokens into the microVM environment.
4. The microVM routes egress through WispKey.
5. WispKey authenticates the instance, checks scope, applies credential host restrictions and policies, writes audit events, and swaps `wk_*` tokens for real secrets only at the proxy boundary.

Host setup with a Unix socket:

```bash
wispkey instance enroll bc-acme-build-001 \
  --tag company:acme \
  --partition customer-acme

wispkey serve --listen unix:/run/wispkey/proxy.sock
```

The boring-computers launcher records the one-time enrollment output and starts the microVM with `WISPKEY_INSTANCE_ID`, `WISPKEY_INSTANCE_SECRET`, and only the `wk_*` tokens it should use. How the guest reaches the listener depends on the runtime: expose a short host Unix socket path, forward a host-only helper to the UDS, or use `vsock://<cid>:<port>` on Linux builds compiled with `--features vsock`.

The invariant is that the guest receives no plaintext secrets. A compromised microVM can use credentials already in its WispKey scope, but out-of-scope credentials fail closed and require a host approval step before retry.

Operationally, treat the instance secret as a bearer credential, rotate it by revoking and re-enrolling, prefer narrow selectors such as `--credential` or tenant tags, keep UDS paths short and host-owned, and keep using credential host restrictions and TOML policies. Instance scope is an additional gate, not a replacement for policy.
