# Webhook signature verification

`POST /api/webhooks/verify` checks one [Standard Webhooks](https://www.standardwebhooks.com/)
v1 signature with a signing secret that stays in the vault. An enrolled instance
sends the raw delivery and gets one result: `valid`, `invalid` or `stale`. The
signing secret, the body and the signatures never come back in a response or an
audit row.

The verifier does not sign, dispatch jobs, deduplicate or store deliveries.

## Protocol

- Signed content: the raw bytes `webhook-id + "." + webhook-timestamp + "." + body`.
  The body is never decoded or normalized.
- Algorithm: HMAC-SHA256 with constant-time comparison.
- Signing secret: `whsec_` followed by the standard base64 of the key bytes.
- `webhook-signature`: one or more space-separated `v1,<base64>` candidates. One
  matching candidate gives `valid`.
- Tolerance: the timestamp must be within 300 seconds of the proxy clock, in
  either direction. Outside that window the result is `stale`, and the key is not
  used.

## Setup

Store the signing secret as an `api_key` credential. Use `printf '%s'`:
`--value-file` keeps every byte, so a trailing newline from `echo` becomes part of
the secret and every signature fails. Give it a host scope that matches no real
host, so the token proxy never substitutes it into outbound traffic.

```sh
printf '%s' "$WEBHOOK_SIGNING_SECRET" | wispkey add billing-webhook-signing \
  --ring routine --type api_key --value-file - --hosts webhook-signing.invalid
wispkey --format json get billing-webhook-signing   # credential.id
wispkey instance enroll billing-receiver --credential billing-webhook-signing
wispkey serve --listen unix:/run/wispkey/proxy.sock
```

The proxy and the credential must be in the same project. The default
`wispkey serve` scopes to the active project.

## Request

```http
POST /api/webhooks/verify HTTP/1.1
x-wispkey-instance-id: <instance UUID>
x-wispkey-instance-secret: <instance secret>
x-wispkey-credential-id: 2c5ea4c0-4067-41e9-8bad-9b1deb4d3b7d
webhook-id: msg_synthetic_0001
webhook-timestamp: 1614265330
webhook-signature: v1,<base64>
content-length: 20

{"test": 2432232314}
```

Copy the provider's `webhook-*` headers and body bytes unchanged. Send each
required header exactly once.

| Input | Rule |
|-------|------|
| Path | Exactly `/api/webhooks/verify`; no query string, no absolute-form target |
| `Origin` | Must be absent. The endpoint sends no CORS headers |
| `x-wispkey-credential-id` | Lowercase hyphenated, non-nil UUID |
| `webhook-id` | 1 to 256 printable ASCII bytes |
| `webhook-timestamp` | Unix seconds, digits only, no leading zero, at most `253402300799` |
| `webhook-signature` | At most 16 `v1` candidates and 4 KiB; any other version rejects the request |
| Body | At most 1 MiB, received within 5 seconds |

## Responses

| Status | Body | Meaning |
|--------|------|---------|
| 200 | `{"result":"valid"}` | A candidate matches and the timestamp is fresh |
| 200 | `{"result":"invalid"}` | No candidate matches |
| 200 | `{"result":"stale"}` | The timestamp is outside the tolerance |
| 400 | `{"error":"malformed verification request"}` | Missing, duplicate, unsupported or malformed input |
| 401 | `{"error":"instance authentication failed"}` | Unknown, revoked or wrong instance identity |
| 403 | `{"error":"credential not permitted"}` | Credential absent, out of scope, outside the routine ring, not an `api_key`, auth registration revoked or expired, or invalid signing-key encoding for a fresh timestamp |
| 405 | `{"error":"method not allowed"}` | Method is not `POST` |
| 408 | `{"error":"webhook body timed out"}` | Body not received within 5 seconds |
| 413 | `{"error":"webhook body too large"}` | Declared or streamed body over 1 MiB |
| 503 | `{"error":"verifier unavailable"}` | Vault locked, session expired, storage or audit failure |

Accept the delivery only on `200` with `valid`. Treat every other status as a
rejection. An absent credential and an out-of-scope credential give the same 403.

## Deduplication

`valid` proves that the delivery is authentic and fresh. It does not prove that
the delivery is new. Inside the 300-second window, a replayed delivery is valid
again. The caller must deduplicate by `webhook-id` before it starts any work.

## Rotation

The verifier never falls back from one credential to another. To rotate:

1. Store the new secret as a second `api_key` credential with `--ring routine`
   (use `--value-file` for the secret), then add it to the instance scope
   with `wispkey instance scope add billing-receiver --credential <new name>`.
2. During the provider's overlap period, the delivery carries signatures from
   both secrets. Verify against the credential ID that the receiver selects. Each
   credential ID matches only its own key.
3. When the provider stops signing with the old secret, remove the old
   credential from the scope, or remove the credential.

## Revocation

| Action | Effect on the next request |
|--------|----------------------------|
| `wispkey instance revoke <instance>` | 401 |
| `wispkey instance scope remove <instance> --credential <name>` | 403 |
| `wispkey remove <name>` | 403 |
| `wispkey auth revoke <name> --project <project>` | 403 |

The verifier reopens the unlocked session and authenticates the instance again
after receiving the body. A lock, session expiry or secret change during upload
therefore invalidates that request. It reloads the session after instance
authentication too, without extending its expiry. It keeps no key cache.
An immediate transaction serializes the stored instance, scope, credential and
auth-registry checks with the result audit write. Delegated auth deadlines are
checked again after a matching HMAC, before the audit commit.

## Availability

The verifier needs an unlocked session. `wispkey lock`, an expired session or a
storage failure gives 503 and never `valid`. Each result writes a metadata-only
audit row (`WebhookVerified` or `WebhookRejected`) with the credential ID in
`credential_name` and `instance:<UUID>` in `target_host`. If that result row cannot
be written, the result is 503. Authenticated verification denials use
`WebhookDenied`; requests rejected before authentication may have no audit row.

## Trust boundary

- Instance identity comes only from the instance ID and secret headers.
- The proxy clock decides freshness. Keep it synchronized.
- Plain TCP gives no transport confidentiality. Use a Unix socket, vsock, or a
  loopback listener on a trusted host, as for other instance requests.
- The endpoint does not prove who sent the webhook beyond holding the signing
  secret, and it does not protect the receiver after it accepts a delivery.
