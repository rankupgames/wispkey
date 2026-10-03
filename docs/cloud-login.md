# WispKey Cloud CLI sign-in (preview)

`wispkey cloud login` uses a registered **public Clerk OAuth application** with
Authorization Code, S256 PKCE, RFC 8707 resource binding and opaque access tokens.
The API deployment must opt in first. This is an interactive system-browser
flow, not a headless/CI credential provider.

```sh
wispkey cloud login
wispkey cloud status
wispkey cloud logout
```

## Deployment contract

The configured `api_url` must be an HTTPS origin, without a path, query, fragment
or credentials. `GET /api/v1/auth/cli-config` must return:

```json
{"success":true,"data":{"issuer":"https://clerk.example.com","clientId":"registered-public-client","resource":"https://api.example.com/api/v1","scopes":["wispkey:sync"],"tokenFormat":"opaque"}}
```

The resource is exactly the configured API origin plus `/api/v1`. The issuer is
an HTTPS origin. The CLI discovers `/.well-known/oauth-authorization-server`
and requires matching issuer, `code`, `authorization_code`, public-client `none`
authentication, and `S256` support. Authorize and token metadata must name that
issuer's exact `/oauth/authorize` and `/oauth/token` endpoints. Cross-origin
endpoints and redirects fail closed. The legacy `WISPKEY_CLOUD_SIGN_IN_URL`
override is removed.

This preview requires a compatible backend implementing the deployment contract above.
The public config endpoint is disabled by default. Clerk's official Frontend API
specifies `resource` on both authorization and token exchange; exchange requires
an exact match to the original authorization grant. Before enabling this preview,
an approved test instance must demonstrate the actual public-client loopback
flow, exact resource audience, online verification response and revocation.
Synthetic fixtures do not establish deployed settings or real-provider behavior.

Operator setup must register `http://127.0.0.1/callback`, enable Public and Require
PKCE, enable the `wispkey:sync` custom scope, select **opaque access tokens**, and
retain the consent screen. Clerk accepts a dynamically assigned port for this
literal loopback redirect. No client secret belongs in the CLI or its config.
This code neither creates OAuth applications nor enables deployed settings.

## Browser and token boundaries

The CLI binds only `127.0.0.1` on a random port and opens the system browser
directly at Clerk's authorization endpoint. Each attempt has independent
256-bit state and PKCE verifier. The callback accepts only a matching state and
an authorization code, never a raw token. It checks the method, path and Host,
rejects duplicate/unknown parameters, bounds bytes and read time, and closes
before exchange. Unrelated invalid requests do not consume the attempt. A valid
provider denial, Ctrl-C, or a 120-second callback timeout ends the attempt.

The code and verifier are submitted directly to Clerk over HTTPS with the same
resource. HTTP proxies and redirects are disabled. Errors never include response
bodies, authorization codes, bearer tokens or the verifier. Live authorization
URLs, state and PKCE challenges are not printed. If the system browser cannot
be launched, the attempt ends; run login on a computer with a browser.

The CLI accepts only a bounded opaque `oat_` bearer with `expires_in` no greater
than 24 hours. It rejects JWT/ID tokens and any extra granted scope. There is no
`offline_access` request, refresh-token storage, or automatic refresh. Clerk may
include a refresh token in its response; the CLI immediately zeroizes and
discards it without persisting, logging, transmitting or using it. Only the
resource-bound access token is retained. Expiry requires `wispkey cloud login`
again.

An opaque token has no locally readable identity. Before saving anything, the
pinned Cloud API verifies it online with Clerk, enforces the dedicated client,
exact singleton resource audience, scope, personal user and bounded lifetime,
then returns matching `clerkUserId`, trusted plan/features and `oauth` context
from `billing/status`:

```json
{"issuer":"https://clerk.example.com","clientId":"registered-public-client","resource":"https://api.example.com/api/v1","issuedAt":1800000000,"expiresAt":1800003600,"tokenFormat":"opaque"}
```

Timestamps are Unix **seconds**. The CLI checks that context, subject consistency,
expiry/lifetime and the token exchange's reported lifetime before persisting.
Entitlements come from the verified API response. The server, not the opaque
token's shape or the local config, remains the authorization authority.

## Local storage and migration

Credentials remain in the existing owner-only `cloud.json` file (0600 on Unix,
restricted ACL on Windows), written atomically. This preview does not use an
OS keychain. The existing `clerk_session_token` field now contains the OAuth
access bearer; the historical `access_token` input alias still parses.
`oauth_session` pins issuer, client, API origin, resource, verified user, token
format, issue/expiry times and a fingerprint covering the bearer plus that full
context. An authentication-generation marker prevents a pending login from
overwriting a concurrent logout. Debug output redacts the bearer, and
status/logout JSON never returns it.

Existing raw callback sessions have no verified OAuth bindings and cannot be
used for sync. Run `wispkey cloud login` to replace them. Account or deployment
changes require `wispkey cloud logout` first. Config migration preserves the API
origin and existing sync data. Sync state remains scoped to the API and account;
logout clears the local auth config without deleting encrypted recovery data.

The separate foreground-watch feature pins its starting configuration: any
logout, renewal or account/config change stops that watch. Restart it after
logging in again; a running watch must never silently switch bearers.

## Logout and revocation

Logout removes local credentials **before** sending an empty-body
`POST /api/v1/auth/cli-logout` to the pinned API with only the bearer in the
Authorization header. The Cloud service verifies the presented token and
resolves its configured Clerk application before invoking Clerk's official
backend revocation endpoint for the associated OAuth grant. The CLI never chooses
a provider token ID or sends
a client secret. Logout does not need a paid plan.

JSON reports `revoked` only for the API's confirmed successful response. Otherwise
it reports `unconfirmed` or `not_attempted`, with the known expiry when available.
A network failure does not restore local credentials; a copied token can remain
valid until expiry if remote revocation is unconfirmed. Legacy unpinned sessions
cannot be safely sent to an inferred endpoint. Logout does not close the browser
session. Revoking the associated grant can affect other tokens or devices that
share that grant.

## Verification and operator acceptance

Automated tests use synthetic HTTPS issuers, stub API responses and disposable
local storage. They cover S256, callback injection and replay, invalid metadata,
redirect rejection, cancellation, timeout, opaque-token verification binding,
migration, redaction, persistence races and logout outcomes. No real Clerk
account, consent grant, token, deployment or billing operation is needed.

Before enabling this preview, check the paired Cloud deployment, public
application, exact resource/audience and custom scope, loopback redirect,
consent, opaque token format/lifetime, entitlement mapping, and browser
login/logout on each supported OS. Synthetic tests do not replace that acceptance.

References: [Clerk CLI PKCE guide](https://clerk.com/blog/adding-clerk-auth-to-your-cli),
[Clerk OAuth behavior and metadata](https://clerk.com/docs/guides/configure/auth-strategies/oauth/how-clerk-implements-oauth),
[Clerk official Frontend API resource contract](https://raw.githubusercontent.com/clerk/openapi-specs/main/fapi/2026-05-12.yml),
[Clerk opaque-token behavior](https://clerk.com/docs/guides/development/machine-auth/token-formats),
[RFC 8252 loopback redirects](https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
