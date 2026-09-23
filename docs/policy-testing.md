# Policy Testing

`policy test` and `policy explain` evaluate one request without opening the
vault, decrypting a credential, writing an audit event, or consuming live rate
capacity.

```bash
wispkey policy test \
  --credential aws-prod \
  --host api.example.com \
  --path /v1/resources \
  --method POST \
  --format json

wispkey policy explain \
  --policy-file ./candidate-policies.toml \
  --credential aws-prod \
  --host api.example.com \
  --path /v1/resources \
  --method POST \
  --at 2026-09-05T14:30:00Z
```

Single-request mode requires `--credential`, `--host`, `--path`, and
`--method`. `--policy-file` reads an uninstalled TOML candidate. Use `-` for
stdin. Policy input is bounded to 1 MiB and the runtime and simulator accept
at most 1024 policy rules. These limits fail closed and prevent unbounded
policy evaluation.

## Time

`--at` and case `request.at` use RFC3339 timestamps with an explicit offset.
WispKey converts the timestamp to the machine's local timezone, then applies
the policy `HH:MM-HH:MM` window to that local clock. Without `--at`, the
current local time is used. Use an injected timestamp in CI; the current-time
default is not deterministic.

For batch input, `--at` is an optional default for cases that do not provide
`request.at`.

## Cases

`policy test --cases cases.json` runs every case and exits with status 1 when
any expected result does not match. The input schema is versioned:

```json
{
  "schema_version": 1,
  "cases": [
    {
      "name": "production-read",
      "request": {
        "credential": "aws-prod",
        "host": "api.example.com",
        "path": "/v1/resources",
        "method": "GET",
        "at": "2026-09-05T14:30:00Z"
      },
      "expected": "allow"
    },
    {
      "name": "production-write",
      "request": {
        "credential": "aws-prod",
        "host": "api.example.com",
        "path": "/v1/resources",
        "method": "POST"
      },
      "expected": "deny"
    }
  ]
}
```

`expected` is `allow` or `deny`. Case input is bounded to 4 MiB and 256 cases.
Malformed case and TOML parser errors return static messages and do not echo
input content.

## JSON Output

Pass `--format json` to either command. Successful output uses
`"schema_version": 1` and contains:

- `command` and `mode`: `test` or `explain`, and `single` or `cases`.
- `source`: `installed` or `candidate`, plus the source path.
- `request`: credential, host, path, method, and optional agent label.
- `agent_identity`: untrusted what-if status, including that the current proxy
  path has no supplied agent identity.
- `evaluation_time`: injected/current source, local RFC3339 time, and local
  clock semantics.
- `decision`: `allow` or `deny`.
- `decision_reason`: an explicit static reason for an allow, or the decisive
  denial reason.
- `matching_policies`: every policy selected by credential and agent in source
  order. Each entry reports `allow` or `deny` and its reason.
- `evaluations`: all policies in source order, including skipped policies and
  their selector reason.
- `decisive_policy`: the first denying policy and reason, or `null`.
- `diagnostics`: proven invalid-rule and conservative shadow-rule findings,
  plus explicit agent identity status. Shadow findings include the related
  earlier policy index and name.
- `rate_limit`: `state` is `fresh_offline`, live `capacity_consumed` is
  `false`, `simulation_state` is `fresh_local_non_live`, and
  `live_capacity_measured` is `false`. The local state preserves ordered
  checks within this simulation only.

The evaluator keeps the runtime first-deny ordering and host, path, method,
agent, time-window, and rate-limit checks. Explanation evaluates later rules
for visibility, but the first denial remains decisive. An allow policy does
not grant access; policies are deny rules and restrictions only.

## Agent Identity

`--agent` is a what-if selector only. It is always reported as
`untrusted_input` and `trusted_for_production: false`. When omitted, the
identity is reported as `missing`. The current proxy path supplies no trusted
agent identity, so a provided label can produce a different selector result
than the proxy's absent-identity behavior. The simulation does not create or
infer a trusted production identity, and the runtime matching semantics remain
unchanged.

## Rate Limits

Simulation starts with empty rate state for every request. It can prove a
zero-capacity rule denial, but it cannot report current live capacity. The
proxy's monotonic rate buckets are not read or mutated by simulation.
