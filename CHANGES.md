# Changes

## Correctness fixes

- `src/proxy/tokens.rs`: replaced token-by-token global `String::replace` with a single left-to-right replacement pass. The resolver now accepts the longest valid known token prefix inside a broad `wk_*` match, so a real token adjacent to lowercase or underscore text resolves instead of being over-matched.
- `src/proxy/tokens.rs`: preserves explicit env-sideload policy denials when a vault is unlocked instead of collapsing them into a later token-not-found error.
- `src/proxy/mod.rs`: strips `transfer-encoding` when recalculating `content-length` for buffered forwarded requests.
- `src/audit/mod.rs` and `src/secure_files.rs`: added owner-only fallback JSONL audit logging for env-sideload proxy use when no unlocked vault database is available.
- `src/proxy/tokens.rs`: records env-sideload policy denials to the vault audit DB when available, or to the fallback JSONL sink otherwise.
- `src/policy/mod.rs`: prunes expired rate-limit entries across buckets and evicts empty stale buckets during rate-limit evaluation.

## Regression tests

- `tests/proxy.rs`: added coverage for valid tokens followed immediately by lowercase/underscore text.
- `tests/proxy.rs`: added coverage proving inserted secret values are not rescanned and corrupted when they contain another wisp token string.
- `src/proxy/tests.rs`: added coverage that forwarded headers cannot keep both `transfer-encoding` and a recomputed `content-length`.
- `tests/env_sideload.rs`: added coverage that vault-less env sideload proxy use writes an audit row without logging the raw secret.
- `tests/env_sideload.rs`: added coverage that env-sideload policy denials with an unlocked vault return the policy denial rather than a misleading token-not-found error.

## Documentation

- `README.md`: updated the category wording to "credential firewall for AI agents", documented fallback sideload audit behavior, added a concise comparison section, and linked the internal threat model.

## Verification

- `cargo fmt -- --check`
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings -W clippy::suspicious -W clippy::style -W clippy::perf -W clippy::complexity`
- `git diff --check`
