# RUG-449: schema-driven records and optional GraphQL evaluation

Status: **experimental assessment, no runtime implementation or migration**.
[RUG-449](https://linear.app/rankupgames/issue/RUG-449/experimental-explore-schema-driven-records-and-optional-graphql)
remains open. The issue requested an idea before implementation; this review
artifact evaluates a synthetic experiment without selecting a production schema,
exposing metadata, changing existing records or deploying an API.

## Starting point and question

WispKey's current whole-value credential editing is separate from a structured
record editor. A schema must not create a storage table, executable validator,
privileged resolver, runner permission or new authorization merely by existing.
Custom field names/descriptions can be sensitive even when values are encrypted.

Evaluate whether one locally defined, versioned schema can improve display and
bounded field updates while preserving all other fields and current encrypted
custody. Compare a local schema registry with a simple typed HTTP representation
before considering GraphQL. GraphQL is optional and has no selected runtime design.

## Bounded experiment candidate

Use one fixed synthetic schema ID/version with two fields: a display label and an
opaque encrypted-value placeholder. Reject unknown schema/version and fields in
this initial experiment; choose forward-compatible preservation versus strict
rejection explicitly before any production editor. A partial update should replace
only the named field, preserve other values and reject type/size mismatch before
any mutation. These rules apply to the synthetic model only.

Keep schemas local by default. If metadata sharing is later proposed, require an
explicit allowlist and authenticated tenant/owner scope. Sharing schema ID/version
may be sufficient for the first compatibility experiment; custom names, descriptions,
defaults and secret annotations do not become safe to expose automatically.
JSON Schema is a candidate vocabulary, not an approved dependency. Evaluate required
subset, offline reference resolution, recursive/large-schema limits, malicious
regular expressions, validator version compatibility and secret-field annotations.
Never fetch arbitrary external schema references during a record update.

## Executable simulation

Run `python3 -B -m unittest discover -s scripts/tests -p 'test_schema_record_model.py' -v`.
The standalone model demonstrates one schema/version, copy-before-update behavior,
unknown version/field denial, bounded field types, preservation of an opaque value,
and minimal metadata projection. Tests verify source data is unchanged on rejection.

The placeholder is not encryption. The model has no vault access, cryptography,
authentication, persistent storage, renderer, sync transport or GraphQL runtime.
Its success cannot establish encrypted storage or secure UI behavior. Existing
production encryption and policy interfaces must be used and tested separately.

## Evaluation matrix and go/no-go

- Local forms/table display: a renderer must avoid secret defaults, automatic
  previews, clipboard leakage and rendering secret annotations as executable code.
  Prove with synthetic UI fixtures before calling it a structured editor.
- Field edits: test real vault read-modify-write atomicity, stale revisions,
  authorization changes and preservation of unknown fields if that policy is chosen.
- Versioning: require explicit migration ownership, reversible compatibility fixtures
  and failure-safe behavior. No automatic legacy conversion is proposed here.
- Metadata: test tenant/owner authorization and deny private schema labels/defaults
  from logs, errors, exports and Cloud sync unless explicitly approved.
- GraphQL: proceed only if a specific approved read/query workflow cannot be served
  adequately by current APIs. Measure query complexity/depth, resolver authorization,
  schema introspection, caching, logging and maintenance cost. Otherwise defer it.

Initial assessment: versioned local form/update semantics are feasible to simulate;
secure production rendering, migrations and metadata permissions remain substantial
work. GraphQL has no demonstrated necessity from the current requirement. The
recommended experiment outcome is a measured local prototype first and an explicit
later API decision, not a commitment to GraphQL or expanded Cloud authority.

Before runtime work, review schema ownership, accepted vocabulary/version policy,
secret annotations, size limits, migration behavior, metadata visibility and the
specific UI/API consumer. Preserve the existing local primitive/private Cloud
orchestration boundary and all separate credential-operation permissions.
