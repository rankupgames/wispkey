"""DRAFT-1 reference model. Synthetic trusted facts only; NEVER a wire/auth API.

No crypto, storage, network, credentials, environment reads or runtime imports.
Verification booleans stand for obligations of a future reviewed adapter.
"""
from dataclasses import dataclass, replace

VERSION = 'wispkey-access-enrollment/draft-1'
RIGHTS = frozenset({'discover', 'replicate', 'request', 'use'})
RINGS = frozenset({'routine', 'restricted', 'critical'})


def classify(value):
    return value if value in RINGS else 'restricted'


@dataclass(frozen=True)
class Scope:
    endpoint: str
    account: str
    vault: str
    project: str
    partition: str


@dataclass(frozen=True)
class Binding:
    scope: Scope
    device: str
    recipient_key: str
    auth_key: str
    root: str
    epoch: int
    policy_revision: str


@dataclass(frozen=True)
class Enrollment:
    binding: Binding
    request_id: str
    nonce: str
    created_at: int
    expires_at: int
    rights: frozenset[str]
    description: str = 'Synthetic secondary'
    state: str = 'pending'
    revision: int = 0
    version: str = VERSION


@dataclass(frozen=True)
class Approval:
    request: Enrollment
    actor: str
    account: str
    owner_signature_verified: bool = False
    current_owner_authority: bool = False
    presence_verified: bool = False
    comparison_verified: bool = False
    possession_verified: bool = False


class Denied(ValueError):
    """Fixed categories only; never echo request data."""


def transition(record, event, now, expected_revision, *, enabled=False, approval=None):
    if not enabled:
        raise Denied('disabled')
    if record.version != VERSION:
        raise Denied('unsupported_version')
    if record.revision != expected_revision:
        raise Denied('stale_revision')
    if record.state not in {'pending', 'approved'}:
        raise Denied('terminal_state')
    if event in {'cancel', 'revoke'}:
        return replace(record, state='revoked', revision=record.revision + 1)
    if now >= record.expires_at:
        return replace(record, state='expired', revision=record.revision + 1)
    if event != 'approve' or record.state != 'pending' or approval is None:
        raise Denied('invalid_transition')
    if not (record.created_at <= now < record.expires_at <= record.created_at + 300):
        raise Denied('invalid_lifetime')
    if record.rights != frozenset({'discover', 'replicate'}):
        raise Denied('unsupported_rights')
    if approval.request != record:
        raise Denied('request_changed')
    if approval.account != record.binding.scope.account:
        raise Denied('wrong_account')
    if approval.actor == record.binding.device:
        raise Denied('self_approval')
    if not all((approval.owner_signature_verified, approval.current_owner_authority,
                approval.presence_verified, approval.comparison_verified,
                approval.possession_verified)):
        raise Denied('approval_proof_required')
    return replace(record, state='approved', revision=record.revision + 1)


@dataclass(frozen=True)
class Grant:
    binding: Binding
    principal: str
    kind: str
    rights: frozenset[str]
    ring: str
    credential: str
    credential_revision: str
    origin: str
    operation: str
    issued_at: int
    expires_at: int
    version: str = VERSION


@dataclass(frozen=True)
class Context:
    binding: Binding
    principal: str
    kind: str
    credential: str
    credential_revision: str
    origin: str
    operation: str
    ring: str
    now: int
    enabled: bool = False
    identity_verified: bool = False
    owner_grant_verified: bool = False
    enrollment_state: str = 'pending'
    enrollment_expires_at: int = 0
    session_expires_at: int = 0
    unlocked: bool = False
    existing_policy_allows: bool = False
    resource_active: bool = False
    exportable: bool = False
    dedicated_partition: bool = False
    entire_partition_routine: bool = False
    route: str = 'device-v1'
    fresh_owner_response_verified: bool = False
    freshness_nonce_matches: bool = False
    freshness_binding_matches: bool = False
    freshness_received_monotonic: int = 0
    now_monotonic: int = 0
    # 30s is an explicit DRAFT budget, not a shipping promise.
    freshness_deadline_monotonic: int = 0
    grant_revoked: bool = False
    plugin_grant_verified: bool = False
    restored: bool = False
    cancelled: bool = False


def decide(grant, context, right):
    c = context
    if not c.enabled:
        return 'disabled'
    if grant.version != VERSION:
        return 'unsupported_version'
    if c.route != 'device-v1':
        return 'legacy_route'
    if c.restored or c.cancelled:
        return 'inactive_context'
    if not (c.identity_verified and c.owner_grant_verified and c.unlocked):
        return 'unverified_authority'
    if c.kind not in {'device', 'plugin'} or (grant.principal, grant.kind) != (c.principal, c.kind):
        return 'principal_mismatch'
    if c.kind == 'device' and c.principal != c.binding.device:
        return 'principal_mismatch'
    if grant.binding != c.binding:
        return 'binding_mismatch'
    if c.enrollment_state != 'approved' or c.grant_revoked:
        return 'revoked_or_unapproved'
    if not (grant.issued_at <= c.now < min(grant.expires_at, c.enrollment_expires_at,
                                          c.session_expires_at)):
        return 'expired'
    if not (c.fresh_owner_response_verified and c.freshness_nonce_matches
            and c.freshness_binding_matches
            and c.freshness_received_monotonic <= c.now_monotonic
            < c.freshness_deadline_monotonic
            <= c.freshness_received_monotonic + 30):
        return 'stale_policy'
    if (grant.credential, grant.credential_revision, grant.origin, grant.operation) != (
            c.credential, c.credential_revision, c.origin, c.operation):
        return 'resource_mismatch'
    if not (c.existing_policy_allows and c.resource_active):
        return 'existing_policy_denied'
    if right not in RIGHTS or right not in grant.rights:
        return 'right_denied'
    if classify(grant.ring) != classify(c.ring):
        return 'ring_changed'
    # First slice deliberately grants no delegated use, even with presence.
    if right == 'use':
        return 'use_not_in_slice'
    if c.kind == 'plugin':
        if not c.plugin_grant_verified or right not in {'discover', 'request'}:
            return 'plugin_denied'
    if right == 'replicate' and not (
            c.kind == 'device' and grant.ring == c.ring == 'routine'
            and c.exportable and c.dedicated_partition and c.entire_partition_routine):
        return 'replication_denied'
    return 'allow'


@dataclass(frozen=True)
class Snapshot:
    binding: Binding
    sequence: int
    ciphertext_hash: str
    payload_version: int = 1
    version: str = VERSION


@dataclass(frozen=True)
class Checkpoint:
    binding: Binding
    sequence: int
    ciphertext_hash: str


def accept_snapshot(snapshot, checkpoint, grant, context, *, signature_verified=False,
                    ciphertext_hash_verified=False, payload_scope_verified=False,
                    current_head=None):
    """Returns a new checkpoint after all checks, or raises without changing state.

    current_head is the tuple from the nonce-bound owner freshness response.
    Real adapters MUST atomically commit payload + checkpoint + revisions.
    """
    verdict = decide(grant, context, 'replicate')
    if verdict != 'allow':
        raise Denied(verdict)
    if snapshot.version != VERSION or snapshot.payload_version != 1:
        raise Denied('unsupported_version')
    if snapshot.binding != context.binding or checkpoint.binding != context.binding:
        raise Denied('snapshot_binding_mismatch')
    if not (signature_verified and ciphertext_hash_verified and payload_scope_verified):
        raise Denied('snapshot_verification_required')
    if current_head != (snapshot.sequence, snapshot.ciphertext_hash):
        raise Denied('not_current_head')
    if snapshot.sequence < 1 or snapshot.sequence < checkpoint.sequence:
        raise Denied('rollback')
    if snapshot.sequence == checkpoint.sequence:
        if snapshot.ciphertext_hash != checkpoint.ciphertext_hash:
            raise Denied('equivocation')
        return checkpoint  # Reconciliation is idempotent, never replayed release.
    return Checkpoint(snapshot.binding, snapshot.sequence, snapshot.ciphertext_hash)
