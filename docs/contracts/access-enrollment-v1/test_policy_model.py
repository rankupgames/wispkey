"""Run with python3 -B -m unittest discover -s docs/contracts/access-enrollment-v1 -v."""
import itertools
import json
from dataclasses import replace
from pathlib import Path
import unittest

from policy_model import (VERSION, Scope, Binding, Enrollment, Approval, Denied,
                          transition, Grant, Context, decide, Snapshot, Checkpoint,
                          accept_snapshot, classify, FreshnessChallenge, accept_freshness)


def fixture():
    binding = Binding(Scope('https://sync.example.test', 'account-a', 'vault-a',
                            'project-a', 'partition-a'), 'device-b', 'recipient-b',
                      'auth-b', 'root-a', 1, 'policy-1')
    grant = Grant(binding, 'device-b', 'device', frozenset({'discover', 'replicate'}),
                  'routine', 'credential-a', 'revision-1', 'https://api.example.test',
                  'read', 100, 400)
    context = Context(binding, 'device-b', 'device', 'credential-a', 'revision-1',
                      'https://api.example.test', 'read', 'routine', 110,
                      enabled=True, identity_verified=True, owner_grant_verified=True,
                      enrollment_state='approved', enrollment_expires_at=400,
                      session_expires_at=400, unlocked=True, existing_policy_allows=True,
                      resource_active=True, exportable=True, dedicated_partition=True,
                      entire_partition_routine=True, fresh_owner_response_verified=True,
                      freshness_nonce_matches=True, freshness_binding_matches=True,
                      freshness_received_monotonic=10, now_monotonic=11,
                      freshness_deadline_monotonic=40,
                      freshness_challenge=FreshnessChallenge(binding, 'nonce-head', 'boot-1', 10, 40, False),
                      clock_epoch='boot-1', clock_certain=True,
                      head_issued_at=100, head_expires_at=400, head_received_at=110)
    return binding, grant, context


def enrollment_fixture():
    binding, _, _ = fixture()
    record = Enrollment(binding, 'request-a', 'nonce-a', 100, 400,
                        frozenset({'discover', 'replicate'}))
    approval = Approval(record, 'owner-device', 'account-a', True, True, True, True, True)
    return record, approval


class PolicyTests(unittest.TestCase):
    def test_portable_decision_vectors(self):
        vectors = json.loads(Path(__file__).with_name('vectors.json').read_text())
        self.assertEqual(vectors['contract'], VERSION)
        self.assertGreaterEqual(len(vectors['decisions']), 40)
        for vector in vectors['decisions']:
            with self.subTest(vector=vector['id']):
                _, grant, context = fixture()
                g = vector.get('grant', {}).copy()
                if 'rights' in g:
                    g['rights'] = frozenset(g['rights'])
                grant = replace(grant, **g)
                context = replace(context, **vector.get('context', {}))
                if 'challenge' in vector:
                    context = replace(context, freshness_challenge=replace(
                        context.freshness_challenge, **vector['challenge']))
                self.assertEqual(decide(grant, context, vector['right']), vector['expect'])

    def test_default_context_is_disabled(self):
        _, grant, context = fixture()
        self.assertEqual(decide(grant, replace(context, enabled=False), 'replicate'), 'disabled')
        self.assertFalse(Context.__dataclass_fields__['enabled'].default)

    def test_every_scope_and_binding_dimension_is_exact(self):
        binding, grant, context = fixture()
        for field in Scope.__dataclass_fields__:
            with self.subTest(field=field):
                changed = replace(binding, scope=replace(binding.scope, **{field: 'other'}))
                self.assertEqual(decide(grant, replace(context, binding=changed), 'replicate'), 'binding_mismatch')
        for field in ('device', 'recipient_key', 'auth_key', 'root', 'epoch', 'policy_revision'):
            with self.subTest(field=field):
                changed = replace(binding, **{field: 2 if field == 'epoch' else 'other'})
                self.assertIn(decide(grant, replace(context, binding=changed), 'replicate'), {'binding_mismatch', 'principal_mismatch'})

    def test_grant_cannot_bind_a_different_device_principal(self):
        _, grant, context = fixture()
        self.assertEqual(decide(replace(grant, principal='device-c'),
                                replace(context, principal='device-c'), 'replicate'),
                         'principal_mismatch')

    def test_rights_never_imply_other_rights(self):
        _, grant, context = fixture()
        rights = ('discover', 'replicate', 'request', 'use')
        for mask in itertools.product((False, True), repeat=4):
            selected = frozenset(r for r, include in zip(rights, mask) if include)
            for right in rights:
                with self.subTest(rights=selected, right=right):
                    outcome = decide(replace(grant, rights=selected), context, right)
                    if right not in selected:
                        self.assertEqual(outcome, 'right_denied')
                    elif right == 'use':
                        self.assertEqual(outcome, 'use_not_in_slice')
                    else:
                        self.assertEqual(outcome, 'allow')

    def test_unclassified_and_future_rings_cannot_replicate(self):
        _, grant, context = fixture()
        for ring in (None, '', 'future', 'Routine', 'restricted', 'critical'):
            with self.subTest(ring=ring):
                self.assertEqual(classify(ring), ring if ring in {'restricted', 'critical'} else 'restricted')
                self.assertEqual(decide(replace(grant, ring=ring), replace(context, ring=ring), 'replicate'), 'replication_denied')

    def test_admission_cannot_survive_release_time_change(self):
        _, grant, context = fixture()
        self.assertEqual(decide(grant, context, 'replicate'), 'allow')
        for change in ({'grant_revoked': True}, {'enrollment_state': 'revoked'},
                       {'ring': 'critical'}, {'credential_revision': 'r2'},
                       {'unlocked': False}, {'cancelled': True}, {'now_monotonic': 40}):
            with self.subTest(change=change):
                self.assertNotEqual(decide(grant, replace(context, **change), 'replicate'), 'allow')

    def test_plugin_is_separate_and_cannot_replicate_or_execute(self):
        _, grant, context = fixture()
        grant = replace(grant, principal='plugin-a', kind='plugin', rights=frozenset({'discover', 'request', 'replicate', 'use'}))
        context = replace(context, principal='plugin-a', kind='plugin')
        self.assertEqual(decide(grant, context, 'discover'), 'plugin_denied')
        context = replace(context, plugin_grant_verified=True)
        for right, expected in [('discover', 'allow'), ('request', 'allow'),
                                ('replicate', 'plugin_denied'), ('use', 'use_not_in_slice')]:
            self.assertEqual(decide(grant, context, right), expected)
        self.assertEqual(decide(grant, replace(context, kind='hosted-executor'), 'discover'), 'principal_mismatch')


class EnrollmentTests(unittest.TestCase):
    def test_default_gate_and_happy_path(self):
        record, approval = enrollment_fixture()
        with self.assertRaisesRegex(Denied, '^disabled$'):
            transition(record, 'approve', 110, 0, approval=approval)
        result = transition(record, 'approve', 110, 0, enabled=True, approval=approval)
        self.assertEqual((result.state, result.revision), ('approved', 1))
        self.assertEqual(record.state, 'pending')

    def test_every_approval_obligation_and_account(self):
        record, approval = enrollment_fixture()
        changes = [{'account': 'account-b'}, {'actor': 'device-b'}]
        changes += [{f: False} for f in ('owner_signature_verified', 'current_owner_authority',
                                        'presence_verified', 'comparison_verified', 'possession_verified')]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(Denied):
                transition(record, 'approve', 110, 0, enabled=True, approval=replace(approval, **change))

    def test_approval_binds_all_request_fields(self):
        record, approval = enrollment_fixture()
        changes = [{'nonce': 'other'}, {'request_id': 'other'}, {'description': 'other'},
                   {'expires_at': 399}, {'rights': frozenset({'discover'})},
                   {'binding': replace(record.binding, recipient_key='attacker-key')},
                   {'binding': replace(record.binding, auth_key='attacker-auth-key')},
                   {'binding': replace(record.binding, scope=replace(record.binding.scope, account='other'))}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(Denied):
                transition(replace(record, **change), 'approve', 110, 0, enabled=True, approval=approval)

    def test_expiry_and_no_revival(self):
        record, approval = enrollment_fixture()
        for now in (400, 401):
            expired = transition(record, 'approve', now, 0, enabled=True, approval=approval)
            self.assertEqual(expired.state, 'expired')
            with self.assertRaisesRegex(Denied, '^terminal_state$'):
                transition(expired, 'approve', 110, 1, enabled=True, approval=approval)
        for now in (99,):
            with self.assertRaisesRegex(Denied, '^invalid_lifetime$'):
                transition(record, 'approve', now, 0, enabled=True, approval=approval)

    def test_duplicate_approval_and_cancel_race_both_serializations(self):
        record, approval = enrollment_fixture()
        approved = transition(record, 'approve', 110, 0, enabled=True, approval=approval)
        with self.assertRaisesRegex(Denied, '^stale_revision$'):
            transition(approved, 'approve', 110, 0, enabled=True, approval=approval)
        revoked = transition(approved, 'cancel', 111, 1, enabled=True)
        self.assertEqual(revoked.state, 'revoked')
        cancelled = transition(record, 'cancel', 110, 0, enabled=True)
        for revision in (0, 1):
            with self.assertRaises(Denied):
                transition(cancelled, 'approve', 111, revision, enabled=True, approval=approval)

    def test_terminal_states_version_rights_and_unbounded_lifetime(self):
        record, approval = enrollment_fixture()
        for change in ({'state': 'revoked'}, {'state': 'expired'}, {'state': 'unknown'},
                       {'version': 'future'}, {'rights': frozenset({'use'})}, {'expires_at': 401}):
            altered = replace(record, **change)
            with self.subTest(change=change), self.assertRaises(Denied):
                transition(altered, 'approve', 110, 0, enabled=True, approval=replace(approval, request=altered))


class FreshnessTests(unittest.TestCase):
    def test_response_vectors(self):
        vectors = json.loads(Path(__file__).with_name('vectors.json').read_text())
        for vector in vectors['freshness_responses']:
            with self.subTest(vector=vector['id']):
                binding, grant, context = fixture()
                changes = {'outstanding': True} | vector.get('challenge', {})
                context = replace(context, freshness_challenge=replace(
                    context.freshness_challenge, **changes))
                context = replace(context, **vector.get('context', {}))
                grant = replace(grant, **vector.get('grant', {}))
                args = dict(nonce='nonce-head', binding=binding, issued_at=100,
                            expires_at=400, signature_verified=True)
                args.update(vector.get('response', {}))
                if vector['expect'] == 'allow':
                    accepted = accept_freshness(grant, context, **args)
                    self.assertFalse(accepted.freshness_challenge.outstanding)
                    self.assertEqual(accepted.freshness_deadline_monotonic, 40)
                    self.assertEqual(decide(grant, accepted, 'replicate'), 'allow')
                else:
                    with self.assertRaisesRegex(Denied, '^' + vector['expect'] + '$'):
                        accept_freshness(grant, context, **args)

    def test_response_consumption_replay_and_no_receipt_extension(self):
        binding, grant, context = fixture()
        context = replace(context, now_monotonic=39,
                          freshness_challenge=replace(context.freshness_challenge, outstanding=True))
        args = dict(nonce='nonce-head', binding=binding, issued_at=100,
                    expires_at=400, signature_verified=True)
        accepted = accept_freshness(grant, context, **args)
        self.assertEqual(accepted.freshness_received_monotonic, 39)
        self.assertEqual(accepted.freshness_deadline_monotonic, 40)
        self.assertEqual(decide(grant, replace(accepted, now_monotonic=40), 'replicate'), 'stale_policy')
        with self.assertRaisesRegex(Denied, '^challenge_not_outstanding$'):
            accept_freshness(grant, accepted, **args)
        for change in ({'clock_epoch': 'boot-2'}, {'clock_certain': False},
                       {'now_monotonic': 38}, {'now': 109}):
            with self.subTest(change=change):
                self.assertNotEqual(decide(grant, replace(accepted, **change), 'replicate'), 'allow')

    def test_wrong_binding_and_missing_challenge(self):
        binding, grant, context = fixture()
        args = dict(nonce='nonce-head', binding=replace(binding, root='wrong-root'),
                    issued_at=100, expires_at=400, signature_verified=True)
        context = replace(context, freshness_challenge=replace(context.freshness_challenge, outstanding=True))
        with self.assertRaisesRegex(Denied, '^freshness_proof_required$'):
            accept_freshness(grant, context, **args)
        with self.assertRaisesRegex(Denied, '^challenge_not_outstanding$'):
            accept_freshness(grant, replace(context, freshness_challenge=None), **args)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        binding, self.grant, self.context = fixture()
        self.snapshot = Snapshot(binding, 2, 'hash-b')
        self.checkpoint = Checkpoint(binding, 1, 'hash-a')
        self.proofs = dict(signature_verified=True, ciphertext_hash_verified=True,
                           payload_scope_verified=True, current_head=(2, 'hash-b'))

    def accept(self, snapshot=None, checkpoint=None, context=None, **proofs):
        return accept_snapshot(snapshot or self.snapshot, checkpoint or self.checkpoint,
                               self.grant, context or self.context, **(self.proofs | proofs))

    def test_forward_progress_and_identical_retry(self):
        checkpoint = self.accept()
        self.assertEqual(checkpoint.sequence, 2)
        self.assertEqual(self.accept(checkpoint=checkpoint), checkpoint)
        self.assertEqual(self.checkpoint.sequence, 1)

    def test_signature_hash_scope_and_head_are_all_required(self):
        for change in ({'signature_verified': False}, {'ciphertext_hash_verified': False},
                       {'payload_scope_verified': False}, {'current_head': None},
                       {'current_head': (3, 'hash-c')}):
            with self.subTest(change=change), self.assertRaises(Denied):
                self.accept(**change)

    def test_rollback_equivocation_and_downgrade(self):
        for change in ({'sequence': 0}, {'sequence': 1, 'ciphertext_hash': 'conflicting'},
                       {'version': 'legacy-wkcs'}, {'payload_version': 0}, {'payload_version': 2}):
            snapshot = replace(self.snapshot, **change)
            with self.subTest(change=change), self.assertRaises(Denied):
                self.accept(snapshot=snapshot, current_head=(snapshot.sequence, snapshot.ciphertext_hash))

    def test_rotation_restoration_and_late_revocation_require_new_authority(self):
        for field, value in [('epoch', 2), ('root', 'new-root'), ('recipient_key', 'new-key')]:
            snapshot = replace(self.snapshot, binding=replace(self.snapshot.binding, **{field: value}))
            with self.subTest(field=field), self.assertRaises(Denied):
                self.accept(snapshot=snapshot)
        for change in ({'restored': True}, {'grant_revoked': True}, {'cancelled': True}):
            with self.subTest(change=change), self.assertRaises(Denied):
                self.accept(context=replace(self.context, **change))

    def test_denials_are_fixed_categories_without_request_material(self):
        sentinel = 'SYNTHETIC-SENSITIVE-DESCRIPTION'
        altered = replace(self.snapshot, binding=replace(self.snapshot.binding, recipient_key=sentinel))
        with self.assertRaises(Denied) as caught:
            self.accept(snapshot=altered)
        self.assertEqual(str(caught.exception), 'snapshot_binding_mismatch')
        self.assertNotIn(sentinel, str(caught.exception))


if __name__ == '__main__':
    unittest.main()
