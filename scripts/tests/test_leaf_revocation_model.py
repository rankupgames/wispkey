"""RUG-267 test-only candidate, assuming authenticated snapshots and authority."""
import unittest


def trust(state, revision, observed_at, now, *, floor=0, max_age=10):
    if state == "revoked":
        return "deny_revoked"
    if state != "active":
        return "deny_unknown"
    if revision < floor:
        return "deny_rollback"
    if observed_at > now or now - observed_at > max_age:
        return "deny_stale"
    return "allow"


class Ledger:
    """In-memory transaction surrogate; provides no durability/authentication."""
    def __init__(self):
        self.requests = {}
        self.revoked = set()
        self.revision = 0

    def revoke(self, request, certificate):
        if request in self.requests:
            prior_certificate, revision = self.requests[request]
            if certificate != prior_certificate:
                raise ValueError("request_conflict")
            return revision
        if certificate not in self.revoked:
            self.revoked.add(certificate)
            self.revision += 1
        self.requests[request] = (certificate, self.revision)
        return self.revision


class RevocationCandidateTests(unittest.TestCase):
    def test_state_matrix(self):
        for state, expected in [("active", "allow"), ("revoked", "deny_revoked"),
                                ("unknown", "deny_unknown"), (None, "deny_unknown")]:
            self.assertEqual(trust(state, 2, 100, 105), expected)

    def test_freshness_and_revision(self):
        self.assertEqual(trust("active", 2, 100, 110), "allow")
        self.assertEqual(trust("active", 2, 100, 111), "deny_stale")
        self.assertEqual(trust("active", 2, 106, 105), "deny_stale")
        self.assertEqual(trust("active", 2, 100, 105, floor=3), "deny_rollback")

    def test_duplicate_and_conflicting_requests(self):
        ledger = Ledger()
        self.assertEqual(ledger.revoke("request-a", "leaf-a"), 1)
        self.assertEqual(ledger.revoke("request-a", "leaf-a"), 1)
        self.assertEqual(ledger.revoke("request-b", "leaf-a"), 1)
        with self.assertRaisesRegex(ValueError, "^request_conflict$"):
            ledger.revoke("request-a", "leaf-b")
        self.assertEqual(ledger.revoked, {"leaf-a"})

    def test_cache_and_restart_recheck(self):
        self.assertEqual(trust("active", 2, 100, 105), "allow")
        self.assertEqual(trust("active", 2, 100, 111), "deny_stale")
        self.assertEqual(trust(None, 0, 0, 111), "deny_unknown")
        self.assertEqual(trust("active", 2, 110, 111, floor=3), "deny_rollback")

    def test_known_revocation_never_expires_into_allow(self):
        self.assertEqual(trust("revoked", 2, 100, 999), "deny_revoked")


if __name__ == "__main__":
    unittest.main()
