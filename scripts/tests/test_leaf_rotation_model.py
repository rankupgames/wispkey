"""RUG-296 ordering simulation only; no real issuance or security authority."""
import copy
import unittest


class Rotation:
    def __init__(self, *, eligible=True):
        self.binding = ("synthetic-owner", "synthetic-context")
        self.state = "prepared" if eligible else "ineligible"
        self.successor = None
        self.predecessor_retired = False
        self.issues = 0

    def issue(self, succeeds=True):
        if self.state != "prepared":
            return
        if succeeds:
            self.successor = "synthetic-successor"
            self.issues += 1
            self.state = "issued"

    def activate(self, binding, *, verified=False):
        if self.state == "issued" and verified and binding == self.binding:
            self.state = "activated"

    def retire(self, *, acknowledged=False):
        if self.state not in ("activated", "retirement_pending"):
            return
        self.state = "retirement_pending"
        if acknowledged:
            self.predecessor_retired = True
            self.state = "complete"


class RotationOrderingTests(unittest.TestCase):
    def test_ineligible_and_issuance_failure(self):
        r = Rotation(eligible=False)
        r.issue()
        self.assertIsNone(r.successor)
        r = Rotation()
        r.issue(False)
        self.assertEqual(r.state, "prepared")
        self.assertFalse(r.predecessor_retired)

    def test_cannot_retire_before_verified_activation(self):
        r = Rotation()
        r.retire(acknowledged=True)
        r.issue()
        r.activate(r.binding)
        r.retire(acknowledged=True)
        self.assertEqual(r.state, "issued")
        self.assertFalse(r.predecessor_retired)

    def test_binding_mismatch_cannot_activate(self):
        r = Rotation()
        r.issue()
        for binding in [("other", r.binding[1]), (r.binding[0], "other")]:
            r.activate(binding, verified=True)
            self.assertEqual(r.state, "issued")

    def test_retirement_failure_is_explicit(self):
        r = Rotation()
        r.issue()
        r.activate(r.binding, verified=True)
        r.retire()
        self.assertEqual(r.state, "retirement_pending")
        self.assertFalse(r.predecessor_retired)
        r.retire(acknowledged=True)
        self.assertEqual(r.state, "complete")

    def test_repeats_and_reconstructed_state(self):
        r = Rotation()
        r.issue()
        r = copy.deepcopy(r)  # State-copy surrogate, not a durable crash test.
        r.issue()
        self.assertEqual(r.issues, 1)
        r.activate(r.binding, verified=True)
        r = copy.deepcopy(r)
        r.retire(acknowledged=True)
        r.retire(acknowledged=True)
        self.assertEqual(r.state, "complete")
        self.assertEqual(r.binding, ("synthetic-owner", "synthetic-context"))


if __name__ == "__main__":
    unittest.main()
