import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("promote", Path(__file__).parents[1] / "promote.py")
promote = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = promote
spec.loader.exec_module(promote)


class PromotionTests(unittest.TestCase):
    def run_chain(self, replies, dry=False):
        calls = []
        def api(path, payload=None):
            calls.append((path, payload))
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply
        steps, code = promote.reconcile("owner/repo", dry, api)
        self.assertFalse(replies)
        return steps, code, calls

    def test_identical_and_behind_are_verified_noops(self):
        steps, code, calls = self.run_chain([
            {"status": s, "ahead_by": 0} for s in ["identical", "behind", "identical"]
        ])
        self.assertEqual(code, 0)
        self.assertEqual([s.state for s in steps], ["verified no-op"] * 3)
        self.assertTrue(all(payload is None for _, payload in calls))

    def test_ahead_and_diverged_create_pr_never_direct_merge(self):
        for status in ["ahead", "diverged"]:
            steps, code, calls = self.run_chain([{"status": status, "ahead_by": 2}, [], {"number": 7}])
            self.assertEqual(code, 0)
            self.assertEqual([s.state for s in steps], ["pending PR", "skipped", "skipped"])
            self.assertEqual(calls[-1][1]["base"], "release")
            self.assertNotIn("/merges", " ".join(c[0] for c in calls))

    def test_repeated_runs_reuse_existing_pr(self):
        for _ in range(2):
            steps, code, calls = self.run_chain([{"status": "ahead", "ahead_by": 1}, [{"number": 7}]])
            self.assertEqual(code, 0)
            self.assertTrue(steps[0].detail.endswith("/7"))
            self.assertEqual(len(calls), 2)

    def test_integrated_promotion_allows_next_backmerge(self):
        steps, code, calls = self.run_chain([
            {"status": "behind", "ahead_by": 0},
            {"status": "diverged", "ahead_by": 3}, [], {"number": 8},
        ])
        self.assertEqual(code, 0)
        self.assertEqual(calls[-1][1]["base"], "main")
        self.assertEqual(steps[2].state, "skipped")

    def test_http_failures_are_nonzero_sanitized_and_stop_chain(self):
        for status in [403, 409, 422, 503]:
            response = subprocess.CompletedProcess([], 7, "", f"secret-probe (HTTP {status})")
            with patch.object(promote.subprocess, "run", return_value=response):
                steps, code = promote.reconcile("owner/repo")
            self.assertEqual(code, 7)
            self.assertEqual([s.state for s in steps], ["failed", "skipped", "skipped"])
            self.assertIn(str(status), promote.summary(steps))
            self.assertNotIn("secret-probe", promote.summary(steps))

    def test_pr_rejection_is_failure_not_already_merged(self):
        steps, code, _ = self.run_chain([
            {"status": "ahead", "ahead_by": 1}, [], promote.ApiFailure("HTTP 409", 1)
        ])
        self.assertEqual(code, 1)
        self.assertEqual(steps[0].state, "failed")

    def test_invalid_comparison_fails_closed(self):
        for value in [{"status": "behind", "ahead_by": 1}, {}, [], {"status": "ahead", "ahead_by": 0}]:
            steps, code, _ = self.run_chain([value])
            self.assertEqual(code, 1)
            self.assertEqual(steps[0].state, "failed")

    def test_dry_run_never_mutates(self):
        steps, code, calls = self.run_chain([{"status": "ahead", "ahead_by": 4}], dry=True)
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("Dry run", steps[0].detail)

    def test_transport_timeout_and_bad_json_fail(self):
        with patch.object(promote.subprocess, "run", side_effect=subprocess.TimeoutExpired("gh", 45)):
            self.assertEqual(promote.reconcile("owner/repo")[1], 1)
        with patch.object(promote.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "invalid", "")):
            self.assertEqual(promote.reconcile("owner/repo")[1], 1)


if __name__ == "__main__":
    unittest.main()
