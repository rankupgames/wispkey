import copy
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("audit_dependencies", Path(__file__).parents[1] / "audit_dependencies.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

EMPTY = {"vulnerabilities": {"found": False, "count": 0, "list": []}, "warnings": {}}
FINDING = {
    "package": {"name": "synthetic-crate", "version": "1.0.0", "source": "secret-source-probe"},
    "advisory": {"id": "RUSTSEC-2000-0001", "description": "secret-description-probe"},
    "versions": {"patched": [">=1.0.1"]},
}


class AuditTests(unittest.TestCase):
    def test_clean_and_warning_only_are_distinct(self):
        report = copy.deepcopy(EMPTY)
        text, code = audit.summarize(report, 0)
        self.assertEqual(code, 0)
        self.assertIn("Blocking advisories: 0", text)
        report["warnings"] = {"unmaintained": [{"package": FINDING["package"]}]}
        text, code = audit.summarize(report, 0)
        self.assertEqual(code, 0)
        self.assertIn("unmaintained: synthetic-crate", text)
        self.assertNotIn("secret-source-probe", text)

    def test_findings_fail_even_if_tool_reports_success(self):
        report = copy.deepcopy(EMPTY)
        report["vulnerabilities"] = {"found": True, "count": 1, "list": [FINDING]}
        for status in [0, 1]:
            text, code = audit.summarize(report, status)
            self.assertEqual(code, 1)
            self.assertIn("RUSTSEC-2000-0001", text)
            self.assertIn(">=1.0.1", text)
            self.assertNotIn("secret-", text)

    def test_unpatched_advisory_has_action(self):
        entry = copy.deepcopy(FINDING)
        entry["versions"]["patched"] = []
        text, code = audit.summarize({"vulnerabilities": {"found": True, "count": 1, "list": [entry]}, "warnings": {}}, 1)
        self.assertIn("replace/remove", text)
        self.assertEqual(code, 1)

    def test_tool_failure_never_becomes_clean(self):
        text, code = audit.summarize(EMPTY, 7)
        self.assertEqual(code, 7)
        self.assertIn("not a clean audit", text)

    def test_missing_invalid_or_inconsistent_json_fails_closed(self):
        for body in ["not-json", "{}", '{"vulnerabilities":null}', json.dumps({**EMPTY, "vulnerabilities": {"found": True, "count": 1, "list": []}})]:
            with patch.object(audit.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, body, "secret-stderr-probe")):
                text, code = audit.run("Cargo.lock")
            self.assertEqual(code, 2)
            self.assertNotIn("secret-stderr-probe", text)

    def test_timeout_is_bounded_and_safe(self):
        with patch.object(audit.subprocess, "run", side_effect=subprocess.TimeoutExpired("cargo", 300)):
            self.assertEqual(audit.run("Cargo.lock")[1], 2)

    def test_invocation_uses_fresh_database_and_no_ignore(self):
        with patch.object(audit.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(EMPTY), "")) as run:
            self.assertEqual(audit.run("Cargo.lock")[1], 0)
            first = run.call_args
            self.assertEqual(audit.run("Cargo.lock")[1], 0)
            second = run.call_args
        self.assertNotEqual(first.kwargs["cwd"], second.kwargs["cwd"])
        self.assertIn("--db", first.args[0])
        self.assertNotIn("--ignore", first.args[0])
        self.assertNotIn("--no-fetch", first.args[0])


if __name__ == "__main__":
    unittest.main()
