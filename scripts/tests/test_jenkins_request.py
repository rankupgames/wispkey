"""The Jenkins request emitter prints only the typed dispatch fields and rejects anything else."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "ci/jenkins/request.py"
SHA = "0123456789abcdef0123456789abcdef01234567"


def emit(*args):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True, check=False)


class JenkinsRequestTests(unittest.TestCase):
    def test_valid_request_contains_only_dispatch_fields(self):
        result = emit("--lane", "browser", "--branch", "0.7", "--source-sha", SHA)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "version": 1, "repository": "https://github.com/rankupgames/wispkey.git",
            "branch": "0.7", "sourceSha": SHA, "lane": "browser",
        })

    def test_invalid_arguments_are_blocked_without_output(self):
        cases = {
            "missing lane": ("--branch", "0.7", "--source-sha", SHA),
            "unknown lane": ("--branch", "0.7", "--source-sha", SHA, "--lane", "windows"),
            "short sha": ("--branch", "0.7", "--source-sha", SHA[:39], "--lane", "rust"),
            "uppercase sha": ("--branch", "0.7", "--source-sha", SHA.upper(), "--lane", "rust"),
            "dot segment": ("--branch", "a/../b", "--source-sha", SHA, "--lane", "rust"),
            "lock suffix": ("--branch", "main.lock", "--source-sha", SHA, "--lane", "rust"),
            "duplicate flag": ("--branch", "0.7", "--branch", "main", "--lane", "rust"),
            "extra flag": ("--branch", "0.7", "--source-sha", SHA, "--lane", "rust", "--host", "x"),
            "empty branch": ("--branch", "", "--source-sha", SHA, "--lane", "rust"),
        }
        for name, args in cases.items():
            with self.subTest(name):
                result = emit(*args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(json.loads(result.stderr)["code"], "invalid_dispatch_arguments")


if __name__ == "__main__":
    unittest.main()
