"""Guard the reviewed workflow trust/artifact contract using stdlib fixtures.

These checks cover the repository's explicit block-style YAML, not YAML syntax;
run actionlint separately when changing workflow structure or expressions.
"""

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = Path(__file__).with_name("workflow_boundaries.json")


def blocks(text, key):
    lines = text.splitlines()
    result = []
    for index, line in enumerate(lines):
        match = re.fullmatch(r"( *)" + re.escape(key) + r":(?: (.*))?", line)
        if not match:
            continue
        indent = len(match[1])
        block = [line.strip()]
        for child in lines[index + 1:]:
            if not child.strip() or child.lstrip().startswith("#"):
                continue
            if len(child) - len(child.lstrip()) <= indent:
                break
            block.append(child[indent:])
        result.append("\n".join(block))
    return result


def boundary(text):
    actions = []
    for step in re.split(r"(?m)^      - ", text)[1:]:
        match = re.search(r"(?:^|\n\s*)uses: ([^@\s]+)@", step)
        if match and match[1] in {
            "actions/checkout", "Swatinem/rust-cache",
            "actions/upload-artifact", "actions/download-artifact",
        }:
            actions.append([match[1], blocks(step, "with")])
    return {
        "events": blocks(text, "on"),
        "permissions": blocks(text, "permissions"),
        "environment": blocks(text, "env"),
        "job_gates": re.findall(r"(?m)^    (?:if|needs): .+$", text),
        "action_inputs": actions,
    }


class WorkflowBoundaryTests(unittest.TestCase):
    def test_events_permissions_secrets_and_artifact_contract(self):
        expected = json.loads(CONTRACT.read_text())
        actual = {
            path.name: boundary(path.read_text())
            for path in (ROOT / ".github/workflows").glob("*.yml")
        }
        self.assertEqual(actual, expected)

    def test_actions_are_immutable_and_untrusted_checkout_is_not_enabled(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            text = path.read_text()
            with self.subTest(workflow=path.name):
                for action in re.findall(r"(?m)^\s*(?:- )?uses: (\S+)", text):
                    self.assertRegex(action, r"^[\w./-]+@[0-9a-f]{40}$")
                self.assertNotRegex(text, r"(?m)^\s*(pull_request_target|workflow_run):")
                self.assertNotIn("allow-unsafe-pr-checkout:", text)

    def test_node_setup_does_not_add_implicit_package_caches(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        steps = [step for step in re.split(r"(?m)^      - ", text)[1:]
                 if "uses: actions/setup-node@" in step]
        self.assertEqual(len(steps), 2)
        for step in steps:
            self.assertRegex(step, r"(?m)^          package-manager-cache: false$")
            self.assertNotRegex(step, r"(?m)^          cache:")

    def test_contract_detects_privilege_and_artifact_drift(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        for before, after in [
            ("contents: read", "contents: write"),
            ("  pull_request:", "  pull_request_target:"),
            ("path: browser-extension/dist/", "path: ."),
            ("shared-key: native-tray", "shared-key: release-verify"),
        ]:
            with self.subTest(change=after):
                self.assertIn(before, text)
                self.assertNotEqual(boundary(text), boundary(text.replace(before, after)))
