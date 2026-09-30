"""Keep full validation on the actual merged main commit, not only the PR tree."""

from pathlib import Path
import re
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"


class CiTriggerTests(unittest.TestCase):
    def test_main_and_development_pushes_run_full_ci_without_path_filters(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        # This intentionally checks the small, explicit trigger contract rather
        # than introducing a YAML dependency into the standard-library fixtures.
        match = re.search(r"(?m)^  push:\n((?:^    .*\n|^\n)*)", workflow)
        self.assertIsNotNone(match, "Full CI must handle push events")
        trigger = match.group(1)
        branches = re.search(r"(?m)^    branches: \[([^\]]+)\]$", trigger)
        self.assertIsNotNone(branches, "Push branches must remain explicit")
        self.assertEqual(
            {name.strip() for name in branches.group(1).split(",")},
            {"main", "development"},
        )
        self.assertNotRegex(trigger, r"(?m)^    (paths|paths-ignore|tags|tags-ignore):")


if __name__ == "__main__":
    unittest.main()
