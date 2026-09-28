import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("verify", Path(__file__).parents[1] / "verify.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerifyTests(unittest.TestCase):
    def run_quietly(self, *args, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            result = verify.run(*args, **kwargs)
        return result, output.getvalue()

    def test_failure_stops_dependent_steps_but_runs_other_suites(self):
        calls = []
        def execute(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 9 if argv[0] == "bad" else 0)
        code, output = self.run_quietly(["first", "second"], {
            "first": [(Path.cwd(), ["bad"]), (Path.cwd(), ["must-not-run"])],
            "second": [(Path.cwd(), ["good"])],
        }, execute=execute, find=lambda name: name)
        self.assertEqual(code, 1)
        self.assertEqual(calls, [["bad"], ["good"]])
        self.assertNotIn("[first] PASSED", output)
        self.assertIn("[second] PASSED", output)

    def test_missing_tool_and_start_failure_are_failures(self):
        catalog = {"suite": [(Path.cwd(), ["unavailable"])]}
        def fail(*args, **kwargs):
            raise OSError("synthetic launch error")
        for kwargs in ({"find": lambda name: None}, {"find": lambda name: name, "execute": fail}):
            code, output = self.run_quietly(["suite"], catalog, **kwargs)
            self.assertEqual(code, 1)
            self.assertNotIn("PASSED", output)

    def test_dry_run_does_not_execute_or_claim_success(self):
        def forbidden(*args, **kwargs):
            self.fail("dry run attempted execution or lookup")
        code, output = self.run_quietly(["suite", "suite"], {"suite": [(Path.cwd(), ["command"])]},
                                      dry_run=True, execute=forbidden, find=forbidden)
        self.assertEqual(code, 0)
        self.assertEqual(output.count("PLANNED"), 1)
        self.assertNotIn("PASSED", output)

    def test_real_subprocess_uses_exact_working_directory_and_exit_status(self):
        with tempfile.TemporaryDirectory(prefix="wispkey runner ") as root:
            path = Path(root)
            script = path / "fixture.py"
            script.write_text("from pathlib import Path\nimport sys\nPath('ran.txt').write_text(sys.argv[1])\nsys.exit(7)\n")
            code, _ = self.run_quietly(["fixture"], {"fixture": [(path, [sys.executable, str(script), "literal spaces & symbols"])]})
            self.assertEqual(code, 1)
            self.assertEqual((path / "ran.txt").read_text(), "literal spaces & symbols")


if __name__ == "__main__":
    unittest.main()
