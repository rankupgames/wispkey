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
offline_spec = importlib.util.spec_from_file_location("offline", Path(__file__).parents[1] / "verify_personal_offline.py")
offline = importlib.util.module_from_spec(offline_spec)
offline_spec.loader.exec_module(offline)


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

    def test_offline_trace_accepts_only_decoded_loopback_connections_and_connected_writes(self):
        trace = '\n'.join([
            'connect(3, {sa_family=AF_INET, sin_port=htons(7700), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS',
            'bind(4, {sa_family=AF_INET6, inet_pton(AF_INET6, "::1", &sin6_addr)}, 28) = 0',
            'sendto(0x3, 0xabc, 0x20, 0x4000, 0, 0) = 0x20',
        ])
        self.assertEqual(offline.inspect_trace(trace), 1)

    def test_offline_trace_rejects_failed_external_unix_and_unknown_egress(self):
        for trace in [
            'connect(3, {sa_family=AF_INET, sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH',
            'connect(3, {sa_family=AF_INET6, inet_pton(AF_INET6, "2001:db8::1", &sin6_addr)}, 28) = -1 ENETUNREACH',
            'connect(3, {sa_family=AF_UNIX, sun_path=""...}, 110) = -1 ENOENT',
            'connect(3, 0xabc, 16) = -1 EFAULT',
            'sendto(0x3, 0xabc, 0x20, 0, 0xdef, 0x10) = -1 ENETUNREACH',
            'sendmsg(0x3, 0xabc, 0) = -1 ENETUNREACH',
            'sendmmsg(0x3, 0xabc, 0x1, 0) = -1 ENETUNREACH',
        ]:
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                offline.inspect_trace(trace)

    def test_cargo_tests_get_a_temporary_vault_removed_even_on_failure(self):
        paths = []
        def execute(argv, **kwargs):
            vault = Path(kwargs["env"]["WISPKEY_VAULT_PATH"])
            self.assertTrue(vault.is_dir())
            (vault / "cloud.json").write_text("synthetic test configuration")
            paths.append(vault)
            return subprocess.CompletedProcess(argv, 1)
        code, _ = self.run_quietly(["cli"], {"cli": [(Path.cwd(), ["cargo", "test", "--locked"])]},
                                  execute=execute, find=lambda name: name)
        self.assertEqual(code, 1)
        self.assertEqual(len(paths), 1)
        self.assertFalse(paths[0].exists())


if __name__ == "__main__":
    unittest.main()
