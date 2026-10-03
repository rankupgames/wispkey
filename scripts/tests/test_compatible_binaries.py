import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("compatible", Path(__file__).parents[1] / "inspect_compatible_binaries.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VersionRequirements(unittest.TestCase):
    def test_only_runtime_needs_are_checked(self):
        text = """Version definition section '.gnu.version_d' contains 1 entry:
  Name: GLIBC_2.99
Version needs section '.gnu.version_r' contains 2 entries:
  Name: GLIBC_2.2.5 Flags: none Version: 3
  Name: GLIBC_2.36 Flags: none Version: 4
"""
        self.assertEqual(MODULE.requirements(text), ["GLIBC_2.2.5", "GLIBC_2.36"])

    def test_newer_private_and_missing_requirements_fail_closed(self):
        for name in ["GLIBC_2.38", "GLIBC_2.39", "GLIBC_PRIVATE", "GLIBC_2.36.1", ""]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                MODULE.requirements("Version needs section '.gnu.version_r':\n  Name: " + name)


@unittest.skipUnless(os.name == "posix", "fixture pipe polling requires Unix")
class ArtifactProtocol(unittest.TestCase):
    def test_delivery_keeps_channel_open_until_completion(self):
        spec = importlib.util.spec_from_file_location("artifact_fixture", Path(__file__).parents[2] / "tests/support/compatible_artifact_fixture.py")
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        with tempfile.TemporaryDirectory() as directory:
            peer = Path(directory) / "peer.py"
            peer.write_text('''import json,select,sys
hello=json.loads(sys.stdin.buffer.readline())
print(json.dumps({"version":1,"attempt_id":hello["attempt_id"],"phase":"ready"}),flush=True)
delivery=json.loads(sys.stdin.buffer.readline())
premature_eof=bool(select.select([sys.stdin.buffer],[],[],0.05)[0])
print(json.dumps({"outcome":"premature-eof" if premature_eof else "succeeded"}),flush=True)
''')
            ready, result = fixture.exchange([sys.executable, "-u", str(peer)], "synthetic-attempt", "deliver")
            self.assertTrue(ready)
            self.assertEqual(result, [{"outcome": "succeeded"}])


if __name__ == "__main__":
    unittest.main()
