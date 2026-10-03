import importlib.util
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
