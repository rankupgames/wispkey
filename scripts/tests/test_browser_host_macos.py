import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("installer", Path(__file__).parents[1] / "install-browser-host-macos.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


@unittest.skipUnless(os.name == "posix", "macOS per-user filesystem contract")
class NativeHostInstallerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="wispkey installer ")
        self.addCleanup(self.scratch.cleanup)
        self.home = Path(self.scratch.name)
        self.host = self.home / "host with spaces"
        self.host.write_text("synthetic executable fixture; never executed")
        self.host.chmod(0o700)

    def plan(self, browser="Chrome", extension_id="a" * 32, host=None):
        return installer.plan(browser, extension_id, host or self.host, self.home)

    def test_exact_manifest_for_each_browser_and_read_only_plan(self):
        for browser in ("Chrome", "Edge", "Firefox"):
            destination, manifest = self.plan(browser, None if browser == "Firefox" else "a" * 32)
            self.assertFalse(destination.parent.exists())
            self.assertEqual(destination.name, "com.wispkey.browser.json")
            self.assertEqual(manifest["path"], str(self.host.resolve()))
            self.assertEqual(manifest["type"], "stdio")
            self.assertEqual(manifest["name"], "com.wispkey.browser")
            if browser == "Firefox":
                self.assertEqual(manifest["allowed_extensions"], [installer.FIREFOX_ID])
                self.assertNotIn("allowed_origins", manifest)
            else:
                self.assertEqual(manifest["allowed_origins"], ["chrome-extension://" + "a" * 32 + "/"])
                self.assertNotIn("allowed_extensions", manifest)
            installer.install(destination, manifest, self.home)
            self.assertEqual(json.loads(destination.read_text()), manifest)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_malformed_or_broad_extension_ids_refused(self):
        for value in (None, "", "*", "A" * 32, "q" * 32, "a" * 31, "a" * 32 + "\n", "chrome-extension://" + "a" * 32 + "/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan(extension_id=value)
        with self.assertRaises(ValueError):
            self.plan("Firefox", "other@example.com")
        with self.assertRaises(ValueError):
            self.plan("Safari")

    def test_invalid_host_paths_refused(self):
        for path in (Path("relative"), self.home, self.home / "missing"):
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                self.plan(host=path)
        for mode in (0o600, 0o777):
            self.host.chmod(mode)
            with self.assertRaises(ValueError):
                self.plan()

    def test_existing_file_and_symlinks_never_overwritten(self):
        destination, manifest = self.plan()
        installer.install(destination, manifest, self.home)
        destination.write_text("existing registration")
        with self.assertRaises(FileExistsError):
            installer.install(destination, manifest, self.home)
        self.assertEqual(destination.read_text(), "existing registration")
        destination.unlink()
        destination.symlink_to(self.host)
        with self.assertRaises(FileExistsError):
            installer.install(destination, manifest, self.home)
        self.assertEqual(self.host.read_text(), "synthetic executable fixture; never executed")
        self.assertEqual(sorted(p.name for p in destination.parent.iterdir()), [destination.name])

    def test_redirected_or_shared_parent_refused(self):
        destination, manifest = self.plan()
        other = self.home / "other"
        other.mkdir()
        (self.home / "Library").symlink_to(other, target_is_directory=True)
        with self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)

        self.assertFalse(list(other.iterdir()))
        (self.home / "Library").unlink()
        (self.home / "Library").mkdir(mode=0o777)
        (self.home / "Library").chmod(0o777)
        with self.assertRaises(ValueError):
            installer.install(destination, manifest, self.home)

    def test_cli_defaults_to_plan_and_requires_explicit_install(self):
        arguments = ["--browser", "Firefox", "--host-path", str(self.host)]
        destination, _ = self.plan("Firefox", None)
        with patch.object(installer.sys, "platform", "darwin"), patch.object(installer.os, "geteuid", return_value=1000), patch.object(installer.Path, "home", return_value=self.home):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(installer.main(arguments), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "planned")
            self.assertFalse(destination.parent.exists())
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(installer.main([*arguments, "--install"]), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "installed")
            self.assertTrue(destination.is_file())

    def test_cli_refuses_root_and_unsupported_platform_before_writing(self):
        for platform, uid in [("linux", 1000), ("darwin", 0)]:
            with patch.object(installer.sys, "platform", platform), patch.object(installer.os, "geteuid", return_value=uid), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(installer.main(["--browser", "Firefox", "--host-path", str(self.host), "--install"]), 1)
        self.assertFalse((self.home / "Library").exists())


if __name__ == "__main__":
    unittest.main()
