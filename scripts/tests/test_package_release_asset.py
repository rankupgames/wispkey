"""Exercise actual release containers and payloads with disposable binaries."""

from pathlib import Path
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "package-release-asset.sh"
COMMIT = "1" * 40


class ReleaseArchiveTests(unittest.TestCase):
    def package(self, directory, target, binary_name):
        root = Path(directory)
        binary = root / binary_name
        binary.write_bytes(b"synthetic binary\x00\xff")
        (root / "LICENSE").write_text("synthetic license\n")
        (root / "README.md").write_text("synthetic readme\n")
        result = subprocess.run(
            ["bash", str(SCRIPT), "--target", target, "--binary", str(binary),
             "--version", "0.4.0", "--commit", COMMIT,
             "--license", str(root / "LICENSE"), "--readme", str(root / "README.md"),
             "--out-dir", str(root / "output with spaces")],
            # macOS metadata sidecars are host-specific, not release payloads.
            env={**os.environ, "COPYFILE_DISABLE": "1"},
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return root / "output with spaces", binary.read_bytes()

    def test_windows_asset_is_a_zip_with_complete_flat_payload(self):
        with tempfile.TemporaryDirectory(prefix="release fixture ") as directory:
            output, binary = self.package(directory, "x86_64-pc-windows-msvc", "wispkey.exe")
            archive = output / "wispkey-x86_64-pc-windows-msvc.zip"
            self.assertTrue(zipfile.is_zipfile(archive), "Windows .zip must be a ZIP container")
            with zipfile.ZipFile(archive) as package:
                self.assertEqual(sorted(package.namelist()), ["LICENSE", "README.md", "VERSION", "wispkey.exe"])
                self.assertIsNone(package.testzip())
                self.assertEqual(package.read("wispkey.exe"), binary)
                self.assertEqual(package.read("LICENSE"), b"synthetic license\n")
                self.assertEqual(package.read("README.md"), b"synthetic readme\n")
                self.assertIn(f"commit: {COMMIT}\n", package.read("VERSION").decode())
                package.extractall(output / "extracted")
            self.assertEqual((output / "extracted/wispkey.exe").read_bytes(), binary)

    def test_unix_asset_remains_gzip_tar_with_executable_payload(self):
        with tempfile.TemporaryDirectory(prefix="release fixture ") as directory:
            output, binary = self.package(directory, "aarch64-apple-darwin", "wispkey")
            archive = output / "wispkey-aarch64-apple-darwin.tar.gz"
            with tarfile.open(archive, "r:gz") as package:
                self.assertEqual(sorted(package.getnames()), ["LICENSE", "README.md", "VERSION", "wispkey"])
                self.assertTrue(package.getmember("wispkey").mode & 0o111)
                self.assertEqual(package.extractfile("wispkey").read(), binary)
                self.assertIn(f"commit: {COMMIT}\n", package.extractfile("VERSION").read().decode())


if __name__ == "__main__":
    unittest.main()
