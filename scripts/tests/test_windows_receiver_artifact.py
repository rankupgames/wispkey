"""Adversarial archive/compiler metadata fixtures; no Rust build or installation."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

SPEC = importlib.util.spec_from_file_location("artifact", Path(__file__).parents[1] / "windows_receiver_artifact.py")
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)
SHA = "a" * 40


def pe():
    data = bytearray(160)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, 0x8664)
    struct.pack_into("<H", data, 88, 0x20B)
    return bytes(data) + b"Receiver transport binding:"


def payload():
    files = {name: b"synthetic fixture" for name in a.PAYLOAD}
    for name in a.BINARIES:
        files[name] = pe()
    files["VERSION"] = f"commit: {SHA}\n".encode()
    report = {"source_commit": SHA, "target": a.TARGET, "features": a.FEATURES,
              "cargo_lock_sha256": a.sha((a.ROOT / "Cargo.lock").read_bytes()),
              "activation": "none", "test_artifact": True,
              "files": {name: a.sha(data) for name, data in files.items()}}
    files["BUILD.json"] = json.dumps(report).encode()
    return files


class WindowsReceiverArtifactTests(unittest.TestCase):
    def test_smoke_command_writes_lf_checksum_subject_names(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            (directory / a.ARCHIVE).write_bytes(b"synthetic archive")
            argv = ["artifact", "smoke", "--directory", root, "--extracted", root, "--commit", SHA]
            with patch.object(sys, "argv", argv), patch.object(a, "smoke", return_value={"synthetic": True}):
                a.main()
            content = (directory / "SHA256SUMS.txt").read_bytes()
            self.assertNotIn(b"\r", content)
            lines = content.split(b"\n")
            self.assertEqual(lines[-1], b"")
            self.assertEqual([line[66:] for line in lines[:-1]], [a.ARCHIVE.encode(), b"smoke-report.json"])
            for line in lines[:-1]:
                self.assertEqual(line[:64].decode(), a.sha((directory / line[66:].decode()).read_bytes()))

    def test_checksum_lf_crlf_preserve_exact_filename_bytes(self):
        names = [b"package.zip", b"name with spaces.zip", b" leading and trailing .zip "]
        lines = [b"a" * 64 + b"  " + name for name in names]
        expected = b"\n".join(lines) + b"\n"
        for endings in ((b"\n",) * 3, (b"\r\n",) * 3, (b"\r\n", b"\n", b"\r\n")):
            with self.subTest(endings=endings), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "SHA256SUMS.txt"
                a.write_checksum_manifest(path, b"".join(line + end for line, end in zip(lines, endings)))
                self.assertEqual(path.read_bytes(), expected)
                self.assertEqual([line[66:] for line in path.read_bytes().split(b"\n")[:-1]], names)

    def test_invalid_checksum_records_do_not_rewrite_manifest(self):
        good = b"a" * 64 + b"  package.zip\n"
        invalid = [b"", good[:-1], good.replace(b"\n", b"\r"), good.replace(b"\n", b"\r\r\n"), good + b"\n",
                   b"a" * 64 + b" package.zip\n", b"a" * 64 + b"  \n",
                   good.replace(b"package", b"bad\rname"), good.replace(b"package", b"bad\x00name")]
        for content in invalid:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as root:
                path = Path(root) / "SHA256SUMS.txt"
                path.write_bytes(good)
                with self.assertRaises(ValueError):
                    a.write_checksum_manifest(path, content)
                self.assertEqual(path.read_bytes(), good)

    def archive(self, root, files):
        path = Path(root) / a.ARCHIVE
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return path

    def test_exact_inventory_hashes_and_receiver_features(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.archive(root, payload())
            report = a.verify(path, SHA)
            self.assertEqual(report["features"], ["experimental-browser-receiver"])
            self.assertEqual(set(report["files"]), a.CONTENTS - {"BUILD.json"})
            with self.assertRaises(ValueError):
                a.verify(path, "b" * 40)

    def test_traversal_duplicate_symlink_and_extra_entries_rejected(self):
        for name in ("../escape.exe", "/absolute", "unexpected.txt"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                files = payload(); files[name] = b"bad"
                with self.assertRaises(ValueError):
                    a.verify(self.archive(root, files), SHA)
        with tempfile.TemporaryDirectory() as root:
            path = self.archive(root, payload())
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "a") as archive:
                    archive.writestr("wispkey.exe", pe())
            with self.assertRaises(ValueError):
                a.verify(path, SHA)
        with tempfile.TemporaryDirectory() as root:
            files = payload(); files.pop("wispkey.exe")
            path = self.archive(root, files)
            with zipfile.ZipFile(path, "a") as archive:
                link = zipfile.ZipInfo("wispkey.exe"); link.create_system = 3; link.external_attr = 0o120777 << 16
                archive.writestr(link, b"outside")
            with self.assertRaises(ValueError):
                a.verify(path, SHA)

    def test_tampering_lockfile_missing_feature_and_non_x64_rejected(self):
        for mutation in ("hash", "feature", "lock", "architecture", "marker"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                files = payload()
                if mutation in ("feature", "lock"):
                    report = json.loads(files["BUILD.json"])
                    report["features" if mutation == "feature" else "cargo_lock_sha256"] = [] if mutation == "feature" else "0" * 64
                    files["BUILD.json"] = json.dumps(report).encode()
                elif mutation == "architecture":
                    data = bytearray(files["wispkey.exe"]); struct.pack_into("<H", data, 68, 0xAA64)
                    files["wispkey.exe"] = bytes(data)
                elif mutation == "marker":
                    files["wispkey-browser-host.exe"] = pe()[:160]
                else:
                    files["extensions/chromium/flow.js"] = b"changed"
                with self.assertRaises(ValueError):
                    a.verify(self.archive(root, files), SHA)

    def test_expanded_size_bound_checked_before_reading_payload(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.archive(root, payload())
            with patch.object(a, "MAX_MEMBER", 1), self.assertRaises(ValueError):
                a.verify(path, SHA)

    def test_compiler_reports_require_both_enabled_release_binaries(self):
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "cargo.json"
            rows = [{"reason": "compiler-artifact", "executable": str(Path(root) / a.TARGET / "release" / name),
                     "features": a.FEATURES, "profile": {"test": False, "opt_level": "z"}} for name in sorted(a.BINARIES)]
            log.write_text("\n".join(map(json.dumps, rows)))
            self.assertEqual(set(a.compiler_binaries(log)), a.BINARIES)
            rows[0]["features"] = []
            log.write_text("\n".join(map(json.dumps, rows)))
            with self.assertRaises(ValueError):
                a.compiler_binaries(log)
            log.write_text(json.dumps(rows[1]))
            with self.assertRaises(ValueError):
                a.compiler_binaries(log)

    def test_subprocess_capture_and_deadline_are_bounded(self):
        for code in ("import time;time.sleep(30)", "import sys;sys.stdout.write('x'*1000000)",
                     "import sys;sys.stderr.write('x'*1000000)"):
            with self.subTest(code=code), self.assertRaises(ValueError):
                a.run(Path(sys.executable), ["-c", code], os.environ.copy(), timeout=0.2)


if __name__ == "__main__":
    unittest.main()
