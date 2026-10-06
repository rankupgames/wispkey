"""Adversarial package fixtures; fake Mach-O bytes are never executed."""
import importlib.util
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
try:
    SPEC = importlib.util.spec_from_file_location("macos_artifact", SCRIPTS / "macos_staging_artifact.py")
    a = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(a)
finally:
    sys.path.pop(0)
SHA = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=a.ROOT, text=True).strip()


def macho(cpu=0x0100000C, kind=2, platform=1):
    return struct.pack("<8I", 0xFEEDFACF, cpu, 0, kind, 1, 24, 0, 0) + struct.pack(
        "<6I", 0x32, 24, platform, 0, 0, 0)


def manifest(family):
    result = {
        "manifest_version": 3, "name": "WispKey local login handoff", "version": "0.4.0",
        "description": "Approve one-time login fills in a separate human-controlled browser profile.",
        "permissions": ["nativeMessaging", "activeTab", "scripting"],
        "action": {"default_popup": "popup.html", "default_title": "WispKey login requests"},
    }
    if family == "chromium":
        result.update(minimum_chrome_version="106", background={"service_worker": "background.js"})
    else:
        result.update(background={"scripts": ["flow.js", "background.js"]}, browser_specific_settings={
            "gecko": {"id": "browser-handoff@wispkey.local", "strict_min_version": "128.0",
                      "data_collection_permissions": {"required": ["none"]}}})
    return json.dumps(result).encode()


def seal(files, source=SHA):
    report = {"source_commit": source, "target": a.TARGET, "features": [],
              "cargo_lock_sha256": a.sha((a.ROOT / "Cargo.lock").read_bytes()),
              "activation": "none", "test_artifact": True,
              "files": {name: a.sha(data) for name, data in files.items() if name != "BUILD.json"}}
    files["BUILD.json"] = json.dumps(report).encode()
    return files


def payload():
    files = a.source_files()
    files.update({name: macho() for name in a.BINARIES})
    for family in ("chromium", "firefox"):
        files[f"extensions/{family}/manifest.json"] = manifest(family)
    return seal(files)


def archive(directory, files):
    path = Path(directory) / a.ARCHIVE
    with zipfile.ZipFile(path, "w") as output:
        for name, data in files.items():
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o600) << 16
            output.writestr(entry, data)
    return path


class MacosArtifactTests(unittest.TestCase):
    def test_empty_synthetic_login_inventory_is_rejected(self):
        empty = json.dumps({"project": "default", "logins": []}).encode()
        calls = []
        def probe(binary, args, env, data=b"", timeout=15):
            calls.append(args)
            code, output = 0, b"{}"
            if binary.name == "wispkey-browser-host":
                body = json.dumps({"ok": False, "error": "unlock WispKey before using browser handoff"}).encode()
                output = struct.pack("<I", len(body)) + body
            elif args == ["--version"]:
                output = b"wispkey 0.4.0\n"
            elif args in (["receiver", "start"], ["cloud", "watch", "--help"]):
                code = 2
            elif args == ["--format", "json", "login", "list"]:
                output = empty  # Both original and restored lists would be empty.
            return subprocess.CompletedProcess(args, code, output, b"")
        with patch.object(a.platform, "system", return_value="Darwin"), \
                patch.object(a.platform, "machine", return_value="arm64"), \
                patch.object(a, "verify", return_value=({}, {name: macho() for name in a.BINARIES})), \
                patch.object(a, "run", side_effect=probe), \
                self.assertRaisesRegex(ValueError, "exactly one"):
            a.smoke("not-executed.zip", SHA)
        self.assertFalse(any(args[:2] == ["backup", "create"] for args in calls))

    def test_saved_login_requires_expected_identity_and_preserves_all_metadata(self):
        login = {"id": "synthetic-login-id", "name": "staging-login", "type": "website_login",
                 "origin": "https://artifact.synthetic.invalid", "lifecycle_state": "pending",
                 "partition_id": "synthetic-partition", "created_at": "synthetic-time"}
        def encoded(rows, project="default"):
            return json.dumps({"project": project, "logins": rows}).encode()
        self.assertEqual(a.synthetic_login_metadata(encoded([login])), login)
        for rows in ([login, login], [{}], [dict(login, id="")], [dict(login, id=None)],
                     [dict(login, name="other")], [dict(login, origin="https://other.invalid")],
                     [dict(login, lifecycle_state="active")], [dict(login, type="api_key")]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                a.synthetic_login_metadata(encoded(rows))
        with self.assertRaisesRegex(ValueError, "project"):
            a.synthetic_login_metadata(encoded([login], project="other"))

    def test_valid_bundle_and_wrong_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = archive(tmp, payload())
            report, files = a.verify(path, SHA)
            self.assertEqual(report["features"], [])
            self.assertEqual(set(files), a.CONTENTS)
            with self.assertRaises(ValueError):
                a.verify(path, "b" * 40)

    def test_wrong_architecture_platform_filetype_and_truncated_commands(self):
        variants = [b"MZ", macho(cpu=0x01000007), macho(kind=1), macho(platform=2),
                    macho()[:-1], macho()[:32], b"\xca\xfe\xba\xbe" + macho()[4:]]
        malformed = bytearray(macho()); struct.pack_into("<I", malformed, 36, 0)
        variants.append(bytes(malformed))
        for data in variants:
            with self.subTest(data=data[:8]), self.assertRaises(ValueError):
                a.macho_arm64(data)

    def test_paths_duplicates_links_devices_and_size_rejected(self):
        for name in ("../escape", "/absolute", "extra.txt"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                files = payload(); files[name] = b"bad"
                with self.assertRaises(ValueError):
                    a.verify(archive(tmp, files), SHA)
        for mode in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFIFO):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                files = payload(); files.pop("wispkey")
                path = archive(tmp, files)
                with zipfile.ZipFile(path, "a") as output:
                    entry = zipfile.ZipInfo("wispkey"); entry.external_attr = (mode | 0o777) << 16
                    output.writestr(entry, b"outside")
                with self.assertRaises(ValueError):
                    a.verify(path, SHA)
        with tempfile.TemporaryDirectory() as tmp:
            path = archive(tmp, payload())
            with patch.object(a, "MAX_MEMBER", 1), self.assertRaises(ValueError):
                a.verify(path, SHA)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "a") as output:
                    output.writestr("wispkey", macho())
            with self.assertRaises(ValueError):
                a.verify(path, SHA)

    def test_rehashed_source_and_permission_changes_still_rejected(self):
        for name in ("extensions/chromium/flow.js", "scripts/install-browser-host-macos.py"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                files = payload(); files[name] = b"changed even with matching self-reported hash"
                with self.assertRaises(ValueError):
                    a.verify(archive(tmp, seal(files)), SHA)
        for field, value in (("host_permissions", ["<all_urls>"]),
                             ("permissions", ["nativeMessaging", "tabs"]),
                             ("externally_connectable", {"matches": ["https://*/*"]})):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                files = payload(); key = "extensions/chromium/manifest.json"
                data = json.loads(files[key]); data[field] = value; files[key] = json.dumps(data).encode()
                with self.assertRaises(ValueError):
                    a.verify(archive(tmp, seal(files)), SHA)

    def test_features_lockfile_and_unsealed_binary_tampering_rejected(self):
        for field, value in (("features", ["experimental-browser-receiver"]),
                             ("cargo_lock_sha256", "0" * 64), ("activation", "enabled")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                files = payload(); data = json.loads(files["BUILD.json"])
                data[field] = value; files["BUILD.json"] = json.dumps(data).encode()
                with self.assertRaises(ValueError):
                    a.verify(archive(tmp, files), SHA)
        with tempfile.TemporaryDirectory() as tmp:
            files = payload(); files["wispkey"] += b"tampered"
            with self.assertRaises(ValueError):
                a.verify(archive(tmp, files), SHA)

    def test_real_package_path_and_compiler_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"; root.mkdir()
            for name in set(a.STATIC.values()) | {"Cargo.lock"}:
                dest = root / name; dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((a.ROOT / name).read_bytes())
            for family in ("chromium", "firefox"):
                for name in a.EXTENSION_FILES:
                    dest = root / "browser-extension/dist" / family / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    data = manifest(family) if name == "manifest.json" else (a.ROOT / "browser-extension/src" / name).read_bytes()
                    dest.write_bytes(data)
                    if name != "manifest.json":
                        src = root / "browser-extension/src" / name
                        src.parent.mkdir(parents=True, exist_ok=True); src.write_bytes(data)
            git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "init.templateDir=",
                   "-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid"]
            for args in (["init", "-q"], ["add", "."], ["commit", "-qm", "synthetic source"]):
                subprocess.run([*git, *args], cwd=root, check=True, capture_output=True)
            source = subprocess.check_output([*git, "rev-parse", "HEAD"], cwd=root, text=True).strip()
            rows = []
            for name in sorted(a.BINARIES):
                binary = Path(tmp) / "target" / a.TARGET / "release" / name
                binary.parent.mkdir(parents=True, exist_ok=True); binary.write_bytes(macho())
                rows.append({"reason": "compiler-artifact", "executable": str(binary), "features": [],
                             "target": {"name": name, "kind": ["bin"]},
                             "profile": {"test": False, "opt_level": "z"}})
            log = Path(tmp) / "cargo.json"
            log.write_text("\n".join(map(json.dumps, rows)))
            output = Path(tmp) / "output"
            with patch.object(a, "ROOT", root):
                a.package(log, output, source)
                report, _ = a.verify(output / a.ARCHIVE, source)
                self.assertEqual(set(report["files"]), a.PAYLOAD)
                with self.assertRaises(FileExistsError):
                    a.package(log, output, source)
                (root / "LICENSE").write_text("changed")
                with self.assertRaisesRegex(ValueError, "clean"):
                    a.package(log, Path(tmp) / "dirty", source)
            for mutation in ("features", "profile", "kind", "target", "duplicate", "missing"):
                with self.subTest(mutation=mutation):
                    changed = json.loads(json.dumps(rows))
                    if mutation == "features": changed[0]["features"] = ["experimental-sync"]
                    if mutation == "profile": changed[0]["profile"]["test"] = True
                    if mutation == "kind": changed[0]["target"]["kind"] = ["example"]
                    if mutation == "target": changed[0]["executable"] = changed[0]["executable"].replace(a.TARGET, "x86_64-apple-darwin")
                    if mutation == "duplicate": changed.append(changed[0])
                    if mutation == "missing": changed.pop()
                    log.write_text("\n".join(map(json.dumps, changed)))
                    with self.assertRaises(ValueError):
                        a.compiler_binaries(log)

    def test_smoke_rejects_non_native_platform_before_execution(self):
        with patch.object(a.platform, "system", return_value="Linux"), self.assertRaises(ValueError):
            a.smoke("not-read.zip", SHA)

    def test_smoke_command_writes_canonical_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / a.ARCHIVE).write_bytes(b"synthetic")
            with patch.object(sys, "argv", ["artifact", "smoke", "--directory", tmp, "--commit", SHA]), \
                    patch.object(a, "smoke", return_value={"synthetic": True}):
                a.main()
            content = (root / "SHA256SUMS.txt").read_bytes()
            self.assertNotIn(b"\r", content)
            for record in content.splitlines():
                digest, name = record.decode().split("  ", 1)
                self.assertEqual(digest, a.sha((root / name).read_bytes()))


if __name__ == "__main__":
    unittest.main()
