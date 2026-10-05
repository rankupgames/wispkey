"""Package and validate a default-off Apple Silicon staging bundle; stdlib only."""
import argparse
import json
from pathlib import Path
import platform
import stat
import struct
import subprocess
import tempfile
import zipfile

# Reuse the existing bounded child runner and canonical checksum writer.
from windows_receiver_artifact import commit, run, sha, write_checksum_manifest

ROOT = Path(__file__).resolve().parents[1]
TARGET = "aarch64-apple-darwin"
ARCHIVE = "wispkey-macos-arm64-staging.zip"
BINARIES = {"wispkey", "wispkey-browser-host"}
STATIC = {
    "LICENSE": "LICENSE",
    "README.md": "docs/macos-staging-artifact.md",
    "docs/browser-handoff.md": "docs/browser-handoff.md",
    "docs/macos-browser-approval.md": "docs/macos-browser-approval.md",
    "scripts/install-browser-host-macos.py": "scripts/install-browser-host-macos.py",
}
EXTENSION_FILES = {"background.js", "flow.js", "popup.js", "popup.html", "popup.css", "manifest.json"}
PAYLOAD = BINARIES | set(STATIC) | {
    f"extensions/{family}/{name}" for family in ("chromium", "firefox") for name in EXTENSION_FILES
}
CONTENTS = PAYLOAD | {"BUILD.json"}
MAX_ARCHIVE = 150 * 1024 * 1024
MAX_MEMBER = 100 * 1024 * 1024


def macho_arm64(data):
    """Require a thin ARM64 macOS executable, not an iOS/fat/object file."""
    if len(data) < 32:
        raise ValueError("truncated Mach-O")
    magic, cpu, _, kind, count, size, _, _ = struct.unpack_from("<8I", data)
    if (magic, cpu, kind) != (0xFEEDFACF, 0x0100000C, 2) or size > len(data) - 32:
        raise ValueError("not an Apple Silicon Mach-O executable")
    offset, macos = 32, False
    for _ in range(count):
        if offset + 8 > 32 + size:
            raise ValueError("truncated load command")
        command, length = struct.unpack_from("<2I", data, offset)
        if length < 8 or length % 8 or offset + length > 32 + size:
            raise ValueError("invalid load command")
        if command == 0x32:  # LC_BUILD_VERSION
            if length < 24 or struct.unpack_from("<I", data, offset + 8)[0] != 1:
                raise ValueError("non-macOS build platform")
            macos = True
        offset += length
    if offset != 32 + size or not macos:
        raise ValueError("missing macOS build platform")


def compiler_binaries(log):
    records = {}
    for line in Path(log).read_text().splitlines():
        row = json.loads(line)
        if row.get("reason") != "compiler-artifact" or not row.get("executable"):
            continue
        path = Path(row["executable"])
        if path.name not in BINARIES:
            continue
        target = row.get("target", {})
        if (row.get("features") != [] or row["profile"]["test"]
                or str(row["profile"]["opt_level"]) != "z"
                or target.get("name") != path.name or target.get("kind") != ["bin"]
                or path.parent.parts[-2:] != (TARGET, "release") or path.is_symlink()):
            raise ValueError("wrong compiler target/features/profile")
        if path.name in records:
            raise ValueError("duplicate compiler executable")
        records[path.name] = path
    if set(records) != BINARIES:
        raise ValueError("missing CLI or native host compiler record")
    return records


def source_files():
    files = {name: (ROOT / relative).read_bytes() for name, relative in STATIC.items()}
    for family in ("chromium", "firefox"):
        for name in EXTENSION_FILES - {"manifest.json"}:
            files[f"extensions/{family}/{name}"] = (ROOT / "browser-extension/src" / name).read_bytes()
    return files


def validate_manifest(data, family):
    manifest = json.loads(data)
    expected = {
        "manifest_version": 3, "name": "WispKey local login handoff", "version": "0.4.0",
        "description": "Approve one-time login fills in a separate human-controlled browser profile.",
        "permissions": ["nativeMessaging", "activeTab", "scripting"],
        "action": {"default_popup": "popup.html", "default_title": "WispKey login requests"},
    }
    if family == "chromium":
        expected.update(minimum_chrome_version="106", background={"service_worker": "background.js"})
    else:
        expected.update(background={"scripts": ["flow.js", "background.js"]}, browser_specific_settings={
            "gecko": {"id": "browser-handoff@wispkey.local", "strict_min_version": "128.0",
                      "data_collection_permissions": {"required": ["none"]}}})
    if manifest != expected:
        raise ValueError("extension manifest changed; review permissions and package contract")


def package(log, directory, source):
    source = commit(source)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != source:
        raise ValueError("checkout does not match source commit")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT):
        raise ValueError("tracked source must be clean")
    files = source_files()
    files.update({name: path.read_bytes() for name, path in compiler_binaries(log).items()})
    for family in ("chromium", "firefox"):
        for name in EXTENSION_FILES:
            data = (ROOT / "browser-extension/dist" / family / name).read_bytes()
            key = f"extensions/{family}/{name}"
            if key in files and files[key] != data:
                raise ValueError("built extension differs from source")
            files[key] = data
    report = {"source_commit": source, "target": TARGET, "features": [],
              "cargo_lock_sha256": sha((ROOT / "Cargo.lock").read_bytes()),
              "activation": "none", "test_artifact": True,
              "files": {name: sha(data) for name, data in sorted(files.items())}}
    files["BUILD.json"] = (json.dumps(report, indent=2) + "\n").encode()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(directory / ARCHIVE, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | (0o700 if name in BINARIES else 0o600)) << 16
            archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED)
    verify(directory / ARCHIVE, source)


def verify(path, source):
    source = commit(source)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != source:
        raise ValueError("verification requires the matching source checkout")
    path = Path(path)
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("archive exceeds bound")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) != len(CONTENTS) or {m.filename for m in members} != CONTENTS:
            raise ValueError("unexpected/duplicate archive paths")
        if any(m.file_size > MAX_MEMBER or m.is_dir() or not stat.S_ISREG(m.external_attr >> 16)
               or m.flag_bits & 1 for m in members):
            raise ValueError("unsupported archive entry")
        if sum(m.file_size for m in members) > MAX_ARCHIVE:
            raise ValueError("expanded archive exceeds bound")
        files = {m.filename: archive.read(m) for m in members}
    for name in BINARIES:
        macho_arm64(files[name])
    for family in ("chromium", "firefox"):
        validate_manifest(files[f"extensions/{family}/manifest.json"], family)
    for name, data in source_files().items():
        if files[name] != data:
            raise ValueError("packaged source file mismatch")
    report = json.loads(files["BUILD.json"])
    expected = {"source_commit": source, "target": TARGET, "features": [],
                "cargo_lock_sha256": sha((ROOT / "Cargo.lock").read_bytes()),
                "activation": "none", "test_artifact": True,
                "files": {name: sha(data) for name, data in files.items() if name != "BUILD.json"}}
    if report != expected:
        raise ValueError("source/target/features or contained-file hash mismatch")
    return report, files


def synthetic_login_metadata(output):
    """Require the saved fixture, so two empty inventories cannot pass restore."""
    data = json.loads(output)
    if not isinstance(data, dict) or data.get("project") != "default":
        raise ValueError("synthetic login inventory has wrong project")
    logins = data.get("logins")
    if not isinstance(logins, list) or len(logins) != 1:
        raise ValueError("expected exactly one saved synthetic login")
    login = logins[0]
    expected = {"name": "staging-login", "type": "website_login",
                "origin": "https://artifact.synthetic.invalid", "lifecycle_state": "pending"}
    if (not isinstance(login, dict) or not isinstance(login.get("id"), str) or not login["id"]
            or any(login.get(key) != value for key, value in expected.items())):
        raise ValueError("saved synthetic login identity or metadata differs")
    return login


def smoke(path, source):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("native Apple Silicon smoke required")
    report, files = verify(path, source)
    with tempfile.TemporaryDirectory(prefix="wispkey-macos-staging-") as tmp:
        root = Path(tmp)
        # Never extract a caller-selected path or inherit a live HOME/credential environment.
        for name, data in files.items():
            target = root / "bundle" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o700 if name in BINARIES else 0o600)
            if target.read_bytes() != data:
                raise ValueError("extracted file mismatch")
        env = {"HOME": str(root / "home"), "PATH": "/usr/bin:/bin", "TMPDIR": tmp,
               "WISPKEY_VAULT_PATH": str(root / "vault"), "WISPKEY_PROTECTOR": "file"}
        Path(env["HOME"]).mkdir()
        cli = root / "bundle/wispkey"

        def command(args, expected=0, child_env=None, data=b""):
            response = run(cli, args, child_env or env, data=data, timeout=30)
            if response.returncode != expected:
                raise ValueError("synthetic CLI probe failed")
            return response.stdout

        version = json.loads((ROOT / "browser-extension/package.json").read_text())["version"]
        if command(["--version"]).strip() != f"wispkey {version}".encode():
            raise ValueError("unexpected CLI version")
        for args in (["signup-profile", "--help"], ["login", "add-existing", "--help"],
                     ["cloud", "resolve", "--help"]):
            command(args)
        command(["receiver", "start"], expected=2)
        command(["cloud", "watch", "--help"], expected=2)
        body = b'{"method":"pending","origin":"https://artifact.synthetic.invalid"}'
        response = run(root / "bundle/wispkey-browser-host", [], env, struct.pack("<I", len(body)) + body)
        expected = {"ok": False, "error": "unlock WispKey before using browser handoff"}
        if (response.returncode or response.stderr or len(response.stdout) < 4
                or struct.unpack("<I", response.stdout[:4])[0] != len(response.stdout) - 4
                or json.loads(response.stdout[4:]) != expected):
            raise ValueError("unconfigured native admission was not denied")
        if Path(env["WISPKEY_VAULT_PATH"]).exists():
            raise ValueError("metadata probes created a vault")
        env.update(WISPKEY_PASSWORD="synthetic-staging-master-only",
                   WISPKEY_BUNDLE_PASSPHRASE="synthetic-staging-bundle-only")
        command(["init"])
        generated = command(["--format", "json", "login", "generate", "staging-login",
                             "--username", "staging@example.invalid", "--url", "https://artifact.synthetic.invalid"])
        if b"staging@example.invalid" in generated or b'"password"' in generated:
            raise ValueError("login generation disclosed identity or password")
        original_login = synthetic_login_metadata(command(["--format", "json", "login", "list"]))
        backup = root / "synthetic.wkbackup"
        command(["backup", "create", "--output", str(backup)])
        command(["backup", "verify", str(backup)])
        wrong = dict(env, WISPKEY_BUNDLE_PASSPHRASE="wrong-synthetic-passphrase")
        command(["backup", "verify", str(backup)], expected=1, child_env=wrong)
        restored = root / "restored"
        command(["backup", "restore", str(backup), "--target", str(restored)])
        restored_env = dict(env, WISPKEY_VAULT_PATH=str(restored))
        command(["unlock"], child_env=restored_env)
        restored_login = synthetic_login_metadata(command(
            ["--format", "json", "login", "list"], child_env=restored_env))
        if original_login != restored_login:
            raise ValueError("restored synthetic login metadata differs")
    return {"source_commit": report["source_commit"], "target": TARGET, "features": [],
            "archive_sha256": sha(Path(path).read_bytes()),
            "checks": ["bounded_inventory_and_source_hashes", "arm64_macos_executables", "extracted_hashes",
                       "cli_version_and_safe_input_help", "no_receiver_or_watch_command", "native_locked_denial",
                       "no_vault_created_by_metadata_probes", "synthetic_login_identity_redaction",
                       "saved_synthetic_login_identity_and_metadata_restored",
                       "encrypted_backup_restore", "wrong_passphrase_denied", "scratch_removed"],
            "installation_performed": False, "native_presence_tested": False, "cloud_contacted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["package", "verify", "smoke"])
    parser.add_argument("--commit", required=True, type=commit)
    parser.add_argument("--cargo-log")
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    path = args.directory / ARCHIVE
    if args.operation == "package":
        package(args.cargo_log, args.directory, args.commit)
    elif args.operation == "verify":
        verify(path, args.commit)
    else:
        report = smoke(path, args.commit)
        (args.directory / "smoke-report.json").write_text(json.dumps(report, indent=2) + "\n")
        names = [ARCHIVE, "smoke-report.json"]
        records = "".join(f"{sha((args.directory / n).read_bytes())}  {n}\n" for n in names)
        write_checksum_manifest(args.directory / "SHA256SUMS.txt", records.encode())


if __name__ == "__main__":
    main()
