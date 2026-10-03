"""Build/verify/smoke the bounded Windows receiver staging bundle; stdlib only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-pc-windows-msvc"
FEATURES = ["experimental-browser-receiver"]
ARCHIVE = "wispkey-windows-x64-receiver-test.zip"
BINARIES = {"wispkey.exe", "wispkey-browser-host.exe"}
EXTENSION_FILES = {"background.js", "flow.js", "popup.js", "popup.html", "popup.css", "manifest.json"}
STATIC = {
    "LICENSE": "LICENSE",
    "README.md": "docs/windows-receiver-test-artifact.md",
    "docs/browser-handoff.md": "docs/browser-handoff.md",
    "docs/browser-receiver.md": "docs/browser-receiver.md",
    "scripts/install-browser-host.ps1": "scripts/install-browser-host.ps1",
}
PAYLOAD = BINARIES | set(STATIC) | {
    f"extensions/{family}/{name}" for family in ("chromium", "firefox") for name in EXTENSION_FILES
}
CONTENTS = PAYLOAD | {"BUILD.json", "VERSION"}
MAX_ARCHIVE = 150 * 1024 * 1024
MAX_MEMBER = 100 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def commit(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("invalid source commit")
    return value


def pe_x64(data):
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not a PE executable")
    offset = struct.unpack_from("<I", data, 60)[0]
    if offset + 26 > len(data) or data[offset:offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    if struct.unpack_from("<H", data, offset + 4)[0] != 0x8664 or struct.unpack_from("<H", data, offset + 24)[0] != 0x20B:
        raise ValueError("not a Windows x64 PE32+ executable")


def compiler_binaries(log):
    records = {}
    for line in Path(log).read_text(encoding="utf-8-sig").splitlines():
        row = json.loads(line)
        if row.get("reason") != "compiler-artifact" or not row.get("executable"):
            continue
        path = Path(row["executable"])
        if path.name not in BINARIES:
            continue
        if sorted(row["features"]) != FEATURES or row["profile"]["test"] or str(row["profile"]["opt_level"]) != "z":
            raise ValueError("wrong executable compiler features/profile")
        if TARGET not in path.parts:
            raise ValueError("wrong compiler target path")
        if path.name in records:
            raise ValueError("duplicate compiler executable")
        records[path.name] = path
    if set(records) != BINARIES:
        raise ValueError("missing receiver-enabled compiler executable")
    return records


def package(log, output, source):
    source = commit(source)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if actual != source:
        raise ValueError("checkout does not match source commit")
    files = {name: path.read_bytes() for name, path in compiler_binaries(log).items()}
    if b"Receiver transport binding:" not in files["wispkey-browser-host.exe"]:
        raise ValueError("receiver-enabled native host marker absent")
    for name, relative in STATIC.items():
        files[name] = (ROOT / relative).read_bytes()
    for family in ("chromium", "firefox"):
        for name in EXTENSION_FILES:
            files[f"extensions/{family}/{name}"] = (ROOT / "browser-extension/dist" / family / name).read_bytes()
    version = json.loads((ROOT / "browser-extension/package.json").read_text())["version"]
    files["VERSION"] = f"name: wispkey-receiver-test\nversion: {version}\ncommit: {source}\ntarget: {TARGET}\nfeatures: {','.join(FEATURES)}\nactivation: none\n".encode()
    report = {"source_commit": source, "target": TARGET, "features": FEATURES,
              "cargo_lock_sha256": sha((ROOT / "Cargo.lock").read_bytes()),
              "activation": "none", "test_artifact": True,
              "files": {name: sha(data) for name, data in sorted(files.items())}}
    files["BUILD.json"] = (json.dumps(report, indent=2) + "\n").encode()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output / ARCHIVE, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    verify(output / ARCHIVE, source)


def verify(path, source):
    source = commit(source)
    path = Path(path)
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("archive exceeds bound")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) != len(CONTENTS) or {m.filename for m in members} != CONTENTS:
            raise ValueError("unexpected/duplicate archive paths")
        if any(m.file_size > MAX_MEMBER or m.is_dir() or (m.external_attr >> 16) & 0o170000 == 0o120000 for m in members):
            raise ValueError("unsupported archive entry")
        if sum(m.file_size for m in members) > MAX_ARCHIVE:
            raise ValueError("expanded archive exceeds bound")
        files = {m.filename: archive.read(m) for m in members}
    for name in BINARIES:
        pe_x64(files[name])
    report = json.loads(files["BUILD.json"])
    if report.get("source_commit") != source or report.get("target") != TARGET or report.get("features") != FEATURES:
        raise ValueError("wrong artifact source/target/features")
    if set(report) != {"source_commit", "target", "features", "cargo_lock_sha256", "activation", "test_artifact", "files"}:
        raise ValueError("unexpected build metadata")
    if report["cargo_lock_sha256"] != sha((ROOT / "Cargo.lock").read_bytes()):
        raise ValueError("wrong source dependency lockfile")
    if report.get("activation") != "none" or report.get("test_artifact") is not True:
        raise ValueError("not a staging artifact")
    expected = {name: sha(data) for name, data in files.items() if name != "BUILD.json"}
    if report.get("files") != expected:
        raise ValueError("contained-file hash mismatch")
    if f"commit: {source}\n".encode() not in files["VERSION"]:
        raise ValueError("VERSION source mismatch")
    if b"Receiver transport binding:" not in files["wispkey-browser-host.exe"]:
        raise ValueError("receiver marker missing")
    return report


def run(binary, args, env, data=b"", timeout=15):
    if len(data) > 4096:
        raise ValueError("smoke input exceeds bound")
    child = subprocess.Popen([str(binary), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env)
    exceeded = threading.Event()
    captured = {}

    def capture(name, stream):
        try:
            captured[name] = stream.read(65537)
            if len(captured[name]) > 65536:
                exceeded.set()
        except OSError:
            exceeded.set()
        finally:
            stream.close()

    threads = [threading.Thread(target=capture, args=(name, stream), daemon=True)
               for name, stream in (("stdout", child.stdout), ("stderr", child.stderr))]
    for thread in threads:
        thread.start()
    try:
        try:
            child.stdin.write(data)
            child.stdin.close()
        except BrokenPipeError:
            pass
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if exceeded.is_set() or time.monotonic() >= deadline:
                raise ValueError("smoke deadline/output bound exceeded")
            time.sleep(0.01)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=1)
    if exceeded.is_set() or any(t.is_alive() for t in threads) or set(captured) != {"stdout", "stderr"}:
        raise ValueError("smoke output capture failed")
    return subprocess.CompletedProcess([str(binary), *args], child.returncode, captured["stdout"], captured["stderr"])


def smoke(archive, extracted, source):
    if os.name != "nt":
        raise ValueError("native Windows smoke required")
    report = verify(archive, source)
    extracted = Path(extracted).resolve()
    actual = {p.relative_to(extracted).as_posix(): p for p in extracted.rglob("*") if p.is_file()}
    if set(actual) != CONTENTS:
        raise ValueError("extracted inventory mismatch")
    with zipfile.ZipFile(archive) as original:
        if actual["BUILD.json"].read_bytes() != original.read("BUILD.json"):
            raise ValueError("extracted build metadata mismatch")
    for name, digest in report["files"].items():
        if sha(actual[name].read_bytes()) != digest:
            raise ValueError("extracted file hash mismatch")
    with tempfile.TemporaryDirectory(prefix="wispkey-receiver-smoke-") as tmp:
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("WISPKEY_")}
        env.update(WISPKEY_VAULT_PATH=str(Path(tmp) / "empty-vault"), USERPROFILE=tmp,
                   APPDATA=str(Path(tmp) / "appdata"), LOCALAPPDATA=str(Path(tmp) / "local"))
        cli = actual["wispkey.exe"]
        for args in (["--version"], ["--help"], ["login", "update-existing", "--help"], ["replace-value", "--help"]):
            response = run(cli, args, env)
            if response.returncode != 0 or not response.stdout:
                raise ValueError("CLI metadata probe failed")
        if run(cli, ["receiver", "start"], env).returncode == 0:
            raise ValueError("unexpected receiver activation command")
        body = json.dumps({"method": "pending", "origin": "https://artifact.synthetic.invalid"}).encode()
        response = run(actual["wispkey-browser-host.exe"], [], env, struct.pack("<I", len(body)) + body)
        if response.returncode != 0 or response.stderr or len(response.stdout) < 4:
            raise ValueError("native host probe failed")
        length = struct.unpack("<I", response.stdout[:4])[0]
        if length != len(response.stdout) - 4:
            raise ValueError("invalid native framing")
        if json.loads(response.stdout[4:]) != {"ok": False, "error": "unlock WispKey before using browser handoff"}:
            raise ValueError("unconfigured native admission was not denied")
        if Path(env["WISPKEY_VAULT_PATH"]).exists():
            raise ValueError("metadata probes created a vault")
    return {"source_commit": source, "platform": "Windows", "target": TARGET,
            "features": FEATURES, "archive_sha256": sha(Path(archive).read_bytes()),
            "checks": ["exact_archive_inventory", "native_expand_archive", "extracted_hashes", "cli_help_version",
                       "safe_input_help", "no_receiver_activation_command", "unconfigured_native_admission_denied",
                       "no_vault_created"], "installation_performed": False, "native_presence_tested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["package", "verify", "smoke"])
    parser.add_argument("--commit", required=True, type=commit)
    parser.add_argument("--cargo-log")
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--extracted", type=Path)
    args = parser.parse_args()
    if args.operation == "package":
        package(args.cargo_log, args.directory, args.commit)
    elif args.operation == "verify":
        verify(args.directory / ARCHIVE, args.commit)
    else:
        report = smoke(args.directory / ARCHIVE, args.extracted, args.commit)
        (args.directory / "smoke-report.json").write_text(json.dumps(report, indent=2) + "\n")
        names = [ARCHIVE, "smoke-report.json"]
        (args.directory / "SHA256SUMS.txt").write_text("".join(f"{sha((args.directory / n).read_bytes())}  {n}\n" for n in names))


if __name__ == "__main__":
    main()
