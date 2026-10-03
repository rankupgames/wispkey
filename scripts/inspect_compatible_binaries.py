#!/usr/bin/env python3
"""Reject incompatible ELF requirements and record test-artifact provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BINARY_NAMES = ("wispkey", "wispkey-operation-helper")
BUILD_IMAGE = "rust@sha256:4673f78db88b71f09d5451bbc404734807918161241215ba0a50bbbe9b448117"
RUNTIME_IMAGE = "debian@sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b"


def requirements(text):
    """Inspect version needs only; definitions are not runtime requirements."""
    needed = []
    in_needs = False
    for line in text.splitlines():
        if line.startswith("Version "):
            in_needs = line.startswith("Version needs section")
        if in_needs:
            for name in re.findall(r"Name: (GLIBC_[A-Za-z0-9_.]+)", line):
                version = name.removeprefix("GLIBC_")
                if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
                    raise ValueError("unexpected GLIBC requirement")
                if tuple(map(int, version.split("."))) > (2, 36):
                    raise ValueError("binary requires newer than GLIBC 2.36")
                needed.append(name)
    if not needed:
        raise ValueError("no GLIBC version requirements found")
    return sorted(set(needed))


def inspect(path):
    def readelf(*flags):
        return subprocess.check_output(["readelf", *flags, str(path)], text=True)
    header = readelf("-h")
    program = readelf("-lW")
    if "Advanced Micro Devices X86-64" not in header or "ELF64" not in header:
        raise ValueError("expected x86_64 ELF64 artifact")
    if "[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]" not in program:
        raise ValueError("unexpected ELF interpreter")
    dynamic = readelf("-dW")
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", dynamic)
    if not needed or "(RPATH)" in dynamic or "(RUNPATH)" in dynamic:
        raise ValueError("unexpected dependency or embedded library search path")
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "needed": needed, "glibc_requirements": requirements(readelf("--version-info", "-W"))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("full source commit required")
    report = {"source_commit": args.commit, "target": "x86_64-unknown-linux-gnu",
              "build_image": BUILD_IMAGE, "runtime_image": RUNTIME_IMAGE,
              "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
              "artifacts": {name: inspect(args.directory / name) for name in BINARY_NAMES}}
    if not report["rustc"].startswith("rustc 1.94.0 "):
        raise ValueError("unexpected build toolchain")
    (args.directory / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.directory / "SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in sorted(args.directory.iterdir()) if path.is_file() and path.name != "SHA256SUMS.txt"))


if __name__ == "__main__":
    main()
