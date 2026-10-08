#!/usr/bin/env python3
"""Prove synthetic Personal operations in a traced, loopback-only Linux namespace."""

import argparse
import errno
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ("smoke", "proxy", "audit", "mcp")
CALL = re.compile(r"\b(connect|bind|sendto|sendmsg|sendmmsg)\(")


def inspect_trace(text):
    """Reject external, Unix-mediated, or undecodable egress, even if it failed."""
    connections = 0
    for line in text.splitlines():
        call = CALL.search(line)
        if not call:
            continue
        operation = call[1]
        if operation in ("connect", "bind"):
            if "sa_family=AF_NETLINK" in line:
                continue
            if "sa_family=AF_INET6" in line:
                allowed = 'inet_pton(AF_INET6, "::1"' in line
            elif "sa_family=AF_INET" in line:
                allowed = 'inet_addr("127.0.0.1")' in line
            else:
                allowed = False
            if not allowed:
                raise ValueError("non-loopback or undecodable connection attempt")
            connections += operation == "connect"
        elif operation == "sendto" and re.search(r",\s*(?:0|NULL),\s*0\)\s*\=", line):
            # A connected TCP write has no caller-selected destination. Its
            # connection was inspected separately; raw buffers are never logged.
            continue
        else:
            raise ValueError("unconnected or undecodable send attempt")
    return connections


def run_isolated(binaries, tracer):
    interfaces = {line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"} or len(Path("/proc/net/route").read_text().splitlines()) > 1:
        raise ValueError("requires a fresh network namespace with only loopback")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    # Negative control occurs before tracing WispKey and must fail immediately.
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("192.0.2.1", 443)) != errno.ENETUNREACH:
            raise ValueError("external network denial was not established")
    if len(binaries) != len(TARGETS):
        raise ValueError("missing required test binaries")
    connections = 0
    with tempfile.TemporaryDirectory(prefix="wispkey-offline-") as scratch:
        environment = {"PATH": os.environ["PATH"], "HOME": scratch, "TMPDIR": scratch,
                       "WISPKEY_VAULT_PATH": str(Path(scratch) / "unused-vault"), "WISPKEY_PROTECTOR": "file"}
        for index, binary in enumerate(binaries):
            prefix = Path(scratch) / f"egress-{index}"
            result = subprocess.run([tracer, "-ff", "-qq", "-s", "0", "-e",
                "trace=connect,bind,sendto,sendmsg,sendmmsg", "-e",
                "raw=sendto,sendmsg,sendmmsg", "-o", str(prefix), binary, "--test-threads=1"],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
            # Never export raw fixture output, including panic text or canaries.
            if result.returncode or b"test result: ok." not in result.stdout:
                raise ValueError(f"Personal fixture {TARGETS[index]} failed")
            traces = list(Path(scratch).glob(prefix.name + ".*"))
            if not traces:
                raise ValueError("network trace was not produced")
            for trace in traces:
                connections += inspect_trace(trace.read_text())
    if not connections:
        raise ValueError("loopback proxy positive control was not observed")
    print(json.dumps({"result": "passed", "suites": TARGETS, "external_network": "denied",
                      "non_loopback_attempts": 0, "loopback_connections": connections,
                      "account_configuration": "absent", "fixture_output": "withheld"}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sudo", action="store_true", help="use noninteractive sudo for the namespace on CI hosts")
    parser.add_argument("--isolated", nargs="+", help=argparse.SUPPRESS)
    parser.add_argument("--tracer", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != "linux":
        raise ValueError("Linux or WSL is required")
    if args.isolated:
        if not args.tracer:
            raise ValueError("missing trace tool")
        run_isolated(args.isolated, args.tracer)
        return
    tracer = shutil.which("strace")
    if not tracer:
        raise ValueError("strace is required")
    command = ["cargo", "test", "--locked", "--no-run", "--message-format=json"]
    for target in TARGETS:
        command += ["--test", target]
    build = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True, timeout=600)
    artifacts = {}
    for line in build.stdout.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-artifact" and item.get("profile", {}).get("test"):
            name = item["target"]["name"]
            if name in TARGETS and item.get("executable"):
                artifacts[name] = item["executable"]
    if set(artifacts) != set(TARGETS):
        raise ValueError("required test build artifacts are missing")
    namespace = ["sudo", "-n", "unshare", "--net"] if args.sudo else ["unshare", "--user", "--map-root-user", "--net"]
    subprocess.run([*namespace, sys.executable, str(Path(__file__).resolve()), "--tracer", tracer,
                    "--isolated", *(artifacts[name] for name in TARGETS)], cwd=ROOT, check=True, timeout=1000)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print(f"Personal offline proof failed: {error}.", file=sys.stderr)
        sys.exit(1)
    except (OSError, subprocess.SubprocessError):
        print("Personal offline proof failed; check tools, namespace permissions, or the build.", file=sys.stderr)
        sys.exit(1)
