#!/usr/bin/env python3
"""Exercise supplied CLI/helper binaries in disposable Debian 12, without kind."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("inspection", ROOT / "scripts/inspect_compatible_binaries.py")
INSPECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSPECTION)
CANARY = b"synthetic-bookworm-artifact-canary-v1"


def no_canary(data):
    if CANARY in data or base64.b64encode(CANARY) in data:
        raise RuntimeError("fixture output contained a canary")


def run(argv, timeout=30):
    result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    no_canary(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"fixture command {Path(argv[0]).name} failed with exit {result.returncode}")
    return result.stdout


def write(path, content, mode=0o600):
    path.write_text(content)
    path.chmod(mode)


def first_line(process):
    deadline = time.monotonic() + 15
    value = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while len(value) < 4096:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise RuntimeError("SSH fixture readiness deadline")
            chunk = os.read(process.stdout.fileno(), 1)
            if not chunk or chunk == b"\n":
                return bytes(value)
            value.extend(chunk)
    raise RuntimeError("SSH fixture response bound")


def exchange(command, attempt, phase=None, expired=False):
    hello = {"version": 1, "attempt_id": attempt, "phase": "hello", "remaining_ms": 10000,
             "deadline_unix_ms": int(time.time() * 1000) + (-1000 if expired else 10000)}
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        try:
            process.stdin.write((json.dumps(hello) + "\n").encode())
            process.stdin.flush()
        except BrokenPipeError:
            pass
        first = first_line(process)
        no_canary(first)
        response = json.loads(first) if first else {}
        ready = response == {"version": 1, "attempt_id": attempt, "phase": "ready"}
        payload = b""
        if ready and phase:
            delivery = {"version": 1, "attempt_id": attempt, "phase": phase}
            if phase == "deliver":
                delivery["credential_b64"] = base64.b64encode(CANARY).decode()
            payload = (json.dumps(delivery) + "\n").encode()
        stdout, stderr = process.communicate(payload, timeout=15)
        no_canary(stdout + stderr)
        result = [json.loads(line) for line in stdout.splitlines()]
        return ready, result
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    for tool in ("docker", "ssh", "ssh-keygen"):
        if not shutil.which(tool):
            raise RuntimeError(f"missing fixture prerequisite: {tool}")
    directory = args.directory.resolve()
    report = json.loads((directory / "build-report.json").read_text())
    if (report["source_commit"] != args.commit or report["target"] != "x86_64-unknown-linux-gnu"
            or report["build_image"] != INSPECTION.BUILD_IMAGE
            or report["runtime_image"] != INSPECTION.RUNTIME_IMAGE):
        raise RuntimeError("artifact provenance mismatch")
    for name in INSPECTION.BINARY_NAMES:
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != report["artifacts"][name]["sha256"]:
            raise RuntimeError("artifact digest mismatch")
    suffix = uuid.uuid4().hex[:12]
    image, container = f"wk-bookworm:{suffix}", f"wk-bookworm-{suffix}"
    with tempfile.TemporaryDirectory(prefix="wk-bookworm-") as temporary:
        scratch = Path(temporary)
        try:
            for name in INSPECTION.BINARY_NAMES:
                shutil.copyfile(directory / name, scratch / name)
                (scratch / name).chmod(0o755)
            for name in ("identity", "wrong-identity"):
                run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(scratch / name)])
            write(scratch / "authorized_keys", 'restrict,command="sudo -n /usr/local/libexec/wispkey-operation-helper" '
                  + (scratch / "identity.pub").read_text())
            write(scratch / "fixed-action", '#!/usr/bin/python3\nimport hashlib,sys\nvalue=sys.stdin.buffer.read()\n'
                  f'if hashlib.sha256(value).hexdigest() != "{hashlib.sha256(CANARY).hexdigest()}": sys.exit(9)\n'
                  'with open("/var/lib/wispkey-helper/accepted", "a") as f: f.write("accepted\\n")\n', 0o755)
            write(scratch / "helper.toml", 'version = 1\nprogram = "/usr/local/libexec/wispkey-fixed-action"\nargs = []\n')
            write(scratch / "sudoers", 'wispkey-ssh ALL=(root) NOPASSWD: /usr/local/libexec/wispkey-operation-helper ""\n')
            write(scratch / "sshd_config", 'Port 22\nHostKey /etc/ssh/ssh_host_ed25519_key\nPermitRootLogin no\n'
                  'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\n'
                  'AllowUsers wispkey-ssh\nDisableForwarding yes\nPermitTTY no\nLogLevel ERROR\n')
            write(scratch / "Dockerfile", f'''FROM {INSPECTION.RUNTIME_IMAGE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo python3 ca-certificates libgcc-s1 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/sh wispkey-ssh && passwd -d wispkey-ssh && mkdir -p /run/sshd /etc/wispkey /var/lib/wispkey-helper /usr/local/libexec /home/wispkey-ssh/.ssh && chmod 700 /var/lib/wispkey-helper /home/wispkey-ssh/.ssh && ssh-keygen -A
COPY wispkey /usr/local/bin/wispkey
COPY wispkey-operation-helper /usr/local/libexec/wispkey-operation-helper
COPY fixed-action /usr/local/libexec/wispkey-fixed-action
COPY helper.toml /etc/wispkey/helper.toml
COPY sudoers /etc/sudoers.d/wispkey
COPY sshd_config /etc/ssh/sshd_config
COPY authorized_keys /home/wispkey-ssh/.ssh/authorized_keys
RUN touch /var/lib/wispkey-helper/attempts.db && chmod 600 /var/lib/wispkey-helper/attempts.db /etc/wispkey/helper.toml /home/wispkey-ssh/.ssh/authorized_keys && chmod 755 /usr/local/bin/wispkey /usr/local/libexec/wispkey-* && chmod 440 /etc/sudoers.d/wispkey && chown -R wispkey-ssh:wispkey-ssh /home/wispkey-ssh/.ssh && visudo -cf /etc/sudoers.d/wispkey
CMD ["/usr/sbin/sshd", "-D", "-e"]
''')
            run(["docker", "build", "--platform", "linux/amd64", "-q", "-t", image, str(scratch)], timeout=300)
            # Independent runtime image has neither a compiler nor build-directory mounts.
            smoke = ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", image]
            libc = run(smoke + ["getconf", "GNU_LIBC_VERSION"]).decode().strip()
            if libc != "glibc 2.36":
                raise RuntimeError("unexpected runtime libc")
            version = run(smoke + ["/usr/local/bin/wispkey", "--version"]).decode().strip()
            if not version.startswith("wispkey "):
                raise RuntimeError("CLI version smoke failed")
            run(smoke + ["/usr/local/bin/wispkey", "--help"])
            dependencies = {}
            for path in ["/usr/local/bin/wispkey", "/usr/local/libexec/wispkey-operation-helper"]:
                output = run(smoke + ["ldd", path]).decode()
                if "not found" in output:
                    raise RuntimeError("runtime dependency missing")
                dependencies[Path(path).name] = output.splitlines()
            packages = run(smoke + ["dpkg-query", "-W"]).decode().splitlines()
            run(["docker", "run", "-d", "--platform", "linux/amd64", "--name", container,
                 "--cpus", "2", "--memory", "512m", "--pids-limit", "64",
                 "--label", "wispkey.acceptance=" + suffix, "-p", "127.0.0.1::22", image])
            port = run(["docker", "port", container, "22/tcp"]).decode().strip()
            if not port.startswith("127.0.0.1:") or not port.split(":")[1].isdigit():
                raise RuntimeError("SSH destination must bind IPv4 loopback only")
            public = run(["docker", "exec", container, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"]).decode().strip()
            write(scratch / "known_hosts", f"[{port.replace(':', ']:')} {public}\n")
            write(scratch / "wrong_hosts", f"[{port.replace(':', ']:')} {(scratch / 'wrong-identity.pub').read_text()}")

            def command(key="identity", hosts="known_hosts"):
                return ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                        "-o", "IdentityAgent=none", "-o", "ClearAllForwardings=yes",
                        "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(scratch / hosts),
                        "-o", "ConnectTimeout=5", "-i", str(scratch / key), "-p", port.split(":")[1],
                        "wispkey-ssh@127.0.0.1", "/usr/local/libexec/wispkey-operation-helper"]

            # Wait for the fixture's own listener without opening an SSH session.
            deadline = time.monotonic() + 10
            while True:
                check = subprocess.run(["docker", "exec", container, "python3", "-c",
                    'import socket; s=socket.create_connection(("127.0.0.1",22),timeout=1); s.close()'], capture_output=True)
                no_canary(check.stdout + check.stderr)
                if check.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("SSH listener readiness deadline")
                time.sleep(0.1)
            for cmd in [command(hosts="wrong_hosts"), command(key="wrong-identity")]:
                if exchange(cmd, str(uuid.uuid4()))[0]:
                    raise RuntimeError("invalid pin/key reached helper readiness")
            attempt = str(uuid.uuid4())
            ready, result = exchange(command(), attempt, "deliver")
            if not ready or result != [{"version": 1, "attempt_id": attempt, "outcome": "succeeded", "count": 1, "exit_code": 0}]:
                raise RuntimeError("artifact helper delivery failed")
            if exchange(command(), attempt)[0]:
                raise RuntimeError("artifact helper accepted replay")
            ready, result = exchange(command(), str(uuid.uuid4()), "cancel")
            if not ready or any(row.get("outcome") == "succeeded" for row in result):
                raise RuntimeError("cancel fixture failed")
            if exchange(command(), str(uuid.uuid4()), expired=True)[0]:
                raise RuntimeError("expired attempt reached readiness")
            if run(["docker", "exec", container, "cat", "/var/lib/wispkey-helper/accepted"]) != b"accepted\n":
                raise RuntimeError("destination executed more than once")
            run(["docker", "logs", container])
            runtime = {"source_commit": args.commit, "runtime_image": INSPECTION.RUNTIME_IMAGE,
                       "libc": libc, "cli_version": version, "dependencies": dependencies,
                       "packages": packages, "ssh_pin_and_key_rejected": True,
                       "delivery_count": 1, "replay_rejected": True, "cancelled_before_delivery": True,
                       "expired_before_delivery": True, "canary_absent_from_outputs": True}
            (directory / "runtime-report.json").write_text(json.dumps(runtime, indent=2) + "\n")
            print("PASS: supplied CLI/helper, glibc 2.36, pinned SSH, exact-once delivery, replay/cancel/expiry, output canaries")
        finally:
            subprocess.run(["docker", "rm", "-f", "-v", container], capture_output=True, timeout=20)
            subprocess.run(["docker", "image", "rm", image], capture_output=True, timeout=20)


if __name__ == "__main__":
    main()
