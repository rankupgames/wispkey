#!/usr/bin/env python3
"""Synthetic POSIX PTY contract for replace-value. No real vault or network access.
Usage: python3 scripts/test_replace_value_prompt.py /absolute/path/to/test/wispkey
"""
import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import termios
import time

BINARY = str(Path(sys.argv[1]).resolve())
CANARY = b"synthetic-hidden-replacement-canary"


def run(env, *args, value=None):
    result = subprocess.run([BINARY, *args], env=env, input=value, capture_output=True, timeout=20)
    assert result.returncode == 0, "synthetic fixture command failed"
    return result.stdout


def row(vault):
    with sqlite3.connect(vault / "vault.db") as db:
        return db.execute("SELECT * FROM credentials").fetchall()


def prompt_case(env, vault, scenario):
    before = row(vault)
    pid, fd = pty.fork()
    if pid == 0:
        args = [BINARY, "replace-value", "entry", "--project", "default", "--partition", "personal"]
        if scenario == "stdin-tty":
            args.append("--stdin")
        os.execve(BINARY, args, env)
    transcript = bytearray()
    exited = False

    def until(marker):
        deadline = time.monotonic() + 15
        while marker not in transcript:
            assert time.monotonic() < deadline, "prompt timed out"
            if select.select([fd], [], [], 0.1)[0]:
                chunk = os.read(fd, 4096)
                assert chunk, "prompt ended early"
                transcript.extend(chunk)

    def hidden_write(value):
        # rpassword writes its prompt immediately before disabling echo.
        deadline = time.monotonic() + 2
        while termios.tcgetattr(fd)[3] & termios.ECHO:
            assert time.monotonic() < deadline, "terminal input is not hidden"
            time.sleep(0.005)
        os.write(fd, value)

    try:
        if scenario != "stdin-tty":
            until(b"Enter complete replacement value: ")
            if scenario == "cancel-first":
                os.kill(pid, signal.SIGINT)
            elif scenario == "eof":
                hidden_write(b"\x04")
            else:
                hidden_write(CANARY + b"\n")
                until(b"Confirm complete replacement value: ")
                if scenario == "cancel-confirm":
                    os.kill(pid, signal.SIGINT)
                else:
                    if scenario == "concurrent-rename":
                        with sqlite3.connect(vault / "vault.db") as db:
                            db.execute("UPDATE credentials SET name='renamed'")
                    hidden_write((b"different-synthetic-value" if scenario == "mismatch" else CANARY) + b"\n")
        deadline = time.monotonic() + 15
        while True:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                exited = True
                break
            assert time.monotonic() < deadline, "prompt process did not exit"
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    chunk = os.read(fd, 4096)
                    if chunk:
                        transcript.extend(chunk)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
        # Drain any bytes written immediately before exit.
        while select.select([fd], [], [], 0)[0]:
            try:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                transcript.extend(chunk)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
        assert CANARY not in transcript and b"wk_" not in transcript, "sensitive output escaped"
        success = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        assert success == (scenario == "success"), "unexpected exit status"
        if scenario == "success":
            after = row(vault)
            assert after[0][4] != before[0][4], "ciphertext did not change"
            template = vault / "template"
            template.write_text("{{ cred:entry }}")
            assert run(env, "inject", "-i", str(template), "--stdout", "--project", "default") == CANARY
        elif scenario == "concurrent-rename":
            after = row(vault)
            assert after[0][1] == "renamed" and after[0][4] == before[0][4], "stale update committed"
        else:
            assert row(vault) == before, "cancelled or invalid input changed the row"
    finally:
        if not exited:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(fd)


scenarios = ["success", "cancel-first", "cancel-confirm", "eof", "mismatch", "concurrent-rename", "stdin-tty"]
for scenario in scenarios:
    with tempfile.TemporaryDirectory(prefix="wispkey-hidden-synthetic-") as scratch:
        vault = Path(scratch)
        env = {"PATH": os.defpath, "HOME": scratch, "WISPKEY_VAULT_PATH": scratch,
               "WISPKEY_PASSWORD": "synthetic-fixture-master", "WISPKEY_PROTECTOR": "file",
               "WISPKEY_SESSION_TIMEOUT": "30"}
        run(env, "init")
        run(env, "add", "entry", "--type", "api_key", "--value-file", "-", value=b"synthetic-before")
        del env["WISPKEY_PASSWORD"]
        prompt_case(env, vault, scenario)
print(json.dumps({"passed": len(scenarios), "scenarios": scenarios, "secret_echo": False}))
