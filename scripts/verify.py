#!/usr/bin/env python3
"""Run named validation suites from any working directory. Python 3.10+."""

import argparse
from contextlib import nullcontext
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def suites(root=ROOT):
    """Each step is (working directory, argv); never invoke a shell."""
    browser = root / "browser-extension"
    tray = root / "crates/wispkey-tray/ui"
    tray_build = [(tray, ["npm", "ci"]), (tray, ["npm", "run", "build"])]
    return {
        "cli": [
            (root, ["cargo", "fmt", "--all", "--", "--check"]),
            (root, ["cargo", "clippy", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"]),
            # Default and all-features exercise different transport branches.
            (root, ["cargo", "test", "--locked"]),
            (root, ["cargo", "test", "--locked", "--all-features"]),
        ],
        "browser": [
            (browser, ["npm", "ci"]),
            (browser, ["npm", "test"]),
            (browser, ["npm", "run", "build"]),
            *tray_build,
            (browser, ["npx", "--no-install", "playwright", "install", "chromium", "firefox"]),
            (browser, ["npm", "run", "test:browser"]),
        ],
        "automation": [(root, [sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-v"])],
        "tray": [*tray_build,
            (root, ["cargo", "clippy", "--locked", "-p", "wispkey-tray", "--all-targets", "--", "-D", "warnings"]),
            (root, ["cargo", "test", "--locked", "-p", "wispkey-tray"]),
            (root, ["cargo", "build", "--locked", "-p", "wispkey-tray"]),
        ],
        "postgres": [(root, ["bash", "tests/support/postgres_operation_fixture.sh"])],
        "cross-node": [(root, [sys.executable, "tests/support/cross_node_fixture.py"])],
    }


def run(selected, catalog, *, dry_run=False, execute=subprocess.run, find=shutil.which):
    failed = []
    for name in dict.fromkeys(selected):
        for directory, argv in catalog[name]:
            print(f"[{name}] {directory}: {' '.join(argv)}", flush=True)
            if dry_run:
                continue
            executable = find(argv[0])
            if executable is None:
                print(f"[{name}] FAILED: required executable {argv[0]} is unavailable", file=sys.stderr)
                failed.append(name)
                break
            try:
                # An accidentally unscoped library test must never write to the
                # developer's normal vault or Cloud configuration.
                isolation = tempfile.TemporaryDirectory(prefix="wispkey-verify-") if argv[:2] == ["cargo", "test"] else nullcontext(None)
                with isolation as vault:
                    options = {"env": dict(os.environ, WISPKEY_VAULT_PATH=vault)} if vault else {}
                    result = execute([executable, *argv[1:]], cwd=directory, check=False, **options)
            except OSError:
                print(f"[{name}] FAILED: could not start {argv[0]}", file=sys.stderr)
                failed.append(name)
                break
            if result.returncode:
                print(f"[{name}] FAILED: exit {result.returncode}", file=sys.stderr)
                failed.append(name)
                break
        else:
            print(f"[{name}] {'PLANNED (not executed)' if dry_run else 'PASSED'}", flush=True)
    return 1 if failed else 0


def main(argv=None):
    catalog = suites()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", action="append", choices=catalog, help="repeat to combine; defaults to cli")
    parser.add_argument("--all", action="store_true", help="cli, browser and automation; optional native tray/PostgreSQL/cross-node require explicit --suite")
    parser.add_argument("--dry-run", action="store_true", help="print commands without executing or claiming a pass")
    args = parser.parse_args(argv)
    selected = (["cli", "browser", "automation"] if args.all else []) + (args.suite or [])
    try:
        return run(selected or ["cli"], catalog, dry_run=args.dry_run)
    except KeyboardInterrupt:
        print("Validation interrupted; incomplete suites did not pass.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
