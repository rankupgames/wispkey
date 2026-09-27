"""Run a fresh RustSec audit and emit only a bounded dependency summary."""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def field(value):
    value = str(value)
    return value if re.fullmatch(r"[A-Za-z0-9_.,+<>=^~* -]{1,160}", value) else "unavailable"


def summarize(report, exit_code):
    vulnerabilities = report["vulnerabilities"]
    findings = vulnerabilities["list"]
    warnings = report["warnings"]
    if not isinstance(findings, list) or not isinstance(warnings, dict):
        raise ValueError("invalid audit report")
    if vulnerabilities["count"] != len(findings) or vulnerabilities["found"] != bool(findings):
        raise ValueError("inconsistent audit report")
    rows = ["## Dependency audit", "", f"Blocking advisories: {len(findings)}", "",
            "| Dependency | Advisory | Remediation |", "| --- | --- | --- |"]
    for entry in findings:
        package, advisory = entry["package"], entry["advisory"]
        advisory_id = advisory["id"]
        if not re.fullmatch(r"RUSTSEC-\d{4}-\d{4}", advisory_id):
            raise ValueError("invalid advisory ID")
        patched = entry["versions"]["patched"]
        if not isinstance(patched, list):
            raise ValueError("invalid patched versions")
        remedy = ", ".join(field(v) for v in patched) or "No patched version; replace/remove dependency or review mitigation"
        rows.append(f"| {field(package['name'])} {field(package['version'])} | [{advisory_id}](https://rustsec.org/advisories/{advisory_id}.html) | {remedy} |")
    rows += ["", "### Informational warnings (not automatically suppressed)", ""]
    warning_count = 0
    for kind, entries in warnings.items():
        if not isinstance(entries, list):
            raise ValueError("invalid warnings")
        for entry in entries:
            warning_count += 1
            package = entry["package"]
            rows.append(f"- {field(kind)}: {field(package['name'])} {field(package['version'])}")
    if not warning_count:
        rows.append("None.")
    if exit_code and not findings:
        rows += ["", "Audit tool failed without a blocking advisory report. Inspect tool/database availability; this is not a clean audit."]
    return "\n".join(rows) + "\n", (exit_code or (1 if findings else 0))


def run(lockfile):
    # A new database is fetched on every invocation. A neutral cwd also avoids
    # silently inheriting branch-local advisory suppression configuration.
    with tempfile.TemporaryDirectory(prefix="wispkey-audit-") as directory:
        try:
            result = subprocess.run(
                ["cargo", "audit", "--json", "--file", str(Path(lockfile).resolve()),
                 "--db", str(Path(directory) / "advisory-db")],
                cwd=directory, capture_output=True, text=True, timeout=300, check=False,
            )
            report, code = summarize(json.loads(result.stdout), result.returncode)
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError, AttributeError):
            report = "## Dependency audit\n\nAudit failed: unavailable tool/database or invalid report. No clean result is claimed.\n"
            code = 2
    return report, code


def main():
    report, code = run(sys.argv[1])
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as output:
            output.write(report)
    return code if 0 <= code < 256 else 2


if __name__ == "__main__":
    raise SystemExit(main())
