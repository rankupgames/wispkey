"""Reconcile the release chain without bypassing branch protection."""

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

CHAIN = (("development", "release"), ("release", "main"), ("main", "development"))


class ApiFailure(Exception):
    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code if 0 < code < 256 else 1


def gh_api(path, payload=None):
    command = ["gh", "api", path]
    if payload is not None:
        command += ["--method", "POST", "--input", "-"]
    try:
        result = subprocess.run(
            command, input=json.dumps(payload) if payload is not None else None,
            capture_output=True, text=True, timeout=45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ApiFailure("GitHub API unavailable or timed out") from None
    if result.returncode:
        # Never echo arbitrary API bodies, branch content, or token-bearing stderr.
        status = re.search(r"HTTP (\d{3})", result.stderr)
        suffix = f" (HTTP {status[1]})" if status else ""
        raise ApiFailure(f"GitHub API request failed{suffix}; check permissions, conflicts, and service status", result.returncode)
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise ApiFailure("GitHub API returned invalid JSON") from None


@dataclass
class Step:
    source: str
    destination: str
    state: str
    detail: str


def reconcile(repo, dry_run=False, api=gh_api):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ApiFailure("GH_REPO must be owner/repository")
    steps, code, blocked = [], 0, False
    for source, destination in CHAIN:
        if blocked:
            steps.append(Step(source, destination, "skipped", "Previous step is not integrated"))
            continue
        try:
            comparison = api(f"repos/{repo}/compare/{destination}...{source}")
            status, ahead = comparison.get("status"), comparison.get("ahead_by")
            if status in ("identical", "behind") and ahead == 0:
                steps.append(Step(source, destination, "verified no-op", "Source is already an ancestor of destination"))
                continue
            if status not in ("ahead", "diverged") or type(ahead) is not int or ahead <= 0:
                raise ApiFailure("Inconsistent branch comparison; refusing to infer a merge")
            if dry_run:
                steps.append(Step(source, destination, "skipped", f"Dry run: {ahead} source commits require a PR"))
                blocked = True
                continue
            prs = api(f"repos/{repo}/pulls?state=open&base={destination}&head={repo.split('/')[0]}:{source}&per_page=100")
            if not isinstance(prs, list) or len(prs) > 1:
                raise ApiFailure("Ambiguous open promotion PRs; inspect before continuing")
            if prs:
                pr = prs[0]
            else:
                pr = api(f"repos/{repo}/pulls", {
                    "base": destination, "head": source,
                    "title": f"Reconcile {source} into {destination}",
                    "body": "Automated branch reconciliation. Review the diff and required checks before merging. This pending PR does not mean the branches are synchronized. Merge with a merge commit to preserve ancestry.",
                })
            number = pr.get("number")
            if type(number) is not int or number <= 0:
                raise ApiFailure("GitHub API returned no valid PR number")
            steps.append(Step(source, destination, "pending PR", f"https://github.com/{repo}/pull/{number}"))
            blocked = True
        except (ApiFailure, AttributeError, TypeError) as error:
            safe = error if isinstance(error, ApiFailure) else ApiFailure("Unexpected GitHub API response shape")
            steps.append(Step(source, destination, "failed", str(safe)))
            code, blocked = safe.code, True
    return steps, code


def summary(steps):
    rows = ["## Branch reconciliation", "", "| Step | State | Detail |", "| --- | --- | --- |"]
    rows += [f"| {s.source} → {s.destination} | {s.state} | {s.detail} |" for s in steps]
    return "\n".join(rows) + "\n"


def main():
    steps, code = reconcile(os.environ.get("GH_REPO", ""), os.environ.get("DRY_RUN", "true").lower() == "true")
    report = summary(steps)
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
            stream.write(report)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
