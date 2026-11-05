"""Emit the shared dispatcher's typed request. This command never submits a build."""

import json
import re
import sys

REPOSITORY = "https://github.com/rankupgames/wispkey.git"
LANES = ("rust", "tray", "browser", "postgres", "cross-node")
FLAGS = ("--branch", "--source-sha", "--lane")
USAGE = "Use --branch <approved-branch> --source-sha <40-hex-commit> --lane rust|tray|browser|postgres|cross-node."


def valid_branch(branch):
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", branch)) and all(
        part and not part.startswith(".") and not part.endswith(".")
        and not part.endswith(".lock") and ".." not in part
        for part in branch.split("/")
    )


def build_request(argv):
    if len(argv) != 2 * len(FLAGS):
        return None
    values = {}
    for key, value in zip(argv[::2], argv[1::2]):
        if key not in FLAGS or key in values:
            return None
        values[key] = value
    branch, source_sha, lane = (values[flag] for flag in FLAGS)
    if not valid_branch(branch) or not re.fullmatch(r"[0-9a-f]{40}", source_sha) or lane not in LANES:
        return None
    return {"version": 1, "repository": REPOSITORY, "branch": branch, "sourceSha": source_sha, "lane": lane}


def main(argv):
    request = build_request(argv)
    if request is None:
        print(json.dumps({"status": "blocked", "code": "invalid_dispatch_arguments", "message": USAGE}), file=sys.stderr)
        return 1
    print(json.dumps(request))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
