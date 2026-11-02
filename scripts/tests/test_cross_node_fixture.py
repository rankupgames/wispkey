import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

FIXTURE = Path(__file__).resolve().parents[2] / "tests/support/cross_node_fixture.py"
IMAGE_ID = "sha256:" + "a" * 64
FOREIGN_NODE_ID = "b" * 64

# Records argv; Docker creates the image, then refuses the SSH container because another owner holds its name.
STUB = f"""#!{sys.executable}
import json, os, sys
from pathlib import Path
tool, args = Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(json.dumps([tool, *args]) + "\\n")
def value(flag):
    return args[args.index(flag) + 1]
if tool == "cargo":
    helper = Path(os.environ["CARGO_TARGET_DIR"], "debug", "wispkey-operation-helper")
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_bytes(b"")
elif tool == "ssh-keygen":
    for suffix in ["", ".pub"]:
        Path(value("-f") + suffix).write_text("synthetic-key\\n")
elif tool == "docker" and args[:2] == ["buildx", "build"]:
    Path(value("--iidfile")).write_text("{IMAGE_ID}")
elif tool == "docker" and args[0] in {{"create", "run"}}:
    sys.exit(125)
elif tool == "docker" and args[0] == "ps":
    print("{FOREIGN_NODE_ID}")
elif tool == "docker" and args[:2] == ["container", "inspect"] and "--format" in args:
    print(json.dumps([{{"Source": "/pre-existing/encryption.json"}}]))
elif tool == "docker" and args[0] in {{"container", "image"}} and "inspect" in args:
    sys.exit(1)
"""


@unittest.skipIf(os.name != "posix", "the fixture runs on Linux only")
class CrossNodeFixtureOwnershipTests(unittest.TestCase):
    def run_fixture(self, temp, suffix):
        tools = Path(temp, "bin")
        tools.mkdir()
        for name in ["docker", "kind", "cargo", "ssh-keygen", "ssh"]:
            (tools / name).write_text(STUB)
            (tools / name).chmod(0o755)
        log = Path(temp, "calls.jsonl")
        environment = {key: value for key, value in os.environ.items() if key not in {"CI_BUDGET_CGROUP", "KIND"}}
        environment.update(PATH=f"{tools}{os.pathsep}{os.environ['PATH']}", STUB_LOG=str(log),
                           CARGO_TARGET_DIR=str(Path(temp, "target")), WISPKEY_CROSS_NODE_SUFFIX=suffix)
        result = subprocess.run([sys.executable, str(FIXTURE)], env=environment, capture_output=True, text=True)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls

    def test_collision_removes_only_resources_this_run_created(self):
        with tempfile.TemporaryDirectory() as temp:
            result, calls = self.run_fixture(temp, "collide")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("docker failed (exit 125)", result.stderr)
        removals = [call for call in calls if call[:2] in (["docker", "rm"], ["docker", "image"], ["kind", "delete"])
                    and "inspect" not in call]
        self.assertEqual(removals, [["docker", "image", "rm", IMAGE_ID]])

    def test_explicit_empty_suffix_fails_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            result, calls = self.run_fixture(temp, "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WISPKEY_CROSS_NODE_SUFFIX must be", result.stderr)
        self.assertEqual([call for call in calls if call[0] == "docker"], [])


if __name__ == "__main__":
    unittest.main()
