import json
import importlib.util
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

FIXTURE = Path(__file__).resolve().parents[2] / "tests/support/cross_node_fixture.py"
IMAGE_ID = "sha256:" + "a" * 64
FOREIGN_NODE_ID = "b" * 64

spec = importlib.util.spec_from_file_location("cross_node_fixture", FIXTURE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

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
elif tool == "docker" and args[:2] == ["image", "rm"]:
    sys.exit(int(os.environ.get("STUB_CLEANUP_EXIT", "0")))
"""


@unittest.skipIf(os.name != "posix", "the fixture runs on Linux only")
class CrossNodeFixtureOwnershipTests(unittest.TestCase):
    def run_fixture(self, temp, suffix, *, cleanup_exit=0, budget=None):
        tools = Path(temp, "bin")
        tools.mkdir()
        for name in ["docker", "kind", "cargo", "ssh-keygen", "ssh"]:
            (tools / name).write_text(STUB)
            (tools / name).chmod(0o755)
        log = Path(temp, "calls.jsonl")
        environment = {key: value for key, value in os.environ.items() if key not in {"CI_BUDGET_CGROUP", "KIND"}}
        environment.update(PATH=f"{tools}{os.pathsep}{os.environ['PATH']}", STUB_LOG=str(log),
                           CARGO_TARGET_DIR=str(Path(temp, "target")), WISPKEY_CROSS_NODE_SUFFIX=suffix,
                           STUB_CLEANUP_EXIT=str(cleanup_exit))
        if budget is not None:
            environment["CI_BUDGET_CGROUP"] = budget
        result = subprocess.run([sys.executable, str(FIXTURE)], env=environment, capture_output=True, text=True)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls

    def test_collision_removes_only_resources_this_run_created(self):
        for cleanup_exit in [0, 1]:
            with self.subTest(cleanup_exit=cleanup_exit), tempfile.TemporaryDirectory() as temp:
                result, calls = self.run_fixture(temp, "collide", cleanup_exit=cleanup_exit)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("docker failed (exit 125)", result.stderr)
            self.assertEqual("cross-node fixture cleanup failed" in result.stderr, cleanup_exit != 0)
            removals = [call for call in calls if call[:2] in (["docker", "rm"], ["docker", "image"], ["kind", "delete"])
                        and "inspect" not in call]
            self.assertEqual(removals, [["docker", "image", "rm", IMAGE_ID]])

    def test_explicit_empty_suffix_fails_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            result, calls = self.run_fixture(temp, "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WISPKEY_CROSS_NODE_SUFFIX must be", result.stderr)
        self.assertEqual([call for call in calls if call[0] == "docker"], [])

    def test_budgeted_kind_fails_before_creating_resources(self):
        with tempfile.TemporaryDirectory() as temp:
            result, calls = self.run_fixture(temp, "bounded", budget="/synthetic.slice")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("kind cannot honor CI_BUDGET_CGROUP", result.stderr)
        self.assertEqual(calls, [])


class CrossNodeFixtureEvidenceTests(unittest.TestCase):
    """Drive the full fixture through a deterministic subprocess CLI boundary."""

    def exercise(self, mode):
        calls = []
        rotated = False
        mount = None
        ssh_id, node_id = 'c' * 64, 'd' * 64
        previous_handler = signal.getsignal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            environment = dict(os.environ, CARGO_TARGET_DIR=str(temp / 'target'), WISPKEY_CROSS_NODE_SUFFIX='stub')
            environment.pop('CI_BUDGET_CGROUP', None)

            def execute(argv, **kwargs):
                nonlocal rotated, mount
                calls.append(argv)
                tool, args = Path(argv[0]).name, argv[1:]
                output, status = b'', 0
                if tool == 'cargo' and args[0] == 'build':
                    helper = temp / 'target/debug/wispkey-operation-helper'
                    helper.parent.mkdir(parents=True)
                    helper.write_bytes(b'stub helper')
                elif tool == 'cargo' and args[0] == 'test':
                    rotated = mode != 'zero-kubernetes'
                elif tool == 'ssh-keygen':
                    key = Path(args[args.index('-f') + 1])
                    key.write_bytes(b'stub key')
                    key.with_suffix('.pub').write_text('ssh-ed25519 stub-key\n')
                elif tool == 'ssh':
                    output = b'{"phase":"ready"}\n'
                elif tool == 'kind':
                    config = json.loads(Path(args[args.index('--config') + 1]).read_text())
                    mount = config['nodes'][0]['extraMounts'][0]['hostPath']
                elif tool == 'docker':
                    if args[:2] == ['buildx', 'build']:
                        Path(args[args.index('--iidfile') + 1]).write_text(IMAGE_ID)
                    elif args[0] == 'create':
                        if mode == 'create-failure':
                            status = 125
                        else:
                            Path(args[args.index('--cidfile') + 1]).write_text(ssh_id)
                    elif args[0] == 'start':
                        if mode == 'start-failure':
                            status = 17
                        elif mode == 'sigterm':
                            handler = signal.getsignal(signal.SIGTERM)
                            self.assertTrue(callable(handler), 'SIGTERM must unwind fixture cleanup')
                            handler(signal.SIGTERM, None)
                    elif args[0] == 'ps':
                        output = (node_id if mount else FOREIGN_NODE_ID).encode()
                    elif args[:2] == ['container', 'inspect']:
                        output = json.dumps([{'Source': mount or '/foreign/encryption.json',
                                              'Destination': '/etc/kubernetes/wispkey-encryption.json'}]).encode()
                    elif args[0] == 'port':
                        output = b'127.0.0.1:12345\n'
                    elif args[0] == 'exec':
                        if 'ssh-keygen' in args:
                            output = b'256 SHA256:stub fixture\n'
                        elif args[-1] == '/var/lib/wispkey-helper/accepted':
                            output = b'accepted\n'
                        elif 'kubectl' in args:
                            command = args[args.index('--kubeconfig=/etc/kubernetes/admin.conf') + 1:]
                            if command[:2] == ['auth', 'can-i']:
                                output, status = b'no\n', 1
                            elif 'etcdctl' in command:
                                output = b'k8s:enc:aescbc:v1:stub'
                            elif command[:2] == ['get', 'namespace']:
                                output = b'{"metadata":{"uid":"namespace-uid"}}'
                            elif command[:2] == ['get', 'secret']:
                                output = json.dumps({'metadata': {'uid': 'secret-uid',
                                    'resourceVersion': '2' if rotated else '1', 'annotations': {'owner': 'preserved'}},
                                    'data': {'other': 'cHJlc2VydmVk'}}).encode()
                            elif command[:2] == ['create', 'token']:
                                output = b'stub-provider-token'
                        else:
                            output = b'stub-public-key'
                    elif args[0] == 'logs':
                        if mode == 'log-failure':
                            status = 29
                        elif mode == 'canary':
                            output = fixture.SECRET
                    elif args[0] == 'rm' and mode == 'cleanup-failure':
                        status = 23
                return subprocess.CompletedProcess(argv, status, stdout=output, stderr=b'')

            fixture_os = SimpleNamespace(name='posix', environ=environment, umask=mock.Mock(), urandom=os.urandom)
            with mock.patch.object(fixture, 'os', fixture_os), mock.patch.object(fixture.shutil, 'which', return_value='stub'), \
                    mock.patch.object(fixture.subprocess, 'run', side_effect=execute), mock.patch('builtins.print'):
                if mode == 'success':
                    fixture.main()
                elif mode == 'sigterm':
                    with self.assertRaises(SystemExit) as error:
                        fixture.main()
                    self.assertEqual(error.exception.code, 143)
                else:
                    expected = {'create-failure': 'docker failed', 'start-failure': 'docker failed',
                                'cleanup-failure': 'fixture cleanup failed', 'log-failure': 'log collection failed',
                                'canary': 'credential appeared', 'zero-kubernetes': 'delivery/revocation'}[mode]
                    with self.assertRaisesRegex(RuntimeError, expected):
                        fixture.main()
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous_handler)
        return calls, ssh_id, node_id

    def test_full_fixture_requires_kubernetes_side_effect_and_successful_clean_logs(self):
        calls, ssh_id, node_id = self.exercise('success')
        self.assertEqual([call for call in calls if call[:2] == ['docker', 'logs']],
                         [['docker', 'logs', ssh_id], ['docker', 'logs', node_id]])
        self.assertTrue(any(call[:3] == ['cargo', 'test', '--locked'] for call in calls))

    def test_failure_and_termination_remove_only_recorded_resources(self):
        for mode in ('create-failure', 'start-failure', 'sigterm', 'cleanup-failure'):
            with self.subTest(mode=mode):
                calls, ssh_id, node_id = self.exercise(mode)
                removals = [call for call in calls if call[:2] == ['docker', 'rm']]
                self.assertEqual(removals, [] if mode == 'create-failure' else
                                 [['docker', 'rm', '-f', '-v', node_id], ['docker', 'rm', '-f', '-v', ssh_id]]
                                 if mode == 'cleanup-failure' else [['docker', 'rm', '-f', '-v', ssh_id]])
                self.assertIn(['docker', 'image', 'rm', IMAGE_ID], calls)

    def test_zero_kubernetes_tests_failed_logs_and_canary_cannot_pass(self):
        for mode in ('zero-kubernetes', 'log-failure', 'canary'):
            with self.subTest(mode=mode):
                self.exercise(mode)


if __name__ == "__main__":
    unittest.main()
