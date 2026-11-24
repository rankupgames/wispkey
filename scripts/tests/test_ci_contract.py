"""Keep paused workflows and the Jenkins source/lane contract consistent."""

import json
import importlib.util
from pathlib import Path
import re
import unittest

from test_workflow_boundaries import blocks


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('jenkins_request', ROOT / 'ci/jenkins/request.py')
request = importlib.util.module_from_spec(spec)
spec.loader.exec_module(request)


class CiContractTests(unittest.TestCase):
    def test_bootstrap_workflows_preserve_automatic_coverage(self):
        for name in ('ci', 'automation-tests', 'owner-ipc-contention', 'cross-node-acceptance'):
            with self.subTest(workflow=name):
                text = (ROOT / f'.github/workflows/{name}.yml').read_text()
                events = blocks(text, 'on')[0]
                self.assertIn('  pull_request:', events)
                self.assertIn('  workflow_dispatch:', events)
                if name in ('ci', 'automation-tests'):
                    self.assertIn('  push:', events)
                if name == 'owner-ipc-contention':
                    self.assertIn('  schedule:', events)
        native = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertEqual(native.count('os: [ubuntu-latest, macos-latest, windows-latest]'), 2)
        self.assertIn('macOS native-host installer and ACL fixtures', native)
        contention = (ROOT / '.github/workflows/owner-ipc-contention.yml').read_text()
        self.assertIn('runs-on: windows-latest', contention)
        self.assertIn('run: ./scripts/test-owner-ipc-contention.ps1', contention)

    def test_dispatch_lanes_match_jenkins_jobs_and_check_arms(self):
        pipeline = (ROOT / 'Jenkinsfile').read_text()
        checks = (ROOT / 'ci/jenkins/check.sh').read_text()
        configured = re.findall(r"checkCommand: 'bash ci/jenkins/check.sh ([\w-]+)'", pipeline)
        arms = re.findall(r'(?m)^([\w-]+)\)$', checks)
        self.assertEqual(len(configured), len(request.LANES))
        self.assertEqual(set(configured), set(request.LANES))
        self.assertEqual(set(arms), set(request.LANES))
        timeouts = re.search(r'def laneTimeoutMinutes = \[([^\]]+)\]', pipeline)
        self.assertIsNotNone(timeouts)
        self.assertEqual(set(re.findall(r"'?([\w-]+)'?: \d+", timeouts[1])), set(request.LANES))

    def test_repository_workflow_preserves_lane_and_artifact_contract(self):
        text = (ROOT / '.github/workflows/jenkins.yml').read_text()
        literal = blocks(text, 'JENKINS_CI')[0].split('\n', 1)[1]
        config = json.loads(literal)
        self.assertEqual(config['schemaVersion'], 1)
        self.assertEqual(config['project'], 'wispkey')
        self.assertEqual(set(config['lanes']), set(request.LANES))
        jobs = text.split('\njobs:\n', 1)[1]
        self.assertEqual(set(re.findall(r'(?m)^  ([a-z-]+):$', jobs)), set(request.LANES))
        for name, lane in config['lanes'].items():
            with self.subTest(lane=name):
                self.assertEqual(lane['status'], 'jenkins/wispkey/' + name)
                self.assertEqual(lane['command'], 'bash ci/jenkins/check.sh ' + name)
                self.assertEqual(lane['pullRequests'], 'same-repository')
                local = name in ('postgres', 'cross-node')
                self.assertEqual(lane['execution'], 'jenkins-only' if local else 'local-first')
                self.assertEqual(lane['runner'], {'os': 'linux', 'profile': 'default-4' if local else 'small-web'})
                self.assertEqual(lane['artifacts'], 'target/jenkins/artifacts/wispkey-browser-extensions.tar' if name == 'browser' else '')
        self.assertEqual(jobs.count('uses: ./.github/workflows/jenkins-submit.yml'), len(request.LANES))
        self.assertEqual(jobs.count('source-sha: ${{ github.event.pull_request.head.sha || github.sha }}'), len(request.LANES))
        self.assertEqual(jobs.count("if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"), len(request.LANES))
        self.assertNotIn('secrets: inherit', jobs)
        self.assertNotIn('machine:', jobs)

    def test_registered_pipeline_requires_exact_source_pin(self):
        pipeline = (ROOT / 'Jenkinsfile').read_text()
        for guard in (
            f"remotes[0].url != '{request.REPOSITORY}'",
            'def revision = params.SOURCE_SHA',
            'revision ==~ /[0-9a-f]{40}/',
            "branches[0].name in [revision, '${SOURCE_SHA}']",
            "sourceRevisionParameter: 'SOURCE_SHA'",
            'pipelineRevision: revision',
            'sourceRepository: remotes[0].url',
            "scriptPath: 'Jenkinsfile'",
        ):
            with self.subTest(guard=guard):
                self.assertIn(guard, pipeline)


if __name__ == '__main__':
    unittest.main()
