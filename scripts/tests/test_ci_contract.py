"""Keep paused workflows and the Jenkins source/lane contract consistent."""

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
    def test_paused_workflows_remain_dispatch_only(self):
        for name in ('ci', 'automation-tests', 'owner-ipc-contention', 'cross-node-acceptance'):
            with self.subTest(workflow=name):
                text = (ROOT / f'.github/workflows/{name}.yml').read_text()
                self.assertEqual(blocks(text, 'on'), ['on:\n  workflow_dispatch:'])

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
