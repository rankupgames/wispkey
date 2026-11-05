"""Exercise the PostgreSQL shell fixture with CLI stubs, without containers."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'tests/support/postgres_operation_fixture.sh'
CONTAINER_ID = 'a' * 64
BASH = (Path(shutil.which('git')).parents[1] / 'bin/bash.exe'
        if os.name == 'nt' and shutil.which('git') else shutil.which('bash'))
STUB = r'''#!/usr/bin/env bash
set -eu
printf '%s' "$(basename "$0")" >> "$STUB_LOG"
printf '\t%s' "$@" >> "$STUB_LOG"
printf '\n' >> "$STUB_LOG"
if [[ "$(basename "$0")" == cargo ]]; then
    if [[ "$STUB_MODE" != zero-tests ]]; then touch "$STUB_STATE"; fi
    exit 0
fi
case "$1" in
create)
    if [[ "$STUB_MODE" == collision ]]; then exit 125; fi
    while [[ "$1" != --cidfile ]]; do shift; done
    printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > "$2"
    if [[ "$STUB_MODE" == partial-create ]]; then exit 125; fi
    ;;
start)
    if [[ "$STUB_MODE" == start-failure || "$STUB_MODE" == start-cleanup-failure ]]; then exit 17; fi
    ;;
rm)
    if [[ "$STUB_MODE" == cleanup-failure || "$STUB_MODE" == start-cleanup-failure ]]; then exit 23; fi
    ;;
port) echo 127.0.0.1:54321 ;;
cp) touch "${@: -1}" ;;
exec)
    if [[ "$*" == *'SHOW ssl'* ]]; then echo on
    elif [[ "$*" == *'pg_get_functiondef'* ]]; then echo 123,synthetic-definition
    elif [[ "$*" == *'-U appuser'* ]]; then
        test -f "$STUB_STATE" || exit 31
        echo preserved-row
    elif [[ "$*" == *'SELECT marker FROM public.fixture_marker'* ]]; then echo preserved-row
    fi
    cat >/dev/null
    ;;
logs)
    if [[ "$STUB_MODE" == log-failure ]]; then exit 29; fi
    if [[ "$STUB_MODE" == canary ]]; then
        echo synthetic_new_password_9214
        # More than a pipe buffer: grep -q must not turn this leak into SIGPIPE success.
        for ((i=0; i<5000; i++)); do echo synthetic-log-padding; done
    elif [[ "$STUB_MODE" == failure-canary ]]; then echo fail_synthetic_canary_9214; fi
    ;;
esac
'''


@unittest.skipUnless(BASH and Path(BASH).exists(), 'Bash is required for the shell fixture')
class PostgresFixtureTests(unittest.TestCase):
    def run_fixture(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            tools = temp / 'bin'
            tools.mkdir()
            for name in ('engine', 'cargo'):
                (tools / name).write_text(STUB, encoding='utf-8', newline='\n')
                (tools / name).chmod(0o755)
            log = temp / 'calls.tsv'
            environment = {key: value for key, value in os.environ.items() if key != 'CI_BUDGET_CGROUP'}
            environment.update(PATH=str(tools) + os.pathsep + os.environ['PATH'],
                               WISPKEY_CONTAINER_ENGINE=(tools / 'engine').as_posix(),
                               WISPKEY_FIXTURE_CONTAINER_NAME='synthetic-fixture',
                               STUB_LOG=log.as_posix(), STUB_STATE=(temp / 'rotated').as_posix(),
                               STUB_MODE=mode, TMPDIR=temp.as_posix())
            result = subprocess.run([str(BASH), str(FIXTURE)], input='', capture_output=True,
                                    text=True, env=environment, timeout=60)
            calls = [line.split('\t') for line in log.read_text().splitlines()] if log.exists() else []
            remaining = [path for path in temp.iterdir() if path.is_dir() and path != tools]
            if mode not in ('cleanup-failure', 'start-cleanup-failure'):
                self.assertEqual(remaining, [], 'successful cleanup must honor a custom TMPDIR')
            else:
                self.assertEqual(len(remaining), 1, 'failed cleanup must retain owned evidence')
            return result, calls

    def test_rotation_uses_locked_exact_test_and_collects_logs_once(self):
        result, calls = self.run_fixture('success')
        self.assertEqual(result.returncode, 0, result.stderr)
        created = next(call for call in calls if call[1] == 'create')
        self.assertIn('POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256', created)
        self.assertIn(['cargo', 'test', '--locked', '--lib',
                       'operations::postgres::tests::disposable_postgres_tls_rotation',
                       '--', '--ignored', '--exact'], calls)
        self.assertEqual([call for call in calls if call[1] == 'logs'], [['engine', 'logs', CONTAINER_ID]])
        self.assertEqual([call for call in calls if call[1] == 'rm'], [['engine', 'rm', '-f', '-v', CONTAINER_ID]])

    def test_foreign_name_collision_removes_nothing(self):
        result, calls = self.run_fixture('collision')
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertEqual([call for call in calls if call[1] in ('rm', 'start')], [])

    def test_created_container_is_removed_after_create_or_start_failure(self):
        for mode, status in [('partial-create', 125), ('start-failure', 17), ('start-cleanup-failure', 17)]:
            with self.subTest(mode=mode):
                result, calls = self.run_fixture(mode)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual([call for call in calls if call[1] == 'rm'],
                                 [['engine', 'rm', '-f', '-v', CONTAINER_ID]])
                self.assertEqual('cleanup failed' in result.stderr, mode == 'start-cleanup-failure')

    def test_cleanup_failure_changes_success_to_failure(self):
        result, calls = self.run_fixture('cleanup-failure')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cleanup failed', result.stderr)

    def test_zero_test_success_cannot_skip_rotation(self):
        result, calls = self.run_fixture('zero-tests')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any('appuser' in call for call in calls))

    def test_failed_log_collection_and_both_canaries_fail(self):
        for mode in ('log-failure', 'canary', 'failure-canary'):
            with self.subTest(mode=mode):
                result, calls = self.run_fixture(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len([call for call in calls if call[1] == 'logs']), 1)
                if mode != 'log-failure':
                    self.assertIn('appeared in PostgreSQL logs', result.stderr)


if __name__ == '__main__':
    unittest.main()
