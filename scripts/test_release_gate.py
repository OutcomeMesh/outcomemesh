import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release
import release_gate as gate

SHA = 'a' * 40


def fixtures():
    return [dict(id=i + 1, path=path, head_sha=SHA, head_branch='main', event=event,
                 status='completed', conclusion='success', run_attempt=1, updated_at='now')
            for i, (path, (event, _)) in enumerate(gate.WORKFLOWS.items())]


class ReleaseGate(unittest.TestCase):
    def test_latest_failure_pending_or_skipped_cannot_hide_behind_old_success(self):
        for status, conclusion in [('completed', 'failure'), ('in_progress', None),
                                   ('queued', None), ('completed', 'skipped'), ('completed', 'cancelled')]:
            for workflow in range(2):
                runs = fixtures()
                bad = dict(runs[workflow], id=20, status=status, conclusion=conclusion)
                with self.assertRaises(ValueError):
                    gate.latest_runs(runs + [bad], SHA)

    def test_exact_main_commit_and_expected_events_required(self):
        for key, value in [('head_sha', 'b' * 40), ('head_branch', 'feature'), ('event', 'pull_request'), ('path', 'other.yml')]:
            runs = fixtures()
            runs[0][key] = value
            with self.assertRaises(ValueError):
                gate.latest_runs(runs, SHA)

    def test_each_job_must_succeed_and_no_required_job_may_be_omitted(self):
        jobs = [dict(name=name, status='completed', conclusion='success') for name in sorted(gate.CI_JOBS)]
        gate.verify_jobs(jobs, gate.CI_JOBS)
        for bad in [jobs[:-1], jobs + [jobs[0]], [dict(j, conclusion='skipped') for j in jobs]]:
            with self.assertRaises(ValueError):
                gate.verify_jobs(bad, gate.CI_JOBS)

    def test_remote_review_uses_exact_attempt_and_detects_reruns(self):
        calls, runs = [], fixtures()
        def api(endpoint):
            calls.append(endpoint)
            if '/attempts/' in endpoint:
                workflow = runs[0] if '/runs/1/' in endpoint else runs[1]
                return {'jobs': [dict(name=n, status='completed', conclusion='success')
                                 for n in gate.WORKFLOWS[workflow['path']][1]]}
            return {'workflow_runs': copy.deepcopy(runs)}
        result = gate.verify_remote('OutcomeMesh/outcomemesh', SHA, api)
        self.assertEqual(len(result), 2)
        self.assertTrue(any('/attempts/1/jobs' in c for c in calls))
        seen = 0
        def changing(endpoint):
            nonlocal seen
            if '/actions/runs?' in endpoint:
                seen += 1
                if seen == 2:
                    runs[0]['run_attempt'] = 2
            return api(endpoint)
        with self.assertRaisesRegex(ValueError, 'state changed'):
            gate.verify_remote('OutcomeMesh/outcomemesh', SHA, changing)

    def test_annotated_tag_notes_ancestry_and_exact_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q')
            git('config', 'user.name', 'Fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            notes = root / 'docs/releases/v0.1.0-alpha.2.md'
            notes.parent.mkdir(parents=True)
            notes.write_text('Release notes\n')
            git('add', '.')
            git('commit', '-qm', 'source')
            sha = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', sha)
            git('tag', '-a', 'v0.1.0-alpha.2', '-m', 'pre-alpha')
            git('tag', 'v0.1.0-alpha.3')
            with patch.object(gate, 'ROOT', root), patch.object(gate, 'run', side_effect=lambda command, *args: git(*args)):
                self.assertEqual(gate.verify_tag('v0.1.0-alpha.2'), sha)
                with self.assertRaisesRegex(ValueError, 'annotated'):
                    gate.verify_tag('v0.1.0-alpha.3')
                notes.write_text('uncommitted change')
                with self.assertRaisesRegex(ValueError, 'clean checkout'):
                    gate.verify_tag('v0.1.0-alpha.2')
                git('add', '.')
                git('commit', '-qm', 'next')
                with self.assertRaisesRegex(ValueError, 'does not match'):
                    gate.verify_tag('v0.1.0-alpha.2')

    def test_reproducibility_compares_full_file_sets_and_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            a, b = Path(temporary) / 'a', Path(temporary) / 'b'
            a.mkdir(); b.mkdir()
            for folder in (a, b):
                (folder / 'archive.tar.gz').write_bytes(b'archive')
                (folder / 'BUILDINFO.json').write_text(json.dumps({'commit': SHA}))
            release.compare_archives(a, b)
            (b / 'BUILDINFO.json').write_text('{}')
            with self.assertRaises(ValueError):
                release.compare_archives(a, b)
            (b / 'BUILDINFO.json').write_bytes((a / 'BUILDINFO.json').read_bytes())
            (b / 'extra').write_text('unexpected')
            with self.assertRaises(ValueError):
                release.compare_archives(a, b)
            (b / 'extra').unlink()
            (b / 'alias').symlink_to(a / 'archive.tar.gz')
            with self.assertRaises(ValueError):
                release.compare_archives(a, b)


if __name__ == '__main__':
    unittest.main()
