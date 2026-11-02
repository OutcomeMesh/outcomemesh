import copy
import unittest

from ci_infrastructure import ALLOCATION_FAILURE, eligible_jobs, recover
from release_gate import CI_JOBS


class InfrastructureRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.repo = 'OutcomeMesh/outcomemesh'
        self.head = 'a' * 40
        self.run = dict(id=10, name='CI', path='.github/workflows/ci.yml', status='completed', conclusion='failure', run_attempt=1,
                        head_repository={'full_name': self.repo}, head_sha=self.head, head_branch='main', event='push', updated_at='unchanged')
        self.jobs = [dict(id=i + 100, name=name, status='completed', conclusion='success', runner_id=1, runner_name='hosted', steps=[{'name': 'test'}], labels=['ubuntu-24.04']) for i, name in enumerate(sorted(CI_JOBS))]
        self.mac = next(j for j in self.jobs if j['name'] == 'macos')
        self.mac.update(conclusion='cancelled', runner_id=0, runner_name='', steps=[], labels=['macos-15'])
        next(j for j in self.jobs if j['name'] == 'required')['conclusion'] = 'failure'
        self.annotations = [dict(annotation_level='failure', message=ALLOCATION_FAILURE)]
        self.posts = []
        self.latest = [self.run]
        self.current = self.head

    def api(self, endpoint, method='GET'):
        if method == 'POST':
            self.posts.append(endpoint)
            return None
        if endpoint.endswith('/actions/runs/10'): return copy.deepcopy(self.run)
        if '/git/ref/' in endpoint: return {'object': {'sha': self.current}}
        if '/annotations?' in endpoint: return self.annotations
        if '/attempts/' in endpoint: return {'jobs': self.jobs}
        if '/actions/runs?' in endpoint: return {'workflow_runs': self.latest}
        if '/pulls/' in endpoint: return self.pr
        raise AssertionError(endpoint)

    def test_bounded_complete_retry_and_read_only_review(self):
        self.assertIn('eligible', recover(self.repo, 10, api=self.api))
        self.assertFalse(self.posts)
        self.assertTrue(recover(self.repo, 10, True, self.api)['retried'])
        self.assertEqual(self.posts, ['repos/' + self.repo + '/actions/runs/10/rerun'])
        self.run['run_attempt'] = 2
        self.assertTrue(recover(self.repo, 10, True, self.api)['retried'])
        self.run['run_attempt'] = 3
        self.assertFalse(recover(self.repo, 10, True, self.api)['retried'])

    def test_real_failures_unknown_jobs_and_started_runner_never_retry(self):
        for changes in [dict(runner_id=1), dict(runner_name='hosted'), dict(steps=[{'name': 'checkout'}]), dict(labels=['self-hosted']), dict(conclusion='success')]:
            jobs = copy.deepcopy(self.jobs)
            next(j for j in jobs if j['name'] == 'macos').update(changes)
            self.assertFalse(eligible_jobs(jobs, self.annotations))
        for name in CI_JOBS - {'macos', 'required'}:
            jobs = copy.deepcopy(self.jobs)
            next(j for j in jobs if j['name'] == name)['conclusion'] = 'failure'
            self.assertFalse(eligible_jobs(jobs, self.annotations))
        self.assertFalse(eligible_jobs(self.jobs[:-1], self.annotations))
        self.assertFalse(eligible_jobs(self.jobs + [self.jobs[0]], self.annotations))
        for annotations in [[], [dict(annotation_level='failure', message='test failed')], self.annotations * 2]:
            self.assertFalse(eligible_jobs(self.jobs, annotations))

    def test_old_heads_and_superseded_runs_never_retry(self):
        self.current = 'b' * 40
        self.assertFalse(recover(self.repo, 10, True, self.api)['retried'])
        self.current = self.head
        self.latest = [self.run, dict(self.run, id=11)]
        self.assertFalse(recover(self.repo, 10, True, self.api)['retried'])
        self.assertFalse(self.posts)

    def test_untrusted_event_and_fork_are_refused(self):
        for changes in [dict(event='workflow_dispatch'), dict(head_repository=None), dict(head_branch='other'), dict(head_repository={'full_name': 'fork/repo'}), dict(path='other.yml'), dict(status='in_progress'), dict(conclusion='cancelled')]:
            before = self.run
            self.run = dict(before, **changes)
            self.assertFalse(recover(self.repo, 10, True, self.api)['retried'])
            self.run = before
        self.assertFalse(self.posts)

    def test_current_same_repository_pr_only(self):
        self.run.update(event='pull_request', head_branch='topic', pull_requests=[{'number': 5}])
        self.pr = {'state': 'open', 'head': {'sha': self.head, 'ref': 'topic', 'repo': {'full_name': self.repo}}, 'base': {'ref': 'main'}}
        self.assertTrue(recover(self.repo, 10, True, self.api)['retried'])
        self.pr['head']['sha'] = 'b' * 40
        self.assertFalse(recover(self.repo, 10, True, self.api)['retried'])
        self.pr['head']['sha'] = self.head
        self.pr['head']['repo']['full_name'] = 'fork/repo'
        self.assertFalse(recover(self.repo, 10, True, self.api)['retried'])
        self.pr['head']['repo'] = None
        self.assertFalse(recover(self.repo, 10, True, self.api)['retried'])

    def test_change_between_reviews_refuses_post(self):
        reads = 0
        def api(endpoint, method='GET'):
            nonlocal reads
            if endpoint.endswith('/actions/runs/10'):
                reads += 1
                if reads == 2: self.run['run_attempt'] = 2
            return self.api(endpoint, method)
        with self.assertRaises(ValueError): recover(self.repo, 10, True, api)
        self.assertFalse(self.posts)


if __name__ == '__main__':
    unittest.main()
