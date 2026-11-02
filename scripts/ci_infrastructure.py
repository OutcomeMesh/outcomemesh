#!/usr/bin/env python3
"""Retry a complete CI run only after proven hosted macOS allocation failure.

Never changes check results, retries test failures, executes PR code, or selects
an old commit. The workflow checks out this script from the protected main branch.
"""
import argparse
import json
import os
import re
import subprocess

from release_gate import CI_JOBS, pages

MAX_ATTEMPTS = 3
ALLOCATION_FAILURE = 'The job was not acquired by Runner of type hosted even after multiple attempts'
MACOS_LABELS = {'macos-15', 'macos-15-intel'}


def eligible_jobs(jobs, annotations):
    names = [j['name'] for j in jobs]
    if len(names) != len(set(names)) or set(names) != CI_JOBS:
        return False
    failed = {j['name'] for j in jobs if j.get('status') != 'completed' or j.get('conclusion') != 'success'}
    if failed != {'macos', 'required'}:
        return False
    job = next(j for j in jobs if j['name'] == 'macos')
    if (job.get('status') != 'completed' or job.get('conclusion') not in {'cancelled', 'failure'}
            or job.get('runner_id') != 0 or job.get('runner_name') != ''
            or job.get('steps') != [] or len(job.get('labels', [])) != 1
            or job['labels'][0] not in MACOS_LABELS):
        return False
    failures = [a for a in annotations if a.get('annotation_level') == 'failure']
    return len(failures) == 1 and failures[0].get('message') == ALLOCATION_FAILURE


def gh_api(endpoint, method='GET'):
    argv = ['gh', 'api', '--method', method, endpoint]
    raw = subprocess.check_output(argv, text=True)
    return json.loads(raw) if raw.strip() else None


def review(repo, run_id, api=gh_api):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or type(run_id) is not int or run_id <= 0:
        raise ValueError('invalid repository/run')
    prefix = f'repos/{repo}'
    run = api(f'{prefix}/actions/runs/{run_id}')
    attempt = run.get('run_attempt', 0)
    if (run.get('id') != run_id or run.get('path') != '.github/workflows/ci.yml'
            or run.get('name') != 'CI' or run.get('status') != 'completed'
            or run.get('conclusion') != 'failure' or type(attempt) is not int
            or not 1 <= attempt < MAX_ATTEMPTS
            or (run.get('head_repository') or {}).get('full_name') != repo
            or not re.fullmatch(r'[0-9a-f]{40}', run.get('head_sha', ''))):
        return None
    head, branch = run['head_sha'], run.get('head_branch')
    if run.get('event') == 'push':
        if branch != 'main' or api(f'{prefix}/git/ref/heads/main')['object']['sha'] != head:
            return None
    elif run.get('event') == 'pull_request':
        prs = run.get('pull_requests', [])
        if len(prs) != 1 or type(prs[0].get('number')) is not int:
            return None
        pr = api(f"{prefix}/pulls/{prs[0]['number']}")
        if (pr.get('state') != 'open' or pr['head']['sha'] != head or pr['head']['ref'] != branch
                or (pr['head'].get('repo') or {}).get('full_name') != repo or pr['base']['ref'] != 'main'):
            return None
    else:
        return None
    latest = pages(api, f'{prefix}/actions/runs?head_sha={head}', 'workflow_runs')
    matching = [r for r in latest if r.get('path') == run['path'] and r.get('event') == run['event'] and r.get('head_branch') == branch]
    if not matching or max(r['id'] for r in matching) != run_id:
        return None
    jobs = pages(api, f'{prefix}/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs')
    candidates = [j for j in jobs if j.get('name') == 'macos']
    if len(candidates) != 1:
        return None
    job = candidates[0]
    if type(job.get('id')) is not int:
        return None
    # Numeric job ID is used under this fixed repository, never an event URL.
    annotations = api(f"{prefix}/check-runs/{job['id']}/annotations?per_page=100")
    if not isinstance(annotations, list) or len(annotations) >= 100 or not eligible_jobs(jobs, annotations):
        return None
    return {'run_id': run_id, 'attempt': attempt, 'head': head, 'updated_at': run['updated_at']}


def recover(repo, run_id, apply=False, api=gh_api):
    decision = review(repo, run_id, api)
    if decision is None:
        return {'retried': False, 'reason': 'no eligible current infrastructure failure'}
    if not apply:
        return {'retried': False, 'eligible': decision}
    if review(repo, run_id, api) != decision:
        raise ValueError('run changed during infrastructure review')
    # Full rerun preserves the exact-head gate: no mix of jobs from old attempts.
    api(f'repos/{repo}/actions/runs/{run_id}/rerun', 'POST')
    return {'retried': True, 'previous_attempt': decision['attempt'], 'head': decision['head']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY', ''))
    parser.add_argument('--run-id', type=int)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    run_id = args.run_id
    if run_id is None:
        with open(os.environ['GITHUB_EVENT_PATH']) as f:
            event = json.load(f)
        run_id = event['workflow_run']['id']
    print(json.dumps(recover(args.repo, run_id, args.apply), sort_keys=True))
