#!/usr/bin/env python3
"""Require the latest complete CI and CodeQL results for an annotated release tag."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlencode

from ci import GROUPS
from version import require_version, require_progression
from release import ROOT, run, validate_version

CI_JOBS = {'prepare', 'hygiene', 'macos', 'windows', 'archives', 'required',
           *('race (' + group + ')' for group in GROUPS)}
CODEQL_JOBS = {'Analyze (go)', 'Analyze (python)', 'Analyze (actions)'}
WORKFLOWS = {
    '.github/workflows/ci.yml': ('push', CI_JOBS),
    'dynamic/github-code-scanning/codeql': ('dynamic', CODEQL_JOBS),
}


def gh_json(endpoint):
    return json.loads(subprocess.check_output(['gh', 'api', endpoint], text=True))


def pages(api, endpoint, field):
    result = []
    separator = '&' if '?' in endpoint else '?'
    for page in range(1, 101):
        response = api(endpoint + separator + urlencode({'per_page': 100, 'page': page}))
        items = response[field]
        result.extend(items)
        if len(items) < 100:
            return result
    raise ValueError('API result exceeds the bounded release review')


def latest_runs(runs, sha):
    selected = []
    for path, (event, _) in WORKFLOWS.items():
        candidates = [r for r in runs if r['path'] == path and r['head_sha'] == sha
                      and r['head_branch'] == 'main' and r['event'] == event]
        if not candidates:
            raise ValueError('missing required workflow: ' + path)
        latest = max(candidates, key=lambda r: r['id'])
        if latest['status'] != 'completed' or latest['conclusion'] != 'success':
            raise ValueError('latest required workflow did not succeed: ' + path)
        selected.append(latest)
    return selected


def verify_jobs(jobs, required):
    names = [job['name'] for job in jobs]
    if len(names) != len(set(names)) or not required.issubset(names):
        raise ValueError('required jobs are missing or duplicated')
    if any(j['status'] != 'completed' or j['conclusion'] != 'success' for j in jobs):
        raise ValueError('a required workflow contains an incomplete, failed or skipped job')


def verify_remote(repo, sha, api=gh_json):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('invalid repository or commit')
    endpoint = f'repos/{repo}/actions/runs?' + urlencode({'head_sha': sha, 'branch': 'main'})
    selected = latest_runs(pages(api, endpoint, 'workflow_runs'), sha)
    evidence = []
    for workflow in selected:
        attempt = workflow['run_attempt']
        jobs = pages(api, f"repos/{repo}/actions/runs/{workflow['id']}/attempts/{attempt}/jobs", 'jobs')
        verify_jobs(jobs, WORKFLOWS[workflow['path']][1])
        evidence.append({'path': workflow['path'], 'run_id': workflow['id'], 'attempt': attempt,
                         'jobs': sorted(j['name'] for j in jobs)})
    # Do not admit a rerun or newer pending run that started during job inspection.
    current = latest_runs(pages(api, endpoint, 'workflow_runs'), sha)
    if [(r['id'], r['run_attempt'], r['updated_at']) for r in current] != [(r['id'], r['run_attempt'], r['updated_at']) for r in selected]:
        raise ValueError('workflow state changed during release review')
    return evidence


def verify_tag(tag):
    validate_version(tag)
    if run('git', 'cat-file', '-t', 'refs/tags/' + tag) != 'tag':
        raise ValueError('release tags must be annotated')
    sha = run('git', 'rev-parse', 'refs/tags/' + tag + '^{commit}')
    if sha != run('git', 'rev-parse', 'HEAD'):
        raise ValueError('checkout does not match release tag')
    subprocess.run(['git', 'merge-base', '--is-ancestor', sha, 'origin/main'], cwd=ROOT, check=True)
    notes = ROOT / 'docs' / 'releases' / (tag + '.md')
    if not notes.is_file() or not notes.read_text().strip():
        raise ValueError('release notes must be committed with the tagged source')
    if run('git', 'status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('release gate requires a clean checkout')
    require_version(ROOT, tag)
    require_progression(tag, run("git", "tag", "--list", "v*").splitlines())
    return sha


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY', ''))
    args = parser.parse_args()
    sha = verify_tag(args.tag)
    evidence = verify_remote(args.repo, sha)
    print(json.dumps({'tag': args.tag, 'commit': sha, 'workflows': evidence}, sort_keys=True))
