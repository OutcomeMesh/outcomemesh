#!/usr/bin/env python3
"""Audit repository protections; optionally add missing CI/CodeQL requirements."""
import argparse
import json
import re
import subprocess

from release_gate import CI_JOBS, CODEQL_JOBS, gh_json

REQUIRED = CI_JOBS | CODEQL_JOBS
ACTIONS_APP_ID = 15368


def required_checks(current):
    # Preserve additional requirements installed by repository administrators.
    checks = {(c['context'], c.get('app_id')) for c in current['checks']}
    checks.update((name, ACTIONS_APP_ID) for name in REQUIRED)
    return {'strict': True, 'checks': [{'context': name, 'app_id': app}
                                     for name, app in sorted(checks, key=lambda c: (c[0], c[1] or 0))]}


def findings(repo, protection, actions, tag_rules):
    missing = []
    expected = {'default_branch': 'main', 'allow_squash_merge': True, 'allow_merge_commit': False,
                'allow_rebase_merge': False, 'delete_branch_on_merge': True, 'allow_auto_merge': True,
                'has_issues': True, 'has_discussions': True}
    for key, value in expected.items():
        if repo.get(key) != value:
            missing.append('repository setting: ' + key)
    checks = protection['required_status_checks']
    have = {(c['context'], c.get('app_id')) for c in checks['checks']}
    if not checks['strict'] or any((n, ACTIONS_APP_ID) not in have for n in REQUIRED):
        missing.append('strict CI and CodeQL requirements')
    review = protection['required_pull_request_reviews']
    if review['required_approving_review_count'] < 1 or not all(review[k] for k in ('dismiss_stale_reviews', 'require_code_owner_reviews', 'require_last_push_approval')):
        missing.append('pull request review policy')
    for name in ('allow_force_pushes', 'allow_deletions'):
        if protection[name]['enabled']:
            missing.append(name)
    if actions != {'default_workflow_permissions': 'read', 'can_approve_pull_request_reviews': False}:
        missing.append('default Actions permissions')
    security = repo.get('security_and_analysis', {})
    for name in ('secret_scanning', 'secret_scanning_push_protection'):
        if security.get(name, {}).get('status') != 'enabled':
            missing.append(name)
    protected = any(r['target'] == 'tag' and r['enforcement'] == 'active'
                    and r['conditions']['ref_name'] == {'include': ['refs/tags/v*'], 'exclude': []}
                    and {'deletion', 'non_fast_forward'}.issubset({rule['type'] for rule in r['rules']})
                    and not r.get('bypass_actors') for r in tag_rules)
    if not protected:
        missing.append('immutable version tags')
    return missing


def audit(repo, *, apply_checks=False, api=gh_json, update=None):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('invalid repository')
    base = 'repos/' + repo
    metadata = api(base)
    protection = api(base + '/branches/main/protection')
    if apply_checks:
        desired = required_checks(protection['required_status_checks'])
        update(base + '/branches/main/protection/required_status_checks', desired)
        protection = api(base + '/branches/main/protection')
    actions = api(base + '/actions/permissions/workflow')
    tag_rules = [api(base + '/rulesets/' + str(r['id'])) for r in api(base + '/rulesets') if r['target'] == 'tag']
    missing = findings(metadata, protection, actions, tag_rules)
    return {'repository': repo, 'missing': missing, 'required_check_count': len(REQUIRED),
            'administrator_bypass': not protection['enforce_admins']['enabled']}


def update_checks(endpoint, payload):
    subprocess.run(['gh', 'api', '--method', 'PATCH', endpoint, '--input', '-'],
                   input=json.dumps(payload), text=True, check=True, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='OutcomeMesh/outcomemesh')
    parser.add_argument('--apply-checks', action='store_true', help='add missing required checks without removing existing protection')
    args = parser.parse_args()
    result = audit(args.repo, apply_checks=args.apply_checks, update=update_checks)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result['missing']:
        raise SystemExit(1)
