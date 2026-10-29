#!/usr/bin/env python3
"""Run disjoint core suites; the same groups are used locally and in Actions."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
GROUPS = {
    'archive': ['-run', '^TestArchive'],
    'prune': ['-run', '^TestPrune'],
    'base': ['-skip', '^(TestArchive|TestPrune|TestRemote|TestManagedCustody|TestAdmission|TestRequired|TestCustody|TestGuardedProfile5)'],
    'custody': ['-run', '^TestCustody', '-skip', '^TestCustodyV2'],
    'custody-v2': ['-run', '^TestCustodyV2', '-skip', '^TestCustodyV2(Enrolled|Required)'],
    'custody-enrolled': ['-run', '^TestCustodyV2Enrolled'],
    'custody-required': ['-run', '^TestCustodyV2Required'],
    'managed': ['-run', '^TestManagedCustody'],
    'remote': ['-run', '^TestRemote'],
    'admission': ['-run', '^Test(Admission|Required)', '-skip', '^TestAdmissionDelivery'],
    'admission-delivery': ['-run', '^TestAdmissionDelivery'],
    'guarded-profile5': ['-run', '^TestGuardedProfile5'],
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('group', choices=[*GROUPS, 'all', 'matrix'])
    args = parser.parse_args()
    if args.group == 'matrix':
        print(json.dumps({'group': list(GROUPS)}))
    else:
        for group in GROUPS if args.group == 'all' else [args.group]:
            subprocess.run([os.environ.get('GO', 'go'), 'test', '-race', './...', *GROUPS[group], '-count=1', '-timeout=40m'], cwd=ROOT, check=True)
