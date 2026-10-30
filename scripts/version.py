#!/usr/bin/env python3
"""The release version is recorded once, in VERSION; tags add the v prefix."""
from pathlib import Path
import re

NORMAL = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')


def numbers(value):
    if not NORMAL.fullmatch(value):
        raise ValueError('version must contain three numbers, for example 0.2.0')
    return tuple(map(int, value.split('.')))


def source_version(root):
    text = (Path(root) / 'VERSION').read_text(encoding='ascii')
    value = text.removesuffix('\n')
    numbers(value)
    if text != value + '\n':
        raise ValueError('VERSION must contain one version and a final newline')
    return value


def require_version(root, tag):
    if tag != 'v' + source_version(root):
        raise ValueError('tag must match the version recorded in VERSION')
    return tag


def require_progression(tag, existing):
    current = numbers(tag.removeprefix('v'))
    for previous in existing:
        if previous == tag or not previous.startswith('v'):
            continue
        # Historical alpha tags stay intact. Their numeric base participates in
        # ordering, but no new numbered prereleases are created by this policy.
        base = previous[1:].split('-', 1)[0]
        if NORMAL.fullmatch(base) and numbers(base) > current:
            raise ValueError('release version must advance beyond existing version tags')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check', 'show'])
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    value = source_version(root)
    if args.command == 'check':
        notes = root / 'docs' / 'releases' / ('v' + value + '.md')
        if not notes.is_file() or not notes.read_text().strip():
            raise SystemExit('VERSION requires committed release notes at ' + str(notes.relative_to(root)))
    print(value)
