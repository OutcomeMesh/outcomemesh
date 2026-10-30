#!/usr/bin/env python3
"""Build official, reproducible OutcomeMesh archives from a clean checkout."""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import zipfile

from version import numbers, require_version, source_version

ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = (('linux', 'amd64'), ('linux', 'arm64'), ('darwin', 'amd64'), ('darwin', 'arm64'), ('windows', 'amd64'), ('windows', 'arm64'))
PREFIX = 'github.com/outcomemesh/outcomemesh/internal/buildinfo.'


def run(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True).strip()


def validate_version(version):
    if not version.startswith('v'):
        raise ValueError('version tag must start with v')
    numbers(version[1:])
    return version


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(path, name, entries, epoch):
    # Normalize metadata before opening output; reject paths on both platforms.
    for relative in [name, *entries]:
        member = PurePosixPath(relative)
        if not relative or member.is_absolute() or '..' in member.parts or str(member) != relative or "\\" in relative or ':' in relative:
            raise ValueError('noncanonical archive member')
    with path.open('xb') as output:
        if path.suffix == '.zip':
            date = datetime.datetime.fromtimestamp(max(epoch, 315532800), datetime.timezone.utc)
            with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
                for relative, (data, mode) in sorted(entries.items()):
                    info = zipfile.ZipInfo(name + '/' + relative, date.timetuple()[:6])
                    info.create_system = 3
                    info.external_attr = (0o100000 | mode) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    zipped.writestr(info, data, compresslevel=9)
        else:
            with gzip.GzipFile(fileobj=output, filename='', mode='wb', mtime=epoch, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
                    for relative, (data, mode) in sorted(entries.items()):
                        info = tarfile.TarInfo(name + '/' + relative)
                        info.size, info.mode, info.mtime = len(data), mode, epoch
                        tar.addfile(info, io.BytesIO(data))


def json_stream(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        yield value
        text = text.lstrip()[end:]


def dependency_notices(env):
    modules = {}
    for package in json_stream(run('go', 'list', '-mod=readonly', '-deps', '-json', './cmd/omd', env=env)):
        module = package.get('Module', {})
        if module and not module.get('Main'):
            if module.get('Replace'):
                raise ValueError('official builds cannot use replacement modules')
            modules[module['Path']] = module
    notices = {}
    dependencies = []
    for name, module in sorted(modules.items()):
        directory = Path(module['Dir'])
        files = sorted(p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')))
        if not files:
            raise ValueError('dependency has no root license/notice: ' + name)
        for path in files:
            notices['THIRD_PARTY_LICENSES/' + name + '@' + module['Version'] + '/' + path.name] = (path.read_bytes(), 0o644)
        dependencies.append({k.lower(): module[k] for k in ('Path', 'Version', 'Sum') if k in module})
    notices['THIRD_PARTY_LICENSES/Go-LICENSE'] = ((Path(run('go', 'env', 'GOROOT', env=env)) / 'LICENSE').read_bytes(), 0o644)
    notices['DEPENDENCIES.json'] = (json_bytes(dependencies), 0o644)
    return notices


def source_manifest():
    tracked = run('git', 'ls-files', '-z').split('\0')
    return ''.join(sha((ROOT / p).read_bytes()) + '  ' + p + '\n' for p in sorted(tracked) if p).encode()


def require_source(commit, manifest):
    if run('git', 'status', '--porcelain', '--untracked-files=normal') or run('git', 'rev-parse', 'HEAD') != commit or source_manifest() != manifest:
        raise ValueError('source changed during packaging; partial output is not a release')


def compare_archives(first, second):
    def files(root):
        result = {}
        for path in Path(root).iterdir():
            if path.is_symlink() or not path.is_file():
                raise ValueError('unexpected object in release output')
            result[path.name] = sha(path.read_bytes())
        if not result:
            raise ValueError('empty release output')
        return result
    if files(first) != files(second):
        raise ValueError('independent builds produced different release bytes')


def build(version, destination, *, cache=None, ci=False):
    validate_version(version)
    require_version(ROOT, version)
    if ci:
        version += "-dev"
    toolchain = (ROOT / '.go-version').read_text().strip()
    if not re.fullmatch(r'1\.[0-9]+\.[0-9]+', toolchain):
        raise ValueError('invalid pinned Go version')
    if not re.search(r'^go ' + re.escape(toolchain) + r'$', (ROOT / 'go.mod').read_text(), re.M):
        raise ValueError('go.mod and .go-version must agree')
    if run('git', 'status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('official archives require a clean checkout')
    commit = run('git', 'rev-parse', 'HEAD')
    epoch = int(run('git', 'show', '-s', '--format=%ct', 'HEAD'))
    date = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    env = {**os.environ, 'GOTOOLCHAIN': 'go' + toolchain, 'GOENV': 'off', 'GOWORK': 'off', 'GOFLAGS': '', 'GOEXPERIMENT': '', 'CGO_ENABLED': '0', 'GOAMD64': 'v1', 'GOARM64': 'v8.0'}
    if cache is not None:
        env['GOCACHE'] = str(cache)
    if run('go', 'env', 'GOVERSION', env=env) != 'go' + toolchain:
        raise ValueError('official build requires the exact pinned Go toolchain')
    subprocess.run(['go', 'mod', 'verify'], cwd=ROOT, env=env, check=True)
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    # Keep the complete source manifest without bundling private build paths.
    manifest = source_manifest()
    (destination / 'SOURCE_MANIFEST.sha256').write_bytes(manifest)
    metadata = {'version': version, 'commit': commit, 'built_at': date, 'go': 'go' + toolchain, 'cgo_enabled': False, 'source_manifest_sha256': sha(manifest), 'platforms': []}
    ldflags = ' '.join('-X ' + PREFIX + key + '=' + value for key, value in [('Version', version), ('Commit', commit), ('Date', date)])
    for system, arch in PLATFORMS:
        require_source(commit, manifest)
        platform_env = {**env, 'GOOS': system, 'GOARCH': arch}
        name = f'outcomemesh-{version}-{system}-{arch}'
        binary = destination / (name + '.binary')
        subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags', ldflags, '-o', str(binary), './cmd/omd'], cwd=ROOT, env=platform_env, check=True)
        data = binary.read_bytes()
        info = {k: v for k, v in metadata.items() if k != 'platforms'}
        info.update(os=system, arch=arch, binary_sha256=sha(data))
        entries = dependency_notices(platform_env)
        executable = 'omd.exe' if system == 'windows' else 'omd'
        invocation = r'.\omd.exe' if system == 'windows' else './omd'
        entries.update({executable: (data, 0o755), 'LICENSE': ((ROOT / 'LICENSE').read_bytes(), 0o644), 'BUILDINFO.json': (json_bytes(info), 0o644), 'README.md': (f'# OutcomeMesh Core {version}\n\nPre-alpha software for development networks. Not ready to secure real value.\n\nPlatform: {system}/{arch}. Built with Go {toolchain}.\n\nRun `{invocation} version --json` to identify this binary.\nSource and documentation: https://github.com/OutcomeMesh/outcomemesh/tree/{commit}\n'.encode(), 0o644)})
        require_source(commit, manifest)
        archive(destination / (name + ('.zip' if system == 'windows' else '.tar.gz')), name, entries, epoch)
        binary.unlink()
        metadata['platforms'].append(info)
        print('Built ' + name, flush=True)
    require_source(commit, manifest)
    (destination / 'BUILDINFO.json').write_bytes(json_bytes(metadata))
    sums = ''.join(sha(p.read_bytes()) + '  ' + p.name + '\n' for p in sorted(destination.iterdir()))
    (destination / 'SHA256SUMS').write_text(sums)
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='v' + source_version(ROOT))
    parser.add_argument('--ci', action='store_true', help='mark unsigned development archives with -dev; never used for releases')
    parser.add_argument('--out', required=True)
    parser.add_argument('--verify-reproducible', action='store_true', help='build twice with separate caches and compare every output byte')
    args = parser.parse_args()
    if not args.out:
        parser.error('--out must name a new output directory')
    if args.verify_reproducible:
        with tempfile.TemporaryDirectory(prefix='outcomemesh-repro-') as temporary:
            base = Path(temporary)
            build(args.version, args.out, cache=base / 'cache-a', ci=args.ci)
            build(args.version, base / 'repeat', cache=base / 'cache-b', ci=args.ci)
            compare_archives(args.out, base / 'repeat')
            print('Both builds produced identical archives and metadata.', flush=True)
    else:
        build(args.version, args.out, ci=args.ci)
