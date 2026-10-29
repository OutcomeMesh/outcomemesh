#!/usr/bin/env python3
"""Private stdio controller for the two-host profile-5 acceptance campaign.

Run only on disposable task placements with public fixture keys. It never opens
an administration network listener, changes firewall rules or copies owner roots.
EOF/exit drains all processes created by this controller. The caller owns SSH.
"""
import base64
import hashlib
import json
import os
import pathlib
import select
import signal
import subprocess
import sys
import time

from support import FaultRelay

MAX_INPUT = 24 * 1024 * 1024

def step_spec(value, root, fixture):
    result = {key: '' for key in ('Step', 'Role', 'Root', 'Fixture', 'Name', 'Input', 'Output', 'Family')}
    result.update(Kind=0, Seed=0, Votes=None)
    if set(value) - set(result):
        raise ValueError('unknown step field')
    result.update(value, Root=root, Fixture=fixture)
    return result

class Host:
    def __init__(self, build, root, role):
        self.build = pathlib.Path(build).resolve(strict=True)
        self.root = pathlib.Path(root)
        if not self.root.is_absolute() or str(self.root) != os.path.realpath(self.root):
            raise ValueError('canonical fresh placement required')
        self.root.mkdir(mode=0o755)
        (self.root / 'private').mkdir(mode=0o700)
        (self.root / 'public').mkdir(mode=0o755)
        (self.root / 'client').mkdir(mode=0o700)
        os.chown(self.root / 'client', 65534, 65534)
        self.hashes = json.loads((self.build / 'binaries.json').read_text())
        for name, digest in self.hashes.items():
            if hashlib.sha256((self.build / name).read_bytes()).hexdigest() != digest:
                raise ValueError('binary pin differs: ' + name)
        self.children = {}
        self.relay = None
        self.serial = 0
        self.env = dict(os.environ, GOMAXPROCS='2')
        # Explicit PUBLIC fixture network seed, distinct from the service keys.
        seed = bytes([46]) * 32
        self.put_client('network.seed', seed.hex().encode())
        self.put_client('relay.seed', (bytes([90 if role == 'a' else 91]) * 32).hex().encode())

    def path(self, name, area='public'):
        if area not in ('public', 'private', 'client') or not isinstance(name, str) or pathlib.Path(name).name != name or name in ('', '.', '..'):
            raise ValueError('flat artifact name required')
        return self.root / area / name

    def put_client(self, name, data):
        path = self.path(name, 'client')
        with path.open('xb') as out:
            out.write(data)
        os.chmod(path, 0o600)
        os.chown(path, 65534, 65534)
        return str(path)

    def spawn(self, name, argv, uid=0, env=None):
        if name in self.children:
            raise ValueError('process name already retained')
        if argv[0] not in [str(self.build / n) for n in self.hashes]:
            raise ValueError('unpinned executable')
        name_bin = pathlib.Path(argv[0]).name
        if hashlib.sha256(pathlib.Path(argv[0]).read_bytes()).hexdigest() != self.hashes[name_bin]:
            raise ValueError('binary changed')
        log = self.path(name + '.log', 'private')
        flags = {} if uid == 0 else {'user': uid, 'group': uid, 'extra_groups': []}
        with log.open('xb') as out:
            p = subprocess.Popen(argv, cwd=self.build, env=env or self.env, stdout=out,
                                 stderr=subprocess.STDOUT, start_new_session=True, **flags)
        self.children[name] = (p, log)
        return p, log

    def result(self, name, timeout=None):
        p, log = self.children[name]
        if timeout is not None:
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
        data = log.read_bytes()
        return {'name': name, 'exit_code': p.poll(), 'log_sha256': hashlib.sha256(data).hexdigest(),
                'output': data.decode(errors='replace')[-16000:]}

    def command(self, args, uid, start):
        if not args or args[0] not in ('work-archive-custody-gateway', 'work-archive-custody-relay', 'work-archive-custody-profile5'):
            raise ValueError('unexpected CLI family')
        if '--mode' in args or '--expected-review-id' in args:
            raise ValueError('review is managed from these exact arguments')
        name = 'cli-' + str(self.serial)
        self.serial += 1
        p, log = self.spawn(name + '-review', [str(self.build / 'omd')] + args, uid)
        review = self.result(name + '-review', 15)
        if review['exit_code']:
            return review
        first = log.read_text().splitlines()[0]
        fields = dict(x.split('=', 1) for x in first.split()[1:] if '=' in x)
        review_id = fields['review_id']
        argv = [str(self.build / 'omd')] + args + ['--mode', 'run', '--expected-review-id', review_id]
        name = start or name
        self.spawn(name, argv, uid)
        if not start:
            return self.result(name, 15)
        end = time.monotonic() + 10
        while time.monotonic() < end:
            result = self.result(name)
            if '_ready ' in result['output'] or result['exit_code'] is not None:
                return result
            time.sleep(.02)
        raise ValueError('daemon did not become ready')

    def dispatch(self, op, x):
        if op == 'put':
            path = self.path(x['name']); raw = base64.b64decode(x['data'], validate=True)
            if path.exists():
                if path.read_bytes() != raw:
                    raise ValueError('public artifact already exists with different bytes')
            else:
                with path.open('xb') as out:
                    out.write(raw)
                os.chmod(path, 0o644)
            return {'sha256': hashlib.sha256(raw).hexdigest()}
        if op == 'controller-position':
            if x['role'] not in ('a', 'b'): raise ValueError('role')
            raw = base64.b64decode(x['data'], validate=True)
            obj = json.loads(raw)
            if set(obj) != {'Sequence', 'Head'}: raise ValueError('position shape')
            self.path(x['role'] + '.position.json').write_bytes(raw)
            return {'updated_public_controller_position': True}
        if op == 'get':
            raw = self.path(x['name'], x.get('area', 'public')).read_bytes()
            if len(raw) > 16 * 1024 * 1024:
                raise ValueError('artifact exceeds bound')
            return {'data': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()}
        if op == 'step':
            name = 'step-' + str(self.serial); self.serial += 1
            spec = step_spec(x, str(self.root), str(self.build / 'fixture/public-fixture'))
            path = self.path(name + '.json', 'private'); path.write_text(json.dumps(spec)); os.chmod(path, 0o600)
            env = dict(self.env, OMESH_PROFILE5_WAN_STEP=str(path))
            self.spawn(name, [str(self.build / 'omd.test'), '-test.run=^TestProfile5WANStep$', '-test.v', '-test.timeout=2m'], env=env)
            return self.result(name, 125)
        if op == 'cli':
            return self.command(x['args'], x.get('uid', 0), x.get('start'))
        if op == 'stop':
            p, _ = self.children[x['name']]
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL if x.get('kill') else signal.SIGTERM)
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL); p.wait()
            return self.result(x['name'])
        if op == 'poll':
            return self.result(x['name'], x.get('wait'))
        if op == 'list':
            return sorted(p.name for p in (self.root / 'public').iterdir())
        if op == 'relay':
            if self.relay is None:
                self.relay = FaultRelay(x['config'])
            return self.relay.policy(**x.get('policy', {}))
        if op == 'relay-stats':
            return self.relay.stats()
        if op == 'barrier':
            name = x['name']; cfg = dict(x['config'])
            for key, value in cfg.items():
                if key in ('Ready', 'Send', 'Output'):
                    cfg[key] = str(self.path(value, 'client'))
            path = self.put_client(name + '.json', json.dumps(cfg).encode())
            env = dict(self.env, OMESH_PROFILE5_WAN_CLIENT=path)
            self.spawn(name, [str(self.build / 'omd.test'), '-test.run=^TestProfile5WANBarrierClient$', '-test.v', '-test.timeout=30s'], 65534, env)
            end = time.monotonic() + 12
            while time.monotonic() < end:
                if pathlib.Path(cfg['Ready']).exists():
                    return {'ready': True, 'name': name}
                if self.children[name][0].poll() is not None:
                    return self.result(name)
                time.sleep(.02)
            raise ValueError('network barrier did not become ready')
        if op == 'send':
            self.put_client(x['name'], b'send\n')
            return {'sent': True}
        if op == 'owner-files':
            owner = self.root / 'private/gateway'
            return {str(p.relative_to(owner)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in owner.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
        if op == 'close':
            return self.close()
        raise ValueError('unknown operation')

    def close(self):
        if self.relay:
            self.relay.close(); self.relay = None
        for name, (p, _) in self.children.items():
            if p.poll() is None:
                self.dispatch('stop', {'name': name, 'kill': True})
        return {'running_children': sum(p.poll() is None for p, _ in self.children.values())}


def main():
    host = Host(sys.argv[1], sys.argv[2], sys.argv[3])
    print(json.dumps({'ready': True, 'binary_hashes': host.hashes}), flush=True)
    try:
        while True:
            line = sys.stdin.buffer.readline(MAX_INPUT + 1)
            if not line:
                break
            if len(line) > MAX_INPUT or not line.endswith(b'\n'):
                raise ValueError('input bound')
            q = json.loads(line)
            try:
                result = host.dispatch(q['op'], q.get('args', {}))
                print(json.dumps({'id': q['id'], 'result': result}), flush=True)
            except Exception as e:
                print(json.dumps({'id': q['id'], 'error': str(e)}), flush=True)
    finally:
        host.close()

if __name__ == '__main__':
    main()
