#!/usr/bin/env python3
"""Real Prune owner/relay/client processes under separate Linux UIDs.

Run as root on disposable test hosts. Only fresh empty containers are chowned;
all originals are created by the owner UID. Remote children are supervised over
SSH stdin, bounded by the Go helper deadline, and stopped on controller loss.
Transport seeds are deterministic test fixtures. No deployment keys are copied.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

PREFIX = 'OUTCOMEMESH_PRUNE_UID_'
LAUNCH = '''import json,os,subprocess,sys
c=json.loads(sys.argv[1]); env=dict(os.environ, TMPDIR=c['work'])
for k in list(env):
 if k.startswith('OUTCOMEMESH_PRUNE_UID_'): del env[k]
env.update(c['env'])
with open(c['log'],'xb') as log:
 p=subprocess.Popen([c['binary'],'-test.run=^TestProcessPruneServiceUIDHelper$','-test.v','-test.timeout=6m'],cwd=c['work'],env=env,stdout=log,stderr=log,user=c['uid'],group=c['uid'],extra_groups=[])
 try:
  command=sys.stdin.readline().strip()
  if command!='wait': p.terminate()
  try: code=p.wait(timeout=30)
  except subprocess.TimeoutExpired: p.kill();p.wait();raise
 finally:
  if p.poll() is None: p.kill();p.wait()
 sys.exit(code)
'''


class Host:
    def __init__(self, cfg):
        if not isinstance(cfg, dict) or set(cfg) - {'binary', 'sha256', 'ssh'} or not {'binary', 'sha256'} <= set(cfg):
            raise ValueError('invalid host configuration')
        self.binary = cfg['binary']
        if not os.path.isabs(self.binary) or os.path.normpath(self.binary) != self.binary:
            raise ValueError('absolute binary required')
        self.ssh = cfg.get('ssh', [])
        if self.ssh and (not isinstance(self.ssh, list) or os.path.basename(self.ssh[0]) != 'ssh' or not {'StrictHostKeyChecking=yes', 'BatchMode=yes'} <= set(self.ssh)):
            raise ValueError('SSH must pin host identity and use noninteractive authentication')
        self.root = ''
        actual = self.python("import hashlib,os,sys; assert sys.platform=='linux' and os.geteuid()==0; h=hashlib.sha256();f=open(sys.argv[1],'rb');[h.update(b) for b in iter(lambda:f.read(1024*1024),b'')];print(h.hexdigest())", self.binary).decode().strip()
        if actual != cfg['sha256']:
            raise ValueError('test executable differs from pinned SHA256')

    def argv(self, argv):
        return self.ssh + [shlex.join(argv)] if self.ssh else argv

    def python(self, code, *args, data=None):
        p = subprocess.run(self.argv(['python3', '-c', code, *args]), input=data, capture_output=True, timeout=25)
        if p.returncode:
            raise RuntimeError(p.stderr.decode(errors='replace')[-3000:])
        return p.stdout

    def create(self):
        self.root = self.python("import os,tempfile; p=tempfile.mkdtemp(prefix='ompsn-',dir='/tmp');os.chmod(p,0o755);print(p)").decode().strip()
        self.python("import os,shutil,sys; r=sys.argv[1]; shutil.copyfile(sys.argv[2],r+'/omd.test');os.chmod(r+'/omd.test',0o755)\nfor name,uid,mode in [('owner',60000,0o700),('relay',65534,0o700),('client',65534,0o700),('public',60000,0o755),('control',0,0o755)]:\n p=r+'/'+name;os.mkdir(p,mode);os.chown(p,uid,uid);os.chmod(p,mode)", self.root, self.binary)

    def read(self, path):
        return self.python("import sys;sys.stdout.buffer.write(open(sys.argv[1],'rb').read())", path)

    def write(self, path, data, mode=0o644):
        self.python("import os,sys;f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,int(sys.argv[2]));b=sys.stdin.buffer.read();os.write(f,b);os.fsync(f);os.close(f)", path, str(mode), data=data)

    def marker(self, name):
        self.write(self.root + '/control/' + name, b'true')

    def wait_file(self, path, child):
        until = time.monotonic() + 40
        while time.monotonic() < until:
            if child.p.poll() is not None:
                raise RuntimeError('child ended early: ' + self.read(child.log).decode(errors='replace'))
            raw = self.python("import os,sys;p=sys.argv[1];print('yes' if os.path.isfile(p) else 'no')", path)
            if raw.strip() == b'yes':
                return self.read(path)
            time.sleep(0.15)
        raise RuntimeError('process readiness timed out: ' + self.read(child.log).decode(errors='replace'))

    def cleanup(self):
        if self.root:
            self.python("import os,shutil,sys;p=sys.argv[1];assert os.path.dirname(p)=='/tmp' and os.path.basename(p).startswith('ompsn-');shutil.rmtree(p)", self.root)


class Child:
    def __init__(self, host, role, mode, work, extra=None):
        self.host = host
        self.log = host.root + '/' + role + '.log'
        env = {PREFIX + 'ROLE': role, PREFIX + 'MODE': mode, PREFIX + 'PUBLIC': host.root + '/public', PREFIX + 'CONTROL': host.root + '/control'}
        env.update(extra or {})
        cfg = dict(binary=host.root + '/omd.test', work=host.root + '/' + work, log=self.log, uid=60000 if role in ('owner', 'replay-owner') else 65534, env=env)
        self.p = subprocess.Popen(host.argv(['python3', '-c', LAUNCH, json.dumps(cfg)]), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def finish(self, wait=True):
        if self.p.stdin and not self.p.stdin.closed:
            self.p.stdin.write(b'wait\n' if wait else b'stop\n')
            self.p.stdin.close()
        code = self.p.wait(timeout=40)
        if wait and code:
            raise RuntimeError(self.host.read(self.log).decode(errors='replace'))


def run(receiver, sender, ip, scenario, report, direction):
    children = []
    mode = 'held' if scenario == 'held' else 'completed'
    try:
        receiver.create(); sender.create()
        def child(host, role, work, extra=None):
            c = Child(host, role, mode, work, extra); children.append(c); return c
        owner = child(receiver, 'owner', 'owner')
        receiver.wait_file(receiver.root + '/public/ready-live', owner)
        manifest = receiver.read(receiver.root + '/public/manifest.json')
        # Copy public signed artifacts and process coordinates only. No private
        # owner roots, seeds, journals, or snapshots are copied to the sender.
        sender.write(sender.root + '/public/manifest.json', manifest)
        relay = child(receiver, 'network-relay', 'relay', {PREFIX + 'LISTEN': '/ip4/0.0.0.0/udp/0/quic-v1'})
        ready = json.loads(receiver.wait_file(receiver.root + '/relay/live.ready', relay))
        route = next(a for a in ready['Addresses'] if a.startswith('/ip4/'))
        parts = route.split('/'); parts[2] = ip; route = '/'.join(parts)
        sender.write(sender.root + '/public/route', route.encode())
        extra = {PREFIX + 'ROUTE': sender.root + '/public/route'}
        if scenario == 'lost-response': extra[PREFIX + 'DROP_RESPONSE'] = '1'
        client = child(sender, 'network-client', 'client', extra); client.finish()
        receiver.marker('stop-live-relay'); relay.finish()
        receiver.marker('stop-live')
        receiver.wait_file(receiver.root + '/public/offline-ready', owner)
        final = receiver.read(receiver.root + '/public/manifest.json')
        state = json.loads(final)
        assert state['Position']['Sequence'] == (1 if mode == 'held' else 2)
        sender.python("import os,sys;os.unlink(sys.argv[1])", sender.root + '/public/manifest.json')
        sender.write(sender.root + '/public/manifest.json', final)
        replay = child(receiver, 'replay-owner', 'owner')
        receiver.wait_file(receiver.root + '/public/ready-replay', replay)
        relay2 = child(receiver, 'network-replay-relay', 'relay', {PREFIX + 'LISTEN': '/ip4/0.0.0.0/udp/0/quic-v1'})
        ready = json.loads(receiver.wait_file(receiver.root + '/relay/replay.ready', relay2))
        route = next(a for a in ready['Addresses'] if a.startswith('/ip4/'))
        parts = route.split('/'); parts[2] = ip
        sender.write(sender.root + '/public/replay-route', '/'.join(parts).encode())
        client2 = child(sender, 'network-replay-client', 'client', {PREFIX + 'ROUTE': sender.root + '/public/replay-route'}); client2.finish()
        receiver.marker('stop-replay-relay'); relay2.finish()
        receiver.marker('stop-replay'); replay.finish()
        receiver.marker('finish-owner'); owner.finish()
        report.append({'direction': direction, 'scenario': scenario, 'passed': True, 'position': state['Position']['Sequence'], 'owner_uid': 60000, 'relay_uid': 65534, 'offline_cold_replay': True})
        print(json.dumps(report[-1]), flush=True)
    finally:
        for c in reversed(children):
            if c.p.poll() is None: c.finish(wait=False)
        sender.cleanup();receiver.cleanup()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config')
    p.add_argument('--local-binary')
    p.add_argument('--out')
    args = p.parse_args()
    if bool(args.config) == bool(args.local_binary): p.error('choose explicit hosts or a local executable')
    if args.local_binary:
        path = str(Path(args.local_binary).resolve())
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        cfg = {'a': {'binary': path, 'sha256': digest}, 'b': {'binary': path, 'sha256': digest}, 'a_ip': '127.0.0.1', 'b_ip': '127.0.0.1'}
    else:
        cfg = json.loads(Path(args.config).read_text())
    report = []
    for receiver, sender in [('a', 'b'), ('b', 'a')]:
        for scenario in ['completed', 'held', 'lost-response']:
            run(Host(cfg[receiver]), Host(cfg[sender]), cfg[receiver + '_ip'], scenario, report, sender + '-to-' + receiver)
    result = {'completed': True, 'runs': report, 'limitations': ['test keys', 'shared administration', 'guard and witnesses colocated with original owner', 'process death does not emulate power loss']}
    if args.out: Path(args.out).write_text(json.dumps(result, indent=2) + '\n')

if __name__ == '__main__':
    main()
