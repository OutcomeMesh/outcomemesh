#!/usr/bin/env python3
"""Two-host protected profile-5 campaign, using existing pinned SSH connections.

Config supplies ssh_a/ssh_b argv (including host-key verification), build/root,
server IPs, independently computed fixture peer IDs and a fresh port range. Only
public artifacts are copied. No production key, root, firewall or user is changed.
"""
import argparse
import base64
import hashlib
import io
import tarfile
import json
import pathlib
import select
import shlex
import subprocess
import time

class Remote:
    def __init__(self, ssh, build, root, role):
        self.role, self.root, self.serial = role, root, 0
        command = shlex.join(['python3', '-u', build + '/profile5_host.py', build, root, role])
        self.p = subprocess.Popen(ssh + [command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, bufsize=1)
        self.ready = self.receive(20)
        if not self.ready.get('ready'):
            raise RuntimeError(self.ready)
        self.history = []

    def receive(self, timeout):
        ready, _, _ = select.select([self.p.stdout], [], [], timeout)
        if not ready:
            raise TimeoutError('host stdio deadline')
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError('host exited: ' + self.p.stderr.read()[-2000:])
        return json.loads(line)

    def call(self, op, **args):
        self.serial += 1
        self.p.stdin.write(json.dumps({'id': self.serial, 'op': op, 'args': args}) + '\n'); self.p.stdin.flush()
        response = self.receive(135)
        if response['id'] != self.serial or 'error' in response:
            raise RuntimeError((self.role, op, response))
        result = response['result']
        meta = result if isinstance(result, dict) else {}
        self.history.append({'op': op, 'step': args.get('Step'), 'name': meta.get('name'),
                             'exit_code': meta.get('exit_code'), 'log_sha256': meta.get('log_sha256')})
        return result

    def get(self, name, area='public'):
        r = self.call('get', name=name, area=area)
        b = base64.b64decode(r['data'], validate=True)
        assert hashlib.sha256(b).hexdigest() == r['sha256']
        return b

    def put(self, name, raw):
        return self.call('put', name=name, data=base64.b64encode(raw).decode())

    def step(self, step, role=None, expect_fail=False, **kw):
        r = self.call('step', Step=step, Role=role or self.role, **kw)
        assert (r['exit_code'] != 0) == expect_fail, (step, r)
        return r

    def close(self):
        result = self.call('close')
        self.p.stdin.close()
        self.p.wait(timeout=15)
        assert result['running_children'] == 0 and self.p.returncode == 0
        return result

class Campaign:
    def __init__(self, cfg, scenario, report):
        self.cfg, self.scenario, self.path = cfg, scenario, pathlib.Path(report)
        self.root = cfg['root'] + '-' + scenario
        self.hosts = {}
        self.report = {'scenario': scenario, 'root': self.root, 'events': [], 'limitations': [
            'one operator; public fixture keys', 'witness artifacts delivered by pinned SSH, not a new witness transport campaign',
            'Linux UID boundary; no root/full-VM clone or physical-power-loss guarantee']}
        self.daemons, self.relays, self.socket_ids, self.serial = {}, {}, {}, 0
        self.endpoints = {}

    def save(self):
        self.path.write_text(json.dumps(self.report, indent=2) + '\n')

    def event(self, name, **data):
        value = dict(event=name, **data); self.report['events'].append(value); self.save()
        print(json.dumps({k:v for k,v in value.items() if k not in ("snapshot", "retained_files")}), flush=True)

    def copy(self, origin, target, *names):
        for name in names:
            self.hosts[target].put(name, self.hosts[origin].get(name))

    def pub(self, name): return self.root + '/public/' + name
    def key(self, name): return self.root + '/client/' + name

    def metadata(self, role): return json.loads(self.hosts['a'].get(role + '.meta.json'))

    def setup(self):
        for role in 'ab':
            self.hosts[role] = Remote(self.cfg['ssh_' + role], self.cfg['build'], self.root, role)
        assert self.hosts['a'].ready['binary_hashes'] == self.hosts['b'].ready['binary_hashes']
        self.report['binaries'] = self.hosts['a'].ready['binary_hashes']; self.save()
        a, b = self.hosts['a'], self.hosts['b']
        a.step('seed'); self.copy('a', 'b', 'draft.json')
        a.step('source'); b.step('source'); self.copy('b', 'a', 'b.observation.json')
        a.step('select'); self.copy('a', 'b', 'genesis', 'enrollment')
        for role in 'ab': self.hosts[role].step('install')
        for origin, target in [('a', 'b'), ('b', 'a')]:
            self.copy(origin, target, *[origin + suffix for suffix in ('.descriptor', '.handoff', '.meta.json', '.position.json')])
        a.step('deployment'); self.copy('a', 'b', 'pair')
        a.step('endorse', Input='deployment-draft', Output='deployment-a')
        self.copy('a', 'b', 'deployment-a')
        b.step('endorse', Input='deployment-a', Output='deployment')
        self.copy('b', 'a', 'deployment')
        # Endorsement advanced both local gateways. Controller takes each exact
        # public response-derived position; it never asks a live owner for a tip.
        bpos = b.get('b.position.json')
        # Replace only the controller's stale PUBLIC bootstrap position.
        a.call('controller-position', role='b', data=base64.b64encode(bpos).decode())
        for role in 'ab': self.hosts[role].step('configure')
        a.step('plan'); self.copy('a', 'b', 'context', 'admit-entry')
        for family in ('admission', 'job', 'serve'):
            for seed in range(70, 74):
                self.hosts['a' if seed < 72 else 'b'].step('witness-init', Seed=seed, Family=family)
        self.quorum('admission', 'admit-entry', 'admit', minority=True)
        self.copy('a', 'b', 'binding')
        self.holds('admitted', 2, 0)
        for role in 'ab':
            self.start_gateway(role)
            self.start_relay(role)
        self.event('original-sources-installed-on-their-respective-hosts')

    def quorum(self, family, entry, name, minority=False):
        a, b = self.hosts['a'], self.hosts['b']
        self.copy('a', 'b', entry)
        votes = []
        for seed in range(70, 73):
            role = 'a' if seed < 72 else 'b'; out = name + '-vote-' + str(seed)
            self.hosts[role].step('witness-vote', Seed=seed, Family=family, Input=entry, Output=out)
            if role == 'b': self.copy('b', 'a', out)
            votes.append(out)
            if minority and len(votes) == 2:
                a.step('quorum', Family=family, Input=entry, Output=name + '-minority', Votes=votes, expect_fail=True)
                assert name + '-minority' not in a.call('list')
                self.event('two-of-four-votes-cannot-form-quorum', family=family)
        a.step('quorum', Family=family, Input=entry, Output=name, Votes=votes)
        self.copy('a', 'b', name)
        for seed in range(70, 74):
            self.hosts['a' if seed < 72 else 'b'].step('witness-commit', Seed=seed, Family=family, Input=name)

    def holds(self, label, pending, sequence):
        snapshots = []
        for seed in range(70, 74):
            h = self.hosts['a' if seed < 72 else 'b']; out = label + '-snapshot-' + str(seed)
            h.step('witness-snapshot', Seed=seed, Family='admission', Output=out)
            s = json.loads(h.get(out)); snapshots.append(s)
            assert s['SpentOperations'] == 2 and s['PendingOperations'] == pending and s['SourceSequence'] == sequence, s
        assert all(s == snapshots[0] for s in snapshots)
        self.event(label, snapshot=snapshots[0], witnesses=4)

    def start_gateway(self, role, recovery=None):
        h = self.hosts[role]; self.serial += 1; name = role + '-gateway-' + str(self.serial)
        pin_name = name + '-pin.json'; h.put(pin_name, self.hosts['a'].get(role + '.position.json'))
        meta = self.metadata(role)
        args = ['work-archive-custody-gateway', '--action', 'serve', '--root', meta['owner'],
                '--descriptor', self.pub(role + '.descriptor'), '--descriptor-id', meta['descriptor_id'],
                '--socket', self.root + '/gateway.sock', '--position', self.pub(pin_name)]
        if recovery:
            self.copy('a', role, recovery + '.request'); args += ['--request', self.pub(recovery + '.request')]
        r = h.call('cli', args=args, start=name)
        assert r['exit_code'] is None and 'custody_gateway_ready' in r['output'], r
        fields = dict(x.split('=', 1) for x in r['output'].split() if '=' in x)
        self.socket_ids[role] = fields['socket_id']; self.daemons[role] = name

    def stop_gateway(self, role, kill=True):
        h = self.hosts[role]; r = h.call('stop', name=self.daemons[role], kill=kill)
        assert r['exit_code'] is not None
        meta = self.metadata(role)
        r = h.call('cli', args=['work-archive-custody-gateway', '--action', 'cleanup-socket', '--root', meta['owner'],
                               '--socket', self.root + '/gateway.sock', '--socket-id', self.socket_ids[role]])
        assert r['exit_code'] == 0, r

    def start_relay(self, role):
        self.serial += 1; name = role + '-relay-' + str(self.serial); meta = self.metadata(role)
        port = self.cfg['port'] + (0 if role == 'b' else 1)
        r = self.hosts[role].call('cli', uid=65534, start=name, args=[
            'work-archive-custody-relay', '--action', 'serve', '--descriptor', self.pub(role + '.descriptor'),
            '--descriptor-id', meta['descriptor_id'], '--socket', self.root + '/gateway.sock',
            '--key', self.key('relay.seed'), '--listen', '/ip4/0.0.0.0/udp/' + str(port) + '/quic-v1',
            '--clients', self.cfg['peers']['client']])
        assert r['exit_code'] is None and 'custody_relay_ready' in r['output'], r
        assert 'peer=' + self.cfg['peers'][role] in r['output'], r
        self.relays[role] = name
        advertised = json.loads(r['output'].split('addresses=')[-1].splitlines()[0])[0]
        self.endpoints[role] = '/ip4/' + self.cfg['ip_' + role] + '/udp/' + str(port) + '/quic-v1/p2p/' + advertised.split('/p2p/')[1]

    def req(self, role, name, kind, data=None):
        kw = dict(Name=name, Kind=kind)
        if data: kw['Input'] = data
        self.hosts['a'].step('request', role=role, **kw)

    def call(self, role, name, suffix='', fail=False, key='network.seed'):
        caller = 'a' if role == 'b' else 'b'; h = self.hosts[caller]
        self.copy('a', caller, name + '.request')
        out = name + suffix + '.response'; meta = self.metadata(role)
        port = self.cfg['port'] + (0 if role == 'b' else 1)
        r = h.call('cli', uid=65534, args=[
            'work-archive-custody-relay', '--action', 'call', '--descriptor', self.pub(role + '.descriptor'),
            '--descriptor-id', meta['descriptor_id'], '--key', self.key(key),
            '--address', self.endpoints[role],
            '--peer', self.cfg['peers'][role], '--request', self.pub(name + '.request'), '--out', self.key(out)])
        assert (r['exit_code'] != 0) == fail, r
        if not fail:
            packet = h.get(out, 'client'); self.hosts['a'].put(out, packet)
            return out
        self.event('remote-request-refused', role=role, request=name, code=r['exit_code'])

    def advance(self, role, name, response):
        self.hosts['a'].step('advance', role=role, Name=name, Input=response)

    def partition(self, name, mode):
        a = self.hosts['a']; port = self.cfg['port']
        cfg = {'front': ['127.0.0.1', port + 2], 'allowed_client': ['127.0.0.1', port + 3],
               'upstream': [self.cfg['ip_b'], port]}
        a.call('relay', config=cfg, policy={'mode': 'pass'})
        ready, send, out = name + '.ready', name + '.send', name + '-lost.response'
        r = a.call('barrier', name=name + '-partition', config={
            'Descriptor': self.pub('b.descriptor'), 'Request': self.pub(name + '.request'),
            'Address': '/ip4/127.0.0.1/udp/' + str(port + 2) + '/quic-v1/p2p/' + self.endpoints['b'].split('/p2p/')[1], 'Peer': self.cfg['peers']['b'],
            'Listen': '/ip4/127.0.0.1/udp/' + str(port + 3) + '/quic-v1', 'Ready': ready, 'Send': send, 'Output': out})
        assert r.get('ready'), r
        a.call('relay', policy={'mode': mode})
        a.call('send', name=send)
        r = a.call('poll', name=name + '-partition', wait=15)
        assert r['exit_code'] != 0, r
        stats = a.call('relay-stats')
        assert sum(n for k, n in stats['counters'].items() if 'partition_drops' in k) > 0, stats
        a.call('relay', policy={'mode': 'pass'})
        self.event('encrypted-udp-partition', request=name, mode=mode, stats=stats, failure_log=r['log_sha256'])

    def run(self):
        try:
            self.setup(); a, b = self.hosts['a'], self.hosts['b']
            self.req('b', 'prepare', 2)
            before = b.call('owner-files')
            self.call('b', 'prepare', '-unlisted-peer', fail=True, key='relay.seed')
            assert before == b.call('owner-files'), 'unlisted peer reached owner'
            response = self.call('b', 'prepare'); self.advance('b', 'prepare', response)
            a.step('claim', Input='prepare.data'); self.quorum('job', 'claim-command', 'claim', minority=True)
            self.req('b', 'execute', 3, 'claim')
            if self.scenario == 'lost-session':
                self.stop_gateway('b'); self.start_gateway('b')
                self.call('b', 'execute', fail=True)
                self.stop_gateway('b'); self.start_gateway('b', 'execute')
                self.call('b', 'execute', suffix='-cold', fail=True)
                before = b.call('owner-files')
                historical = self.call('b', 'prepare', suffix='-historical')
                assert a.get(historical) == a.get('prepare.response'), 'historical candidate changed'
                assert before == b.call('owner-files'), 'candidate retry recreated private state'
                self.call('b', 'execute', suffix='-after-candidate', fail=True)
                self.event('historical-candidate-is-not-a-live-session')
                a.step('unknown'); self.quorum('job', 'unknown-command', 'unknown')
                self.holds('unknown-remains-held', 2, 0)
                files = b.call('owner-files')
                assert not any(n.endswith('/entry') or n.endswith('/result') for n in files), files.keys()
                self.event('lost-session-cannot-execute-or-manufacture-result', retained_files=files)
            else:
                self.partition('execute', 'drop-reverse')
                files = b.call('owner-files')
                assert any(n.endswith('/result') for n in files), files.keys()
                before = dict(files)
                b.call('stop', name=self.relays['b'], kill=True); self.stop_gateway('b'); self.start_gateway('b', 'execute'); self.start_relay('b')
                response = self.call('b', 'execute', '-cold'); after = b.call('owner-files')
                assert before == after, 'cold retry changed retained service data'
                self.advance('b', 'execute', response)
                self.event('cold-exact-response-no-second-effect', response_sha256=hashlib.sha256(a.get(response)).hexdigest())
                self.call('b', 'prepare', suffix='-stale', fail=True)
                a.step('unknown'); self.quorum('job', 'unknown-command', 'unknown')
                self.holds('completed-but-not-accepted-stays-held', 2, 0)
                a.step('prefix', Input='unknown'); self.req('b', 'record-command', 4, 'prefix')
                before = b.call('owner-files'); self.partition('record-command', 'drop')
                assert before == b.call('owner-files'), 'fully dropped request reached service'
                response = self.call('b', 'record-command'); self.advance('b', 'record-command', response)
                self.quorum('job', 'record-command.data', 'record'); a.step('bundle', Input='unknown')
                self.stop_gateway('a'); self.start_gateway('a')
                self.req('a', 'accept', 5, 'bundle'); response = self.call('a', 'accept'); self.advance('a', 'accept', response)
                # Kill/reopen A at its externally retained accepted cursor, then
                # serve both sides over WAN and close all original witnesses.
                self.stop_gateway('a'); self.start_gateway('a')
                a.step('serve-proposal'); self.quorum('serve', 'serve-command', 'serve-quorum')
                for role in 'ab':
                    data = 'serve-' + role + '-data'; a.step('serve-data', role=role, Output=data)
                    name = 'serve-' + role; self.req(role, name, 7, data); response = self.call(role, name); self.advance(role, name, response)
                a.step('closure'); self.quorum('admission', 'close-entry', 'close')
                self.holds('fulfilled-original-admission-closed', 0, 1)
            for role in 'ab':
                h = self.hosts[role]; name = role + '-final-handoff'; h.step('verify-source', Output=name)
                assert h.get(name) == h.get(role + '.handoff'), 'original sealed source changed'
            archive = self.path.with_suffix('.public.tar.gz')
            manifest = {}
            with tarfile.open(archive, 'w:gz') as tar:
                for role in 'ab':
                    h = self.hosts[role]
                    for name in h.call('list'):
                        raw = h.get(name); full = role + '/' + name
                        manifest[full] = hashlib.sha256(raw).hexdigest()
                        info = tarfile.TarInfo(full); info.size = len(raw); info.mode = 0o644
                        tar.addfile(info, io.BytesIO(raw))
            self.report['public_artifacts'] = {'archive': archive.name, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'files': manifest}
            self.report['passed'] = True
        except BaseException as e:
            self.report['passed'] = False; self.report['error'] = repr(e); raise
        finally:
            self.report['cleanup'] = {}
            for role, h in self.hosts.items():
                try: self.report['cleanup'][role] = h.close()
                except Exception as e: self.report['cleanup'][role] = {'error': repr(e)}
                self.report['history_' + role] = h.history
            self.save()


def main():
    p = argparse.ArgumentParser(); p.add_argument('--config', required=True); p.add_argument('--scenario', choices=['fulfilled', 'lost-session'], required=True); p.add_argument('--report', required=True)
    args = p.parse_args(); Campaign(json.loads(pathlib.Path(args.config).read_text()), args.scenario, args.report).run()

if __name__ == '__main__': main()
