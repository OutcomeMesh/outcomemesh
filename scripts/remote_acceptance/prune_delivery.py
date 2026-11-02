#!/usr/bin/env python3
"""Scheduled Prune command acceptance over two explicitly configured hosts.

Original authority/executor stores exist only on the receiver. Production CLI
commands drive delivery and recovery; separate test binaries provide precise kill
barriers. Only public artifacts cross hosts. No firewall or production root is
modified, and every child is supervised over private stdio.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re

from run import Host, Supervisor, AcceptanceError, require, digest_id


PREPARE = 'work-prune-scheduled-delivery-prepare'
OUTBOX = 'work-prune-scheduled-delivery-outbox'
SERVE = 'work-prune-scheduled-serve-quic'
DELIVER = 'work-prune-scheduled-deliver-quic'
APPLY = 'work-prune-scheduled-command'


def flags(args):
    require(isinstance(args, list) and len(args) % 2 == 0, 'invalid fixture arguments')
    result = {}
    for name, value in zip(args[::2], args[1::2]):
        require(isinstance(name, str) and name.startswith('--') and name not in result,
                'duplicate or invalid fixture flag')
        require(isinstance(value, str) and not any(c in value for c in '\0\r\n'), 'invalid flag value')
        result[name] = value
    return result


def hash_text(value):
    require(isinstance(value, list) and len(value) == 32 and all(type(x) is int and 0 <= x <= 255 for x in value),
            'invalid native hash representation')
    return bytes(value).hex()


def relative(root, path):
    require(isinstance(path, str) and os.path.isabs(path) and os.path.normpath(path) == path,
            'noncanonical fixture path')
    require(os.path.commonpath((root, path)) == root and path != root, 'fixture path escapes its root')
    return os.path.relpath(path, root)


def reachable_route(addresses, ip, port):
    for address in addresses:
        match = re.fullmatch(r'/ip4/[^/]+/udp/([0-9]+)/quic-v1/p2p/([A-Za-z0-9]+)', address)
        if match and int(match[1]) == port:
            return '/ip4/%s/udp/%d/quic-v1/p2p/%s' % (ip, port, match[2])
    raise AcceptanceError('readiness has no complete pinned QUIC route')


def validate_config(cfg):
    require(isinstance(cfg, dict) and set(cfg) == {'version', 'scenario', 'a', 'b', 'server_ip', 'port'}, 'invalid campaign fields')
    require(type(cfg['version']) is int and cfg['version'] == 1, 'unsupported campaign version')
    require(cfg['scenario'] in ('cancellation', 'settlement'), 'unknown outcome scenario')
    ip = ipaddress.ip_address(cfg['server_ip'])
    require(ip.version == 4 and not ip.is_unspecified and not ip.is_multicast, 'explicit unicast IPv4 route required')
    require(type(cfg['port']) is int and 1024 <= cfg['port'] <= 65535, 'invalid dedicated port')
    for name in ('a', 'b'):
        h = cfg[name]
        required = {'kind', 'root', 'binary', 'test_binary', 'store_test_binary', 'support'}
        require(isinstance(h, dict) and set(h) in (required, required | {'ssh'}), 'invalid host fields')
        require(h['kind'] in ('local', 'ssh') and (h['kind'] == 'ssh') == ('ssh' in h), 'invalid host transport')
        for field in required - {'kind'}:
            require(isinstance(h[field], str) and os.path.isabs(h[field]) and os.path.normpath(h[field]) == h[field],
                    'host paths must be absolute and normalized')
        if h['kind'] == 'ssh':
            argv = h['ssh']
            require(isinstance(argv, list) and argv and all(isinstance(x, str) and not any(c in x for c in '\0\r\n') for x in argv), 'invalid pinned SSH argv')
            require(os.path.basename(argv[0]) == 'ssh' and 'StrictHostKeyChecking=yes' in argv and 'BatchMode=yes' in argv,
                    'SSH requires explicit host verification and noninteractive authentication')
    require(cfg['a']['root'] != cfg['b']['root'], 'roles must use distinct private roots')
    return cfg


def assert_transition(before, after, kind, ticket, evidence):
    old = before['Review']['Authority']['Authority']
    new = after['Review']['Authority']['Authority']
    require(after['Review']['AlreadyApplied'] is True, 'original command is not confirmed')
    require(new['Sequence'] == old['Sequence'] + 1, 'authority sequence changed more than once')
    require(new['Pending'] == old['Pending'] + (1 if kind == 'admit' else -1), 'pending work changed incorrectly')
    old_ops, new_ops = old['Operations'], new['Operations']
    require(len(new_ops) == len(old_ops) + (1 if kind == 'admit' else 0), 'spent operation history changed')
    if kind == 'complete':
        require(sum(hash_text(op['TicketID']) == ticket for op in old_ops) == 1, 'completion selected no unique original ticket')
    for op in old_ops:
        if kind == 'complete' and hash_text(op['TicketID']) == ticket:
            matching = [x for x in new_ops if x['TicketID'] == op['TicketID']]
            require(len(matching) == 1 and hash_text(matching[0]['EvidenceID']) == evidence,
                    'completion lost full original evidence')
            require(hash_text(matching[0]['CompletionID']) != '00' * 32, 'completion record is absent')
            expected = dict(op, EvidenceID=matching[0]['EvidenceID'], CompletionID=matching[0]['CompletionID'])
            require(matching[0] == expected, 'completion changed its original operation binding')
        else:
            require(op in new_ops, 'another obligation changed')
    if kind == 'complete':
        require(before['Executor'] == after['Executor'], 'completion rewrote executor outcome')


class Campaign:
    def __init__(self, cfg):
        self.cfg = validate_config(cfg)
        self.a, self.b = Host(cfg['a']), Host(cfg['b'])
        self.supervisors = []
        self.report = {'version': 1, 'scenario': cfg['scenario'], 'completed': False, 'steps': [],
                       'limitations': ['public test keys', 'receiver colocates original authority and executor',
                                       'test binaries supply deterministic kill barriers',
                                       'no remote deletion permission or independent copy fencing claim']}

    def new_root(self, host):
        host.execute(['python3', '-c', 'import os,sys; p=sys.argv[1]; assert os.path.realpath(p)==p; os.mkdir(p,0o700)', host.root])

    def supervisor(self, host, commands, store=False):
        if store:
            cfg = dict(host.config, test_binary=host.config['store_test_binary'])
            host = Host(cfg)
        s = Supervisor(host, commands)
        self.supervisors.append(s)
        return s

    def close(self):
        errors = []
        for s in reversed(self.supervisors):
            try:
                s.close()
            except Exception as e:
                errors.append(type(e).__name__)
        require(not errors, 'supervisor cleanup failed: ' + ','.join(errors))

    def cli(self, host, args, fail=False):
        p = host.execute([host.binary] + args, timeout=30, check=False)
        require((p.returncode != 0) == fail, 'unexpected CLI exit for ' + args[0] + ': ' + p.stderr.decode('utf-8', 'replace')[-1200:])
        if fail:
            require(not p.stdout, 'failed CLI emitted a successful result')
            return None
        return json.loads(p.stdout)

    def record(self, s, name, prefix=''):
        seen = []
        for _ in range(32):
            try:
                line = s.line(name)
            except AcceptanceError as error:
                raise AcceptanceError('process missed its record; last output: ' + repr(seen[-4:])) from error
            if line.startswith(prefix):
                return line[len(prefix):].rstrip('\n')
            seen.append(line)
        raise AcceptanceError('missing bounded process record')

    def start(self, s, name, barrier=False):
        s.rpc('start', name=name)
        text = self.record(s, name, 'prune_wan_barrier_ready ' if barrier else '')
        data = json.loads(text)
        require(data.get('listen'), 'service published no route')
        if not barrier:
            require(data.get('ready') is True and data.get('automatic_resume') is False,
                    'service readiness enabled implicit recovery')
        return data

    def stop(self, s, name, kill=False):
        s.rpc('kill' if kill else 'terminate', name=name)
        code = s.rpc('wait', name=name, timeout=15)['returncode']
        require((code != 0) == kill, 'unexpected service shutdown result')

    def review(self, meta):
        result = self.cli(self.a, [APPLY] + meta['owner_args'])
        require(result.pop('review_id') == hash_text(result['Review']['ReviewID']), 'CLI review summary differs from native pin')
        require(result.pop('confirmed_sequence') == result['Review']['Authority']['Confirmed']['Sequence'], 'CLI sequence summary differs')
        require(result.pop('confirmed_head') == hash_text(result['Review']['Authority']['Confirmed']['HeadID']), 'CLI head summary differs')
        result.pop('effect_id', None)
        return result

    def step(self, meta):
        n, kind = meta['step'], meta['kind']
        require(type(n) is int and n == len(self.report['steps']) and n < 4, 'unexpected fixture step')
        require(kind == ('admit' if n < 2 else 'complete'), 'unexpected fixture phase')
        require(meta['scenario'] == self.cfg['scenario'], 'fixture scenario changed')
        v = flags(meta['owner_args'])
        require(set(v) <= {'--plan', '--plan-id', '--assignment-id', '--entry', '--entry-id', '--inventory', '--inventory-id',
                           '--authority', '--authority-pins', '--executor', '--executor-pins', '--journal',
                           '--max-challenge-lifetime-seconds', '--max-proof-age-seconds', '--max-renewal-term-seconds'}, 'unreviewed fixture argument')
        for key in ('--plan', '--entry', '--inventory', '--authority', '--authority-pins', '--executor', '--executor-pins', '--journal'):
            if key in v:
                relative(self.a.root, v[key])
        prefix = 'step-' + str(n) + '-'
        sender_files = {}
        for name, source in [('assignment', meta['assignment']), ('plan', v['--plan']), ('entry', v['--entry'])] + ([('inventory', v['--inventory'])] if kind == 'complete' else []):
            target = prefix + name
            self.b.write(target, self.a.read(relative(self.a.root, source)))
            sender_files[name] = self.b.root + '/' + target
        peers = ['--client-peer-id', digest_id(meta['client_peer_id']), '--server-peer-id', digest_id(meta['server_peer_id'])]
        prepare = [PREPARE, '--plan', sender_files['plan'], '--plan-id', digest_id(v['--plan-id']),
                   '--assignment-id', digest_id(meta['assignment_id']), '--entry', sender_files['entry'], '--entry-id', digest_id(v['--entry-id']),
                   '--request-id', digest_id(meta['request_id']), '--executor-binding-id', digest_id(meta['executor_binding_id']),
                   '--receiver-review-id', digest_id(meta['receiver_review_id'])] + peers
        if kind == 'complete':
            prepare += ['--inventory', sender_files['inventory'], '--inventory-id', digest_id(v['--inventory-id'])]
        prepared = self.cli(self.b, prepare)
        intent_id = digest_id(prepared['intent_id'])
        require(prepared['sent'] is False and prepared['execution_authorized'] is False, 'preparation granted execution')
        intent_b, intent_a = self.b.root + '/' + prefix + 'intent', self.a.root + '/' + prefix + 'intent'
        self.cli(self.b, prepare + ['--mode', 'publish', '--intent-id', intent_id, '--out', intent_b])
        self.a.write(prefix + 'intent', self.b.read(prefix + 'intent'))
        outbox = self.b.root + '/' + prefix + 'outbox'
        box = [OUTBOX, '--assignment', sender_files['assignment'], '--assignment-id', meta['assignment_id'], '--intent-id', intent_id, '--outbox', outbox]
        self.cli(self.b, box + ['--mode', 'create', '--intent', intent_b])
        listen = '/ip4/0.0.0.0/udp/%d/quic-v1' % self.cfg['port']
        relative(self.a.root, meta['server_key'])
        serve = [SERVE] + meta['owner_args'] + ['--intent', intent_a, '--intent-id', intent_id, '--key', meta['server_key'], '--listen', listen] + peers
        server = self.supervisor(self.a, {'server': {'argv': [self.a.binary] + serve}})
        before = self.review(meta)
        require(before == meta['before'], 'receiver review changed before delivery')
        ready = self.start(server, 'server')
        address = reachable_route(ready['listen'], self.cfg['server_ip'], self.cfg['port'])
        self.stop(server, 'server')
        require(self.review(meta) == before, 'route discovery changed original owners')
        deliver = [DELIVER, '--assignment', sender_files['assignment'], '--assignment-id', meta['assignment_id'], '--intent-id', intent_id,
                   '--outbox', outbox, '--key', self.b.root + '/client.seed', '--peer', address]
        client = self.supervisor(self.b, {'client': {'argv': [self.b.binary] + deliver}})
        events = []
        if n == 0:
            unavailable = reachable_route([address], '127.0.0.1', self.cfg['port']).replace('/udp/%d/' % self.cfg['port'], '/udp/1/')
            self.cli(self.b, deliver[:-1] + [unavailable, '--timeout', '100ms'], fail=True)
            for kill in (False, True):
                self.start(server, 'server'); self.stop(server, 'server', kill)
                require(self.review(meta) == before, 'idle restart changed original owners')
            events += ['unreachable-route', 'idle-sigterm', 'idle-sigkill']
        mode = 'server' if n < 2 else 'client'
        stage = ['pins-admission-confirm-before-publish', 'scheduled-delivery-confirmed',
                 'scheduled-outbox-reply-verified', 'scheduled-outbox-after-publish'][n]
        host = self.a if mode == 'server' else self.b
        barrier_cfg = {'Root': host.root, 'Mode': mode, 'Stage': stage, 'IntentID': intent_id}
        if mode == 'server':
            barrier_cfg.update(Command=meta['command'], IntentPath=intent_a, Listen=listen)
        else:
            barrier_cfg.update(AssignmentPath=sender_files['assignment'], AssignmentID=meta['assignment_id'], Outbox=outbox, Address=address)
        conf_name = prefix + 'barrier.json'
        host.write(conf_name, json.dumps(barrier_cfg).encode())
        barrier = self.supervisor(host, {'barrier': {'argv': [host.config['store_test_binary'], '-test.run=^TestProcessPruneWANBarrier$', '-test.v'],
                                                 'env': {'OMESH_REMOTE_GATE_ARGS': host.root + '/' + conf_name}}}, store=True)
        if mode == 'server':
            self.start(barrier, 'barrier', True)
            client.rpc('start', name='client')
        else:
            self.start(server, 'server')
            barrier.rpc('start', name='barrier')
        try:
            require(self.record(barrier, 'barrier', 'prune_wan_barrier_reached ') == stage, 'wrong durable crash boundary')
        except AcceptanceError as error:
            details = client.rpc('status', name='client') if mode == 'server' else barrier.rpc('status', name='barrier')
            raise AcceptanceError('barrier was not reached; process status: ' + repr(details)) from error
        self.stop(barrier, 'barrier', True)
        if mode == 'server':
            client.expect_failure('client')
        else:
            self.stop(server, 'server', n == 2)
        events.append('test-barrier-kill:' + stage)
        retained = self.cli(self.b, box)
        require(retained['receipt_present'] is (n == 3), 'crash promoted or discarded a durable receipt')
        cut = self.review(meta)
        if n == 0:
            require(cut['Review']['Authority']['Pending'] is not None or cut['Executor']['Protection']['Pending'] is not None,
                    'interruption did not leave an original unconfirmed write')
            self.cli(self.a, serve, fail=True)
            require(self.review(meta) == cut, 'server startup resumed unknown work')
            self.cli(self.a, [APPLY] + meta['owner_args'] + ['--mode', 'resume', '--expected-review-id', hash_text(cut['Review']['ReviewID'])])
            cut = self.review(meta)
            events += ['pending-startup-refused', 'explicit-local-resume']
        assert_transition(before, cut, kind, meta['ticket_id'], meta['evidence_id'])
        if n != 3:
            self.start(server, 'server')
            delivered = self.cli(self.b, deliver)
            self.stop(server, 'server')
        else:
            delivered = self.cli(self.b, deliver[:-1] + ['offline'])
        require(delivered['delivery_confirmed'] is True and delivered['execution_authorized'] is False, 'missing historical delivery confirmation')
        receipt = self.cli(self.b, box)
        offline = self.cli(self.b, deliver[:-1] + ['offline'])
        require(receipt['receipt_present'] is True and offline['receipt_nonce'] == receipt['receipt_nonce'], 'offline retry changed receipt')
        after = self.review(meta)
        require(after == cut, 'exact retry changed original accounting')
        events += ['exact-original-retry', 'offline-receipt']
        self.start(server, 'server'); self.stop(server, 'server')
        require(self.review(meta) == after, 'historical startup changed owners')
        self.report['steps'].append({'step': n, 'kind': kind, 'intent_id': intent_id, 'assignment_id': meta['assignment_id'],
                                     'evidence_id': meta['evidence_id'], 'pending_before': before['Review']['Authority']['Authority']['Pending'],
                                     'pending_after': after['Review']['Authority']['Authority']['Pending'], 'events': events,
                                     'original_accounting_preserved': True})
        for s in (barrier, client, server):
            s.close()

    def run(self):
        self.new_root(self.a); self.new_root(self.b)
        self.b.write('client.seed', bytes([46]) * 32)
        self.a.write('fixture.json', json.dumps({'Root': self.a.root, 'Scenario': self.cfg['scenario']}).encode())
        driver = self.supervisor(self.a, {'fixture': {'argv': [self.a.test_binary, '-test.run=^TestProcessPruneWANFixture$', '-test.v'],
                                                      'env': {'OMESH_REMOTE_GATE_ARGS': self.a.root + '/fixture.json'}}})
        self.report['binaries'] = {role: {name: host.sha256(host.config[name]) for name in ('binary', 'test_binary', 'store_test_binary')}
                                   for role, host in (('receiver', self.a), ('sender', self.b))}
        require(self.report['binaries']['receiver'] == self.report['binaries']['sender'], 'hosts use different tested binaries')
        driver.rpc('start', name='fixture')
        for n in range(4):
            self.step(json.loads(self.record(driver, 'fixture', 'prune_wan_step ')))
            driver.rpc('send', name='fixture', line='continue ' + str(n))
        require(self.record(driver, 'fixture', 'prune_wan_done ') == self.cfg['scenario'], 'fixture did not finish its full outcome')
        require(driver.rpc('wait', name='fixture', timeout=15)['returncode'] == 0, 'fixture accounting assertions failed')
        self.close()
        self.report['completed'] = True
        self.report['children_drained'] = True
        return self.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    campaign = Campaign(json.loads(Path(args.config).read_text()))
    try:
        campaign.run()
    finally:
        try:
            campaign.close()
        finally:
            Path(args.report).write_text(json.dumps(campaign.report, indent=2) + '\n')
    print(json.dumps({'completed': True, 'scenario': campaign.cfg['scenario'], 'steps': len(campaign.report['steps'])}))


if __name__ == '__main__':
    main()
