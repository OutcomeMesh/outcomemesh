"""Reject ambiguous campaign pins and accounting changes before claiming success."""
import copy
import unittest

from prune_delivery import validate_config, flags, hash_text, relative, assert_transition, reachable_route
from run import AcceptanceError


class PruneDeliveryTests(unittest.TestCase):
    def config(self):
        host = {'kind': 'local', 'root': '/task/a', 'binary': '/build/omd',
                'test_binary': '/build/omd.test', 'store_test_binary': '/build/store.test', 'support': '/build/support.py'}
        return {'version': 1, 'scenario': 'settlement', 'a': host, 'b': dict(host, root='/task/b'),
                'server_ip': '127.0.0.1', 'port': 43891}

    def test_config_requires_explicit_distinct_roles(self):
        cfg = self.config()
        self.assertEqual(validate_config(cfg), cfg)
        for key, value in [('version', True), ('scenario', 'unknown'), ('port', True), ('port', 22), ('server_ip', '0.0.0.0')]:
            with self.subTest(key=key, value=value), self.assertRaises((ValueError, AcceptanceError)):
                validate_config(dict(cfg, **{key: value}))
        with self.assertRaises(AcceptanceError):
            validate_config(dict(cfg, b=cfg['a']))
        with self.assertRaises(AcceptanceError):
            validate_config(dict(cfg, password='forbidden'))

    def test_ssh_requires_pinned_noninteractive_configuration(self):
        cfg = self.config()
        ssh = ['ssh', '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes', 'fixture-host']
        cfg['a'] = dict(cfg['a'], kind='ssh', ssh=ssh)
        validate_config(cfg)
        for argv in [['ssh', 'fixture-host'], ['sshpass', '-p', 'secret'], ['ssh', '-o', 'StrictHostKeyChecking=no', 'host']]:
            with self.assertRaises(AcceptanceError):
                validate_config(dict(cfg, a=dict(cfg['a'], ssh=argv)))

    def test_flag_and_public_artifact_bounds(self):
        self.assertEqual(flags(['--plan', '/task/plan']), {'--plan': '/task/plan'})
        for argv in [['--plan'], ['--plan','a','--plan','b'], ['file','x'], ['--key','line\nline']]:
            with self.assertRaises(AcceptanceError): flags(argv)
        for path in ['/outside/file', '/task/a/../seed', '/task/ab/file', '/task/a']:
            with self.assertRaises(AcceptanceError): relative('/task/a', path)
        self.assertEqual(relative('/task/a', '/task/a/public/plan'), 'public/plan')
        for value in [None, [False] * 32, [256] * 32, [1] * 31]:
            with self.assertRaises(AcceptanceError): hash_text(value)

    def test_route_preserves_transport_identity_and_requires_quic_endpoint(self):
        route = '/ip4/127.0.0.1/udp/43891/quic-v1/p2p/12D3KooFixture'
        self.assertEqual(reachable_route([route], '192.0.2.1', 43891), route.replace('127.0.0.1', '192.0.2.1'))
        for invalid in [route.split('/p2p/')[0], route.replace('/quic-v1', '/tcp'), route.replace('43891', '43892')]:
            with self.assertRaises(AcceptanceError): reachable_route([invalid], '192.0.2.1', 43891)

    def state(self, pending=2, sequence=5):
        operations = [{'TicketID': [1]*32, 'EvidenceID': [0]*32, 'CompletionID': [0]*32, 'OperationID': [3]*32},
                      {'TicketID': [2]*32, 'EvidenceID': [0]*32, 'CompletionID': [0]*32, 'OperationID': [4]*32}]
        return {'Review': {'AlreadyApplied': True, 'Authority': {'Authority': {
            'Sequence': sequence, 'Pending': pending, 'Operations': operations}}}, 'Executor': {'outcome': 'full-settlement'}}

    def test_completion_preserves_old_work_and_full_evidence(self):
        before = self.state()
        after = copy.deepcopy(before)
        state = after['Review']['Authority']['Authority']
        state.update(Sequence=6, Pending=1)
        state['Operations'][1]['EvidenceID'] = [8]*32
        state['Operations'][1]['CompletionID'] = [9]*32
        assert_transition(before, after, 'complete', '02'*32, '08'*32)
        with self.assertRaises(AcceptanceError): assert_transition(before, after, 'complete', '05'*32, '08'*32)
        variants = []
        changed = copy.deepcopy(after); changed['Executor']['outcome'] = 'bare-effect'; variants.append(changed)
        changed = copy.deepcopy(after); changed['Review']['Authority']['Authority']['Operations'][0]['OperationID'] = [9]*32; variants.append(changed)
        changed = copy.deepcopy(after); changed['Review']['Authority']['Authority']['Operations'][1]['EvidenceID'] = [7]*32; variants.append(changed)
        changed = copy.deepcopy(after); changed['Review']['Authority']['Authority']['Sequence'] = 7; variants.append(changed)
        for changed in variants:
            with self.assertRaises(AcceptanceError): assert_transition(before, changed, 'complete', '02'*32, '08'*32)


if __name__ == '__main__':
    unittest.main()
