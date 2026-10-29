"""Regression tests for canonical distributed fixture control and cleanup."""
import base64
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch

import profile5
import profile5_host

class Profile5SupportTests(unittest.TestCase):
    def test_step_has_every_canonical_go_field(self):
        spec = profile5_host.step_spec({'Step': 'seed', 'Role': 'a'}, '/task', '/fixture')
        self.assertEqual(set(spec), {'Step', 'Role', 'Root', 'Fixture', 'Name', 'Input', 'Output', 'Family', 'Kind', 'Seed', 'Votes'})
        self.assertIsNone(spec['Votes'])
        self.assertEqual(spec['Kind'], 0)
        self.assertEqual(spec['Output'], '')
        self.assertEqual(spec['Root'], '/task')
        with self.assertRaises(ValueError):
            profile5_host.step_spec({'step': 'seed'}, '/task', '/fixture')

    def test_step_cannot_override_task_placement(self):
        spec = profile5_host.step_spec({'Root': '/other', 'Fixture': '/other'}, '/task', '/fixture')
        self.assertEqual(spec['Root'], '/task')
        self.assertEqual(spec['Fixture'], '/fixture')

    def test_no_artifact_path_escape(self):
        host = profile5_host.Host.__new__(profile5_host.Host)
        host.root = pathlib.Path('/task')
        for name, area in [('../key','public'), ('/key','public'), ('key','../'), ('..','private'), ('','client')]:
            with self.assertRaises(ValueError): host.path(name, area)
        self.assertEqual(host.path('request'), pathlib.Path('/task/public/request'))

    def test_public_output_no_replace(self):
        host = profile5_host.Host.__new__(profile5_host.Host)
        with tempfile.TemporaryDirectory() as root:
            host.root = pathlib.Path(root); (host.root/'public').mkdir()
            x = {'name':'response', 'data':base64.b64encode(b'first').decode()}
            host.dispatch('put', x); host.dispatch('put', x)
            with self.assertRaises(ValueError):
                host.dispatch('put', dict(x, data=base64.b64encode(b'other').decode()))
            self.assertEqual((host.root/'public/response').read_bytes(), b'first')

    def test_rpc_list_result_is_valid_and_request_id_is_pinned(self):
        r = profile5.Remote.__new__(profile5.Remote)
        r.serial=0; r.role='a'; r.history=[]; r.p=Mock(); r.p.stdin=io.StringIO()
        r.receive=Mock(return_value={'id':1,'result':['request']})
        self.assertEqual(r.call('list'), ['request'])
        self.assertEqual(json.loads(r.p.stdin.getvalue())['id'], 1)
        r.receive=Mock(return_value={'id':1,'result':{}})
        with self.assertRaises(RuntimeError): r.call('list')

    def test_close_drains_owned_children_and_fault_relay(self):
        h = profile5_host.Host.__new__(profile5_host.Host); relay=Mock(); h.relay=relay
        a,b=Mock(),Mock(); a.poll.side_effect=[None,0]; b.poll.return_value=0
        h.children={'running':(a,None),'done':(b,None)}; h.dispatch=Mock()
        self.assertEqual(h.close(), {'running_children':0})
        relay.close.assert_called_once(); h.dispatch.assert_called_once_with('stop',{'name':'running','kill':True})

if __name__=='__main__': unittest.main()
