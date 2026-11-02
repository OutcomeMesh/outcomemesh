import unittest
from unittest.mock import Mock, patch

from prune_service import Host


class PruneProcessSupervisionTests(unittest.TestCase):
    def setUp(self):
        self.host = Host.__new__(Host)
        self.host.python = Mock(side_effect=[b'no', b'yes'])
        self.host.read = Mock(return_value=b'retained result')
        self.child = Mock(log='owner.log')
        self.child.p.poll.return_value = None

    def test_slow_offline_settlement_can_finish_within_its_bound(self):
        with patch('prune_service.time.monotonic', side_effect=[0, 41, 80]), patch('prune_service.time.sleep'):
            result = self.host.wait_file('offline-ready', self.child, timeout=120)
        self.assertEqual(result, b'retained result')
        self.host.read.assert_called_once_with('offline-ready')

    def test_startup_and_settlement_both_remain_bounded(self):
        for kwargs, expired in [({}, 41), ({'timeout': 120}, 121)]:
            with self.subTest(kwargs=kwargs), patch('prune_service.time.monotonic', side_effect=[0, expired]):
                with self.assertRaisesRegex(RuntimeError, 'readiness timed out'):
                    self.host.wait_file('ready', self.child, **kwargs)
        self.host.python.assert_not_called()

    def test_dead_owner_is_not_hidden_by_the_longer_bound(self):
        self.child.p.poll.return_value = 1
        with patch('prune_service.time.monotonic', side_effect=[0, 1]):
            with self.assertRaisesRegex(RuntimeError, 'child ended early'):
                self.host.wait_file('offline-ready', self.child, timeout=120)
        self.host.python.assert_not_called()


if __name__ == '__main__':
    unittest.main()
