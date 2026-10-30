import unittest

import repository


class RepositoryRequirements(unittest.TestCase):
    def test_reconcile_preserves_additional_protection_and_app_bindings(self):
        original = {'strict': False, 'checks': [{'context': 'external-audit', 'app_id': 42},
                                                {'context': 'required', 'app_id': -1}]}
        desired = repository.required_checks(original)
        self.assertTrue(desired['strict'])
        self.assertIn({'context': 'external-audit', 'app_id': 42}, desired['checks'])
        self.assertIn({'context': 'required', 'app_id': -1}, desired['checks'])
        for name in repository.REQUIRED:
            self.assertIn({'context': name, 'app_id': 15368}, desired['checks'])
        self.assertEqual(desired, repository.required_checks(desired))
        self.assertFalse(original['strict'])

    def test_read_only_audit_never_updates_protection(self):
        def forbidden(*args):
            self.fail('read-only audit called mutation')
        # Invalid configuration must fail before any API call, including update.
        with self.assertRaises(ValueError):
            repository.audit('../wrong/repo', api=forbidden, update=forbidden)


if __name__ == '__main__':
    unittest.main()
