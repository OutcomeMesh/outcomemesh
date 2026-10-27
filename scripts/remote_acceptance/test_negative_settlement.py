import copy
import unittest

import negative_settlement
from run import AcceptanceError


class NegativeSettlementTests(unittest.TestCase):
    def report(self):
        state = {"a": {"assignment_id": "a" * 64, "confirmed_sequence": 4, "confirmed_head": "b" * 64,
                       "pending_operations": 2, "pending_attempt": False, "active_remote": False,
                       "journal_sequence": 0, "serve_ticket_id": "c" * 64, "original_identities": {"source": 19}},
                 "b": {"assignment_id": "a" * 64, "journal_sequence": 0, "worker_stage": 4, "worker_pending": 0}}
        after = copy.deepcopy(state)
        after["a"].update(confirmed_sequence=5, confirmed_head="d" * 64, pending_operations=1)
        return {"schema_version": 1, "scenario": "b-restart-before-result", "kind": 2, "passed": True,
                "assignment_id": "a" * 64, "negative_id": "e" * 64, "audit_complete_id": "d" * 64,
                "negative_report_sha256": "f" * 64, "before": state, "after": after,
                "exact_retry": True, "serve_signing_rejected": True, "new_execution_rejected": True,
                "positive_capture_rejected": True, "observed_kernel_boot_sha256": {"a": "1" * 64, "b": "2" * 64}}

    def test_administrative_disposition_keeps_one_obligation(self):
        self.assertEqual(negative_settlement.validate(self.report())["pending_operations"], 1)

    def test_rejects_released_hold_or_changed_source(self):
        for mutate in (lambda r: r["after"]["a"].update(pending_operations=0),
                       lambda r: r["after"]["a"].update(journal_sequence=1),
                       lambda r: r["after"]["b"].update(journal_sequence=1),
                       lambda r: r["after"]["a"]["original_identities"].update(source=20),
                       lambda r: r["after"]["a"].update(serve_ticket_id="9" * 64),
                       lambda r: r.update(exact_retry=False),
                       lambda r: r.update(kind=1),
                       lambda r: r["observed_kernel_boot_sha256"].update(b="1" * 64)):
            report = self.report()
            mutate(report)
            with self.assertRaises(AcceptanceError):
                negative_settlement.validate(report)


if __name__ == "__main__":
    unittest.main()
