import copy
import unittest

import negative
from run import AcceptanceError


class NegativeEvidenceTests(unittest.TestCase):
    def report(self):
        states = {"a": {"assignment_id": "a" * 64, "confirmed_sequence": 4,
                         "pending_operations": 2, "active_remote": False,
                         "pending_attempt": False, "journal_sequence": 0},
                  "b": {"assignment_id": "a" * 64, "journal_sequence": 0,
                         "worker_stage": 4, "worker_pending": 0, "disposition": 2}}
        probes = {"a": ("control-key", "authority", "authority-pins", "journal", "artifacts", "anchor"),
                  "b": ("control-key", "worker", "journal", "objects", "anchor")}
        return {"scenario": "b-restart-before-result", "passed": True,
                "assignment_id": "a" * 64, "before": copy.deepcopy(states), "after": states,
                "exact_retry": True, "new_execution_rejected": True,
                "ordinary_tickets_retained": True,
                "observed_kernel_boot_sha256": {"a": "1" * 64, "b": "2" * 64},
                "placements": {"a": "b" * 64, "b": "c" * 64},
                "observations": [{"negative_id": "d" * 64, "artifact_sha256": "e" * 64,
                                  "kind": 2, "ordinary_tickets_retained": True, "source_advanced": False}],
                "copy_probes": {role: [{"name": name, "rejected": True, "exit_code": 2} for name in names]
                                for role, names in probes.items()}}

    def test_unknown_evidence_does_not_bless_completion_or_reexecution(self):
        report = self.report()
        self.assertEqual(negative.validate(report)["copy_probes_rejected"], 11)
        for mutation in (lambda r: r.update(new_execution_rejected=False),
                         lambda r: r["after"]["a"].update(pending_operations=0),
                         lambda r: r["observations"][0].update(kind=1),
                         lambda r: r["copy_probes"]["a"][0].update(exit_code=0),
                         lambda r: r["copy_probes"]["b"].pop(),
                         lambda r: r["observed_kernel_boot_sha256"].update(b="1" * 64)):
            selected = copy.deepcopy(report)
            mutation(selected)
            with self.assertRaises(AcceptanceError):
                negative.validate(selected)

    def test_unchanged_originals_are_required(self):
        report = self.report()
        report["after"]["b"]["journal_sequence"] = 1
        with self.assertRaises(AcceptanceError):
            negative.validate(report)

    def test_replacing_one_selected_flag_does_not_add_a_second(self):
        self.assertEqual(negative.replace_flag(["command", "--key", "/original"], "--key", "/copy"),
                         ["command", "--key", "/copy"])
        with self.assertRaises(AcceptanceError):
            negative.replace_flag(["command", "--key", "one", "--key", "two"], "--key", "copy")


if __name__ == "__main__":
    unittest.main()
