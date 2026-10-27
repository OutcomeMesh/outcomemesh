import copy
import unittest

import witness
from run import AcceptanceError, ZERO


class WitnessReportTests(unittest.TestCase):
    def report(self):
        commands = {name: char * 64 for name, char in zip(("claim", "unknown", "result", "conflict"), "bcde")}
        certificates = {name: char * 64 for name, char in zip(("claim", "unknown", "result"), "123")}
        initial = {"sequence": 0, "head": "a" * 64, "pending": ZERO}
        states = [dict(initial) for _ in range(4)]
        events = []

        def event(i, name=None, sequence=None, before=None, fail=False):
            pin = copy.deepcopy(before or states[i])
            entry = {"member": i, "before": pin, "request_id": "%064x" % (len(events) + 1),
                     "command": name, "certificate": certificates.get(sequence), "completed": not fail}
            if fail:
                entry["refused"] = True
            elif name:
                after = dict(pin, pending=commands[name], phase=pin["sequence"], held=pin["sequence"] > 0)
                entry.update(after=after, response_sha256="f" * 64)
                states[i] = {key: after[key] for key in ("sequence", "head", "pending")}
            else:
                n = {"claim": 1, "unknown": 2, "result": 3}[sequence]
                after = {"sequence": n, "head": commands[sequence], "pending": ZERO, "phase": n, "held": True}
                entry.update(after=after, response_sha256="f" * 64)
                states[i] = {key: after[key] for key in ("sequence", "head", "pending")}
            events.append(entry)

        for i in (2, 3, 0):
            event(i, "claim")
        for i in (0, 2, 3):
            before = copy.deepcopy(states[i])
            event(i, sequence="claim")
            event(i, sequence="claim", before=before)
        event(1, sequence="claim")
        for i in (0, 1, 2):
            event(i, "unknown")
        for i in range(4):
            event(i, sequence="unknown")
        event(2, "claim", before=initial, fail=True)
        event(2, "conflict", before=initial, fail=True)
        for i in (0, 2, 3):
            event(i, "result")
        for i in range(4):
            event(i, sequence="result")
        return {"schema_version": 1, "members": 4, "threshold": 3, "logical_members_per_host": [2, 2],
                "passed": True, "scope_id": "a" * 64, "commands": commands, "certificates": certificates,
                "observed_kernel_boot_sha256": {"a": "4" * 64, "b": "5" * 64},
                "two_member_outage_refused": True, "duplicate_member_refused": True,
                "one_member_outage_quorum_passed": True, "unknown_sigkill_retained": True,
                "stale_cold_pin_refused": True, "late_claim_refused": True,
                "unclaimed_close_after_unknown_refused": True, "commit_exact_retries": 3,
                "result_commitment_is_opaque": True, "current_custody_source_acceptance_checked": False,
                "independent_four_host_deployment": False, "events": events,
                "final": [dict(pin, phase=3, held=True) for pin in states]}

    def test_complete_original_histories_and_remaining_holds(self):
        self.assertEqual(witness.validate(self.report())["obligations_held"], 4)

    def test_rejects_missing_duplicated_or_released_evidence(self):
        for mutate in (lambda r: r["events"].clear(),
                       lambda r: r["events"].append(copy.deepcopy(r["events"][0])),
                       lambda r: r["final"][0].update(held=False),
                       lambda r: r["events"][0]["after"].update(sequence=1),
                       lambda r: r["observed_kernel_boot_sha256"].update(b="4" * 64),
                       lambda r: r.update(independent_four_host_deployment=True),
                       lambda r: r.update(current_custody_source_acceptance_checked=True)):
            report = self.report()
            mutate(report)
            with self.assertRaises(AcceptanceError):
                witness.validate(report)


if __name__ == "__main__":
    unittest.main()
