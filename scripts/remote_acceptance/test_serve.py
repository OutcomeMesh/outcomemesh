import copy
import json
import struct
import unittest

import serve
from run import AcceptanceError, ZERO


class ServeReportTests(unittest.TestCase):
    def report(self):
        cases = []
        for i, name in enumerate((*serve.SCENARIOS, "unclaimed")):
            closed = name in ("lost-result", "unclaimed")
            state = {"Pending": not closed, "ArchiveHeld": True, "MinimumRetainUntil": 123,
                     "AttemptID": "a" * 64 if closed else ZERO, "ReceiptID": "b" * 64 if closed else ZERO}
            checks = {"typed_witness_rejects_unsigned_evidence": True, "lost_witness_output_exact_cold_retry": True,
                      "two_votes_and_duplicate_refused": True, "b_requires_a_applied_receipt": True,
                      "a_and_b_lost_output_exact_cold_resume": True, "original_sources_and_proof_times_unchanged": True,
                      "execution_closed_archive_held": True, "cold_key_copy_without_original_result_refused": True} if closed else {"unresolved_serve_and_archive_held": True}
            cases.append({"scenario": name, "scope_id": "%064x" % (i + 1), "serve_scope_id": "%064x" % (i + 10),
                          "states": {"a": copy.deepcopy(state), "b": copy.deepcopy(state)}, "checks": checks,
                          "witnesses": [{"sequence": 1, "head": "d" * 64, "pending": ZERO} for _ in range(4)] if closed else [],
                          "observed_kernel_boot_sha256": {"a": "1" * 64, "b": "2" * 64}, "passed": True,
                          "independent_four_domain_deployment": False, "archive_retirement_authorized": False})
        return {"schema_version": 1, "passed": True, "cases": cases}

    def test_all_four_outcomes_keep_archives(self):
        self.assertEqual(serve.validate(self.report()), {"cases": 4, "joint_hosts": 2, "logical_witnesses": 4,
                                                       "closed_jobs": 2, "unresolved_jobs_held": 2, "archives_released": 0})

    def test_missing_or_contradictory_evidence_refused(self):
        mutations = [lambda r: r["cases"].pop(), lambda r: r.update(passed=False),
                     lambda r: r["cases"][0].update(independent_four_domain_deployment=True),
                     lambda r: r["cases"][0].update(archive_retirement_authorized=True),
                     lambda r: r["cases"][0]["states"]["a"].update(ArchiveHeld=False),
                     lambda r: r["cases"][1]["states"]["b"].update(Pending=False),
                     lambda r: r["cases"][1]["states"]["a"].update(AttemptID="f" * 64),
                     lambda r: r["cases"][2]["states"]["a"].update(MinimumRetainUntil=0),
                     lambda r: r["cases"][0]["states"]["b"].update(AttemptID="f" * 64),
                     lambda r: r["cases"][0]["checks"].pop("cold_key_copy_without_original_result_refused"),
                     lambda r: r["cases"][0]["checks"].update(b_requires_a_applied_receipt=False),
                     lambda r: r["cases"][3]["checks"].pop("a_and_b_lost_output_exact_cold_resume"),
                     lambda r: r["cases"][3]["witnesses"].pop(),
                     lambda r: r["cases"][0]["witnesses"][0].update(pending="f" * 64),
                     lambda r: r["cases"][3]["witnesses"][0].update(head="e" * 64),
                     lambda r: r["cases"][0]["observed_kernel_boot_sha256"].update(b="1" * 64),
                     lambda r: r["cases"][3].update(serve_scope_id=r["cases"][0]["serve_scope_id"])]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report = self.report(); mutate(report)
                with self.assertRaises(AcceptanceError): serve.validate(report)

    def test_real_go_hash_arrays_are_decoded_strictly(self):
        state = {"Pending": True, "ArchiveHeld": True, "MinimumRetainUntil": 123,
                 "AttemptID": [0] * 32, "ReceiptID": list(range(32))}
        decoded = serve.decode_status(json.dumps(state).encode())
        self.assertEqual(decoded["AttemptID"], ZERO)
        self.assertEqual(decoded["ReceiptID"], bytes(range(32)).hex())
        for key in (ZERO, [0] * 31, [0] * 33, [True] * 32, [-1] * 32, [256] * 32):
            bad = copy.deepcopy(state); bad["AttemptID"] = key
            with self.assertRaises(AcceptanceError): serve.decode_status(json.dumps(bad).encode())
        for change in ({"Pending": 1}, {"ArchiveHeld": False}, {"MinimumRetainUntil": 0}):
            bad = dict(state, **change)
            with self.assertRaises(AcceptanceError): serve.decode_status(json.dumps(bad).encode())

    def test_exact_v0_observation_layout(self):
        scope, member = "a" * 64, "b" * 64
        raw = bytearray(308); raw[:10] = b"OMCFOB00\0\0"; raw[42:74] = bytes.fromhex(member); raw[74:106] = bytes.fromhex(scope)
        raw[106:114] = struct.pack(">Q", 1); raw[114:146] = b"c" * 32
        self.assertEqual(serve.observation(bytes(raw), scope, member, 1, (b"c" * 32).hex(), ZERO)["sequence"], 1)
        for bad in (raw[:-1], raw + bytes(32), bytes(raw[:9]) + b"\1" + bytes(raw[10:])):
            with self.assertRaises(AcceptanceError): serve.observation(bytes(bad), scope, member, 1, (b"c" * 32).hex(), ZERO)
        with self.assertRaises(AcceptanceError): serve.observation(bytes(raw), scope, member, 0, scope, ZERO)


if __name__ == "__main__":
    unittest.main()
