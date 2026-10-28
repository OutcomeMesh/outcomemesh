import copy
import unittest

import delivery
import enrolled_delivery as enrolled
from run import AcceptanceError, ZERO
import test_delivery as fixtures


class EnrolledDeliveryCampaignTests(unittest.TestCase):
    def report(self):
        r = fixtures.AdmissionDeliveryCampaignTests().report()
        r["runtime_registry_enforced"] = True
        for i, c in enumerate(r["cases"]):
            def h(n): return "%064x" % (10000 + i * 100 + n)
            proof = h(1)
            c["delivery"]["protocol"] = enrolled.PROTOCOL
            for d in (c["delivery"], c["delivery"]["enrollment"], c["delivery"]["receipt"]): d["registry_enrollment_id"] = proof
            candidate = {"assignment_id": h(2), "candidate_id": c["genesis_id"], "candidate_descriptor_id": h(3)}
            g = {"format": 2, "policy": 4, "registry_id": h(4), "descriptor_id": h(5), "selection_id": h(6), "registry_enrollment_id": proof,
                 "candidate": candidate, "protected_physical_enrollment": False, "legacy_cutover": False,
                 "checks": {k: True for k in enrolled.REGISTRY_CHECKS}, "members": [],
                 "artifacts": [{"sha256": h(20 + j), "host": "a" if j % 2 else "b", "path": "/public/%d" % j} for j in range(20)]}
            for seed in range(111, 115):
                g["members"].append({"seed": seed, "host": "a" if seed <= 112 else "b", "final": {
                    "registry_id": g["registry_id"], "descriptor_id": g["descriptor_id"], "sequence": 1, "head": g["selection_id"],
                    "pending_id": ZERO, "selection_final": True, "selected_assignment_id": candidate["assignment_id"],
                    "selected_genesis_id": candidate["candidate_id"], "selected_descriptor_id": candidate["candidate_descriptor_id"]}})
            c["registry"] = g
        return r

    def test_complete_enrolled_campaign_keeps_unknown_held(self):
        s = enrolled.validate(self.report())
        self.assertTrue(s["runtime_registry_enforced"])
        self.assertEqual(s["registry_selections"], 2)
        self.assertEqual(s["signed_policy"], 4)
        self.assertEqual(s["unknown_still_held"], 1)
        self.assertFalse(s["delivery_execution_granted"])

    def test_hash_only_downgraded_or_overstated_report_refused(self):
        mutations = [lambda r: r.update(runtime_registry_enforced=False), lambda r: r["cases"][0].pop("registry"),
                     lambda r: r["cases"][0]["registry"].update(format=1), lambda r: r["cases"][0]["registry"].update(policy=3),
                     lambda r: r["cases"][0]["registry"].update(protected_physical_enrollment=True),
                     lambda r: r["cases"][0]["registry"].update(legacy_cutover=True),
                     lambda r: r["cases"][0]["registry"]["checks"].pop("received_both_full_proofs"),
                     lambda r: r["cases"][0]["delivery"]["receipt"].update(registry_enrollment_id=ZERO),
                     lambda r: r["cases"][0]["delivery"].update(protocol=delivery.PROTOCOL),
                     lambda r: r["cases"][0]["registry"]["candidate"].update(candidate_id="f" * 64),
                     lambda r: r["cases"][0]["registry"]["members"].pop(),
                     lambda r: r["cases"][0]["registry"]["members"][0].update(host="b"),
                     lambda r: r["cases"][0]["registry"]["members"][0]["final"].update(sequence=0),
                     lambda r: r["cases"][0]["registry"]["members"][0]["final"].update(pending_id="f" * 64),
                     lambda r: r["cases"][0]["registry"]["members"][0]["final"].update(selected_descriptor_id="f" * 64),
                     lambda r: r["cases"][0]["registry"]["artifacts"].clear(),
                     lambda r: r["cases"][1]["registry"].update(registry_id=r["cases"][0]["registry"]["registry_id"])]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                r = self.report(); mutate(r)
                with self.assertRaises(AcceptanceError): enrolled.validate(r)

    def enrollment(self):
        raw = b"OMCVDEN4\0\4" + b"".join(bytes([i]) * 32 for i in range(1, 8)) + b"\2" + b"\10" * 32 + b"\11" * 32
        self.assertEqual(len(raw), 299)
        return raw

    def receipt(self):
        return b"OMCVDAR4\0\4" + b"".join(bytes([i]) * 32 for i in range(1, 7)) + b"\2" + b"\10" * 64

    def test_public_frames_expose_registry_proof_and_exact_identity(self):
        e = enrolled.decode_enrollment(self.enrollment()); r = enrolled.decode_receipt(self.receipt())
        self.assertEqual(e["registry_enrollment_id"], "09" * 32)
        self.assertEqual(r["registry_enrollment_id"], "06" * 32)
        self.assertEqual(e["role"], r["role"])
        with self.assertRaises(AcceptanceError): delivery.decode_enrollment(self.enrollment())
        with self.assertRaises(AcceptanceError): delivery.decode_receipt(self.receipt())
        for raw, fn in ((self.enrollment(), enrolled.decode_enrollment), (self.receipt(), enrolled.decode_receipt)):
            for bad in (raw[:-1], raw+b"\0", b"OMCVDEN2\0\2"+raw[10:], raw[:9]+b"\2"+raw[10:]):
                with self.assertRaises(AcceptanceError): fn(bad)

    def test_legacy_report_stays_in_legacy_validation(self):
        r = fixtures.AdmissionDeliveryCampaignTests().report()
        with self.assertRaises(AcceptanceError): enrolled.validate(r)
        with self.assertRaises(AcceptanceError): delivery.validate(self.report())
        self.assertEqual(enrolled.EnrolledCase.delivery_cli, enrolled.CLI)
        self.assertEqual(enrolled.EnrolledCase.runtime_cli, enrolled.RUNTIME)
