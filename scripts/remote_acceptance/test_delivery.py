import copy
import unittest

import delivery
from run import AcceptanceError, ZERO
import test_required as required_fixtures


class AdmissionDeliveryCampaignTests(unittest.TestCase):
    def report(self):
        report = required_fixtures.RequiredRuntimeCampaignTests().report()
        report["durable_admission_delivery"] = True
        for i, case in enumerate(report["cases"]):
            source = copy.deepcopy(case["admission_before_runtime"]["sources_after"])
            eid, did, rid = ("%064x" % (3000 + i * 10 + j) for j in range(3))
            e = {"context_id": case["context_id"], "scope_id": case["scope_id"], "binding_id": case["binding_id"],
                 "enrollment_id": eid, "sender_peer_id": "1" * 64, "recipient_peer_id": "2" * 64,
                 "placement_id": "3" * 64, "nonce": "%064x" % (4000 + i), "receipt_public_key": "4" * 64, "role": 2}
            r = {key: e[key] for key in ("context_id", "scope_id", "binding_id", "enrollment_id", "role")}
            r.update(delivery_id=did, receipt_id=rid, sha256="5" * 64)
            case["delivery"] = {"proof_only": True, "execution_granted": False, "runtime_owner_created_by_delivery": False,
                                "protocol": delivery.PROTOCOL, "context_id": case["context_id"], "scope_id": case["scope_id"],
                                "binding_id": case["binding_id"], "enrollment": e, "delivery_id": did, "receipt": r,
                                "route_sha256": "6" * 64, "network_attempts": 3, "outboxes": 2, "receivers": 1,
                                "checks": {name: True for name in delivery.CHECKS}, "sources_before": source,
                                "sources_after": copy.deepcopy(source), "cleanup_complete": True,
                                "observed_kernel_boot_sha256": copy.deepcopy(case["execution"]["observed_kernel_boot_sha256"]),
                                "artifacts": [{"host": "a" if n % 2 else "b", "path": "/fresh/public-%d" % n,
                                               "sha256": "%064x" % (n + 1)} for n in range(11)]}
        return report

    def test_delivery_then_required_runtime_retains_unknown_work(self):
        summary = delivery.validate(self.report())
        self.assertEqual(summary["durable_proof_deliveries"], 2)
        self.assertEqual(summary["proof_delivery_network_attempts"], 6)
        self.assertEqual(summary["delivery_source_appends"], 0)
        self.assertFalse(summary["delivery_execution_granted"])
        self.assertEqual(summary["unknown_still_held"], 1)

    def test_incomplete_or_overstated_delivery_evidence_is_refused(self):
        mutations = [lambda r: r.update(durable_admission_delivery=False), lambda r: r["cases"][0].pop("delivery"),
                     lambda r: r["cases"][0]["delivery"].update(proof_only=False),
                     lambda r: r["cases"][0]["delivery"].update(execution_granted=True),
                     lambda r: r["cases"][0]["delivery"].update(runtime_owner_created_by_delivery=True),
                     lambda r: r["cases"][0]["delivery"].update(cleanup_complete=False),
                     lambda r: r["cases"][0]["delivery"].update(protocol="/outcomemesh/custody/v2"),
                     lambda r: r["cases"][0]["delivery"].update(binding_id="f" * 64),
                     lambda r: r["cases"][0]["delivery"].update(network_attempts=1),
                     lambda r: r["cases"][0]["delivery"].update(outboxes=1),
                     lambda r: r["cases"][0]["delivery"].update(receivers=4),
                     lambda r: r["cases"][0]["delivery"]["checks"].pop("offline_send_stays_unresolved"),
                     lambda r: r["cases"][0]["delivery"]["enrollment"].update(placement_id=ZERO),
                     lambda r: r["cases"][0]["delivery"]["enrollment"].update(sender_peer_id="2" * 64),
                     lambda r: r["cases"][0]["delivery"]["receipt"].update(enrollment_id="f" * 64),
                     lambda r: r["cases"][0]["delivery"]["receipt"].update(delivery_id="f" * 64),
                     lambda r: r["cases"][0]["delivery"]["receipt"].update(role=1),
                     lambda r: r["cases"][0]["delivery"]["receipt"].update(sha256=ZERO),
                     lambda r: r["cases"][0]["delivery"]["sources_after"]["b"].update(source_sequence=1),
                     lambda r: r["cases"][0]["delivery"]["sources_after"]["b"].update(consumed=True),
                     lambda r: r["cases"][0]["delivery"]["sources_before"].pop("clone"),
                     lambda r: r["cases"][0]["delivery"]["artifacts"].clear(),
                     lambda r: r["cases"][0]["delivery"]["artifacts"][0].update(sha256="?"),
                     lambda r: r["cases"][0]["delivery"]["observed_kernel_boot_sha256"].update(a="f" * 64)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report = self.report(); mutate(report)
                with self.assertRaises(AcceptanceError):
                    delivery.validate(report)

    def enrollment(self):
        return b"OMCVDEN2\0\2" + b"".join(bytes([i]) * 32 for i in range(1, 8)) + b"\2" + b"\10" * 32

    def receipt(self):
        return b"OMCVDAR2\0\2" + b"".join(bytes([i]) * 32 for i in range(1, 6)) + b"\2" + b"\6" * 64

    def test_public_framing_and_hashes_are_exact(self):
        raw = self.enrollment(); e = delivery.decode_enrollment(raw)
        self.assertEqual(e["context_id"], "01" * 32)
        self.assertEqual(e["recipient_peer_id"], "05" * 32)
        self.assertEqual(e["receipt_public_key"], "08" * 32)
        self.assertEqual(e["role"], 2)
        self.assertEqual(e["enrollment_id"], delivery.digest(delivery.DOMAIN + "/enrollment/id", raw))
        raw = self.receipt(); r = delivery.decode_receipt(raw)
        self.assertEqual(r["delivery_id"], "01" * 32)
        self.assertEqual(r["binding_id"], "05" * 32)
        self.assertEqual(r["role"], 2)
        self.assertEqual(r["receipt_id"], delivery.digest(delivery.DOMAIN + "/receipt/id", raw))
        for decode, raw in ((delivery.decode_enrollment, self.enrollment()), (delivery.decode_receipt, self.receipt())):
            for bad in (raw[:-1], raw + b"\0", raw[:9] + b"\3" + raw[10:], b"wrong" + raw[5:], raw[:10] + b"\0" * 32 + raw[42:]):
                with self.subTest(decode=decode, bad=bad[:10]):
                    with self.assertRaises(AcceptanceError):
                        decode(bad)
        with self.assertRaises(AcceptanceError):
            delivery.decode_receipt(self.receipt()[:-64] + b"\0" * 64)


if __name__ == "__main__":
    unittest.main()
