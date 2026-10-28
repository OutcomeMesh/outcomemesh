import copy
import json
from pathlib import Path
import struct
import unittest

import admission
from run import AcceptanceError, ZERO


def go_hash(value):
    return list(bytes.fromhex(value))


class AdmissionCoordinatorTests(unittest.TestCase):
    def report(self):
        aid, cid, pid, did, eid = (str(i) * 64 for i in range(1, 6))
        gid = admission.digest("OMESH/custody/v2/admission/genesis/id", bytes.fromhex(aid))
        source = {"source_sequence": 0, "source_head": ZERO, "receipt_id": "e" * 64,
                  "original_identities_sha256": "d" * 64, "consumed": False, "result": False, "accepted": False}
        members = []
        for i in range(4):
            initial = {"genesis_id": gid, "sequence": 0, "head": gid, "pending_id": ZERO,
                       "spent_operations": 0, "pending_operations": 0, "active_context_id": ZERO,
                       "active_plan_id": ZERO, "source_sequence": 0, "source_head": ZERO,
                       "source_receipt_id": "e" * 64, "retain_until": 123, "coordinator_only": True,
                       "execution_granted": False, "status_artifact": "f" * 64}
            final = dict(initial, sequence=1, head=eid, spent_operations=2, pending_operations=2,
                         active_context_id=cid, active_plan_id=pid)
            members.append({"member": i, "host": "a" if i < 2 else "b", "signing_public_key": "%064x" % (100 + i),
                            "initial": initial, "final": final,
                            "before_vote": {"sequence": 0, "head": gid, "pending": ZERO},
                            "before_commit": {"sequence": 0, "head": gid, "pending": eid}})
        return {"schema_version": 1, "passed": True, "cleanup_complete": True, "assignment_id": aid,
                "context_id": cid, "plan_id": pid, "genesis_id": gid, "descriptor_id": did, "entry_id": eid,
                "authority_public_key": "a" * 64, "members": members,
                "sources_before": {role: copy.deepcopy(source) for role in ("a", "b", "clone")},
                "sources_after": {role: copy.deepcopy(source) for role in ("a", "b", "clone")},
                "checks": {name: True for name in admission.CHECKS},
                "observed_kernel_boot_sha256": {"a": "1" * 64, "b": "2" * 64},
                "coordinator_only": True, "execution_granted": False, "runtime_admission_enforced": False,
                "independent_four_domain_deployment": False, "budget_exhaustion_tested": False}

    def test_complete_reservation_stays_held_without_execution(self):
        self.assertEqual(admission.validate(self.report()), {"joint_hosts": 2, "logical_witnesses": 4,
                         "committed_admissions": 1, "spent_operations": 2, "pending_operations": 2,
                         "source_appends": 0, "execution_granted": False})

    def test_missing_or_contradictory_evidence_refused(self):
        mutations = [lambda r: r.update(passed=False), lambda r: r.update(cleanup_complete=False),
                     lambda r: r.update(execution_granted=True), lambda r: r.update(runtime_admission_enforced=True),
                     lambda r: r.update(independent_four_domain_deployment=True), lambda r: r.update(budget_exhaustion_tested=True),
                     lambda r: r.update(genesis_id="f" * 64), lambda r: r["checks"].pop("active_job_still_held"),
                     lambda r: r["checks"].update(stale_pins_refused=False), lambda r: r["members"].pop(),
                     lambda r: r["members"][3].update(signing_public_key=r["members"][0]["signing_public_key"]),
                     lambda r: r["members"][3].update(host="a"),
                     lambda r: r["members"][0]["before_vote"].update(pending="f" * 64),
                     lambda r: r["members"][0]["before_commit"].update(head="f" * 64),
                     lambda r: r["members"][0]["final"].update(pending_operations=0),
                     lambda r: r["members"][0]["final"].update(spent_operations=0),
                     lambda r: r["members"][0]["final"].update(pending_id="f" * 64),
                     lambda r: r["members"][0]["final"].update(active_context_id=ZERO),
                     lambda r: r["members"][0]["final"].update(active_plan_id=ZERO),
                     lambda r: r["members"][1]["final"].update(source_receipt_id="a" * 64),
                     lambda r: r["members"][0]["final"].update(retain_until=1),
                     lambda r: r["members"][2]["final"].update(sequence=2),
                     lambda r: r["sources_after"]["a"].update(source_sequence=1),
                     lambda r: r["sources_after"]["b"].update(consumed=True),
                     lambda r: r["sources_after"]["clone"].update(original_identities_sha256="f" * 64),
                     lambda r: r["observed_kernel_boot_sha256"].update(b="1" * 64)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report = self.report(); mutate(report)
                with self.assertRaises(AcceptanceError): admission.validate(report)

    def snapshot(self):
        gid, eid, cid, pid = (str(i) * 64 for i in range(1, 5))
        position = {"Sequence": 1, "HeadID": go_hash(eid)}
        return {"Snapshot": {"GenesisID": go_hash(gid), "Position": copy.deepcopy(position),
                             "SpentOperations": 2, "PendingOperations": 2, "ActiveContextID": go_hash(cid),
                             "ActivePlanID": go_hash(pid), "SourceSequence": 0, "SourceHeadID": go_hash(ZERO),
                             "SourceReceiptID": go_hash("a" * 64), "CurrentReceipt": {"RetainUntil": 123}, "RetainUntil": 123},
                "Pin": {"Position": copy.deepcopy(position), "PendingID": go_hash(ZERO)},
                "CoordinatorOnly": True, "ExecutionGranted": False}

    def test_real_go_hash_arrays_are_decoded_strictly(self):
        decoded = admission.decode_snapshot(json.dumps(self.snapshot()).encode())
        self.assertEqual(decoded["spent_operations"], 2)
        self.assertEqual(decoded["pending_id"], ZERO)
        for value in (ZERO, [0] * 31, [0] * 33, [True] * 32, [-1] * 32, [256] * 32):
            bad = self.snapshot(); bad["Snapshot"]["GenesisID"] = value
            with self.assertRaises(AcceptanceError): admission.decode_snapshot(json.dumps(bad).encode())
        mutations = [lambda s: s.update(ExecutionGranted=True), lambda s: s.update(CoordinatorOnly=False),
                     lambda s: s["Pin"]["Position"].update(Sequence=0),
                     lambda s: s["Snapshot"].update(SpentOperations=True),
                     lambda s: s["Snapshot"].update(PendingOperations=65536),
                     lambda s: s["Snapshot"].update(RetainUntil=0),
                     lambda s: s["Snapshot"]["CurrentReceipt"].update(RetainUntil=124)]
        for mutate in mutations:
            bad = self.snapshot(); mutate(bad)
            with self.assertRaises(AcceptanceError): admission.decode_snapshot(json.dumps(bad).encode())

    def test_public_genesis_preparation_preserves_framing(self):
        context = (Path(__file__).resolve().parents[2] / "node/custodyv2/testdata/public-fixture/context").read_bytes()
        raw = admission.genesis_from_context(context)
        self.assertEqual(raw[:10], b"OMCVAGN2\0\2")
        fields, offset = [], 10
        for _ in range(3):
            value, _, offset = admission.read_field(raw, offset); fields.append(value)
        self.assertEqual(fields[0][:10], b"OMCVASG2\0\2")
        self.assertEqual(admission.genesis_from_context(context), raw)
        for bad in (context[:-1], context + b"\0", context[:9] + b"\1" + context[10:]):
            with self.assertRaises(AcceptanceError): admission.genesis_from_context(bad)

    def test_canonical_unsigned_lengths_refuse_aliases_and_overflow(self):
        for length in (0, 1, 127, 128, 16384):
            raw = admission.encode_uvarint(length) + bytes(length)
            value, field, offset = admission.read_field(raw, 0)
            self.assertEqual(len(value), length); self.assertEqual(field, raw); self.assertEqual(offset, len(raw))
        for raw in (b"", b"\x80\x00", b"\x81\x00\0", bytes([255]) * 10, b"\x02\0"):
            with self.assertRaises(AcceptanceError): admission.read_field(raw, 0)


if __name__ == "__main__":
    unittest.main()
