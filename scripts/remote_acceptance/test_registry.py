import copy
import json
from pathlib import Path
import unittest

import admission
import registry
from run import AcceptanceError, ZERO


def go_hash(value):
    return list(bytes.fromhex(value))


class RegistryAcceptanceTests(unittest.TestCase):
    def report(self):
        gid, did, changed, sid, other_sid = (str(i) * 64 for i in range(1, 6))
        candidate = {"assignment_id": "a" * 64, "candidate_descriptor_id": "b" * 64}
        other = {"assignment_id": "c" * 64, "candidate_descriptor_id": "d" * 64}
        for c in (candidate, other):
            c["candidate_id"] = registry.digest("OMESH/custody/v2/admission/genesis/id", bytes.fromhex(c["assignment_id"]))
        members = []
        for seed in range(111, 115):
            initial = {"registry_id": gid, "descriptor_id": did, "sequence": 0, "head": gid, "pending_id": ZERO,
                       "selected_assignment_id": ZERO, "selected_genesis_id": ZERO, "selected_descriptor_id": ZERO,
                       "maximum_operations": 32, "maximum_pending": 8, "selection_final": False,
                       "selection_only": True, "execution_granted": False, "legacy_cutover": False, "status_artifact": "e" * 64}
            final = dict(initial, sequence=1, head=sid, selected_assignment_id=candidate["assignment_id"],
                         selected_genesis_id=candidate["candidate_id"], selected_descriptor_id=candidate["candidate_descriptor_id"], selection_final=True)
            members.append({"seed": seed, "host": "a" if seed < 113 else "b", "signing_public_key": "%064x" % seed,
                            "initial": initial, "final": final,
                            "before_commit": {"sequence": 0, "head": gid, "pending": other_sid if seed == 114 else sid}})
        effects = {role: {name: False for name in registry.EFFECT_PATHS} for role in ("a", "b")}
        artifacts = [{"host": "a" if i < 13 else "b", "path": "/private/fixture/public-%d" % i,
                      "sha256": "a" * 64, "artifact_id": "b" * 64} for i in range(26)]
        return {"schema_version": 1, "passed": True, "cleanup_complete": True,
                "registry_id": gid, "descriptor_id": did, "changed_descriptor_id": changed,
                "selection_id": sid, "other_selection_id": other_sid, "candidate": candidate, "other_candidate": other,
                "maximum_operations": 32, "maximum_pending": 8, "members": members,
                "checks": {name: True for name in registry.CHECKS}, "artifacts": artifacts,
                "original_records": {str(seed): {"selection.vote": ("d" if seed == 114 else "c") * 64,
                                                 "selection.certificate": "e" * 64} for seed in range(111, 115)},
                "effects_before": copy.deepcopy(effects), "effects_after": copy.deepcopy(effects),
                "observed_kernel_boot_sha256": {"a": "a" * 64, "b": "b" * 64},
                "roots": {"a": "/private/a", "b": "/private/b"}, "source_manifest": "f" * 64,
                "binaries": {"omd": "a" * 64, "omd.test": "b" * 64},
                "selection_only": True, "execution_granted": False, "legacy_cutover": False, "operator_channel": True,
                "runtime_registry_enforced": False, "protected_physical_enrollment": False, "services_started": 0,
                "independent_four_domain_deployment": False, "alternate_qc_subset_tested": False, "no_live_owner_transferred": True}

    def test_complete_operator_selection_keeps_minority_and_has_no_effect(self):
        self.assertEqual(registry.validate(self.report()), {"joint_hosts": 2, "logical_witnesses": 4, "selected_assignments": 1,
                         "retained_minority_votes": 1, "source_appends": 0, "execution_granted": False, "legacy_cutover": False})

    def test_missing_or_contradictory_campaign_provenance_is_refused(self):
        mutations = [lambda r: r.update(passed=False), lambda r: r.update(cleanup_complete=False),
                     lambda r: r.update(selection_only=False), lambda r: r.update(execution_granted=True),
                     lambda r: r.update(runtime_registry_enforced=True), lambda r: r.update(protected_physical_enrollment=True),
                     lambda r: r.update(independent_four_domain_deployment=True), lambda r: r.update(alternate_qc_subset_tested=True),
                     lambda r: r.update(legacy_cutover=True), lambda r: r.update(services_started=1),
                     lambda r: r.update(no_live_owner_transferred=False), lambda r: r.update(operator_channel=False),
                     lambda r: r.update(selection_id=r["other_selection_id"]), lambda r: r.update(changed_descriptor_id=r["descriptor_id"]),
                     lambda r: r["checks"].pop("lost_commit_output_exact_cold_retry"),
                     lambda r: r["checks"].update(changed_descriptor_same_registry_refused=False),
                     lambda r: r["members"].pop(), lambda r: r["members"][3].update(host="a"),
                     lambda r: r["members"][1].update(signing_public_key=r["members"][0]["signing_public_key"]),
                     lambda r: r["members"][3]["before_commit"].update(pending=r["selection_id"]),
                     lambda r: r["members"][0]["final"].update(head=r["other_selection_id"]),
                     lambda r: r["members"][0]["final"].update(sequence=2),
                     lambda r: r["members"][0]["final"].update(pending_id=r["selection_id"]),
                     lambda r: r["members"][0]["final"].update(selected_descriptor_id="f" * 64),
                     lambda r: r["members"][0]["final"].update(maximum_operations=33),
                     lambda r: r["candidate"].update(candidate_id="a" * 64),
                     lambda r: r["effects_after"]["b"].update(owner=True),
                     lambda r: r["observed_kernel_boot_sha256"].update(b="a" * 64),
                     lambda r: r["original_records"]["114"].update(**{"selection.vote": "c" * 64}),
                     lambda r: r["original_records"]["113"].update(**{"selection.certificate": "d" * 64}),
                     lambda r: r["artifacts"].clear(), lambda r: r["artifacts"].append(copy.deepcopy(r["artifacts"][0])),
                     lambda r: r["binaries"].update(omd=ZERO)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report = self.report(); mutate(report)
                with self.assertRaises(AcceptanceError): registry.validate(report)

    def snapshot(self, final=False):
        gid, did, sid, aid, cid, cdid = (str(i) * 64 for i in range(1, 7))
        position = {"Sequence": int(final), "HeadID": go_hash(sid if final else gid)}
        return {"Snapshot": {"RegistryID": go_hash(gid), "DescriptorID": go_hash(did), "Position": copy.deepcopy(position),
                             "SelectedAssignmentID": go_hash(aid if final else ZERO), "SelectedGenesisID": go_hash(cid if final else ZERO),
                             "SelectedDescriptorID": go_hash(cdid if final else ZERO), "MaximumOperations": 32,
                             "MaximumPending": 8, "SelectionFinal": final},
                "Pin": {"Position": copy.deepcopy(position), "PendingID": go_hash(ZERO)},
                "SelectionOnly": True, "ExecutionGranted": False, "LegacyCutover": False}

    def test_snapshot_decoder_preserves_actual_go_hash_arrays_and_state(self):
        for final in (False, True):
            result = registry.decode_snapshot(json.dumps(self.snapshot(final)).encode())
            self.assertEqual(result["sequence"], int(final)); self.assertEqual(result["selection_final"], final)
        for value in (ZERO, [0] * 31, [0] * 33, [True] * 32, [-1] * 32, [256] * 32):
            bad = self.snapshot(); bad["Snapshot"]["RegistryID"] = value
            with self.assertRaises(AcceptanceError): registry.decode_snapshot(json.dumps(bad).encode())
        mutations = [lambda s: s.update(ExecutionGranted=True), lambda s: s.update(LegacyCutover=True),
                     lambda s: s.update(SelectionOnly=False), lambda s: s["Snapshot"].update(MaximumPending=65536),
                     lambda s: s["Snapshot"].update(MaximumOperations=True),
                     lambda s: s["Snapshot"].update(SelectionFinal=False),
                     lambda s: s["Pin"].update(PendingID=go_hash("a" * 64)),
                     lambda s: s["Pin"]["Position"].update(Sequence=0)]
        for mutate in mutations:
            bad = self.snapshot(True); mutate(bad)
            with self.assertRaises(AcceptanceError): registry.decode_snapshot(json.dumps(bad).encode())

    def test_candidate_and_selection_identity_formats_have_distinct_domains(self):
        context = (Path(__file__).resolve().parents[2] / "node/custodyv2/testdata/public-fixture/context").read_bytes()
        raw = admission.genesis_from_context(context)
        ids = registry.candidate_ids(raw)
        self.assertEqual(ids["candidate_id"], registry.digest("OMESH/custody/v2/admission/genesis/id", bytes.fromhex(ids["assignment_id"])))
        self.assertNotEqual(ids["candidate_id"], ids["candidate_descriptor_id"])
        selection = b"OMCRSEL1\0\1" + b"a" * 32 + b"b" * 32 + raw + b"s" * 192
        self.assertNotEqual(registry.selection_id(selection), registry.artifact(selection))
        for bad in (b"", raw[:9] + b"\1" + raw[10:]):
            with self.assertRaises(AcceptanceError): registry.candidate_ids(bad)
        for bad in (b"", selection[:9] + b"\2" + selection[10:], b"x" * (8 * 1024 * 1024 + 1)):
            with self.assertRaises(AcceptanceError): registry.selection_id(bad)


if __name__ == "__main__": unittest.main()
