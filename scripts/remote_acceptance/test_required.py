import copy
import unittest

import required
import test_admission as admission_fixtures
from run import AcceptanceError, ZERO


class RequiredRuntimeCampaignTests(unittest.TestCase):
    def admission(self, index):
        ad = admission_fixtures.AdmissionCoordinatorTests().report()
        if index:
            # Use canonical hex strings even for values above one decimal digit.
            aid, cid, pid, did, eid = ("%064x" % i for i in (6, 7, 8, 9, 10))
            gid = required.digest("OMESH/custody/v2/admission/genesis/id", bytes.fromhex(aid))
            ad.update(assignment_id=aid, context_id=cid, plan_id=pid, descriptor_id=did, entry_id=eid, genesis_id=gid)
            for m in ad["members"]:
                m["initial"].update(genesis_id=gid, head=gid)
                m["final"].update(genesis_id=gid, head=eid, active_context_id=cid, active_plan_id=pid)
                m["before_vote"].update(head=gid)
                m["before_commit"].update(head=gid, pending=eid)
        return ad

    def execution(self, scenario, scope, cid, closed, ad):
        source = copy.deepcopy(ad["sources_before"]["a"])
        source.update(source_sequence=int(closed), source_head="f" * 64 if closed else ZERO,
                      receipt_id="c" * 64 if closed else "e" * 64)
        a, b, clone = copy.deepcopy(source), copy.deepcopy(source), copy.deepcopy(ad["sources_before"]["clone"])
        a.update(accepted=closed); b.update(result=closed, consumed=closed)
        events, pins, number = [], [{"sequence": 0, "head": scope, "pending": ZERO} for _ in range(4)], 0
        for sequence in range(3 if closed else 2):
            command = "%064x" % (sequence + 100)
            for i in (range(4) if sequence == 0 else (0, 2, 3)):
                number += 1; before = copy.deepcopy(pins[i]); after = dict(before, pending=command)
                events.append({"kind": "witness", "member": i, "request_id": "%064x" % number,
                               "before": before, "after": after, "command_id": command, "completed": True})
                pins[i] = after
            for i in range(4):
                number += 1; before = copy.deepcopy(pins[i]); after = {"sequence": sequence + 1, "head": command, "pending": ZERO}
                events.append({"kind": "witness", "member": i, "request_id": "%064x" % number,
                               "before": before, "after": after, "certificate": "selected.qc", "completed": True})
                pins[i] = after
        common = {"sources_initially_zero", "two_witnesses_not_quorum", "duplicate_member_not_quorum", "witness_sigkill_exact_vote_recovered", "no_effect_before_claim", "original_owner_identities_preserved"}
        common |= {"result_reply_cut_after_durable_b", "target_sigkill_result_retained", "a_lost_output_receipt_recovered", "exact_result_bytes_retained", "copied_persistent_keys_old_claim_refused", "late_execution_refused"} if closed else {"target_sigkill_before_effect", "old_live_session_claim_refused", "unknown_without_result_held"}
        return {"scenario": scenario, "scope_id": scope, "context_id": cid, "passed": True,
                "independent_four_domain_deployment": False, "serve_resolved": False,
                "observed_kernel_boot_sha256": ad["observed_kernel_boot_sha256"],
                "witnesses": [dict(p, phase=3 if closed else 2, held=True, session="a" * 64) for p in pins],
                "events": events, "checks": {k: True for k in common}, "a": a, "b": b, "clone": clone,
                "original_identity_pins": {"a": a["original_identities_sha256"], "b": b["original_identities_sha256"]}}

    def report(self):
        cases = []
        for i, scenario in enumerate(required.SCENARIOS):
            closed = scenario == "lost-result"; ad = self.admission(i)
            scope, binding = "%064x" % (1000 + i), "%064x" % (2000 + i)
            e = self.execution(scenario, scope, ad["context_id"], closed, ad)
            state = {"ArchiveHeld": True, "Pending": not closed, "MinimumRetainUntil": 123}
            checks = {name: True for name in required.CHECKS}
            serve_checks = {"a_and_b_lost_output_exact_cold_resume": True, "cold_key_copy_without_original_result_refused": True} if closed else {"unresolved_serve_and_archive_held": True}
            if closed: checks["consumption_and_acceptance_bind_exact_admission"] = True
            ledger = {"closed": closed, "sequence": 2 if closed else 1, "head": "b" * 64 if closed else ad["entry_id"], "members": []}
            for m in ad["members"]:
                final = dict(m["final"], sequence=ledger["sequence"], head=ledger["head"], pending_operations=0 if closed else 2,
                             active_context_id=ZERO if closed else ad["context_id"], active_plan_id=ZERO if closed else ad["plan_id"],
                             source_sequence=int(closed), source_head=e["a"]["source_head"], source_receipt_id=e["a"]["receipt_id"])
                ledger["members"].append({"member": m["member"], "host": m["host"], "signing_public_key": m["signing_public_key"], "final": final})
            cases.append({"scenario": scenario, "scope_id": scope, "binding_id": binding, "context_id": ad["context_id"], "plan_id": ad["plan_id"], "genesis_id": ad["genesis_id"],
                          "passed": True, "cleanup_complete": True, "runtime_admission_enforced": True, "legacy_v1_migrated": False,
                          "independent_four_domain_deployment": False, "checks": checks, "admission_before_runtime": ad, "execution": e,
                          "serve": {"scenario": scenario, "scope_id": scope, "checks": serve_checks, "states": {"a": copy.deepcopy(state), "b": copy.deepcopy(state)}},
                          "accounting_final": ledger, "sources_after_accounting": {role: copy.deepcopy(e[role]) for role in ("a", "b", "clone")}})
        return {"schema_version": 1, "passed": True, "cases": cases}

    def test_bound_execution_and_unknown_budget(self):
        self.assertEqual(required.validate(self.report()), {"cases": 2, "joint_hosts": 2, "logical_witnesses": 4,
                         "runtime_admission_enforced": True, "fulfilled_and_accounting_closed": 1, "unknown_still_held": 1, "archives_released": 0})

    def test_missing_and_contradictory_provenance_refused(self):
        mutations = [lambda r: r["cases"].pop(), lambda r: r["cases"][0].update(runtime_admission_enforced=False),
                     lambda r: r["cases"][0].update(legacy_v1_migrated=True), lambda r: r["cases"][0].update(cleanup_complete=False),
                     lambda r: r["cases"][1].update(binding_id=r["cases"][0]["binding_id"]),
                     lambda r: r["cases"][0]["checks"].pop("missing_binding_refused"),
                     lambda r: r["cases"][0]["checks"].pop("consumption_and_acceptance_bind_exact_admission"),
                     lambda r: r["cases"][0]["admission_before_runtime"].update(context_id="f" * 64),
                     lambda r: r["cases"][0]["execution"]["events"].clear(),
                     lambda r: r["cases"][0]["execution"]["events"][0]["before"].update(pending="f" * 64),
                     lambda r: r["cases"][0]["execution"]["clone"].update(source_sequence=1),
                     lambda r: r["cases"][0]["execution"]["witnesses"][0].update(session=ZERO),
                     lambda r: r["cases"][1]["execution"]["b"].update(source_sequence=1),
                     lambda r: r["cases"][0]["serve"]["states"]["a"].update(ArchiveHeld=False),
                     lambda r: r["cases"][1]["serve"]["states"]["b"].update(Pending=False),
                     lambda r: r["cases"][0]["accounting_final"]["members"][0]["final"].update(source_sequence=0),
                     lambda r: r["cases"][0]["accounting_final"]["members"][0]["final"].update(spent_operations=0),
                     lambda r: r["cases"][1]["accounting_final"]["members"][0]["final"].update(pending_operations=0),
                     lambda r: r["cases"][0]["accounting_final"]["members"][0]["final"].update(source_receipt_id="f" * 64),
                     lambda r: r["cases"][0]["accounting_final"]["members"].pop(),
                     lambda r: r["cases"][0]["sources_after_accounting"]["b"].update(source_sequence=2)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r = self.report(); mutation(r)
                with self.assertRaises(AcceptanceError): required.validate(r)

    def test_binding_record_is_exact_and_versioned(self):
        bid, aid = "a" * 64, "b" * 64
        for magic in ("OMCVUSE3", "OMCVPEN3"):
            raw = magic.encode() + b"\0\3" + bytes.fromhex(bid + aid) + b"\1x"
            required.retained_record(raw, magic, bid, aid)
            for bad in (raw[:74], b"wrong" + raw[5:], raw[:9] + b"\2" + raw[10:]):
                with self.assertRaises(AcceptanceError): required.retained_record(bad, magic, bid, aid)
            with self.assertRaises(AcceptanceError): required.retained_record(raw, magic, aid, bid)


if __name__ == "__main__": unittest.main()
