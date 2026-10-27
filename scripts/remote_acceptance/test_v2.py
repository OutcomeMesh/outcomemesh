import copy
import hashlib
import struct
import unittest

import v2
from run import AcceptanceError, ZERO


class V2WANReportTests(unittest.TestCase):
    def case(self, name, digit):
        scope = str(digit) * 64
        pins = [{"sequence": 0, "head": scope, "pending": ZERO} for _ in range(4)]
        events = []
        number = 0
        def vote(i, command):
            nonlocal number
            number += 1
            before = copy.deepcopy(pins[i]); after = dict(before, pending=command)
            events.append({"kind": "witness", "member": i, "before": before, "after": after,
                           "request_id": "%064x" % number, "command_id": command, "completed": True})
            pins[i] = {k: after[k] for k in before}
        def commit(i, command, certificate):
            nonlocal number
            number += 1
            before = copy.deepcopy(pins[i]); after = dict(before, sequence=before["sequence"] + 1, head=command, pending=ZERO)
            events.append({"kind": "witness", "member": i, "before": before, "after": after,
                           "request_id": "%064x" % number, "command_id": None, "certificate": certificate, "completed": True})
            pins[i] = {k: after[k] for k in before}
        claim = "c" * 64
        for i in (2, 3, 0): vote(i, claim)
        vote(3, claim)
        for i in range(4): commit(i, claim, "claim.qc")
        commands = [("u" * 64, "unknown.qc")] if name == "lost-session" else [("d" * 64, "result.qc")]
        if name == "lost-result": commands.insert(0, ("e" * 64, "unknown.qc"))
        for command, certificate in commands:
            for i in (0, 2, 3): vote(i, command)
            for i in range(4): commit(i, command, certificate)
        common = {"sources_initially_zero", "two_witnesses_not_quorum", "duplicate_member_not_quorum",
                  "witness_sigkill_exact_vote_recovered", "no_effect_before_claim", "original_owner_identities_preserved"}
        if name == "lost-session": common |= {"target_sigkill_before_effect", "old_live_session_claim_refused", "unknown_without_result_held"}
        else: common |= {"probe_weak_refused", "probe_wrong-scope_refused", "probe_legacy_refused", "probe_late_refused",
                         "exact_result_bytes_retained", "copied_persistent_keys_old_claim_refused", "late_execution_refused"}
        if name == "lost-result": common |= {"result_reply_cut_after_durable_b", "target_sigkill_result_retained", "a_lost_output_receipt_recovered"}
        if name == "expired-result": common.add("expired_result_not_accepted")
        final = [dict(p, phase=2 if name == "lost-session" else 3, held=True, session="f" * 64) for p in pins]
        return {"scenario": name, "scope_id": scope, "checks": {k: True for k in common}, "witnesses": final,
                "passed": True, "independent_four_domain_deployment": False, "serve_resolved": False,
                "observed_kernel_boot_sha256": {"a": "1" * 64, "b": "2" * 64}, "events": events,
                "original_identity_pins": {"a": "3" * 64, "b": "4" * 64},
                "a": {"source_sequence": int(name == "lost-result"), "source_head": "a" * 64, "accepted": name == "lost-result", "original_identities_sha256": "3" * 64},
                "b": {"source_sequence": int(name != "lost-session"), "source_head": "a" * 64, "original_identities_sha256": "4" * 64}, "clone": {"source_sequence": 0}}

    def report(self):
        return {"schema_version": 1, "passed": True,
                "cases": [self.case(name, i + 5) for i, name in enumerate(v2.SCENARIOS)]}

    def test_complete_transcripts_and_remaining_obligations(self):
        self.assertEqual(v2.validate(self.report())["serve_obligations_released"], 0)

    def test_rejects_missing_or_contradictory_evidence(self):
        mutations = [lambda r: r["cases"].pop(), lambda r: r["cases"][0]["events"].clear(),
                     lambda r: r["cases"][0]["checks"].pop("result_reply_cut_after_durable_b"),
                     lambda r: r["cases"][0]["events"][0]["before"].update(pending="a" * 64),
                     lambda r: r["cases"][0]["witnesses"][0].update(held=False),
                     lambda r: r["cases"][0]["witnesses"][0].update(session="0" * 64),
                     lambda r: r["cases"][0].update(serve_resolved=True),
                     lambda r: r["cases"][1]["b"].update(source_sequence=1),
                     lambda r: r["cases"][2]["a"].update(source_sequence=1),
                     lambda r: r["cases"][0]["a"].update(original_identities_sha256="f" * 64),
                     lambda r: r["cases"][0]["observed_kernel_boot_sha256"].update(b="1" * 64),
                     lambda r: r["cases"][1].update(scope_id=r["cases"][0]["scope_id"]),
                     lambda r: r["cases"][0]["witnesses"][0].update(head="f" * 64)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report = self.report(); mutate(report)
                with self.assertRaises(AcceptanceError): v2.validate(report)

    def test_only_v1_witness_layout_is_decoded(self):
        scope, witness, request = "a" * 64, "b" * 64, "c" * 64
        obs = bytearray(340); obs[:10] = b"OMCFOB00\0\1"; obs[10:42] = bytes.fromhex(request)
        obs[42:74] = bytes.fromhex(witness); obs[74:106] = bytes.fromhex(scope)
        obs[106:114] = struct.pack(">Q", 2); obs[114:146] = b"h" * 32; obs[178] = 2; obs[243] = 1; obs[244:276] = b"s" * 32
        raw = b"OMCFWS00\0\1" + bytes(obs) + b"\0"
        value = v2.response_pin(raw, scope, witness, request)
        self.assertEqual(value["sequence"], 2); self.assertEqual(value["session"], (b"s" * 32).hex())
        for bad in (raw[:9] + b"\0" + raw[10:], raw[:350], b"broken" + raw[6:]):
            with self.assertRaises(AcceptanceError): v2.response_pin(bad, scope, witness, request)
        with self.assertRaises(AcceptanceError): v2.response_pin(raw, "d" * 64, witness, request)

    def test_public_artifact_domain_is_separate(self):
        raw = b"OMCFCM00\0\1" + bytes(201)
        self.assertEqual(v2.artifact(raw), hashlib.sha256(b"OMESH/custody/v2/artifact/id" + raw).hexdigest())
        self.assertNotEqual(v2.command_id(raw), v2.artifact(raw))
        with self.assertRaises(AcceptanceError): v2.command_id(b"OMCFCM00\0\0" + raw[10:])


if __name__ == "__main__": unittest.main()
