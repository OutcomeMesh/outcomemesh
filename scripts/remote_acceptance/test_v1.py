"""No SSH or daemon needed: reject incomplete/mixed V1 acceptance evidence."""

import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import v1
import v1_matrix
import v1_report
from run import AcceptanceError


class V1EvidenceTests(unittest.TestCase):
    def states(self):
        common = {"assignment_id": "a" * 64, "journal_sequence": 2,
                  "journal_head_id": "b" * 64, "current_receipt_id": "c" * 64,
                  "proof_id": "d" * 64, "responded_at": 123}
        a = dict(common, confirmed_sequence=12, pending_operations=0,
                 pending_attempt=False, active_remote=False, original_identities={"journal": "1:2"})
        b = dict(common, worker_stage=4, worker_pending=0, disposition=3,
                 result_id="b" * 64, seal_id="f" * 64,
                 original_identities={"journal": "3:4"})
        return a, b

    def test_success_requires_same_scope_exact_result_and_closed_tickets(self):
        a, b = self.states()
        v1.validate_success(a, b, 2)
        for role, key, value in (("a", "pending_operations", 1), ("a", "active_remote", True),
                                 ("a", "pending_attempt", True), ("a", "confirmed_sequence", 13),
                                 ("b", "assignment_id", "e" * 64), ("b", "responded_at", 124),
                                 ("b", "proof_id", "e" * 64), ("b", "result_id", "e" * 64),
                                 ("b", "worker_pending", 4), ("b", "disposition", 2)):
            aa, bb = copy.deepcopy(a), copy.deepcopy(b)
            (aa if role == "a" else bb)[key] = value
            with self.subTest(role=role, field=key), self.assertRaises(AcceptanceError):
                v1.validate_success(aa, bb, 2)

    def test_soak_compares_original_root_and_lock_identities(self):
        a, b = self.states()
        baseline = {"a": copy.deepcopy(a["original_identities"]), "b": copy.deepcopy(b["original_identities"])}
        v1.validate_success(a, b, 2, baseline)
        a["original_identities"]["journal"] = "1:99"
        with self.assertRaises(AcceptanceError):
            v1.validate_success(a, b, 2, baseline)

    def test_reports_are_exclusive_and_preserve_old_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            v1.publish_report(path, {"passed": True, "cycle": 1})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                v1.publish_report(path, {"passed": True, "cycle": 2})
            self.assertEqual(original, path.read_bytes())
            self.assertEqual(json.loads(original)["cycle"], 1)

    def test_rejects_missing_complete_review(self):
        class Fake:
            def __init__(self, complete, lines):
                self.complete, self.lines = complete, lines

            def rpc(self, method, **_):
                return {} if method == "send" else {"complete": self.complete, "lines": self.lines}

        lines = ["remote_custody_review review_id=" + "a" * 64 + "\n", "scope:\n", '{"ConfirmedSequence":3}\n', "remote_custody_scope_end\n"]
        self.assertEqual(v1.full_remote_review(Fake(True, lines))["ConfirmedSequence"], 3)
        for complete, report in ((False, lines), (True, lines[:-1]), (True, lines[:1])):
            with self.assertRaises(AcceptanceError):
                v1.full_remote_review(Fake(complete, report))

    def test_fixture_extraction_restores_private_directory_modes(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name in ("fixture", "fixture/role-a"):
                entry = tarfile.TarInfo(name)
                entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(entry)
            secret = tarfile.TarInfo("fixture/role-a/seed")
            secret.mode, secret.size = 0o644, 4
            archive.addfile(secret, io.BytesIO(b"test"))

        class Result:
            def __init__(self, data):
                self.stdout = data

        class Host:
            test_binary = "/private/test"
            count = 0

            def execute(self, *args, **kwargs):
                self.count += 1
                responses = (b"", b"remote_v1_fixture root=/private/exports/v1-fixture-test\n", buffer.getvalue())
                return Result(responses[self.count - 1])

        with tempfile.TemporaryDirectory() as temporary:
            root, _ = v1_matrix.export_fixture(Host(), "/private/exports", Path(temporary) / "export")
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "role-a").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "role-a/seed").stat().st_mode & 0o777, 0o600)

    def report(self):
        a, b = self.states()
        for state in (a, b):
            state["journal_sequence"] = 1
        a["confirmed_sequence"] = 6
        cycle = {"cycle": 1, "passed": True, "delayed_start_rejected": True,
                 "final": {"a": a, "b": b}, "last_completion": "e" * 64,
                 "relay": {"counters": {"forward_sent_packets": 3, "reverse_sent_packets": 4}}}
        for key, digit in (("intent_id", "1"), ("challenge_id", "2"), ("plan_id", "3"), ("begin_id", "4")):
            cycle[key] = digit * 64
        return {"scenario": "healthy", "passed": True, "copied_live_roots": False,
                "binaries_unchanged_after_run": True,
                "observed_kernel_boot_sha256": {"a": "5" * 64, "b": "6" * 64},
                "assignment_id": "a" * 64, "cycles": [cycle], "cycle_count": 1,
                "normal_binary_sha256": "7" * 64, "cli_test_binary_sha256": "8" * 64,
                "gate_test_binary_sha256": "9" * 64,
                "build_provenance": {"source_manifest": "a" * 64}, "controller_sha256": "b" * 64}

    def test_sanitizer_revalidates_success_instead_of_trusting_passed_flag(self):
        report = self.report()
        self.assertTrue(v1_report.validate_report(report)["passed"])
        for mutate in (lambda r: r["cycles"][0]["final"]["a"].update(pending_operations=1),
                       lambda r: r["cycles"][0].update(delayed_start_rejected=False),
                       lambda r: r["observed_kernel_boot_sha256"].update(b="5" * 64),
                       lambda r: r.update(cycle_count=2)):
            changed = copy.deepcopy(report)
            mutate(changed)
            with self.assertRaises(AcceptanceError):
                v1_report.validate_report(changed)

    def test_negative_disposition_cannot_claim_closed_success(self):
        report = self.report()
        report["scenario"] = "unseen-seal"
        cycle = report["cycles"][0]
        a, b = cycle["final"]["a"], cycle["final"]["b"]
        cycle.pop("last_completion")
        a.update(confirmed_sequence=4, pending_operations=2, journal_sequence=0)
        b.update(journal_sequence=0, disposition=1, result_id=v1.ZERO)
        for state in (a, b):
            state["journal_head_id"] = v1.ZERO
            state.pop("proof_id")
            state.pop("responded_at")
        cycle.update(ordinary_tickets_retained=True, success_capture_rejected=True,
                     after_partition=dict(a, active_remote=True, confirmed_sequence=3),
                     relay={"counters": {"forward_sent_packets": 3, "reverse_sent_packets": 3,
                                         "forward_partition_drops": 2}})
        self.assertTrue(v1_report.validate_report(report)["ordinary_tickets_retained"])
        cycle["last_completion"] = "e" * 64
        with self.assertRaises(AcceptanceError):
            v1_report.validate_report(report)
        cycle.pop("last_completion")
        a["pending_operations"] = 0
        with self.assertRaises(AcceptanceError):
            v1_report.validate_report(report)

    def test_matrix_requires_every_scenario_and_one_controller_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "healthy.json"
            report = self.report()
            v1.publish_report(path, report)
            self.assertEqual(v1_report.summarize([path])["completed_cycles"], 1)
            self.assertEqual(v1_report.summarize([path])["successful_ticket_completions"], 2)
            with self.assertRaises(AcceptanceError):
                v1_report.summarize([path], require_matrix=True)
            with self.assertRaises(AcceptanceError):
                v1_report.summarize([path, path])
            other = copy.deepcopy(report)
            other["scenario"] = "soak"
            other["assignment_id"] = "c" * 64
            for state in other["cycles"][0]["final"].values():
                state["assignment_id"] = other["assignment_id"]
            other["controller_sha256"] = "d" * 64
            other_path = Path(directory) / "soak.json"
            v1.publish_report(other_path, other)
            with self.assertRaises(AcceptanceError):
                v1_report.summarize([path, other_path])

    def test_soak_cannot_advance_positions_with_a_reused_result(self):
        report = self.report()
        report.update(scenario="soak", cycle_count=2)
        second = copy.deepcopy(report["cycles"][0])
        second["cycle"] = 2
        for name, digit in (("intent_id", "5"), ("challenge_id", "6"),
                            ("plan_id", "7"), ("begin_id", "8")):
            second[name] = digit * 64
        for state in second["final"].values():
            state["journal_sequence"] = 2
        second["final"]["a"]["confirmed_sequence"] = 12
        report["cycles"].append(second)
        with self.assertRaises(AcceptanceError):
            v1_report.validate_report(report)


if __name__ == "__main__":
    unittest.main()
