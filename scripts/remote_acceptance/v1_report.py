#!/usr/bin/env python3
"""Validate retained private V1 reports and publish a sanitized evidence index."""

import argparse
import hashlib
import json
from pathlib import Path

from run import AcceptanceError, ZERO, digest_id, require
from v1 import SCENARIOS, publish_report, validate_success


NEGATIVE = {"unseen-seal": 1, "b-restart-before-result": 2, "expired-cache": 3}


def validate_report(value):
    scenario = value["scenario"]
    require(value.get("passed") is True and scenario in SCENARIOS and value.get("copied_live_roots") is False and
            value.get("binaries_unchanged_after_run") is True, "missing completed unchanged-binary acceptance")
    boots = value.get("observed_kernel_boot_sha256", {})
    require(set(boots) == {"a", "b"} and digest_id(boots["a"]) != digest_id(boots["b"]), "two distinct observed remote kernels required")
    aid = digest_id(value["assignment_id"])
    cycles = value["cycles"]
    require(value["cycle_count"] == len(cycles) and 1 <= len(cycles) <= 64 and
            (len(cycles) == 1 or scenario == "soak"), "incomplete or unbounded cycle history")
    baseline, seen = None, {name: set() for name in ("intent_id", "challenge_id", "plan_id", "begin_id",
                                                   "journal_head_id", "current_receipt_id", "proof_id")}
    placement_a, placements_b = None, set()
    for n, cycle in enumerate(cycles, 1):
        if value.get("placement_required", False):
            pins = cycle.get("placements", {})
            require(set(pins) == {"a", "b"}, "required placement pins missing")
            a_pin, b_pin = digest_id(pins["a"]), digest_id(pins["b"])
            require(placement_a is None or placement_a == a_pin, "A placement was re-enrolled during reuse")
            require(b_pin not in placements_b, "new B worker reused a prior placement")
            placement_a = a_pin
            placements_b.add(b_pin)
        require(cycle.get("passed") is True and cycle["cycle"] == n and cycle.get("delayed_start_rejected") is True,
                "cycle did not finish its exact delayed-Start check")
        for name in ("intent_id", "challenge_id", "plan_id", "begin_id"):
            selected = digest_id(cycle[name])
            require(selected not in seen[name], "new cycle reused an old immutable operation")
            seen[name].add(selected)
        a, b = cycle["final"]["a"], cycle["final"]["b"]
        require(a["assignment_id"] == b["assignment_id"] == aid, "mixed assignment evidence")
        digest_id(b["seal_id"])
        for state in (a,b):
            if state["journal_sequence"] == 0:
                require(state["journal_head_id"] == ZERO and "proof_id" not in state and "responded_at" not in state,
                        "empty source claims a committed proof")
        if scenario in NEGATIVE:
            require(a["confirmed_sequence"] == 4 and a["pending_operations"] == 2 and not a["active_remote"] and
                    not a["pending_attempt"] and a["journal_sequence"] == 0 and
                    b["worker_stage"] == 4 and b["worker_pending"] == 0 and b["disposition"] == NEGATIVE[scenario] and
                    cycle.get("ordinary_tickets_retained") is True and cycle.get("success_capture_rejected") is True,
                    "unknown/expired/unseen branch was promoted to successful completion")
            require(b["journal_sequence"] == (1 if scenario == "expired-cache" else 0), "negative source history changed")
            require("last_completion" not in cycle, "negative branch claims a successful completion")
            if scenario != "expired-cache":
                require(b["result_id"] == ZERO, "no-result branch invented a retained result")
            else:
                require(digest_id(b["result_id"]) == b["journal_head_id"] and cycle.get("fresh_restart_rejected") is True,
                        "expired branch refreshed or lost its retained result")
        else:
            validate_success(a, b, n, baseline)
            for name in ("journal_head_id", "current_receipt_id", "proof_id"):
                selected = digest_id(a[name])
                require(selected not in seen[name], "new cycle reused a prior source result")
                seen[name].add(selected)
            digest_id(cycle["last_completion"])
            if baseline is None:
                baseline = {"a": a["original_identities"], "b": b["original_identities"]}
        if scenario in ("partition-before", "unseen-seal"):
            hold = cycle["after_partition"]
            require(hold["active_remote"] and hold["confirmed_sequence"] == 3 and hold["pending_operations"] == 2 and
                    hold["journal_sequence"] == 0, "partition did not retain original authority")
        if scenario in ("b-restart-before-result", "b-restart-after-result", "expired-cache"):
            before = cycle["after_b_death"]
            require(before["a"]["active_remote"] and before["a"]["confirmed_sequence"] == 3 and
                    before["a"]["journal_sequence"] == 0 and before["b"]["worker_stage"] == 2,
                    "B death lost its original hold/Started branch")
            for role in ("a", "b"):
                require(before[role]["original_identities"] == cycle["final"][role]["original_identities"],
                        "B recovery replaced an original source/lock")
            if scenario == "b-restart-before-result":
                require(before["b"]["journal_sequence"] == b["journal_sequence"] == 0 and cycle.get("fresh_restart_rejected") is True,
                        "restart without cache minted fresh work")
            else:
                for key in ("journal_head_id", "current_receipt_id", "proof_id", "responded_at"):
                    require(before["b"][key] == b[key], "recovery or expiry replaced the original cached result")
        if scenario.startswith("a-restart-"):
            hold = cycle["after_a_death"]
            require(hold["active_remote"] and hold["confirmed_sequence"] == 3 and hold["pending_operations"] == 2 and
                    hold["journal_sequence"] == (0 if scenario == "a-restart-before-data" else 1) and
                    hold["original_identities"] == a["original_identities"], "A restart replaced or released its original owner/source")
        if scenario == "seal-reply-loss":
            before = cycle["lost_seal_reply"]
            require(before["a"]["active_remote"] and before["a"]["confirmed_sequence"] == 3 and
                    before["b"]["worker_stage"] == 4 and before["b"]["seal_id"] == b["seal_id"] and
                    cycle["metadata_only_reconciliation"]["confirmed_sequence"] == 3,
                    "lost acknowledgement or metadata read fabricated a confirmed Drain")
            for role in ("a", "b"):
                require(before[role]["original_identities"] == cycle["final"][role]["original_identities"],
                        "seal recovery replaced an original source/lock")
        counters = cycle["relay"]["counters"]
        require(counters.get("forward_sent_packets", 0) and counters.get("reverse_sent_packets", 0), "no actual bidirectional datagrams recorded")
        if scenario in ("partition-before", "unseen-seal"):
            require(counters.get("forward_partition_drops", 0) > 0, "partition scenario dropped no packets")
        if scenario == "loss-delay" or scenario == "soak" and n % 4 == 0:
            require(counters.get("forward_pattern_drops", 0) + counters.get("reverse_pattern_drops", 0) > 0, "loss scenario dropped no packets")
    return {"scenario": scenario, "cycle_count": len(cycles), "assignment_id": aid,
            "local_placement_required": value.get("placement_required", False),
            "final_authority_sequence": cycles[-1]["final"]["a"]["confirmed_sequence"],
            "final_source_sequences": [cycles[-1]["final"][x]["journal_sequence"] for x in ("a", "b")],
            "final_pending_operations": cycles[-1]["final"]["a"]["pending_operations"],
            "final_active_remote": cycles[-1]["final"]["a"]["active_remote"],
            "ordinary_tickets_retained": scenario in NEGATIVE,
            "delayed_start_rejected_on_every_cycle": True,
            "original_roots_reused": len(cycles) > 1,
            "single_assignment": True, "passed": True}


def summarize(paths, require_matrix=False):
    records, assignments = [], set()
    builds, sources, controllers, scenarios = set(), set(), set(), set()
    for path in paths:
        raw = path.read_bytes()
        value = json.loads(raw)
        selected = validate_report(value)
        require(selected["scenario"] not in scenarios, "duplicate scenario report")
        scenarios.add(selected["scenario"])
        require(selected["assignment_id"] not in assignments, "matrix reused an assignment between independent scenarios")
        assignments.add(selected["assignment_id"])
        selected["private_report_sha256"] = hashlib.sha256(raw).hexdigest()
        records.append(selected)
        builds.add(tuple(digest_id(value[key]) for key in ("normal_binary_sha256", "cli_test_binary_sha256", "gate_test_binary_sha256")))
        sources.add(digest_id(value["build_provenance"]["source_manifest"]))
        controllers.add(digest_id(value["controller_sha256"]))
    require(records and len(builds) == len(sources) == len(controllers) == 1, "reports use different build/source/controller pins")
    if require_matrix:
        require({r["scenario"] for r in records} == set(SCENARIOS), "required WAN scenario missing")
        require(any(r["scenario"] == "soak" and r["cycle_count"] >= 32 for r in records), "32-cycle same-assignment series missing")
    binaries = next(iter(builds))
    completed = sum(r["cycle_count"] for r in records)
    negative = sum(r["cycle_count"] for r in records if r["ordinary_tickets_retained"])
    return {"schema_version": 1, "scope": "controlled same-assignment V1 WAN fault and bounded reuse acceptance",
            "session_lifecycle": "fresh intent/plan/worker per cycle; interrupted sessions retain the same worker and immutable scope",
            "source_manifest_sha256": next(iter(sources)),
            "controller_sha256": next(iter(controllers)),
            "binaries": dict(zip(("omd", "omd.test", "store.test"), binaries)), "scenarios": records,
            "completed_cycles": completed, "successful_cycles": completed - negative,
            "negative_cycles_with_ordinary_tickets_retained": negative,
            "successful_ticket_completions": 2 * (completed - negative),
            "required_matrix_checked": require_matrix, "passed": True,
            "boundaries": ["owner-controlled keys and original local roots remain trusted", "not independent key/root copy fencing",
                           "negative branches retain ordinary tickets; no negative-completion workflow claimed",
                           "bounded controlled series, not device-failure or sustained adversarial public-testnet evidence",
                           "no external audit or mainnet authorization"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--require-matrix", action="store_true")
    args = parser.parse_args()
    publish_report(args.out, summarize(args.input, args.require_matrix))


if __name__ == "__main__":
    try:
        main()
    except (AcceptanceError, OSError, ValueError, KeyError) as exc:
        raise SystemExit("remote_v1_report_failed " + str(exc))
