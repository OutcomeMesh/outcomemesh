#!/usr/bin/env python3
"""Recover retained V1 negative branches with explicit local placement checks.

Configuration selects existing, closed original role roots. No owner is created,
reset or transferred. Only public evidence is exchanged. Copy probes use separate
private scratch directories after both original CLI owners have closed.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

from run import AcceptanceError, Host, Supervisor, digest_id, fields, require
from v1 import Role, close_supervisor, full_remote_review, publish_report
from v1_report import validate_report


KINDS = {"unseen-seal": [1], "b-restart-before-result": [2], "expired-cache": [3, 4]}


def replace_flag(args, flag, value):
    selected = list(args)
    require(selected.count(flag) == 1, "expected one selected flag")
    selected[selected.index(flag) + 1] = value
    return selected


def without_flags(args, names):
    selected, i = [], 0
    while i < len(args):
        if args[i] in names:
            i += 2
        else:
            selected.append(args[i])
            i += 1
    return selected


def capture(role, base, path, remote=None, retained=None):
    args = base + ["--negative", path]
    if remote:
        args += ["--remote-result", remote[0], "--remote-result-id", remote[1]]
    if retained:
        args += ["--negative-id", retained]
    supervisor = Supervisor(role.h, {"audit": {"argv": [role.h.binary] + args}})
    try:
        supervisor.start("audit", "remote_custody_ready")
        result = supervisor.action("audit", "remote_custody", "capture-negative", "negative")
        require(result["ordinary_tickets_retained"] == "true" and result["completion_submitted"] == "false" and
                result["source_advanced"] == "false", "negative capture claimed an effect/completion")
        observed = full_remote_review(supervisor)
        require(observed["ConfirmedSequence"] == 4 and observed["Pending"] == 2 and
                observed["NegativeID"] == result["negative_id"], "observation released original obligations")
        supervisor.stop("audit")
        return {"negative_id": digest_id(result["negative_id"]), "kind": int(result["kind"]),
                "ordinary_tickets_retained": True, "source_advanced": False,
                "artifact_sha256": hashlib.sha256(role.h.execute(["cat", path]).stdout).hexdigest()}
    finally:
        close_supervisor(supervisor)


def enroll(role, name, anchor):
    role.h.execute(["python3", "-c", "import os,sys; os.makedirs(sys.argv[1],mode=0o700,exist_ok=False)", anchor])
    args = without_flags(role.runtime(name), {"--drain", "--terminal"})
    args = replace_flag(args, "--mode", "placement-review") + ["--placement", anchor + "/record"]
    reviewed = role.record(args, "remote_custody_placement")
    require(reviewed["keys_loaded"] == "false" and reviewed["owners_opened"] == "false", "enrollment opened a private owner")
    pin = digest_id(reviewed["placement_id"])
    role.once(replace_flag(args, "--mode", "placement-create") + ["--placement-id", pin])
    role.placement_flags = ["--placement", anchor + "/record", "--placement-id", pin, "--require-placement=true"]
    return pin


def probe(role, name, base, flag, source, directory=False):
    target = role.path("copy-probe-" + uuid.uuid4().hex)
    script = ("import os,shutil,sys; "
              "shutil.copytree(sys.argv[1],sys.argv[2]) if sys.argv[3]=='directory' else shutil.copyfile(sys.argv[1],sys.argv[2]); "
              "os.chmod(sys.argv[2],0o700 if sys.argv[3]=='directory' else 0o600)")
    role.h.execute(["python3", "-c", script, source, target, "directory" if directory else "file"])
    args = replace_flag(base, "--mode", "review")
    if flag == "--placement":
        target += "/record"
    result = role.h.execute([role.h.binary] + replace_flag(args, flag, target), check=False)
    require(result.returncode != 0 and b"placement" in result.stderr and b"remote_custody_ready" not in result.stdout,
            "copy reached the selected original owner: " + name)
    return {"name": name, "rejected": True, "exit_code": result.returncode}


def run(config, prior_path):
    raw = prior_path.read_bytes()
    prior = json.loads(raw)
    validate_report(prior)
    scenario = prior["scenario"]
    require(scenario in KINDS and prior["cycle_count"] == 1, "choose one retained negative scenario")
    roles, before, boots = {}, {}, {}
    for name in ("a", "b"):
        host = Host(config["hosts"][name])
        boots[name] = hashlib.sha256(host.execute(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()).hexdigest()
        require(boots[name] == prior["observed_kernel_boot_sha256"][name], "retained owner moved to a different observed kernel")
        require(host.sha256(host.binary) == config["expected_binaries"]["omd"] and
                host.sha256(host.test_binary) == config["expected_binaries"]["omd.test"], "unpinned current binary")
        role = Role(host, json.loads(host.read("scope.json")))
        role.n, role.ids = 1, {"assignment": prior["assignment_id"], "plan": prior["cycles"][0]["plan_id"],
                              "begin": prior["cycles"][0]["begin_id"]}
        before[name] = role.inspect()
        role.ids["intent"], role.ids["audit"] = before[name]["intent_id"], before[name]["audit_ticket_id"]
        role.ids["serve"] = before[name]["serve_ticket_id"]
        original = prior["cycles"][0]["final"][name]
        require(all(before[name][key] == value for key, value in original.items()), "retained original changed before upgrade")
        roles[name] = role
    a, b = roles["a"], roles["b"]
    run_id = uuid.uuid4().hex
    placements = {name: enroll(role, name, config["anchor_parents"][name] + "/" + run_id)
                  for name, role in roles.items()}
    base_a = without_flags(a.runtime("a"), {"--terminal"}) + ["--drain-id", before["a"]["drain_id"]]
    # The route is used only for a refused execution check; no listener or relay
    # is started, and the owned runtime must reject before opening a host.
    late = json.loads(a.h.read(a.op("late-start.json")))
    base_a = replace_flag(base_a, "--peer", late["peer"])
    observations = []
    path = a.path(a.op("negative-" + run_id))
    first = capture(a, base_a, path)
    retry = capture(a, base_a, path, retained=first["negative_id"])
    require(first == retry, "lost-output recovery changed the retained observation")
    observations.append(first)
    if scenario == "expired-cache":
        output = b.path(b.op("sealed-result-" + run_id))
        supervisor = Supervisor(b.h, {"serve": {"argv": [b.h.binary] + b.runtime("b") + ["--result-out", output]}})
        try:
            supervisor.start("serve", "remote_custody_ready")
            exported = supervisor.action("serve", "remote_custody", "export-result", "exported")
            require(exported["proof_refreshed"] == "false", "export refreshed a proof")
            supervisor.stop("serve")
        finally:
            close_supervisor(supervisor)
        public_result = a.op("remote-result-" + run_id)
        a.h.write(public_result, b.h.execute(["cat", output]).stdout)
        selected = digest_id(exported["result_id"])
        require(selected == before["b"]["journal_head_id"], "export replaced the original B result")
        observations.append(capture(a, base_a, path + "-verified", remote=(a.path(public_result), selected)))
        require(hashlib.sha256(a.h.execute(["cat", path]).stdout).hexdigest() == first["artifact_sha256"], "verification rewrote the earlier commitment-only observation")
    require([r["kind"] for r in observations] == KINDS[scenario], "wrong negative classification")
    supervisor = Supervisor(a.h, {"audit": {"argv": [a.h.binary] + base_a + ["--negative", path, "--negative-id", first["negative_id"]]}})
    try:
        supervisor.start("audit", "remote_custody_ready")
        token = supervisor.review("audit", "remote_custody")
        supervisor.rpc("send", name="audit", line="execute " + token)
        supervisor.expect_failure("audit")
        status = supervisor.rpc("status", name="audit")
        require("remote custody scope, owner or result" in status["stderr_tail"], "execution failed for a transport/input reason instead of its drained owner")
    finally:
        close_supervisor(supervisor)
    copies = {}
    for name, role in roles.items():
        base = base_a if name == "a" else role.runtime("b")
        key = role.path("keys/" + ("a-control.seed" if name == "a" else "b-control.seed"))
        tests = [probe(role, "control-key", base, "--control-key", key)]
        for root in (("authority", "authority-pins", "journal", "artifacts") if name == "a" else ("worker", "journal", "objects")):
            source = role.path("workers/001" if root == "worker" else root)
            tests.append(probe(role, root, base, "--" + root, source, directory=True))
        anchor = role.placement_flags[1].rsplit("/", 1)[0]
        tests.append(probe(role, "anchor", base, "--placement", anchor, directory=True))
        copies[name] = tests
    after = {name: role.inspect() for name, role in roles.items()}
    require(before == after, "negative processing/copy rejection changed an original owner or proof")
    for role in roles.values():
        role.h.hashes.clear()
        require(role.h.sha256(role.h.binary) == config["expected_binaries"]["omd"] and
                role.h.sha256(role.h.test_binary) == config["expected_binaries"]["omd.test"], "current binary changed")
    return {"schema_version": 1, "scenario": scenario, "assignment_id": prior["assignment_id"],
            "prior_report_sha256": hashlib.sha256(raw).hexdigest(), "provenance": config["provenance"],
            "binaries": config["expected_binaries"], "controller_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "before": before, "after": after, "placements": placements, "observations": observations,
            "copy_probes": copies, "exact_retry": True, "new_execution_rejected": True,
            "observed_kernel_boot_sha256": boots,
            "ordinary_tickets_retained": True, "passed": True}


def validate(value):
    require(value["scenario"] in KINDS and value["passed"] is True and value["before"] == value["after"] and
            value["exact_retry"] is True and value["new_execution_rejected"] is True and value["ordinary_tickets_retained"] is True,
            "incomplete or changed negative lifecycle evidence")
    require([v["kind"] for v in value["observations"]] == KINDS[value["scenario"]], "wrong outcome classification")
    for observed in value["observations"]:
        digest_id(observed["negative_id"])
        digest_id(observed["artifact_sha256"])
        require(observed["ordinary_tickets_retained"] is True and observed["source_advanced"] is False, "negative observation released work")
    a, b = value["after"]["a"], value["after"]["b"]
    require(a["confirmed_sequence"] == 4 and a["pending_operations"] == 2 and not a["active_remote"] and
            not a["pending_attempt"] and a["journal_sequence"] == 0 and a["assignment_id"] == b["assignment_id"] == value["assignment_id"],
            "negative evidence claimed authority/source completion")
    require(b["journal_sequence"] == (1 if value["scenario"] == "expired-cache" else 0) and b["worker_stage"] == 4 and b["worker_pending"] == 0,
            "B's sealed source changed")
    require(b["disposition"] == {"unseen-seal": 1, "b-restart-before-result": 2, "expired-cache": 3}[value["scenario"]], "wrong sealed B disposition")
    boots = value["observed_kernel_boot_sha256"]
    require(set(boots) == {"a", "b"} and digest_id(boots["a"]) != digest_id(boots["b"]), "two distinct observed kernels required")
    for name, required in (("a", {"control-key", "authority", "authority-pins", "journal", "artifacts", "anchor"}),
                           ("b", {"control-key", "worker", "journal", "objects", "anchor"})):
        digest_id(value["placements"][name])
        probes = value["copy_probes"][name]
        require({p["name"] for p in probes} == required and len(probes) == len(required) and
                all(p["rejected"] is True and p["exit_code"] != 0 for p in probes), "copy rejection missing")
    return {"scenario": value["scenario"], "assignment_id": value["assignment_id"], "observation_kinds": KINDS[value["scenario"]],
            "ordinary_tickets_retained": 2, "original_source_sequences": [a["journal_sequence"], b["journal_sequence"]],
            "copy_probes_rejected": sum(len(v) for v in value["copy_probes"].values()), "passed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--prior-report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    value = run(json.loads(args.config.read_text()), args.prior_report)
    validate(value)
    publish_report(args.out, value)
    print("remote_negative_acceptance scenario=%s passed=true copies_rejected=11" % value["scenario"])


if __name__ == "__main__":
    try:
        main()
    except (AcceptanceError, OSError, ValueError, KeyError) as exc:
        raise SystemExit("remote_negative_acceptance_failed " + str(exc))
