#!/usr/bin/env python3
"""Explicitly dispose one retained negative Audit while preserving original Serve.

Requires separately retained WAN and negative-observation reports and existing
closed original owners. It never creates an assignment, resets a root, imports
B's result, transfers private material, completes Serve or starts a listener.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import uuid

from negative import validate as validate_negative, without_flags, replace_flag
from run import AcceptanceError, Host, Supervisor, digest_id, require
from v1 import Role, PREFIX, close_supervisor, publish_report
from v1_report import validate_report


def select_observation(role, observation):
    # The SHA and content ID come from the retained report. Scan only bounded,
    # public observation artifacts in the exact selected operation directory.
    script = ("import hashlib,itertools,json,os,sys; p=sys.argv[1]; names=[e.name for e in itertools.islice(os.scandir(p),257)]; "
              "assert len(names)<=256; out=[]\n"
              "for n in names:\n"
              " if n.startswith('negative-'):\n"
              "  f=p+'/'+n; assert not os.path.islink(f); size=os.stat(f).st_size; assert size<=65536\n"
              "  if hashlib.sha256(open(f,'rb').read()).hexdigest()==sys.argv[2]: out.append(n)\n"
              "print(json.dumps(out))")
    names = json.loads(role.h.execute(["python3", "-c", script, role.path(role.op("")), observation["artifact_sha256"]]).stdout)
    require(len(names) == 1, "select one exact retained observation")
    name = names[0]
    nonce = name.removeprefix("negative-").removesuffix("-verified")
    require(re.fullmatch("[0-9a-f]{32}", nonce) is not None, "unexpected retained observation name")
    return role.path(role.op(name)), nonce


def run(config, negative_report, wan_report):
    negative_raw, wan_raw = negative_report.read_bytes(), wan_report.read_bytes()
    prior, wan = json.loads(negative_raw), json.loads(wan_raw)
    validate_negative(prior)
    validate_report(wan)
    require(prior["prior_report_sha256"] == hashlib.sha256(wan_raw).hexdigest() and
            prior["assignment_id"] == wan["assignment_id"], "reports select different original owners")
    roles, before, boots = {}, {}, {}
    for name in ("a", "b"):
        host = Host(config["hosts"][name])
        boots[name] = hashlib.sha256(host.execute(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()).hexdigest()
        require(boots[name] == prior["observed_kernel_boot_sha256"][name], "original kernel changed")
        for binary, path in (("omd", host.binary), ("omd.test", host.test_binary)):
            require(host.sha256(path) == config["expected_binaries"][binary], "current binary differs from pin")
        role = Role(host, json.loads(host.read("scope.json")))
        role.n = 1
        cycle = wan["cycles"][0]
        role.ids = {"assignment": prior["assignment_id"], "plan": cycle["plan_id"],
                    "begin": cycle["begin_id"], "challenge": cycle["challenge_id"]}
        before[name] = role.inspect()
        require(before[name] == prior["after"][name], "original owner changed since retained negative report")
        role.ids.update(intent=before[name]["intent_id"], audit=before[name]["audit_ticket_id"],
                        serve=before[name]["serve_ticket_id"])
        roles[name] = role
    a = roles["a"]
    observation = prior["observations"][-1]
    path, nonce = select_observation(a, observation)
    a.placement_flags = ["--placement", config["anchor_parents"]["a"] + "/" + nonce + "/record",
                         "--placement-id", prior["placements"]["a"], "--require-placement=true"]
    late = json.loads(a.h.read(a.op("late-start.json")))
    base = without_flags(a.runtime("a", late["peer"], before["a"]["drain_id"]), {"--terminal"})
    base += ["--negative", path, "--negative-id", observation["negative_id"]]
    common = a.common() + a.plan() + a.begin() + a.challenge() + [
        "--kind", "negative-audit-complete", "--purpose", "audit",
        "--expected-sequence", str(before["a"]["confirmed_sequence"]), "--expected-head", before["a"]["confirmed_head"],
        "--admission", a.path(a.op("audit")), "--admission-id", a.ids["audit"],
        "--negative", path, "--negative-id", observation["negative_id"]]
    bad = a.once([PREFIX + "command-sign"] + replace_flag(common, "--purpose", "serve"), check=False)
    require(bad.returncode != 0 and b"Serve must remain pending" in bad.stderr, "offline negative Serve signing was allowed")
    name = "negative-audit-complete-" + uuid.uuid4().hex
    args = [PREFIX + "command-sign"] + common
    review = a.record(args, "remote_custody_signing")["review_id"]
    command, entry = a.path(a.op(name + ".command")), a.path(a.op(name))
    a.once(args + ["--mode", "sign", "--expected-review-id", review,
                   "--actor-key", a.path("keys/audit-consumer.seed"), "--out", command])
    args = [PREFIX + "command-cosign"] + common + ["--command", command]
    review = a.record(args, "remote_custody_signing")["review_id"]
    signed = a.record(args + ["--mode", "sign", "--expected-review-id", review,
                             "--authority-key", a.path("keys/authority.seed"), "--out", entry], "remote_custody_signing")
    entry_id = digest_id(signed["entry_id"])
    selected = base + ["--complete-entry", entry, "--complete-entry-id", entry_id]
    for retry in (False, True):
        supervisor = Supervisor(a.h, {"audit": {"argv": [a.h.binary] + selected}})
        try:
            supervisor.start("audit", "remote_custody_ready")
            result = supervisor.action("audit", "remote_custody", "apply-negative-audit-complete", "audit_disposed")
            require(result["entry_id"] == entry_id and result["appended"] == ("false" if retry else "true") and
                    result["serve_ticket_retained"] == "true" and result["execution_outcome_resolved"] == "false" and
                    result["source_advanced"] == "false", "administrative disposition changed effect semantics")
            supervisor.stop("audit")
        finally:
            close_supervisor(supervisor)
    for action in ("execute", "capture"):
        probe_args = list(base)
        if action == "capture":
            probe_args += ["--terminal", a.path(a.op("forbidden-positive-" + uuid.uuid4().hex))]
        supervisor = Supervisor(a.h, {"audit": {"argv": [a.h.binary] + probe_args}})
        try:
            supervisor.start("audit", "remote_custody_ready")
            token = supervisor.review("audit", "remote_custody")
            supervisor.rpc("send", name="audit", line=action + " " + token)
            supervisor.expect_failure("audit")
            detail = supervisor.rpc("status", name="audit")["stderr_tail"]
            expected = "already completed" if action == "execute" else "remote custody scope, owner or result"
            require(expected in detail, "refusal came from an unrelated failure")
        finally:
            close_supervisor(supervisor)
    after = {name: role.inspect() for name, role in roles.items()}
    report = {"schema_version": 1, "scenario": prior["scenario"], "assignment_id": prior["assignment_id"],
              "kind": observation["kind"], "negative_id": observation["negative_id"], "audit_complete_id": entry_id,
              "before": before, "after": after, "exact_retry": True, "serve_signing_rejected": True,
              "new_execution_rejected": True, "positive_capture_rejected": True,
              "observed_kernel_boot_sha256": boots, "negative_report_sha256": hashlib.sha256(negative_raw).hexdigest(),
              "binaries": config["expected_binaries"], "passed": True}
    validate(report)
    return report


def validate(value):
    kinds = {"unseen-seal": 1, "b-restart-before-result": 2, "expired-cache": 4}
    require(value["schema_version"] == 1 and kinds.get(value["scenario"]) == value["kind"] and value["passed"] is True,
            "unsupported negative Audit settlement")
    for field in ("assignment_id", "negative_id", "audit_complete_id", "negative_report_sha256"):
        digest_id(value[field])
    for field in ("exact_retry", "serve_signing_rejected", "new_execution_rejected", "positive_capture_rejected"):
        require(value[field] is True, "remaining obligation gate missing: " + field)
    before, after = value["before"], value["after"]
    require(before["b"] == after["b"], "B's original source changed")
    original = copy.deepcopy(before["a"])
    require(original["assignment_id"] == value["assignment_id"] and original["confirmed_sequence"] == 4 and
            original["pending_operations"] == 2 and not original["active_remote"] and not original["pending_attempt"],
            "settlement did not start at the retained drained owner")
    require(original["journal_sequence"] == 0 and before["b"]["assignment_id"] == value["assignment_id"] and
            before["b"]["journal_sequence"] == (1 if value["scenario"] == "expired-cache" else 0) and
            before["b"]["worker_stage"] == 4 and before["b"]["worker_pending"] == 0,
            "original sealed source is inconsistent with the selected disposition")
    original.update(confirmed_sequence=5, confirmed_head=value["audit_complete_id"], pending_operations=1)
    require(original == after["a"], "settlement changed a source, identity or unresolved Serve obligation")
    boots = value["observed_kernel_boot_sha256"]
    require(set(boots) == {"a", "b"} and digest_id(boots["a"]) != digest_id(boots["b"]), "distinct original kernels required")
    return {"scenario": value["scenario"], "kind": value["kind"], "pending_operations": 1,
            "source_positions": [after["a"]["journal_sequence"], after["b"]["journal_sequence"]], "passed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "negative-report", "wan-report", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = run(json.loads(args.config.read_text()), args.negative_report, args.wan_report)
    publish_report(args.out, result)
    print(json.dumps(validate(result), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (AcceptanceError, OSError, ValueError, KeyError) as exc:
        raise SystemExit("negative Audit settlement failed: " + str(exc)) from exc
