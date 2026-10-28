#!/usr/bin/env python3
"""Mandatory-admission V2 owners on two hosts under real execution faults.

The shared admission is certified before original owner creation. Normal reviewed
CLI paths retain the full binding, execute the selected volatile session and
apply Serve/accounting closure. No witness/root resets or legacy migration.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

from run import ZERO, fields, require
from v1 import publish_report
import v2
from v2 import Case, artifact, digest, once, reviewed, transfer
from admission import Admission, decode_snapshot, entry_id, validate as validate_admission
from serve import Serve, broken

CLI = "work-archive-custody-v2-required"
OWNER_ACTIONS = {"create-target", "create-acceptor", "serve-target", "accept", "resume", "receipt"}
SERVE_ACTIONS = {"apply-a", "apply-b", "resume-a", "resume-b", "status-a", "status-b"}
SCENARIOS = ("lost-result", "lost-session")
CHECKS = {"raw_target_create_refused", "raw_acceptor_create_refused", "raw_target_open_refused",
          "raw_acceptor_open_refused", "missing_binding_refused", "wrong_binding_pin_refused",
          "binding_cli_matches_admission", "binding_retained_before_execution", "binding_bytes_retained_after_job", "accounting_does_not_change_source"}


def retained_record(raw, magic, binding, admission):
    require(type(raw) is bytes and len(raw) > 74 and raw[:10] == magic.encode() + b"\0\3" and
            raw[10:42].hex() == binding and raw[42:74].hex() == admission,
            "consumed/pending record lost exact admission binding")


class RequiredCase(Case):
    export_test = "TestExportCustodyV2RequiredWANFixture"
    serving_prefix = "custody_v2_required_serving"
    runtime_cli = CLI
    runtime_prefix = "custody_v2_required"

    def prepare_context(self):
        super().prepare_context()
        self.required_checks = {}
        self.admission = Admission(self)
        self.admission_report = copy.deepcopy(self.admission.run())
        args = [self.runtime_cli, "--action", "binding", "--context", self.a.root + "/context", "--context-id", self.public["ContextID"],
                "--scope-id", self.scope, "--genesis", self.a.root + "/admission-genesis", "--genesis-id", self.admission.gid,
                "--genesis-descriptor-id", self.admission.did, "--certificates", self.a.root + "/admission-certificate",
                "--certificate-ids", artifact(self.a.read("admission-certificate")), "--out", self.a.root + "/required-binding"]
        emitted = once(self.a, reviewed(self.a, args), self.runtime_prefix + "_artifact")
        raw = self.a.read("required-binding")
        self.binding_id = digest("OMESH/custody/v2/required/admission-binding/id", raw)
        require(emitted["binding_id"] == self.binding_id and emitted["admission_required"] == "true", "binding CLI changed proof identity/mode")
        for h in (self.b, self.clone): transfer(self.a, h, "required-binding")
        self.required_checks["binding_cli_matches_admission"] = True

    def args(self, h, action, extra=()):
        if action not in OWNER_ACTIONS: return super().args(h, action, extra)
        return [self.runtime_cli, "--action", action, "--context", h.root + "/context", "--context-id", self.public["ContextID"],
                "--scope-id", self.scope, "--binding", h.root + "/required-binding", "--binding-id", self.binding_id] + list(extra)

    def act(self, h, action, extra=(), fail=False):
        if action not in OWNER_ACTIONS: return super().act(h, action, extra, fail)
        args = self.args(h, action, extra)
        if fail:
            result = once(h, args, check=False); require(result.returncode != 0, "invalid required input accepted"); return result
        prefix = self.runtime_prefix + "_created" if action.startswith("create-") else self.runtime_prefix + "_artifact"
        emitted = once(h, reviewed(h, args), prefix)
        require(emitted["admission_required"] == "true" and emitted["binding_id"] == self.binding_id, "owner lost required binding")
        return emitted

    def refuse_raw(self, h, action, extra, input_bytes=None):
        args = Case.args(self, h, action, extra)
        attempted = reviewed(h, args)
        if input_bytes is None:
            result = h.execute([h.binary] + attempted, timeout=30, check=False)
        else:
            # The owner CLI requires dedicated OS pipes. SSH channel descriptors
            # alone need not be pipes, so create the same local child contract as
            # the ordinary Supervisor rather than failing on stdin's file type.
            script = ("import subprocess,sys\n"
                      "p=subprocess.run(sys.argv[1:],input=b'close\\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)\n"
                      "sys.stdout.buffer.write(p.stdout);sys.stderr.buffer.write(p.stderr);sys.exit(p.returncode)\n")
            result = h.execute(["python3", "-c", script, h.binary] + attempted, timeout=40, check=False)
        require(result.returncode != 0 and b"requires the exact retained admission binding" in result.stderr,
                "raw owner path did not refuse the signed required mode")

    def create_owners(self):
        self.refuse_raw(self.b, "create-target", ["--root", self.b.root + "/raw-target", "--journal", self.b.root + "/journal", "--objects", self.b.root + "/objects"])
        self.required_checks["raw_target_create_refused"] = True
        self.refuse_raw(self.a, "create-acceptor", ["--root", self.a.root + "/raw-acceptor", "--journal", self.a.root + "/journal"])
        self.required_checks["raw_acceptor_create_refused"] = True
        normal = self.args(self.b, "create-target", ["--root", self.b.root + "/missing-binding-owner", "--journal", self.b.root + "/journal", "--objects", self.b.root + "/objects"])
        missing = copy.copy(normal)
        for flag in ("--binding", "--binding-id"):
            i = missing.index(flag); del missing[i:i + 2]
        require(once(self.b, missing, check=False).returncode != 0, "required owner accepted missing binding")
        self.required_checks["missing_binding_refused"] = True
        wrong = copy.copy(normal); wrong[wrong.index("--binding-id") + 1] = "f" * 64
        require(once(self.b, wrong, check=False).returncode != 0, "required owner accepted wrong binding pin")
        self.required_checks["wrong_binding_pin_refused"] = True
        super().create_owners()
        self.refuse_raw(self.a, "receipt", ["--root", self.a.root + "/owner", "--journal", self.a.root + "/journal", "--sign-key", self.a.root + "/keys/authority.seed", "--out", self.a.root + "/raw-open-receipt"])
        self.required_checks["raw_acceptor_open_refused"] = True
        self.refuse_raw(self.b, "serve-target", ["--root", self.b.root + "/owner", "--journal", self.b.root + "/journal", "--objects", self.b.root + "/objects", "--sign-key", self.b.root + "/keys/control.seed", "--replica-key", self.b.root + "/keys/replica.seed", "--transport-key", self.b.root + "/keys/transport.seed"], input_bytes=b"close\n")
        self.required_checks["raw_target_open_refused"] = True
        for h in (self.a, self.b, self.clone):
            require(h.read("owner/admission") == h.read("required-binding"), "owner ready did not retain exact binding")
        self.required_checks["binding_retained_before_execution"] = True

    def binding_after_job(self):
        for h in (self.a, self.b, self.clone):
            require(h.read("owner/admission") == h.read("required-binding"), "job replaced its admission binding")
        self.required_checks["binding_bytes_retained_after_job"] = True
        if self.scenario == "lost-result":
            self.validate_retained_records()
            self.required_checks["consumption_and_acceptance_bind_exact_admission"] = True


    def validate_retained_records(self):
        retained_record(self.b.read("owner/consumed"), "OMCVUSE3", self.binding_id, self.admission.eid)
        retained_record(self.a.read("owner/pending"), "OMCVPEN3", self.binding_id, self.admission.eid)


class RequiredServe(Serve):
    def args(self, h, action, extra=()):
        if action not in SERVE_ACTIONS: return super().args(h, action, extra)
        return [self.c.runtime_cli, "--action", "serve-" + action, "--context", h.root + "/context", "--context-id", self.c.public["ContextID"],
                "--scope-id", self.c.scope, "--binding", h.root + "/required-binding", "--binding-id", self.c.binding_id] + list(extra)

    def act(self, h, action, extra=(), fail=False, lose=False):
        if action not in SERVE_ACTIONS: return super().act(h, action, extra, fail, lose)
        args = self.args(h, action, extra)
        review = once(h, args, check=not fail)
        if fail and review.returncode != 0: self.checks[action + "_refused"] = True; return
        r = fields(review.stdout.decode(), self.c.runtime_prefix + "_review")
        require(r["keys_loaded"] == r["owners_opened"] == "false" and r["admission_required"] == "true", "Serve owner review bypassed admission")
        args += ["--mode", "run", "--expected-review-id", r["review_id"]]
        if lose: broken(h, args)
        else:
            result = once(h, args, check=not fail)
            if fail: require(result.returncode != 0, "invalid required Serve applied"); self.checks[action + "_refused"] = True; return
            record = fields(result.stdout.decode(), self.c.runtime_prefix + "_artifact")
            require(record["admission_required"] == "true" and record["binding_id"] == self.c.binding_id, "Serve owner lost binding")
        name = extra[list(extra).index("--out") + 1]
        self.artifacts.append({"host": "a" if h.root == self.a.root else "b", "path": name,
                               "sha256": hashlib.sha256(h.read(name[len(h.root) + 1:])).hexdigest()})


def accounting_final(case, closed):
    ad, a, b = case.admission, case.a, case.b
    selected, sequence = ad.eid, 1
    if closed:
        transfer(b, a, "serve-b-recovered")
        ad.act(a, "close-entry", ad.context(a) + ["--sequence", "1", "--head-id", ad.eid, "--sign-key", a.root + "/keys/authority.seed",
               "--in", a.root + "/serve-certificate", "--in-id", artifact(a.read("serve-certificate")),
               "--a-receipt", a.root + "/serve-a-recovered", "--a-receipt-id", artifact(a.read("serve-a-recovered")),
               "--b-receipt", a.root + "/serve-b-recovered", "--b-receipt-id", artifact(a.read("serve-b-recovered")), "--out", a.root + "/admission-close-entry"])
        selected = entry_id(a.read("admission-close-entry")); transfer(a, b, "admission-close-entry")
        paths, pins = [], []
        for i in range(4):
            h, common = ad.member_args(i, 1, ad.eid, ZERO); name = "admission-close-vote-%d" % i
            ad.act(h, "witness-vote", common + ad.ip(h, "admission-close-entry") + ["--out", h.root + "/" + name])
            if i >= 2: transfer(h, a, name)
            paths.append(a.root + "/" + name); pins.append(artifact(a.read(name)))
        ad.act(a, "certificate", ad.ip(a, "admission-close-entry") + ["--votes", ",".join(paths[:3]), "--vote-ids", ",".join(pins[:3]), "--out", a.root + "/admission-close-certificate"])
        transfer(a, b, "admission-close-certificate")
        for i in range(4):
            h, common = ad.member_args(i, 1, ad.eid, selected); name = "admission-close-committed-%d" % i
            args = common + ad.ip(h, "admission-close-certificate") + ["--out", h.root + "/" + name]
            ad.act(h, "witness-commit", args, lose=(i == 1))
            retry = copy.copy(args); retry[-1] += "-recovered"; ad.act(h, "witness-commit", retry)
            require(h.read(name) == h.read(name + "-recovered"), "global Close cold recovery changed checkpoint")
        sequence = 2
    members = []
    for i in range(4):
        h, common = ad.member_args(i, sequence, selected, ZERO); name = "admission-final-required-%d" % i
        ad.act(h, "witness-status", common + ["--out", h.root + "/" + name])
        members.append({"member": i, "host": "a" if i < 2 else "b", "signing_public_key": case.public["Members"][i]["signing_public_key"],
                        "final": decode_snapshot(h.read(name))})
    return {"closed": closed, "sequence": sequence, "head": selected, "members": members,
            "artifacts": copy.deepcopy(ad.artifacts[len(case.admission_report["artifacts"]):])}



def validate_execution_events(case):
    pins = [{"sequence": 0, "head": case["scope_id"], "pending": ZERO} for _ in range(4)]
    count = 0
    for event in case["events"]:
        require(event.get("kind") in ("witness", "target") and re.fullmatch("[0-9a-f]{64}", event.get("request_id", "")), "invalid execution event")
        if event["kind"] != "witness": continue
        i = event["member"]
        require(type(i) is int and 0 <= i < 4, "invalid execution member")
        if not event["completed"]:
            require(event.get("refused") is True, "unclassified execution witness outcome"); continue
        require(event["before"] == pins[i], "execution witness before pin changed")
        after = event["after"]
        if event.get("command_id"):
            require(after["sequence"] == pins[i]["sequence"] and after["head"] == pins[i]["head"] and after["pending"] == event["command_id"], "invalid execution vote")
        else:
            require(event.get("certificate") and after["sequence"] == pins[i]["sequence"] + 1 and after["pending"] == ZERO and after["head"] != ZERO, "invalid execution commit")
        pins[i] = {k: after[k] for k in ("sequence", "head", "pending")}; count += 1
    require(count >= (22 if case["scenario"] == "lost-result" else 15), "incomplete execution witness transcript")
    require(all(pins[i]["sequence"] == w["sequence"] and pins[i]["head"] == w["head"] and pins[i]["pending"] == ZERO for i, w in enumerate(case["witnesses"])), "terminal execution pin lacks history")


def validate(report):
    require(report.get("schema_version") == 1 and report.get("passed") is True, "incomplete required runtime campaign")
    cases = report.get("cases", [])
    require(len(cases) == 2 and {c["scenario"] for c in cases} == set(SCENARIOS), "missing required runtime fault class")
    require(len({c["scope_id"] for c in cases}) == len({c["binding_id"] for c in cases}) == len({c["genesis_id"] for c in cases}) == 2, "required job/binding/admission scope reused")
    for c in cases:
        require(c["passed"] and c["cleanup_complete"] and c["runtime_admission_enforced"] is True and c["legacy_v1_migrated"] is False and
                c["independent_four_domain_deployment"] is False, "required campaign overstated activation/deployment")
        require(CHECKS <= c["checks"].keys() and all(v is True for v in c["checks"].values()), "missing required admission guard")
        require(re.fullmatch("[0-9a-f]{64}", c["binding_id"]) and c["binding_id"] != ZERO, "missing binding pin")
        ad = c["admission_before_runtime"]; validate_admission(ad)
        require(ad["context_id"] == c["context_id"] and ad["plan_id"] == c["plan_id"] and ad["genesis_id"] == c["genesis_id"], "admission authorized another job")
        e, s, ledger = c["execution"], c["serve"], c["accounting_final"]
        closed = c["scenario"] == "lost-result"
        require(e["passed"] and e["scenario"] == c["scenario"] and e["scope_id"] == c["scope_id"] and e["context_id"] == c["context_id"] and
                e["independent_four_domain_deployment"] is False and e["serve_resolved"] is False, "execution snapshot changed required job")
        require(e["observed_kernel_boot_sha256"] == ad["observed_kernel_boot_sha256"], "admission/execution hosts changed")
        phase, seq = (3, 3) if closed else (2, 2)
        require(len(e["witnesses"]) == 4 and all(w["phase"] == phase and w["sequence"] == seq and w["held"] and w["session"] != ZERO for w in e["witnesses"]) and
                len({w["head"] for w in e["witnesses"]}) == len({w["session"] for w in e["witnesses"]}) == 1, "execution witness history diverged")
        common = {"sources_initially_zero", "two_witnesses_not_quorum", "duplicate_member_not_quorum", "witness_sigkill_exact_vote_recovered", "no_effect_before_claim", "original_owner_identities_preserved"}
        common |= {"result_reply_cut_after_durable_b", "target_sigkill_result_retained", "a_lost_output_receipt_recovered", "exact_result_bytes_retained", "copied_persistent_keys_old_claim_refused", "late_execution_refused"} if closed else {"target_sigkill_before_effect", "old_live_session_claim_refused", "unknown_without_result_held"}
        require(common <= e["checks"].keys() and all(v is True for v in e["checks"].values()), "missing original runtime fault checks")
        validate_execution_events(e)
        require(e["a"]["source_sequence"] == e["b"]["source_sequence"] == int(closed) and e["clone"]["source_sequence"] == 0, "required effect/source count changed")
        for role in ("a", "b"): require(e[role]["original_identities_sha256"] == e["original_identity_pins"][role], "original owner identity changed")
        require(all({k: v for k, v in c["sources_after_accounting"][role].items() if k != "now"} == {k: v for k, v in e[role].items() if k != "now"} for role in ("a", "b", "clone")), "accounting mutated original sources")
        require(s["scenario"] == c["scenario"] and s["scope_id"] == c["scope_id"] and all(v is True for v in s["checks"].values()), "Serve selected another job or failed")
        require(all(x["ArchiveHeld"] and x["Pending"] != closed and x["MinimumRetainUntil"] > 0 for x in s["states"].values()), "Serve/retention disposition wrong")
        if closed:
            require(c["checks"].get("consumption_and_acceptance_bind_exact_admission") and s["checks"].get("a_and_b_lost_output_exact_cold_resume") and s["checks"].get("cold_key_copy_without_original_result_refused"), "missing required consumed/Serve recovery")
        else: require(s["checks"].get("unresolved_serve_and_archive_held"), "unknown Serve released")
        require(ledger["closed"] == closed and ledger["sequence"] == (2 if closed else 1) and len(ledger["members"]) == 4, "accounting closure missing")
        require(len({m["signing_public_key"] for m in ledger["members"]}) == 4 and [m["host"] for m in ledger["members"]] == ["a", "a", "b", "b"], "accounting witness roles changed")
        for m in ledger["members"]:
            x = m["final"]
            require(x["genesis_id"] == c["genesis_id"] and x["sequence"] == ledger["sequence"] and x["head"] == ledger["head"] and x["pending_id"] == ZERO and x["spent_operations"] == 2 and
                    x["pending_operations"] == (0 if closed else 2) and x["source_sequence"] == int(closed) and x["source_head"] == e["a"]["source_head"] and
                    x["source_receipt_id"] == e["a"]["receipt_id"] and x["active_context_id"] == (ZERO if closed else c["context_id"]) and x["active_plan_id"] == (ZERO if closed else c["plan_id"]) and
                    x["retain_until"] >= max(v["MinimumRetainUntil"] for v in s["states"].values()), "accounting state or retention disagrees with required source")
    return {"cases": 2, "joint_hosts": 2, "logical_witnesses": 4, "runtime_admission_enforced": True,
            "fulfilled_and_accounting_closed": 1, "unknown_still_held": 1, "archives_released": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--config", required=True); parser.add_argument("--out", required=True)
    args = parser.parse_args(); config = json.loads(Path(args.config).read_text()); cases = []
    for scenario in SCENARIOS:
        print("custody_required_start " + scenario, flush=True)
        case = RequiredCase(config, scenario)
        try:
            execution = case.run(); case.binding_after_job()
            service = RequiredServe(case); states = service.close() if scenario == "lost-result" else service.held()
            ledger = accounting_final(case, scenario == "lost-result")
            source_after = {role: case.inspect(h) for role, h in (("a", case.a), ("b", case.b), ("clone", case.clone))}
            require(all({k: v for k, v in source_after[role].items() if k != "now"} == {k: v for k, v in execution[role].items() if k != "now"} for role in source_after), "accounting altered original source history")
            case.required_checks["accounting_does_not_change_source"] = True
        finally: case.cleanup()
        case.admission_report["cleanup_complete"] = case.cleanup_complete
        cases.append({"scenario": scenario, "scope_id": case.scope, "context_id": case.public["ContextID"], "plan_id": case.public["PlanID"],
                      "genesis_id": case.admission.gid, "binding_id": case.binding_id, "binding_artifact_id": artifact(case.a.read("required-binding")),
                      "checks": case.required_checks, "admission_before_runtime": case.admission_report, "execution": execution,
                      "serve": service.report(scenario, states), "accounting_final": ledger, "sources_after_accounting": source_after, "roots": {"a": case.a.root, "b": case.b.root},
                      "cleanup_complete": case.cleanup_complete, "runtime_admission_enforced": True, "legacy_v1_migrated": False,
                      "independent_four_domain_deployment": False, "passed": True})
        publish_report(args.out + ".checkpoint-" + case.nonce, {"schema_version": 1, "passed": False, "completed_cases": cases})
        print("custody_required_pass " + scenario, flush=True)
    report = {"schema_version": 1, "passed": True, "cases": cases, "source_manifest": config["source_manifest"], "binaries": config["expected_binaries"]}
    report["summary"] = validate(report); publish_report(args.out, report)
    print("custody_required_complete " + json.dumps(report["summary"], sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
