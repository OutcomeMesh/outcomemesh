#!/usr/bin/env python3
"""Typed V2 Serve disposition on two hosts using reviewed CLI processes.

Runs the V2 execution fault matrix first. Serve voting uses standalone typed
CLI commands on each host, not the hash-only witness RPC. All keys are public
fixtures; two kernels do not establish four independent failure domains.
"""
import argparse
import copy
import json
from pathlib import Path
import struct

from run import ZERO, require
from v1 import publish_report
from v2 import Case, Member, SCENARIOS, artifact, digest, once, transfer, validate as validate_execution

CLI = "work-archive-custody-v2-serve"


def broken(host, args):
    script = ("import json,os,subprocess,sys\n"
              "r,w=os.pipe();os.close(r)\n"
              "try:p=subprocess.run(sys.argv[1:],stdout=w,stderr=subprocess.PIPE,timeout=40);print(json.dumps({'returncode':p.returncode}))\n"
              "finally:os.close(w)\n")
    result = json.loads(host.execute(["python3", "-c", script, host.binary] + args).stdout)
    require(result["returncode"] != 0, "lost stdout was reported as success")


def observation(raw, scope, member, sequence, head, pending):
    require(len(raw) == 308 and raw[:10] == b"OMCFOB00\0\0", "wrong Serve witness observation")
    require(raw[42:74].hex() == member and raw[74:106].hex() == scope, "witness/scope changed")
    require(struct.unpack(">Q", raw[106:114])[0] == sequence and raw[114:146].hex() == head and
            raw[146:178].hex() == pending, "Serve witness position changed")
    return {"sequence": sequence, "head": head, "pending": pending, "observation_artifact": artifact(raw)}


def decode_status(raw):
    value = json.loads(raw)
    require(type(value.get("Pending")) is bool and value.get("ArchiveHeld") is True and
            type(value.get("MinimumRetainUntil")) is int and value["MinimumRetainUntil"] > 0,
            "invalid Serve status/retention")
    for name in ("AttemptID", "ReceiptID"):
        key = value.get(name)
        require(type(key) is list and len(key) == 32 and all(type(b) is int and 0 <= b <= 255 for b in key),
                "invalid Go hash array in Serve status")
        value[name] = bytes(key).hex()
    return value


class Serve:
    def __init__(self, case):
        self.c = case
        self.a, self.b = case.a, case.b
        self.sid = case.public["ServeScopeID"]
        self.checks = {}
        self.witnesses = []
        self.artifacts = []

    def args(self, h, action, extra=()):
        return [CLI, "--action", action, "--context", h.root + "/context", "--context-id", self.c.public["ContextID"],
                "--scope-id", self.c.scope, "--serve-scope-id", self.sid] + list(extra)

    def act(self, h, action, extra=(), fail=False, lose=False):
        args = self.args(h, action, extra)
        review = once(h, args, check=not fail)
        if fail and review.returncode != 0:
            self.checks[action + "_refused"] = True
            return
        from run import fields
        r = fields(review.stdout.decode(), "custody_v2_serve_review")
        require(r["keys_loaded"] == r["owners_opened"] == "false", "Serve review opened a key or owner")
        args += ["--mode", "run", "--expected-review-id", r["review_id"]]
        if lose:
            broken(h, args)
        else:
            result = once(h, args, check=not fail)
            if fail:
                require(result.returncode != 0, "invalid Serve transition succeeded")
                self.checks[action + "_refused"] = True
                return
        if "--out" in extra:
            path = extra[list(extra).index("--out") + 1]
            self.artifacts.append({"host": "a" if h.root == self.a.root else "b", "path": path,
                                   "sha256": __import__("hashlib").sha256(h.read(path[len(h.root) + 1:])).hexdigest()})

    def ip(self, h, name, label="in"):
        return ["--" + label, h.root + "/" + name, "--" + label + "-id", artifact(h.read(name))]

    def owner(self, h):
        if h.root == self.a.root:
            return ["--root", h.root + "/owner", "--journal", h.root + "/journal", "--sign-key", h.root + "/keys/authority.seed"]
        return ["--root", h.root + "/owner", "--journal", h.root + "/journal", "--objects", h.root + "/objects",
                "--sign-key", h.root + "/keys/control.seed", "--replica-key", h.root + "/keys/replica.seed"]

    def status(self, h, name):
        role = "a" if h.root == self.a.root else "b"
        self.act(h, "status-" + role, self.owner(h) + ["--out", h.root + "/" + name])
        value = decode_status(h.read(name))
        require(value["ArchiveHeld"] is True, "Serve status released archive")
        return value

    def held(self):
        # Neither a claim nor an unknown QC can replace the no-claim proof.
        name = "unknown.qc" if self.c.scenario == "lost-session" else "claim.qc"
        self.act(self.a, "proposal-unclaimed", self.ip(self.a, name) + ["--out", self.a.root + "/invalid-cancel"], fail=True)
        if self.c.scenario == "expired-result":
            self.act(self.a, "proposal-fulfilled", self.ip(self.a, "bundle") + self.ip(self.a, "result", "proof") +
                     ["--out", self.a.root + "/invalid-fulfilled"], fail=True)
        states = {role: self.status(h, "serve-held") for role, h in (("a", self.a), ("b", self.b))}
        require(all(s["Pending"] and s["AttemptID"] == ZERO and s["ReceiptID"] == ZERO for s in states.values()), "unknown outcome closed Serve")
        self.checks["unresolved_serve_and_archive_held"] = True
        return states

    def close(self, unclaimed=False):
        a, b = self.a, self.b
        before = {role: self.c.inspect(h) for role, h in (("a", a), ("b", b))}
        if unclaimed:
            self.act(a, "proposal-unclaimed", self.ip(a, "unclaimed.qc") + ["--out", a.root + "/serve-draft"])
        else:
            self.act(a, "proposal-fulfilled", self.ip(a, "bundle") + self.ip(a, "accepted-recovered", "proof") + ["--out", a.root + "/serve-draft"])
        self.act(a, "sign-proposal", self.ip(a, "serve-draft") + ["--sign-role", "authority", "--sign-key", a.root + "/keys/authority.seed", "--out", a.root + "/serve-authority"])
        transfer(a, b, "serve-authority")
        self.act(b, "sign-proposal", self.ip(b, "serve-authority") + ["--sign-role", "consumer", "--sign-key", b.root + "/keys/serve.seed", "--out", b.root + "/serve-proposal"])
        transfer(b, a, "serve-proposal")
        self.act(a, "decision", self.ip(a, "serve-proposal") + ["--sign-key", a.root + "/keys/authority.seed", "--out", a.root + "/serve-command"])
        transfer(a, b, "serve-command")
        raw = a.read("serve-command")
        require(raw[:10] == b"OMCFCM00\0\0", "wrong decision command version")
        decision = digest("OMESH/custody-fence/command/id/v0", raw)
        # Incomplete typed evidence must not even leave a pending witness vote.
        partial = bytearray(a.read("serve-proposal")); partial[-64:] = bytes(64)
        a.write("serve-unsigned", bytes(partial))
        vote_paths, vote_ids, entries = [], [], []
        for i in range(4):
            h = a if i < 2 else b
            root = h.root + "/serve-witness-%d" % i
            public = self.c.public["Members"][i]["signing_public_key"]
            common = ["--root", root, "--witness", public, "--sign-key", h.root + "/keys/witness-%d.seed" % i]
            self.act(h, "witness-create", common + ["--out", root + "-created"])
            observation(h.read("serve-witness-%d-created" % i), self.sid, public, 0, self.sid, ZERO)
            if i == 0:
                self.act(h, "witness-vote", common + self.ip(h, "serve-unsigned") + self.ip(h, "serve-command", "proof") +
                         ["--sequence", "0", "--head-id", self.sid, "--pending-id", ZERO, "--out", root + "-invalid"], fail=True)
            extra = common + self.ip(h, "serve-proposal") + self.ip(h, "serve-command", "proof") + ["--sequence", "0", "--head-id", self.sid, "--pending-id", ZERO, "--out", root + "-vote"]
            self.act(h, "witness-vote", extra, lose=(i == 2))
            retry = copy.copy(extra); retry[-1] += "-recovered"
            self.act(h, "witness-vote", retry)
            name = "serve-witness-%d-vote" % i
            require(h.read(name) == h.read(name + "-recovered"), "cold lost-vote recovery changed signature")
            if h.root != a.root: transfer(h, a, name)
            vote_paths.append(a.root + "/" + name); vote_ids.append(artifact(a.read(name)))
            entries.append((h, common, public, root))
        self.checks["typed_witness_rejects_unsigned_evidence"] = True
        self.checks["lost_witness_output_exact_cold_retry"] = True
        base = self.ip(a, "serve-proposal") + self.ip(a, "serve-command", "proof")
        self.act(a, "certificate", base + ["--votes", ",".join(vote_paths[:2]), "--vote-ids", ",".join(vote_ids[:2]), "--out", a.root + "/serve-weak"], fail=True)
        self.act(a, "certificate", base + ["--votes", ",".join([vote_paths[0]] * 3), "--vote-ids", ",".join([vote_ids[0]] * 3), "--out", a.root + "/serve-duplicate"], fail=True)
        self.checks["two_votes_and_duplicate_refused"] = True
        self.act(a, "certificate", base + ["--votes", ",".join(vote_paths[:3]), "--vote-ids", ",".join(vote_ids[:3]), "--out", a.root + "/serve-certificate"])
        transfer(a, b, "serve-certificate")
        for i, (h, common, public, root) in enumerate(entries):
            extra = common + self.ip(h, "serve-certificate") + ["--sequence", "0", "--head-id", self.sid, "--pending-id", decision, "--out", root + "-committed"]
            self.act(h, "witness-commit", extra)
            self.witnesses.append(observation(h.read("serve-witness-%d-committed" % i), self.sid, public, 1, decision, ZERO))
            retry = copy.copy(extra); retry[-1] += "-recovered"; self.act(h, "witness-commit", retry)
        self.act(b, "apply-b", self.owner(b) + self.ip(b, "serve-certificate") + self.ip(b, "serve-proposal", "proof") + ["--out", b.root + "/serve-without-a"], fail=True)
        self.checks["b_requires_a_applied_receipt"] = True
        self.act(a, "apply-a", self.owner(a) + self.ip(a, "serve-certificate") + ["--out", a.root + "/serve-a-applied"], lose=True)
        self.act(a, "resume-a", self.owner(a) + self.ip(a, "serve-certificate") + ["--out", a.root + "/serve-a-recovered"])
        require(a.read("serve-a-applied") == a.read("serve-a-recovered") == a.read("owner/serve.settled"), "A lost output changed receipt")
        transfer(a, b, "serve-a-recovered")
        self.act(b, "apply-b", self.owner(b) + self.ip(b, "serve-certificate") + self.ip(b, "serve-a-recovered", "proof") + ["--out", b.root + "/serve-b-applied"], lose=True)
        self.act(b, "resume-b", self.owner(b) + self.ip(b, "serve-certificate") + self.ip(b, "serve-a-recovered", "proof") + ["--out", b.root + "/serve-b-recovered"])
        require(b.read("serve-b-applied") == b.read("serve-b-recovered") == b.read("owner/serve.settled"), "B lost output changed receipt")
        self.checks["a_and_b_lost_output_exact_cold_resume"] = True
        if not unclaimed:
            clone = self.c.clone
            for name, source in (("serve-certificate", a), ("serve-a-recovered", a)): transfer(source, clone, name)
            self.act(clone, "apply-b", self.owner(clone) + self.ip(clone, "serve-certificate") + self.ip(clone, "serve-a-recovered", "proof") + ["--out", clone.root + "/serve-clone-applied"], fail=True)
            self.checks["cold_key_copy_without_original_result_refused"] = True
        states = {role: self.status(h, "serve-closed") for role, h in (("a", a), ("b", b))}
        require(all(not s["Pending"] and s["ArchiveHeld"] and s["ReceiptID"] != ZERO for s in states.values()), "Serve did not close with retention held")
        after = {role: self.c.inspect(h) for role, h in (("a", a), ("b", b))}
        require(all({k: v for k, v in before[role].items() if k != "now"} == {k: v for k, v in after[role].items() if k != "now"} for role in before), "settlement changed original source/result/receipt")
        self.checks["original_sources_and_proof_times_unchanged"] = True
        self.checks["execution_closed_archive_held"] = True
        return states

    def report(self, scenario, states):
        return {"scenario": scenario, "scope_id": self.c.scope, "serve_scope_id": self.sid,
                "states": states, "checks": self.checks, "witnesses": self.witnesses,
                "artifacts": self.artifacts, "roots": {"a": self.a.root, "b": self.b.root},
                "observed_kernel_boot_sha256": self.c.boots, "passed": True,
                "independent_four_domain_deployment": False, "archive_retirement_authorized": False}


def validate(report):
    require(report.get("schema_version") == 1 and report.get("passed") is True, "incomplete Serve campaign")
    cases = report["cases"]
    require(len(cases) == 4 and {c["scenario"] for c in cases} == set(SCENARIOS) | {"unclaimed"}, "missing disposition case")
    require(len({c["scope_id"] for c in cases}) == 4 and len({c["serve_scope_id"] for c in cases}) == 4, "scope reused")
    for c in cases:
        require(c["passed"] and not c["independent_four_domain_deployment"] and not c["archive_retirement_authorized"], "overstated Serve guarantee")
        require(c["scope_id"] != c["serve_scope_id"] and c["observed_kernel_boot_sha256"]["a"] != c["observed_kernel_boot_sha256"]["b"], "scope or host isolation missing")
        require(all(c["checks"].values()) and all(s["ArchiveHeld"] for s in c["states"].values()), "failed check or archive released")
        closed = c["scenario"] in ("lost-result", "unclaimed")
        require(all(s["Pending"] != closed and s["MinimumRetainUntil"] > 0 for s in c["states"].values()), "incorrect Serve disposition")
        if closed:
            required = {"typed_witness_rejects_unsigned_evidence", "lost_witness_output_exact_cold_retry", "two_votes_and_duplicate_refused", "b_requires_a_applied_receipt", "a_and_b_lost_output_exact_cold_resume", "original_sources_and_proof_times_unchanged", "execution_closed_archive_held"}
            require(required <= c["checks"].keys() and len(c["witnesses"]) == 4, "missing closure evidence")
            require(all(w["sequence"] == 1 and w["pending"] == ZERO for w in c["witnesses"]) and len({w["head"] for w in c["witnesses"]}) == 1, "Serve witness histories diverged")
            require(all(s["AttemptID"] != ZERO and s["ReceiptID"] != ZERO for s in c["states"].values()) and len({s["AttemptID"] for s in c["states"].values()}) == 1, "missing or mismatched applied receipts")
            if c["scenario"] == "lost-result":
                require(c["checks"].get("cold_key_copy_without_original_result_refused"), "missing cold copy refusal")
        else:
            require(c["checks"].get("unresolved_serve_and_archive_held") and not c["witnesses"] and all(s["AttemptID"] == s["ReceiptID"] == ZERO for s in c["states"].values()), "unresolved work released")
    return {"cases": 4, "joint_hosts": 2, "logical_witnesses": 4, "closed_jobs": 2, "unresolved_jobs_held": 2, "archives_released": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True); parser.add_argument("--out", required=True)
    args = parser.parse_args(); config = json.loads(Path(args.config).read_text()); cases, executions = [], []
    for scenario in SCENARIOS:
        print("custody_serve_start " + scenario, flush=True)
        case = Case(config, scenario)
        executions.append(case.run())
        s = Serve(case)
        states = s.close() if scenario == "lost-result" else s.held()
        cases.append(s.report(scenario, states))
        publish_report(args.out + ".checkpoint-" + case.nonce, {"schema_version": 1, "passed": False, "completed_cases": cases, "execution": executions})
        print("custody_serve_pass " + scenario, flush=True)
    case = Case(config, "lost-session")
    s = Serve(case)
    try:
        for i in range(4):
            m = Member(case, i); case.members.append(m); m.create(); m.start()
        s.act(case.a, "unclaimed-command", ["--sign-key", case.a.root + "/keys/authority.seed", "--evidence-id", digest("OMESH/test/serve/cancel", case.nonce.encode()), "--out", case.a.root + "/unclaimed-command"])
        case.certify("unclaimed-command", "unclaimed.qc")
    finally:
        case.cleanup()
    states = s.close(unclaimed=True)
    cases.append(s.report("unclaimed", states))
    execution = {"schema_version": 1, "passed": True, "cases": executions}
    validate_execution(execution)
    report = {"schema_version": 1, "passed": True, "cases": cases, "execution": execution,
              "source_manifest": config["source_manifest"], "binaries": config["expected_binaries"]}
    report["summary"] = validate(report); publish_report(args.out, report)
    print("custody_serve_complete " + json.dumps(report["summary"], sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
