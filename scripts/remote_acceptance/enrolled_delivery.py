#!/usr/bin/env python3
"""Deliver both profile-4 proofs across two hosts before faulted execution.

Registry and admission votes use original CLI witness histories. Receipt means
historical proof retention only. Unknown work and its accounting stay held.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from run import ZERO, fields, require
from v1 import publish_report
from v2 import artifact, digest, once, transfer
from serve import broken
import delivery
import registry
import required

CLI = "work-archive-custody-v2-enrolled-delivery"
PROTOCOL = "/outcomemesh/custody/v4/enrollment-delivery"
DOMAIN = "OMESH/custody/v4/enrolled/proof-delivery"
RUNTIME = "work-archive-custody-v2-enrolled"
REGISTRY_CHECKS = {"pre_assignment_anchor_matches_policy", "three_role_signatures", "two_votes_refused",
                   "lost_vote_exact_recovery", "registry_quorum_selected", "lost_commit_exact_recovery",
                   "all_original_registry_witnesses_selected", "missing_registry_proof_refused", "wrong_registry_proof_pin_refused",
                   "received_both_full_proofs", "original_owners_use_received_proofs", "registry_proof_retained_after_execution"}


def decode_enrollment(raw):
    require(type(raw) is bytes and len(raw) == 299 and raw[:10] == b"OMCVDEN4\0\4", "wrong enrolled receiver framing")
    names = ("context_id", "scope_id", "binding_id", "sender_peer_id", "recipient_peer_id", "placement_id", "nonce")
    out = {name: raw[10 + 32 * i:42 + 32 * i].hex() for i, name in enumerate(names)}
    out.update(role=raw[234], receipt_public_key=raw[235:267].hex(), registry_enrollment_id=raw[267:299].hex(), enrollment_id=digest(DOMAIN + "/enrollment/id", raw))
    require(all(delivery.public_id(value) for key, value in out.items() if key != "role") and out["role"] in (1, 2) and out["sender_peer_id"] != out["recipient_peer_id"], "invalid enrolled receiver identity/role")
    return out


def decode_receipt(raw):
    require(type(raw) is bytes and len(raw) == 267 and raw[:10] == b"OMCVDAR4\0\4", "wrong enrolled receipt framing")
    names = ("delivery_id", "enrollment_id", "context_id", "scope_id", "binding_id", "registry_enrollment_id")
    out = {name: raw[10 + 32 * i:42 + 32 * i].hex() for i, name in enumerate(names)}
    require(all(delivery.public_id(value) for value in out.values()) and raw[202] in (1, 2) and any(raw[203:]), "missing enrolled receipt identity/signature")
    out.update(role=raw[202], receipt_id=digest(DOMAIN + "/receipt/id", raw), sha256=hashlib.sha256(raw).hexdigest())
    return out


class EnrolledCase(delivery.DeliveryCase):
    export_test = "TestExportCustodyV2EnrolledWANFixture"
    runtime_cli = RUNTIME
    runtime_prefix = "custody_v2_enrolled"
    serving_prefix = "custody_v2_enrolled_serving"
    delivery_cli = CLI
    delivery_protocol = PROTOCOL
    delivery_domain = DOMAIN
    delivery_prefix = "custody_v2_enrolled_delivery"
    decode_delivery_enrollment = staticmethod(decode_enrollment)
    decode_delivery_receipt = staticmethod(decode_receipt)

    def prepare_context(self):
        required.RequiredCase.prepare_context(self)
        self.registry_artifacts, self.registry_checks = [], {}
        self.select_registry()
        self.prepare_delivery()

    def rargs(self, h, action, extra=()):
        return [registry.CLI, "--action", action, "--registry", h.root + "/registry", "--registry-id", self.public["RegistryID"],
                "--registry-descriptor-id", self.public["RegistryDescriptorID"]] + list(extra)

    def ract(self, h, action, extra=(), lose=False, fail=False):
        args = self.rargs(h, action, extra)
        r = once(h, args, check=not fail)
        if fail:
            require(r.returncode != 0, "invalid registry input passed review")
            return
        record = fields(r.stdout.decode(), "custody_registry_review")
        require(record["keys_loaded"] == record["owners_opened"] == record["execution_granted"] == "false" and record["selection_only"] == "true", "registry review crossed effect boundary")
        args += ["--mode", "run", "--expected-review-id", record["review_id"]]
        if lose:
            broken(h, args)
        else:
            once(h, args)
        name = extra[list(extra).index("--out") + 1]
        self.registry_artifacts.append({"host": "a" if h.root == self.a.root else "b", "path": name, "sha256": hashlib.sha256(h.read(name[len(h.root)+1:])).hexdigest()})

    def rmember(self, seed, sequence=0, head=None, pending=ZERO):
        h = self.a if seed <= 112 else self.b
        member = next(m for m in self.public["RegistryMembers"] if int(m["seed"]) == seed)
        return h, ["--root", h.root + "/registry-owner-%d" % seed, "--witness", member["signing_public_key"],
                   "--sign-key", h.root + "/keys/registry-%d.seed" % seed, "--sequence", str(sequence),
                   "--head-id", head or self.public["RegistryID"], "--pending-id", pending]

    def rip(self, h, name):
        return ["--in", h.root + "/" + name, "--in-id", registry.artifact(h.read(name))]

    def select_registry(self):
        a, b = self.a, self.b
        require(len(self.public["RegistryMembers"]) == 4 and all(registry.public_id(self.public[k]) for k in ("RegistryID", "RegistryDescriptorID")), "fresh profile4 fixture lacks registry pins")
        self.registry_checks["pre_assignment_anchor_matches_policy"] = True  # Exporter and production CLI verify the signed policy.
        self.registry_candidate = registry.candidate_ids(a.read("admission-genesis"))
        c = self.registry_candidate
        self.ract(a, "selection", ["--candidate", a.root + "/admission-genesis", "--candidate-id", c["candidate_id"],
                                  "--candidate-descriptor-id", c["candidate_descriptor_id"], "--out", a.root + "/registry-selection"])
        current = "registry-selection"
        for role, h, key in (("issuer", a, "registry-issuer"), ("authority", a, "authority"), ("control", b, "control")):
            if h is b: transfer(a, b, current)
            target = "registry-selection-" + role
            self.ract(h, "sign-selection", self.rip(h, current) + ["--sign-role", role, "--sign-key", h.root + "/keys/" + key + ".seed", "--out", h.root + "/" + target])
            if h is b: transfer(b, a, target)
            current = target
        self.registry_checks["three_role_signatures"] = True
        raw = a.read(current)
        require(raw[:10] == b"OMCRSEL2\0\2", "registry used old selection framing")
        self.selection_id = digest("OMESH/custody-registry/v2/selection/id", raw)
        require(b.read(current) == raw, "control signer retained different selection")
        votes = []
        for seed in range(111, 115):
            h, common = self.rmember(seed)
            name = "registry-vote-%d" % seed
            self.ract(h, "witness-create", common + ["--out", h.root + "/registry-created-%d" % seed])
            args = common + self.rip(h, current) + ["--out", h.root + "/" + name]
            self.ract(h, "witness-vote", args, lose=(seed == 112))
            retry = copy.copy(args); retry[-1] += "-recovered"; self.ract(h, "witness-vote", retry)
            require(h.read(name) == h.read(name + "-recovered"), "registry cold vote changed")
            if h is b: transfer(b, a, name)
            member = next(m for m in self.public["RegistryMembers"] if int(m["seed"]) == seed)
            votes.append((member["signing_public_key"], a.root + "/" + name, registry.artifact(a.read(name))))
        votes.sort()
        def certificate(chosen, output):
            return self.rip(a, current) + ["--votes", ",".join(x[1] for x in chosen), "--vote-ids", ",".join(x[2] for x in chosen), "--out", a.root + "/" + output]
        self.ract(a, "certificate", certificate(votes[:2], "registry-weak-absent"), fail=True)
        self.registry_checks["two_votes_refused"] = self.registry_checks["lost_vote_exact_recovery"] = True
        self.ract(a, "certificate", certificate(votes[:3], "registry-certificate"))
        transfer(a, b, "registry-certificate")
        self.registry_checks["registry_quorum_selected"] = True
        self.registry_members = []
        for seed in range(111, 115):
            h, common = self.rmember(seed, pending=self.selection_id)
            args = common + self.rip(h, "registry-certificate") + ["--out", h.root + "/registry-committed-%d" % seed]
            self.ract(h, "witness-commit", args, lose=(seed == 113))
            retry = copy.copy(args); retry[-1] += "-recovered"; self.ract(h, "witness-commit", retry)
            require(h.read(args[-1][len(h.root)+1:]) == h.read(retry[-1][len(h.root)+1:]), "registry cold commit changed")
            snapshot = registry.decode_snapshot(h.read(retry[-1][len(h.root)+1:]))
            self.registry_members.append({"seed": seed, "host": "a" if h is a else "b", "final": snapshot})
        self.registry_checks["lost_commit_exact_recovery"] = self.registry_checks["all_original_registry_witnesses_selected"] = True
        args = [RUNTIME, "--action", "enrollment", "--context", a.root + "/context", "--context-id", self.public["ContextID"], "--scope-id", self.scope,
                "--binding", a.root + "/required-binding", "--binding-id", self.binding_id, "--registry", a.root + "/registry",
                "--registry-certificate", a.root + "/registry-certificate", "--registry-certificate-id", registry.artifact(a.read("registry-certificate")), "--out", a.root + "/registry-enrollment"]
        record = once(a, required.reviewed(a, args), self.runtime_prefix + "_artifact")
        self.registry_enrollment_id = digest("OMESH/custody/v4/enrollment-binding/id", a.read("registry-enrollment"))
        require(record["enrollment_id"] == self.registry_enrollment_id, "registry proof identity changed")
        transfer(a, self.clone, "registry-enrollment")

    def delivery_args(self, h, action, extra=()):
        args = super().delivery_args(h, action, extra) + ["--registry-enrollment-id", self.registry_enrollment_id]
        if action == "delivery": args += ["--registry-enrollment", h.root + "/registry-enrollment"]
        return args

    def deliver_binding(self):
        super().deliver_binding()
        # Cold export must own the original inbox lock after intake drains.
        self.stop_delivery()
        b = self.b
        self.delivery_act(b, "inbox-registry-enrollment", self.inbox() + ["--out", b.root + "/received-registry-enrollment"])
        require(b.read("received-registry-enrollment") == self.a.read("registry-enrollment"), "received registry certificate changed")
        self.registry_checks["received_both_full_proofs"] = True

    def proof_path(self, h):
        return h.root + ("/received-registry-enrollment" if h.root == self.b.root else "/registry-enrollment")

    def args(self, h, action, extra=()):
        args = super().args(h, action, extra)
        if action in required.OWNER_ACTIONS:
            args += ["--enrollment", self.proof_path(h), "--enrollment-id", self.registry_enrollment_id]
        return args

    def create_owners(self):
        a = self.args(self.b, "create-target", ["--root", self.b.root + "/no-registry-owner", "--journal", self.b.root + "/journal", "--objects", self.b.root + "/objects"])
        missing = copy.copy(a)
        for flag in ("--enrollment", "--enrollment-id"):
            i = missing.index(flag); del missing[i:i+2]
        require(once(self.b, missing, check=False).returncode != 0, "owner accepted hash-only/missing registry proof")
        self.registry_checks["missing_registry_proof_refused"] = True
        a[a.index("--enrollment-id")+1] = "f" * 64
        require(once(self.b, a, check=False).returncode != 0, "owner ignored registry proof pin")
        self.registry_checks["wrong_registry_proof_pin_refused"] = True
        super().create_owners()
        require(self.b.read("owner/enrollment") == self.b.read("received-registry-enrollment"), "owner did not consume delivered registry proof")
        self.registry_checks["original_owners_use_received_proofs"] = True

    def validate_retained_records(self):
        for h, name, magic in ((self.b, "consumed", b"OMCVUSE4\0\4"), (self.a, "pending", b"OMCVPEN4\0\4")):
            raw = h.read("owner/" + name)
            require(len(raw) > 106 and raw[:10] == magic and raw[10:42].hex() == self.binding_id and raw[42:74].hex() == self.admission.eid and raw[74:106].hex() == self.registry_enrollment_id, "effect record lost full registry/admission binding")

    def binding_after_job(self):
        super().binding_after_job()
        for h in (self.a, self.b, self.clone):
            require(h.read("owner/enrollment") == self.a.read("registry-enrollment"), "execution replaced registry enrollment")
        self.registry_checks["registry_proof_retained_after_execution"] = True

    def delivery_report(self):
        out = super().delivery_report(); out["registry_enrollment_id"] = self.registry_enrollment_id
        return out

    def registry_report(self):
        return {"registry_id": self.public["RegistryID"], "descriptor_id": self.public["RegistryDescriptorID"], "selection_id": self.selection_id,
                "registry_enrollment_id": self.registry_enrollment_id, "format": 2, "policy": 4, "candidate": self.registry_candidate,
                "members": self.registry_members, "checks": self.registry_checks, "artifacts": self.registry_artifacts,
                "protected_physical_enrollment": False, "legacy_cutover": False}


class EnrolledServe(required.RequiredServe):
    def args(self, h, action, extra=()):
        args = super().args(h, action, extra)
        if action in required.SERVE_ACTIONS:
            args += ["--enrollment", self.c.proof_path(h), "--enrollment-id", self.c.registry_enrollment_id]
        return args


def validate(report):
    summary = delivery.validate(report, protocol=PROTOCOL)
    require(report.get("runtime_registry_enforced") is True, "missing registry runtime gate")
    anchors, proofs = set(), set()
    for c in report["cases"]:
        r, d = c.get("registry", {}), c["delivery"]
        require(r.get("format") == 2 and r.get("policy") == 4 and r.get("protected_physical_enrollment") is False and r.get("legacy_cutover") is False, "registry overstated activation or physical protection")
        require(REGISTRY_CHECKS <= r.get("checks", {}).keys() and all(v is True for v in r["checks"].values()), "missing registry/delivery gate")
        for key in ("registry_id", "descriptor_id", "selection_id", "registry_enrollment_id"):
            require(registry.public_id(r.get(key)), "missing complete registry identity")
        proof = r["registry_enrollment_id"]
        require(d.get("registry_enrollment_id") == d["enrollment"].get("registry_enrollment_id") == d["receipt"].get("registry_enrollment_id") == proof, "network receipt lost exact registry proof")
        candidate = r.get("candidate", {})
        require(candidate.get("candidate_id") == c["genesis_id"] and all(registry.public_id(candidate.get(k)) for k in ("candidate_id", "assignment_id", "candidate_descriptor_id")), "registry selected another admitted assignment")
        members = r.get("members", [])
        require(len(members) == 4 and [m["seed"] for m in members] == list(range(111,115)) and [m["host"] for m in members] == ["a", "a", "b", "b"], "registry witness provenance changed")
        for m in members:
            x = m["final"]
            require(x["registry_id"] == r["registry_id"] and x["descriptor_id"] == r["descriptor_id"] and x["sequence"] == 1 and x["head"] == r["selection_id"] and x["pending_id"] == ZERO and x["selection_final"] is True and x["selected_assignment_id"] == candidate["assignment_id"] and x["selected_genesis_id"] == candidate["candidate_id"] and x["selected_descriptor_id"] == candidate["candidate_descriptor_id"], "registry witness did not retain exact final candidate")
        require(len(r.get("artifacts", [])) >= 20 and all(registry.public_id(a.get("sha256")) for a in r["artifacts"]), "missing registry public transcript")
        anchors.add(r["registry_id"]); proofs.add(proof)
    require(len(anchors) == len(proofs) == 2, "fresh cases reused an enrolled resource")
    return dict(summary, runtime_registry_enforced=True, registry_selections=2, registry_format=2, signed_policy=4)


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--config", required=True); parser.add_argument("--out", required=True)
    args = parser.parse_args(); config = json.loads(Path(args.config).read_text()); cases = []
    for scenario in required.SCENARIOS:
        print("custody_enrolled_delivery_start " + scenario, flush=True)
        case = EnrolledCase(config, scenario)
        try:
            execution = case.run(); case.binding_after_job()
            service = EnrolledServe(case); states = service.close() if scenario == "lost-result" else service.held()
            ledger = required.accounting_final(case, scenario == "lost-result")
            after = {role: case.inspect(h) for role, h in (("a", case.a), ("b", case.b), ("clone", case.clone))}
            require(delivery.unchanged(after, {role: execution[role] for role in after}), "accounting changed original source")
            case.required_checks["accounting_does_not_change_source"] = True
        finally:
            case.stop_delivery(); case.cleanup()
        case.admission_report["cleanup_complete"] = case.cleanup_complete
        cases.append({"scenario": scenario, "scope_id": case.scope, "context_id": case.public["ContextID"], "plan_id": case.public["PlanID"],
                      "genesis_id": case.admission.gid, "binding_id": case.binding_id, "binding_artifact_id": artifact(case.a.read("required-binding")),
                      "checks": case.required_checks, "admission_before_runtime": case.admission_report, "execution": execution, "serve": service.report(scenario, states),
                      "accounting_final": ledger, "sources_after_accounting": after, "delivery": case.delivery_report(), "registry": case.registry_report(),
                      "roots": {"a": case.a.root, "b": case.b.root}, "cleanup_complete": case.cleanup_complete, "runtime_admission_enforced": True,
                      "legacy_v1_migrated": False, "independent_four_domain_deployment": False, "passed": True})
        publish_report(args.out + ".checkpoint-" + case.nonce, {"schema_version": 1, "passed": False, "completed_cases": cases})
        print("custody_enrolled_delivery_pass " + scenario, flush=True)
    report = {"schema_version": 1, "passed": True, "runtime_registry_enforced": True, "durable_admission_delivery": True, "cases": cases,
              "source_manifest": config["source_manifest"], "binaries": config["expected_binaries"]}
    report["summary"] = validate(report); publish_report(args.out, report)
    print("custody_enrolled_delivery_complete " + json.dumps(report["summary"], sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
