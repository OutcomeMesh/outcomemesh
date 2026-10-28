#!/usr/bin/env python3
"""Select one registry candidate through real reviewed CLI owners on two hosts.

This operator-channel campaign creates only fresh registry witness roots. It
never starts custody work, imports a legacy owner or claims protected enrollment.
Public deterministic fixture keys are not deployment or failure-domain evidence.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from admission import hash_array, read_field, uint
from run import Host, ZERO, fields, require
from serve import broken
from v1 import publish_report
from v2 import digest, install_fresh, once, transfer


CLI = "work-archive-custody-registry"
DOMAIN = "OMESH/custody-registry/v1/"
CHECKS = {
    "unstarted_fixture_original_roots", "registry_cli_matches_pinned_descriptor",
    "distributed_issuer_authority_control_signatures", "two_votes_not_quorum",
    "duplicate_vote_not_quorum", "lost_vote_output_exact_cold_retry",
    "retained_vote_refuses_other_assignment", "majority_certificate_verified",
    "minority_vote_retained_after_majority_commit", "lost_commit_output_exact_cold_retry",
    "all_witnesses_same_final_choice", "selected_registry_refuses_new_assignment",
    "stale_position_refused", "external_descriptor_pin_refused",
    "changed_descriptor_same_registry_refused", "refusals_leave_original_records_unchanged",
    "no_execution_owner_or_source_created",
}
EFFECT_PATHS = ("owner", "target", "acceptor", "journal", "objects", "authority", "authority-pins")


def public_id(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) and value != ZERO


def artifact(raw):
    return digest(DOMAIN + "cli/artifact/id", raw)


def selection_id(raw):
    require(type(raw) is bytes and 266 <= len(raw) <= 8 << 20 and raw[:10] == b"OMCRSEL1\0\1", "wrong registry selection framing")
    return digest(DOMAIN + "selection/id", raw)


def candidate_ids(raw):
    require(type(raw) is bytes and raw[:10] == b"OMCVAGN2\0\2", "wrong candidate genesis framing")
    assignment, _, _ = read_field(raw, 10)
    require(assignment[:10] == b"OMCVASG2\0\2", "wrong outer candidate assignment")
    aid = digest("OMESH/custody/v2/assignment/id", assignment)
    return {"assignment_id": aid,
            "candidate_id": digest("OMESH/custody/v2/admission/genesis/id", bytes.fromhex(aid)),
            "candidate_descriptor_id": digest("OMESH/custody/v2/admission/genesis/descriptor", raw)}


def decode_snapshot(raw):
    value = json.loads(raw)
    require(type(value) is dict and value.get("SelectionOnly") is True and value.get("ExecutionGranted") is False and
            value.get("LegacyCutover") is False, "registry status overstated activation or execution")
    snapshot, pin = value.get("Snapshot"), value.get("Pin")
    require(type(snapshot) is dict and type(pin) is dict, "missing registry snapshot or pin")
    position, external = snapshot.get("Position"), pin.get("Position")
    require(type(position) is dict and type(external) is dict, "missing registry position")
    sequence, head = uint(position.get("Sequence")), hash_array(position.get("HeadID"))
    require(sequence <= 1 and sequence == uint(external.get("Sequence")) and head == hash_array(external.get("HeadID")), "registry snapshot/pin position mismatch")
    final = snapshot.get("SelectionFinal")
    require(type(final) is bool and final == (sequence == 1), "invalid final registry state")
    result = {"registry_id": hash_array(snapshot.get("RegistryID")), "descriptor_id": hash_array(snapshot.get("DescriptorID")),
              "sequence": sequence, "head": head, "pending_id": hash_array(pin.get("PendingID")),
              "selected_assignment_id": hash_array(snapshot.get("SelectedAssignmentID")),
              "selected_genesis_id": hash_array(snapshot.get("SelectedGenesisID")),
              "selected_descriptor_id": hash_array(snapshot.get("SelectedDescriptorID")),
              "maximum_operations": uint(snapshot.get("MaximumOperations"), 32),
              "maximum_pending": uint(snapshot.get("MaximumPending"), 16),
              "selection_final": final, "selection_only": True, "execution_granted": False,
              "legacy_cutover": False, "status_artifact": artifact(raw)}
    require(public_id(result["registry_id"]) and public_id(result["descriptor_id"]) and public_id(head) and
            0 < result["maximum_pending"] <= result["maximum_operations"], "invalid registry identity or policy cap")
    if final:
        require(result["pending_id"] == ZERO and all(public_id(result[k]) for k in ("selected_assignment_id", "selected_genesis_id", "selected_descriptor_id")), "selected registry lost complete candidate identity")
    else:
        require(head == result["registry_id"] and all(result[k] == ZERO for k in ("selected_assignment_id", "selected_genesis_id", "selected_descriptor_id")), "initial registry invented a selected candidate")
    return result


class Campaign:
    def __init__(self, config):
        self.config, self.checks, self.artifacts, self.members = config, {}, [], []
        self.nonce = uuid.uuid4().hex
        self.hosts, self.boots = {}, {}
        for name in ("a", "b"):
            selected = dict(config["hosts"][name]); selected["root"] += "/" + self.nonce
            h = self.hosts[name] = Host(selected)
            for path, expected in ((h.binary, config["expected_binaries"]["omd"]), (h.test_binary, config["expected_binaries"]["omd.test"])):
                require(h.sha256(path) == expected, "native registry binary pin changed")
            require(h.sha256(h.config["support"]) == config["support_sha256"], "support source pin changed")
            self.boots[name] = hashlib.sha256(h.execute(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()).hexdigest()
        require(self.boots["a"] != self.boots["b"], "two distinct observed kernels required")
        self.a, self.b = self.hosts["a"], self.hosts["b"]
        parent = config["export_parent"] + "/" + self.nonce
        self.a.execute(["mkdir", "-p", "-m", "700", parent])
        cwd = config.get("test_cwd")
        require(type(cwd) is str and os.path.isabs(cwd), "explicit native fixture test_cwd required")
        wrapper = "import os,sys;os.chdir(sys.argv[1]);os.execv(sys.argv[2],sys.argv[2:])"
        output = self.a.execute(["python3", "-c", wrapper, cwd, self.a.test_binary,
                                 "-test.run=^TestExportCustodyRegistryFixture$", "-test.count=1", "-test.v"],
                                {"OUTCOMEMESH_REMOTE_FIXTURE_OUT": parent}).stdout.decode()
        matches = re.findall(r"custody_registry_fixture root=(\S+) roots_created=false", output)
        require(len(matches) == 1, "missing unstarted registry fixture export")
        for role, h in self.hosts.items(): install_fresh(self.a, matches[0] + "/" + role, h)
        self.public = json.loads(self.a.read("public.json"))
        require(self.public == json.loads(self.b.read("public.json")) and self.public.get("OwnersCreated") is False and
                self.public.get("SelectionOnly") is True and self.public.get("ExecutionGranted") is False and self.public.get("TestKeysPublic") is True,
                "fixture contains an owner or overstated execution")
        self.gid, self.did = self.public["RegistryID"], self.public["RegistryDescriptorID"]
        self.cap = json.loads(self.a.read("registry-draft.json"))
        self.candidate = candidate_ids(self.a.read("candidate")); self.other = candidate_ids(self.a.read("candidate-other"))
        require(self.candidate["candidate_id"] == self.public["CandidateID"] and self.candidate["candidate_descriptor_id"] == self.public["CandidateDescriptorID"] and
                self.other["candidate_id"] == self.public["OtherCandidateID"] and self.other["candidate_descriptor_id"] == self.public["OtherCandidateDescriptorID"] and
                self.candidate["assignment_id"] != self.other["assignment_id"], "fixture candidate semantic pin changed")
        self.before_effects = self.inspect_effects()
        require(all(not any(values.values()) for values in self.before_effects.values()), "fixture created a source or execution owner")
        self.checks["unstarted_fixture_original_roots"] = True

    def inspect_effects(self):
        script = "import json,os,sys;print(json.dumps({n:os.path.exists(sys.argv[1]+'/'+n) for n in sys.argv[2:]}))"
        return {role: json.loads(h.execute(["python3", "-c", script, h.root] + list(EFFECT_PATHS)).stdout) for role, h in self.hosts.items()}

    def args(self, h, action, extra=(), registry="registry", descriptor=None):
        result = [CLI, "--action", action, "--registry-id", self.gid, "--registry-descriptor-id", descriptor or self.did]
        if action != "genesis": result += ["--registry", h.root + "/" + registry]
        return result + list(extra)

    def act(self, h, action, extra=(), fail=False, lose=False, require_review=False, registry="registry", descriptor=None):
        args = self.args(h, action, extra, registry, descriptor)
        result = once(h, args, check=not fail)
        if fail and result.returncode != 0:
            require(not require_review, "valid public registry input failed before retained-state check")
            return
        review = fields(result.stdout.decode(), "custody_registry_review")
        require(review["keys_loaded"] == review["owners_opened"] == review["execution_granted"] == review["legacy_cutover"] == "false" and
                review["selection_only"] == "true", "registry review crossed execution or private-key boundary")
        args += ["--mode", "run", "--expected-review-id", review["review_id"]]
        if lose:
            broken(h, args)
        else:
            result = once(h, args, check=not fail)
            if fail:
                require(result.returncode != 0, "invalid registry action succeeded")
                return
            emitted = fields(result.stdout.decode(), "custody_registry_artifact")
            require(emitted["selection_only"] == "true" and emitted["execution_granted"] == emitted["legacy_cutover"] == "false", "registry output overstated execution")
        name = extra[list(extra).index("--out") + 1]
        self.track(h, name[len(h.root) + 1:])

    def track(self, h, name):
        raw = h.read(name)
        self.artifacts.append({"host": "a" if h.root == self.a.root else "b", "path": h.root + "/" + name,
                               "sha256": hashlib.sha256(raw).hexdigest(), "artifact_id": artifact(raw)})

    def ip(self, h, name):
        return ["--in", h.root + "/" + name, "--in-id", artifact(h.read(name))]

    def member(self, seed, sequence=0, head=None, pending=ZERO):
        record = next(m for m in self.public["Members"] if m["seed"] == seed)
        h = self.hosts[record["host"]]
        return h, ["--root", h.root + "/witness-" + str(seed), "--witness", record["public"],
                   "--sign-key", h.root + "/keys/%d.seed" % seed, "--sequence", str(sequence),
                   "--head-id", head or self.gid, "--pending-id", pending]

    def sign_candidate(self, other=False):
        name = "selection-other" if other else "selection"
        candidate = self.other if other else self.candidate
        filename = "candidate-other" if other else "candidate"
        self.act(self.a, "selection", ["--candidate", self.a.root + "/" + filename,
                 "--candidate-id", candidate["candidate_id"], "--candidate-descriptor-id", candidate["candidate_descriptor_id"],
                 "--out", self.a.root + "/" + name + "-unsigned"])
        source = name + "-unsigned"
        for role, seed in (("issuer", 110), ("authority", 1)):
            target = name + "-" + role
            self.act(self.a, "sign-selection", self.ip(self.a, source) + ["--sign-role", role, "--sign-key", self.a.root + "/keys/%d.seed" % seed, "--out", self.a.root + "/" + target])
            source = target
        transfer(self.a, self.b, source)
        self.act(self.b, "sign-selection", self.ip(self.b, source) + ["--sign-role", "control", "--sign-key", self.b.root + "/keys/14.seed", "--out", self.b.root + "/" + name])
        transfer(self.b, self.a, name)
        return selection_id(self.a.read(name))

    def records(self):
        result = {}
        for member in self.public["Members"]:
            seed = member["seed"]; h, _ = self.member(seed)
            result[str(seed)] = {name: hashlib.sha256(h.read("witness-%d/%s" % (seed, name))).hexdigest() for name in ("selection.vote", "selection.certificate")}
        return result

    def run(self):
        a, b = self.a, self.b
        self.act(a, "genesis", ["--draft", a.root + "/registry-draft.json", "--out", a.root + "/registry"])
        require(digest(DOMAIN + "descriptor/id", a.read("registry")) == self.did, "registry CLI changed pinned descriptor")
        transfer(a, b, "registry"); self.checks["registry_cli_matches_pinned_descriptor"] = True
        self.sid, self.other_sid = self.sign_candidate(), self.sign_candidate(other=True)
        require(self.sid != self.other_sid, "different candidates selected the same artifact")
        self.checks["distributed_issuer_authority_control_signatures"] = True
        vote_names = []
        for seed in range(111, 115):
            h, common = self.member(seed); initial_name = "witness-%d-created" % seed
            self.act(h, "witness-create", common + ["--out", h.root + "/" + initial_name])
            initial = decode_snapshot(h.read(initial_name))
            choice, selected = ("selection-other", self.other_sid) if seed == 114 else ("selection", self.sid)
            vote_name = "witness-%d-vote" % seed
            args = common + self.ip(h, choice) + ["--out", h.root + "/" + vote_name]
            self.act(h, "witness-vote", args, lose=seed == 113)
            self.act(h, "witness-vote", common + self.ip(h, choice) + ["--out", h.root + "/" + vote_name + "-recovered"])
            raw = h.read(vote_name)
            require(raw == h.read(vote_name + "-recovered") and len(raw) == 202 and raw[:10] == b"OMCRVOT1\0\1" and
                    raw[10:42].hex() == self.gid and raw[42:74].hex() == self.did and raw[74:106].hex() == selected and
                    raw[106:138].hex() == next(m["public"] for m in self.public["Members"] if m["seed"] == seed), "cold vote changed exact registry/choice/member")
            if seed < 114:
                if h is not a: transfer(h, a, vote_name)
                vote_names.append(vote_name)
            self.members.append({"seed": seed, "host": "a" if h is a else "b", "signing_public_key": raw[106:138].hex(),
                                 "initial": initial, "before_commit": {"sequence": 0, "head": self.gid, "pending": selected}})
        self.checks["lost_vote_output_exact_cold_retry"] = True
        for seed in (111, 112, 113):
            # Use the original zero-pending position so public preflight is
            # valid. Refusal must come from the original retained vote, rather
            # than a mismatched pending ID supplied by this controller.
            h, common = self.member(seed)
            self.act(h, "witness-vote", common + self.ip(h, "selection-other") + ["--out", h.root + "/refused-other-vote-%d" % seed], fail=True, require_review=True)
        self.checks["retained_vote_refuses_other_assignment"] = True
        vote_names.sort(key=lambda name: a.read(name)[106:138])
        def quorum(names, target, fail=False):
            self.act(a, "certificate", self.ip(a, "selection") + ["--votes", ",".join(a.root + "/" + name for name in names),
                     "--vote-ids", ",".join(artifact(a.read(name)) for name in names), "--out", a.root + "/" + target], fail=fail)
        quorum(vote_names[:2], "refused-weak-certificate", fail=True); self.checks["two_votes_not_quorum"] = True
        quorum([vote_names[0], vote_names[0], vote_names[1]], "refused-duplicate-certificate", fail=True); self.checks["duplicate_vote_not_quorum"] = True
        quorum(vote_names, "certificate"); transfer(a, b, "certificate")
        self.checks["majority_certificate_verified"] = True
        for member in self.members:
            seed = member["seed"]; pending = member["before_commit"]["pending"]
            h, common = self.member(seed, pending=pending); name = "witness-%d-committed" % seed
            self.act(h, "witness-commit", common + self.ip(h, "certificate") + ["--out", h.root + "/" + name], lose=seed == 114)
            self.act(h, "witness-commit", common + self.ip(h, "certificate") + ["--out", h.root + "/" + name + "-recovered"])
            require(h.read(name) == h.read(name + "-recovered"), "cold commit changed exact selected snapshot")
            h, final_args = self.member(seed, 1, self.sid)
            final_name = "witness-%d-final" % seed
            self.act(h, "witness-status", final_args + ["--out", h.root + "/" + final_name])
            member["final"] = decode_snapshot(h.read(final_name))
        self.checks["lost_commit_output_exact_cold_retry"] = True
        self.checks["all_witnesses_same_final_choice"] = True
        require(b.read("witness-114/selection.vote") == b.read("selection-other") and b.read("witness-114/selection.certificate") == b.read("certificate"), "majority commit discarded minority record")
        self.checks["minority_vote_retained_after_majority_commit"] = True
        original = self.records()
        for seed in range(111, 115):
            # A vote names the original unselected slot. The selected original
            # owner must reject that before-position and the other assignment;
            # sequence 1 is deliberately not a valid new vote request.
            h, common = self.member(seed)
            self.act(h, "witness-vote", common + self.ip(h, "selection-other") + ["--out", h.root + "/refused-selected-vote-%d" % seed], fail=True, require_review=True)
            h, stale = self.member(seed)
            self.act(h, "witness-status", stale + ["--out", h.root + "/refused-stale-%d" % seed], fail=True, require_review=True)
        self.checks["selected_registry_refuses_new_assignment"] = self.checks["stale_position_refused"] = True
        h, common = self.member(111, 1, self.sid)
        self.act(h, "witness-status", common + ["--out", h.root + "/refused-foreign-descriptor"], fail=True, descriptor="f" * 64)
        self.checks["external_descriptor_pin_refused"] = True
        changed = copy.deepcopy(self.cap); changed["MaximumOperations"] += 1
        a.write("registry-changed-draft.json", (json.dumps(changed) + "\n").encode())
        args = [CLI, "--action", "genesis", "--draft", a.root + "/registry-changed-draft.json", "--out", a.root + "/registry-changed"]
        review = fields(once(a, args).stdout.decode(), "custody_registry_review")
        require(review["registry_id"] == self.gid and review["registry_descriptor_id"] != self.did, "changed policy reset the resource namespace")
        once(a, args + ["--mode", "run", "--expected-review-id", review["review_id"]]); self.track(a, "registry-changed")
        self.changed_did = digest(DOMAIN + "descriptor/id", a.read("registry-changed"))
        require(self.changed_did == review["registry_descriptor_id"], "changed descriptor semantic pin changed")
        self.act(a, "witness-status", common + ["--out", a.root + "/refused-changed-descriptor"], fail=True, require_review=True,
                 registry="registry-changed", descriptor=self.changed_did)
        self.checks["changed_descriptor_same_registry_refused"] = True
        require(self.records() == original, "refused operation changed original vote or certificate")
        self.original_records = original; self.checks["refusals_leave_original_records_unchanged"] = True
        self.after_effects = self.inspect_effects()
        require(self.before_effects == self.after_effects and all(not any(values.values()) for values in self.after_effects.values()), "registry selection created an execution source or owner")
        self.checks["no_execution_owner_or_source_created"] = True
        return self.report()

    def report(self):
        return {"schema_version": 1, "passed": True, "cleanup_complete": True,
                "registry_id": self.gid, "descriptor_id": self.did, "changed_descriptor_id": self.changed_did,
                "selection_id": self.sid, "other_selection_id": self.other_sid,
                "candidate": self.candidate, "other_candidate": self.other,
                "maximum_operations": self.cap["MaximumOperations"], "maximum_pending": self.cap["MaximumPending"],
                "members": self.members, "checks": self.checks, "artifacts": self.artifacts,
                "original_records": self.original_records, "effects_before": self.before_effects, "effects_after": self.after_effects,
                "observed_kernel_boot_sha256": self.boots, "roots": {role: h.root for role, h in self.hosts.items()},
                "source_manifest": self.config["source_manifest"], "binaries": self.config["expected_binaries"],
                "selection_only": True, "execution_granted": False, "legacy_cutover": False, "operator_channel": True,
                "runtime_registry_enforced": False, "protected_physical_enrollment": False, "services_started": 0,
                "independent_four_domain_deployment": False, "alternate_qc_subset_tested": False, "no_live_owner_transferred": True}


def validate(report):
    require(report.get("schema_version") == 1 and report.get("passed") is True and report.get("cleanup_complete") is True, "incomplete registry campaign")
    require(report.get("selection_only") is True and report.get("execution_granted") is False and report.get("legacy_cutover") is False and
            report.get("operator_channel") is True and report.get("runtime_registry_enforced") is False and report.get("protected_physical_enrollment") is False and
            report.get("independent_four_domain_deployment") is False and report.get("services_started") == 0 and
            report.get("alternate_qc_subset_tested") is False and report.get("no_live_owner_transferred") is True, "registry campaign overstated deployment or permission")
    for key in ("registry_id", "descriptor_id", "changed_descriptor_id", "selection_id", "other_selection_id", "source_manifest"):
        require(public_id(report.get(key)), "missing registry public identity")
    require(report["descriptor_id"] != report["changed_descriptor_id"] and report["selection_id"] != report["other_selection_id"], "descriptor/candidate identity conflated")
    checks = report.get("checks", {})
    require(CHECKS <= checks.keys() and all(value is True for value in checks.values()), "missing registry acceptance check")
    candidate, other = report.get("candidate", {}), report.get("other_candidate", {})
    require(set(candidate) == set(other) == {"assignment_id", "candidate_id", "candidate_descriptor_id"} and
            all(public_id(value) for value in list(candidate.values()) + list(other.values())) and
            candidate["assignment_id"] != other["assignment_id"] and candidate["candidate_id"] != other["candidate_id"], "missing distinct candidate identities")
    for c in (candidate, other):
        require(digest("OMESH/custody/v2/admission/genesis/id", bytes.fromhex(c["assignment_id"])) == c["candidate_id"], "candidate semantic genesis is not assignment-derived")
    caps = (uint(report.get("maximum_operations"), 32), uint(report.get("maximum_pending"), 16))
    require(0 < caps[1] <= caps[0], "invalid registry caps")
    members = report.get("members", [])
    require(len(members) == 4 and [m.get("seed") for m in members] == list(range(111, 115)) and
            [m.get("host") for m in members] == ["a", "a", "b", "b"] and
            len({m.get("signing_public_key") for m in members}) == 4 and all(public_id(m.get("signing_public_key")) for m in members), "registry witness roles or unique members changed")
    for member in members:
        initial, final, before = member.get("initial", {}), member.get("final", {}), member.get("before_commit", {})
        expected_pending = report["other_selection_id"] if member["seed"] == 114 else report["selection_id"]
        require(before == {"sequence": 0, "head": report["registry_id"], "pending": expected_pending}, "minority or before-commit pin changed")
        for snapshot in (initial, final):
            require(snapshot.get("registry_id") == report["registry_id"] and snapshot.get("descriptor_id") == report["descriptor_id"] and
                    snapshot.get("maximum_operations") == caps[0] and snapshot.get("maximum_pending") == caps[1] and
                    snapshot.get("selection_only") is True and snapshot.get("execution_granted") is False and snapshot.get("legacy_cutover") is False and
                    public_id(snapshot.get("status_artifact")), "registry snapshot descriptor/cap/permission changed")
        require(initial.get("sequence") == 0 and initial.get("head") == report["registry_id"] and initial.get("pending_id") == ZERO and
                initial.get("selection_final") is False and all(initial.get(k) == ZERO for k in ("selected_assignment_id", "selected_genesis_id", "selected_descriptor_id")), "initial registry was already selected")
        require(final.get("sequence") == 1 and final.get("head") == report["selection_id"] and final.get("pending_id") == ZERO and final.get("selection_final") is True and
                final.get("selected_assignment_id") == candidate["assignment_id"] and final.get("selected_genesis_id") == candidate["candidate_id"] and
                final.get("selected_descriptor_id") == candidate["candidate_descriptor_id"], "terminal registry choice differs")
    boots = report.get("observed_kernel_boot_sha256", {})
    require(set(boots) == {"a", "b"} and all(public_id(value) for value in boots.values()) and boots["a"] != boots["b"], "two observed kernels missing")
    require(report.get("effects_before") == report.get("effects_after") and set(report.get("effects_before", {})) == {"a", "b"} and
            all(set(values) == set(EFFECT_PATHS) and all(value is False for value in values.values()) for values in report["effects_before"].values()), "selection created or modified execution sources/owners")
    records = report.get("original_records", {})
    require(set(records) == {str(seed) for seed in range(111, 115)} and all(set(value) == {"selection.vote", "selection.certificate"} and
            all(public_id(sha) for sha in value.values()) for value in records.values()), "original retained record pins missing")
    require(len({value["selection.certificate"] for value in records.values()}) == 1 and
            len({records[str(seed)]["selection.vote"] for seed in (111, 112, 113)}) == 1 and
            records["114"]["selection.vote"] != records["111"]["selection.vote"], "minority proposal or exact majority certificate not preserved")
    artifacts = report.get("artifacts", [])
    require(len(artifacts) >= 25 and {a.get("host") for a in artifacts} == {"a", "b"} and
            all(type(a.get("path")) is str and public_id(a.get("sha256")) and public_id(a.get("artifact_id")) for a in artifacts) and
            len({(a["host"], a["path"]) for a in artifacts}) == len(artifacts), "incomplete public registry artifacts")
    binaries = report.get("binaries", {})
    require(set(binaries) == {"omd", "omd.test"} and all(public_id(value) for value in binaries.values()), "missing native binary provenance")
    return {"joint_hosts": 2, "logical_witnesses": 4, "selected_assignments": 1,
            "retained_minority_votes": 1, "source_appends": 0, "execution_granted": False, "legacy_cutover": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True); parser.add_argument("--out", required=True)
    args = parser.parse_args()
    campaign = Campaign(json.loads(Path(args.config).read_text()))
    report = campaign.run(); report["summary"] = validate(report)
    publish_report(args.out, report)
    print("custody_registry_complete " + json.dumps(report["summary"], sort_keys=True), flush=True)


if __name__ == "__main__": main()
