#!/usr/bin/env python3
"""Exercise the opt-in V2 admission coordinator on two original test hosts.

No target Prepare/Execute or execution-network setup is called. Every admission
signature, vote and commit uses a reviewed standalone CLI process. This does
not test or claim mandatory admission enforcement in raw V2 execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from run import ZERO, fields, require
from serve import broken
from v1 import publish_report
from v2 import Case, artifact, digest, once, transfer

CLI = "work-archive-custody-v2-admission"
MAX_PUBLIC_BYTES = 8 * 1024 * 1024
CHECKS = {
    "sources_initially_zero", "genesis_cli_matches_public_context", "two_votes_not_quorum",
    "duplicate_vote_not_quorum", "lost_witness_vote_exact_cold_retry",
    "lost_witness_commit_exact_cold_retry", "all_witnesses_same_assignment_position",
    "active_job_refuses_second_admit", "refused_second_admit_wrote_no_vote",
    "stale_pins_refused", "original_sources_and_identities_unchanged",
    "no_execution_or_source_append", "active_job_still_held",
}


def encode_uvarint(value):
    require(type(value) is int and 0 <= value < 1 << 64, "invalid unsigned length")
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128); value >>= 7
    out.append(value)
    return bytes(out)


def read_field(raw, offset):
    start, length = offset, 0
    for index in range(10):
        require(offset < len(raw), "truncated canonical length")
        byte = raw[offset]; offset += 1
        require(index != 9 or byte <= 1, "canonical length overflow")
        length |= (byte & 127) << (7 * index)
        if byte < 128:
            require(raw[start:offset] == encode_uvarint(length), "noncanonical length")
            require(length <= MAX_PUBLIC_BYTES and offset + length <= len(raw), "public field exceeds bound")
            end = offset + length
            return raw[offset:end], raw[start:end], end
    require(False, "unterminated canonical length")


def genesis_from_context(raw):
    # Public preparation only: preserve the exact assignment/manifest/initial
    # field encodings and policy tail from the signed canonical Context. The
    # actual CLI independently validates Context and must emit identical bytes.
    require(type(raw) is bytes and len(raw) <= MAX_PUBLIC_BYTES and raw[:10] == b"OMCVCTX2\0\2", "wrong V2 context")
    values, encoded, offset = [], [], 10
    for _ in range(5):
        value, field, offset = read_field(raw, offset); values.append(value); encoded.append(field)
    tail = raw[offset:]
    require(len(tail) >= 26, "truncated custody policy")
    auditors = struct.unpack(">H", tail[24:26])[0]
    require(auditors <= 64 and len(tail) == 26 + 32 * auditors, "wrong custody policy framing")
    require(values[0][:10] == b"OMCVASG2\0\2" and values[3] == values[4], "genesis requires the initial predecessor")
    return b"OMCVAGN2\0\2" + encoded[0] + encoded[2] + encoded[3] + tail


def hash_array(value):
    require(type(value) is list and len(value) == 32 and
            all(type(byte) is int and 0 <= byte <= 255 for byte in value), "invalid Go JSON hash array")
    return bytes(value).hex()


def uint(value, bits=64):
    require(type(value) is int and 0 <= value < 1 << bits, "invalid unsigned JSON counter")
    return value


def decode_snapshot(raw):
    value = json.loads(raw)
    require(type(value) is dict and value.get("CoordinatorOnly") is True and value.get("ExecutionGranted") is False,
            "snapshot overstated execution authority")
    snapshot, pin = value.get("Snapshot"), value.get("Pin")
    require(type(snapshot) is dict and type(pin) is dict, "missing coordinator snapshot or pin")
    position = snapshot.get("Position"); before = pin.get("Position")
    require(type(position) is dict and type(before) is dict, "missing coordinator position")
    seq, head = uint(position.get("Sequence")), hash_array(position.get("HeadID"))
    require(seq == uint(before.get("Sequence")) and head == hash_array(before.get("HeadID")), "snapshot/pin position differs")
    receipt = snapshot.get("CurrentReceipt")
    require(type(receipt) is dict, "missing retained current receipt")
    retain = uint(snapshot.get("RetainUntil"))
    receipt_retain = uint(receipt.get("RetainUntil"))
    require(retain >= receipt_retain > 0, "coordinator lost archive retention")
    return {"genesis_id": hash_array(snapshot.get("GenesisID")), "sequence": seq, "head": head,
            "pending_id": hash_array(pin.get("PendingID")),
            "spent_operations": uint(snapshot.get("SpentOperations"), 32),
            "pending_operations": uint(snapshot.get("PendingOperations"), 16),
            "active_context_id": hash_array(snapshot.get("ActiveContextID")),
            "active_plan_id": hash_array(snapshot.get("ActivePlanID")),
            "source_sequence": uint(snapshot.get("SourceSequence")),
            "source_head": hash_array(snapshot.get("SourceHeadID")),
            "source_receipt_id": hash_array(snapshot.get("SourceReceiptID")),
            "retain_until": retain, "coordinator_only": True, "execution_granted": False,
            "status_artifact": artifact(raw)}


def entry_id(raw):
    require(len(raw) >= 147 and raw[:10] == b"OMCVAEN2\0\2", "wrong admission entry")
    return digest("OMESH/custody/v2/admission/entry/id", raw)


class Admission:
    def __init__(self, case):
        self.case, self.a, self.b = case, case.a, case.b
        self.expected_genesis = genesis_from_context(self.a.read("context"))
        self.gid = digest("OMESH/custody/v2/admission/genesis/id", bytes.fromhex(case.public["AssignmentID"]))
        self.did = digest("OMESH/custody/v2/admission/genesis/descriptor", self.expected_genesis)
        self.checks, self.artifacts, self.members = {}, [], []

    def args(self, host, action, extra=()):
        result = [CLI, "--action", action, "--genesis-id", self.gid, "--genesis-descriptor-id", self.did]
        if action != "genesis": result += ["--genesis", host.root + "/admission-genesis"]
        return result + list(extra)

    def act(self, host, action, extra=(), fail=False, lose=False, require_review=False):
        args = self.args(host, action, extra)
        result = once(host, args, check=not fail)
        if fail and result.returncode != 0:
            require(not require_review, "valid admission input failed before current-state check")
            return result
        reviewed = fields(result.stdout.decode(), "custody_v2_admission_review")
        require(reviewed.get("keys_loaded") == reviewed.get("owners_opened") == "false" and
                reviewed.get("coordinator_only") == "true" and reviewed.get("execution_granted") == "false",
                "admission review loaded an owner/key or granted execution")
        args += ["--mode", "run", "--expected-review-id", reviewed["review_id"]]
        if lose:
            broken(host, args)
        else:
            result = once(host, args, check=not fail)
            if fail:
                require(result.returncode != 0, "invalid admission transition succeeded")
                return result
            emitted = fields(result.stdout.decode(), "custody_v2_admission_artifact")
            require(emitted.get("coordinator_only") == "true" and emitted.get("execution_granted") == "false",
                    "admission output claimed execution authority")
        path = extra[list(extra).index("--out") + 1]
        raw = host.read(path[len(host.root) + 1:])
        self.artifacts.append({"host": "a" if host.root == self.a.root else "b", "path": path,
                               "sha256": hashlib.sha256(raw).hexdigest(), "artifact_id": artifact(raw)})

    def ip(self, host, name):
        return ["--in", host.root + "/" + name, "--in-id", artifact(host.read(name))]

    def context(self, host):
        return ["--context", host.root + "/context", "--context-id", self.case.public["ContextID"]]

    def member_args(self, index, sequence, head, pending):
        host = self.a if index < 2 else self.b
        return host, ["--root", host.root + "/admission-witness-%d" % index,
                      "--witness", self.case.public["Members"][index]["signing_public_key"],
                      "--sign-key", host.root + "/keys/witness-%d.seed" % index,
                      "--sequence", str(sequence), "--head-id", head, "--pending-id", pending]

    def run(self):
        a, b, case = self.a, self.b, self.case
        before = {role: case.inspect(h) for role, h in (("a", a), ("b", b), ("clone", case.clone))}
        require(all(s["source_sequence"] == 0 and not any(s[k] for k in ("consumed", "result", "accepted")) for s in before.values()), "fixture performed an effect")
        self.checks["sources_initially_zero"] = True
        self.act(a, "genesis", self.context(a) + ["--out", a.root + "/admission-genesis"])
        require(a.read("admission-genesis") == self.expected_genesis, "CLI genesis differs from the pinned public descriptor")
        self.checks["genesis_cli_matches_public_context"] = True
        transfer(a, b, "admission-genesis")
        self.act(a, "admit-entry", self.context(a) + ["--sequence", "0", "--head-id", self.gid,
                 "--sign-key", a.root + "/keys/authority.seed", "--out", a.root + "/admission-entry"])
        self.eid = entry_id(a.read("admission-entry")); transfer(a, b, "admission-entry")
        vote_paths, vote_ids = [], []
        for i in range(4):
            host, common = self.member_args(i, 0, self.gid, ZERO)
            prefix = host.root + "/admission-witness-%d" % i
            self.act(host, "witness-create", common + ["--out", prefix + "-created"])
            initial = decode_snapshot(host.read("admission-witness-%d-created" % i))
            self.act(host, "witness-vote", common + self.ip(host, "admission-entry") + ["--out", prefix + "-vote"], lose=(i == 2))
            self.act(host, "witness-vote", common + self.ip(host, "admission-entry") + ["--out", prefix + "-vote-recovered"])
            name = "admission-witness-%d-vote" % i
            raw = host.read(name)
            require(raw == host.read(name + "-recovered") and len(raw) == 138 and raw[:10] == b"OMCVAVT2\0\2" and
                    raw[10:42].hex() == self.eid and raw[42:74].hex() == case.public["Members"][i]["signing_public_key"],
                    "cold vote retry changed selected entry or signer")
            if i >= 2: transfer(host, a, name)
            vote_paths.append(a.root + "/" + name); vote_ids.append(artifact(a.read(name)))
            self.members.append({"member": i, "host": "a" if i < 2 else "b", "signing_public_key": case.public["Members"][i]["signing_public_key"],
                                 "initial": initial, "before_vote": {"sequence": 0, "head": self.gid, "pending": ZERO},
                                 "before_commit": {"sequence": 0, "head": self.gid, "pending": self.eid}})
        self.checks["lost_witness_vote_exact_cold_retry"] = True
        cert_base = self.ip(a, "admission-entry")
        for paths, ids, label in ((vote_paths[:2], vote_ids[:2], "weak"), ([vote_paths[0]] * 3, [vote_ids[0]] * 3, "duplicate")):
            self.act(a, "certificate", cert_base + ["--votes", ",".join(paths), "--vote-ids", ",".join(ids), "--out", a.root + "/admission-" + label], fail=True)
        self.checks["two_votes_not_quorum"] = self.checks["duplicate_vote_not_quorum"] = True
        self.act(a, "certificate", cert_base + ["--votes", ",".join(vote_paths[:3]), "--vote-ids", ",".join(vote_ids[:3]), "--out", a.root + "/admission-certificate"])
        transfer(a, b, "admission-certificate")
        for i in range(4):
            host, common = self.member_args(i, 0, self.gid, self.eid)
            prefix = host.root + "/admission-witness-%d" % i
            self.act(host, "witness-commit", common + self.ip(host, "admission-certificate") + ["--out", prefix + "-committed"], lose=(i == 1))
            self.act(host, "witness-commit", common + self.ip(host, "admission-certificate") + ["--out", prefix + "-commit-recovered"])
            require(host.read("admission-witness-%d-committed" % i) == host.read("admission-witness-%d-commit-recovered" % i), "cold commit recovery changed snapshot")
        self.checks["lost_witness_commit_exact_cold_retry"] = True
        self.act(a, "admit-entry", self.context(a) + ["--sequence", "1", "--head-id", self.eid,
                 "--sign-key", a.root + "/keys/authority.seed", "--out", a.root + "/admission-second-entry"])
        require(entry_id(a.read("admission-second-entry")) != self.eid, "second entry did not select the new position")
        transfer(a, b, "admission-second-entry")
        host, common = self.member_args(2, 1, self.eid, ZERO)
        refused = self.act(host, "witness-vote", common + self.ip(host, "admission-second-entry") + ["--out", host.root + "/admission-invalid-second-vote"], fail=True, require_review=True)
        require(b"active job" in refused.stderr, "second admission did not fail on its active job")
        self.checks["active_job_refuses_second_admit"] = True
        host, stale = self.member_args(0, 0, self.gid, ZERO)
        refused = self.act(host, "witness-status", stale + ["--out", host.root + "/admission-stale-status"], fail=True, require_review=True)
        require(b"position differs" in refused.stderr, "stale status did not fail on its position")
        self.checks["stale_pins_refused"] = True
        for i in range(4):
            host, common = self.member_args(i, 1, self.eid, ZERO)
            name = "admission-witness-%d-final" % i
            self.act(host, "witness-status", common + ["--out", host.root + "/" + name])
            self.members[i]["final"] = decode_snapshot(host.read(name))
            marker = host.execute(["python3", "-c", "import os,sys;print(int(os.path.exists(sys.argv[1])))", host.root + "/admission-witness-%d/00000002.vote" % i]).stdout.strip()
            require(marker == b"0", "refused admission left a position-two vote")
        self.checks["refused_second_admit_wrote_no_vote"] = True
        self.checks["all_witnesses_same_assignment_position"] = True
        after = {role: case.inspect(h) for role, h in (("a", a), ("b", b), ("clone", case.clone))}
        require(all({k: v for k, v in before[role].items() if k != "now"} == {k: v for k, v in after[role].items() if k != "now"} for role in before), "coordinator altered original source/owner")
        self.checks["original_sources_and_identities_unchanged"] = True
        self.checks["no_execution_or_source_append"] = True
        self.checks["active_job_still_held"] = True
        report = {"schema_version": 1, "passed": True, "assignment_id": case.public["AssignmentID"], "context_id": case.public["ContextID"],
                  "plan_id": case.public["PlanID"], "genesis_id": self.gid, "descriptor_id": self.did, "entry_id": self.eid,
                  "authority_public_key": case.public["Keys"]["authority"], "members": self.members,
                  "sources_before": before, "sources_after": after, "checks": self.checks, "artifacts": self.artifacts,
                  "roots": {"a": a.root, "b": b.root}, "observed_kernel_boot_sha256": case.boots,
                  "coordinator_only": True, "execution_granted": False, "runtime_admission_enforced": False,
                  "independent_four_domain_deployment": False, "budget_exhaustion_tested": False}
        return report


def validate(report):
    require(report.get("schema_version") == 1 and report.get("passed") is True and report.get("cleanup_complete") is True, "incomplete admission coordinator campaign")
    require(report.get("coordinator_only") is True and report.get("execution_granted") is False and
            report.get("runtime_admission_enforced") is False and report.get("independent_four_domain_deployment") is False and
            report.get("budget_exhaustion_tested") is False, "campaign overstated execution, budget or deployment guarantees")
    for key in ("assignment_id", "context_id", "plan_id", "genesis_id", "descriptor_id", "entry_id", "authority_public_key"):
        require(type(report.get(key)) is str and re.fullmatch("[0-9a-f]{64}", report[key]) and report[key] != ZERO, "missing canonical admission ID/key")
    require(report["genesis_id"] == digest("OMESH/custody/v2/admission/genesis/id", bytes.fromhex(report["assignment_id"])), "genesis namespace changed")
    require(CHECKS <= report.get("checks", {}).keys() and all(v is True for v in report["checks"].values()), "missing or failed coordinator check")
    boots = report.get("observed_kernel_boot_sha256", {})
    require(set(boots) == {"a", "b"} and boots["a"] != boots["b"], "two observed kernels required")
    members = report.get("members", [])
    require(len(members) == 4 and {m["member"] for m in members} == set(range(4)) and len({m["signing_public_key"] for m in members}) == 4, "incomplete distinct witness roster")
    for member in members:
        require(member["host"] == ("a" if member["member"] < 2 else "b"), "witness host placement changed")
        require(re.fullmatch("[0-9a-f]{64}", member["signing_public_key"]) and member["signing_public_key"] != ZERO, "invalid witness key")
        require(member["before_vote"] == {"sequence": 0, "head": report["genesis_id"], "pending": ZERO} and
                member["before_commit"] == {"sequence": 0, "head": report["genesis_id"], "pending": report["entry_id"]}, "independent witness pin changed")
        for label in ("initial", "final"):
            s = member[label]; active = label == "final"
            require(s["genesis_id"] == report["genesis_id"] and s["sequence"] == int(active) and
                    s["head"] == (report["entry_id"] if active else report["genesis_id"]) and s["pending_id"] == ZERO and
                    s["spent_operations"] == s["pending_operations"] == (2 if active else 0) and
                    s["active_context_id"] == (report["context_id"] if active else ZERO) and
                    s["active_plan_id"] == (report["plan_id"] if active else ZERO) and
                    s["source_sequence"] == 0 and s["source_head"] == ZERO and s["source_receipt_id"] != ZERO and
                    s["retain_until"] > 0 and s["coordinator_only"] is True and s["execution_granted"] is False,
                    "incorrect coordinator reservation/position/source")
        require(member["initial"]["retain_until"] == member["final"]["retain_until"] and
                member["initial"]["source_receipt_id"] == member["final"]["source_receipt_id"], "admission changed retention/source receipt")
    require(len({m["final"]["source_receipt_id"] for m in members}) == 1 and len({m["final"]["retain_until"] for m in members}) == 1, "witness source anchors diverged")
    for role in ("a", "b", "clone"):
        before, after = report["sources_before"][role], report["sources_after"][role]
        require(before["source_sequence"] == after["source_sequence"] == 0 and before["source_head"] == after["source_head"] == ZERO and
                before["original_identities_sha256"] == after["original_identities_sha256"] and
                before["receipt_id"] == after["receipt_id"] == members[0]["final"]["source_receipt_id"] and
                not any(after[k] for k in ("consumed", "result", "accepted")), "coordinator changed original source or owner")
    return {"joint_hosts": 2, "logical_witnesses": 4, "committed_admissions": 1, "spent_operations": 2,
            "pending_operations": 2, "source_appends": 0, "execution_granted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True); parser.add_argument("--out", required=True)
    args = parser.parse_args(); config = json.loads(Path(args.config).read_text())
    case = Case(config, "lost-session")
    try:
        print("custody_admission_start", flush=True)
        report = Admission(case).run()
    finally:
        case.cleanup()
    require(case.cleanup_complete, "admission fixture cleanup incomplete")
    report.update(source_manifest=config["source_manifest"], binaries=config["expected_binaries"], cleanup_complete=True)
    report["summary"] = validate(report)
    publish_report(args.out, report)
    print("custody_admission_complete " + json.dumps(report["summary"], sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
