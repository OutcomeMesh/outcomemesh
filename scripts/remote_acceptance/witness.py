#!/usr/bin/env python3
"""Controlled four-member witness acceptance on two original Linux hosts.

Each host runs two independent logical member journals. This tests wire/CLI
behavior and outages, not four independent failure domains or protected keys.
Fixtures use public deterministic test keys. Original V1 custody roots are unused.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid

from run import AcceptanceError, Host, Supervisor, digest_id, fields, require, ZERO
from v1 import close_supervisor, publish_report

PREFIX = "work-archive-custody-witness"


def once(host, args, prefix=None, check=True):
    result = host.execute([host.binary] + args, timeout=30, check=check)
    return fields(result.stdout.decode(), prefix) if prefix else result


def review(host, args):
    return digest_id(once(host, args, "custody_witness_review")["review_id"])


def response_pin(raw, scope, member, request):
    require(raw[:8] == b"OMCFWS00" and raw[8:10] == b"\0\0" and len(raw) >= 319, "wrong response format")
    obs = raw[10:318]
    require(obs[:10] == b"OMCFOB00\0\0" and obs[10:42].hex() == request and
            obs[42:74].hex() == member and obs[74:106].hex() == scope, "response changed request/member/scope")
    return {"sequence": struct.unpack(">Q", obs[106:114])[0], "head": obs[114:146].hex(),
            "pending": obs[146:178].hex(), "phase": obs[178], "held": obs[243] == 1}


class Member:
    def __init__(self, controller, index):
        self.c, self.index = controller, index
        self.h = controller.hosts["a" if index < 2 else "b"]
        self.metadata = controller.public["members"][index]
        self.root = self.h.root + "/member-" + str(index)
        self.pin = {"sequence": 0, "head": controller.scope, "pending": ZERO}
        self.supervisor, self.address = None, None

    def args(self, pin=None):
        p = pin or self.pin
        args = [PREFIX, "--scope", self.h.root + "/scope", "--scope-id", self.c.scope,
                "--root", self.root, "--witness-public-key", self.metadata["signing_public_key"],
                "--expected-sequence", str(p["sequence"]), "--expected-head", p["head"],
                "--sign-key", self.h.root + "/sign-" + str(self.index),
                "--transport-key", self.h.root + "/transport-" + str(self.index),
                "--transport-public-key", self.metadata["transport_public_key"],
                "--clients", self.c.public["client_peer_id"], "--timeout", "5s",
                "--listen", "/ip4/0.0.0.0/udp/%d/quic-v1" % self.c.config["ports"][self.index]]
        if p["pending"] != ZERO:
            args += ["--pending-id", p["pending"]]
        return args

    def create(self):
        args = self.args() + ["--mode", "create-review"]
        pin = review(self.h, args)
        args[args.index("create-review")] = "create"
        once(self.h, args + ["--expected-review-id", pin], "custody_witness_state")

    def start(self):
        args = self.args()
        pin = review(self.h, args)
        self.supervisor = Supervisor(self.h, {"witness": {"argv": [self.h.binary] + args + [
            "--mode", "serve", "--expected-review-id", pin]}})
        ready = self.supervisor.start("witness", "custody_witness_serving")
        require(ready["scope_id"] == self.c.scope and ready["witness_public_key"] == self.metadata["signing_public_key"], "wrong original member started")
        self.address = "/ip4/%s/udp/%d/quic-v1/p2p/%s" % (
            self.h.config["public_ip"], self.c.config["ports"][self.index], ready["address"].rsplit("/p2p/", 1)[1])

    def stop(self, kill=False):
        if self.supervisor is None:
            return
        supervisor, self.supervisor = self.supervisor, None
        try:
            if kill:
                supervisor.rpc("kill", name="witness")
                require(supervisor.rpc("wait", name="witness", timeout=15)["returncode"] == -9, "expected native SIGKILL")
            else:
                supervisor.stop("witness")
        finally:
            close_supervisor(supervisor)

    def inspect(self):
        result = once(self.h, self.args())
        text = result.stdout.decode()
        require(fields(text, "custody_witness_review")["keys_loaded"] == "false", "review loaded signing keys")
        context = json.loads(text.split("\nscope:\n", 1)[1])["Context"]
        x = context["Snapshot"]
        return {"sequence": x["Position"]["Sequence"], "head": bytes(x["Position"]["HeadID"]).hex(),
                "phase": x["Phase"], "held": x["ObligationHeld"], "pending": self.pin["pending"]}


class Controller:
    def __init__(self, config):
        self.config, self.events = config, []
        nonce = uuid.uuid4().hex
        self.hosts = {}
        self.provenance = {}
        for name in ("a", "b"):
            selected = dict(config["hosts"][name])
            selected["root"] += "/" + nonce
            h = Host(selected)
            h.execute(["python3", "-c", "import os,sys; os.makedirs(os.path.dirname(sys.argv[1]),mode=0o700,exist_ok=True); os.mkdir(sys.argv[1],0o700)", h.root])
            for binary in ("omd", "omd.test"):
                path = h.binary if binary == "omd" else h.test_binary
                require(h.sha256(path) == config["expected_binaries"][binary], "unpinned native binary")
            self.provenance[name] = hashlib.sha256(h.execute(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()).hexdigest()
            self.hosts[name] = h
        require(self.provenance["a"] != self.provenance["b"], "two distinct observed kernels required")
        a = self.hosts["a"]
        parent = config["export_parent"] + "/" + nonce
        a.execute(["mkdir", "-m", "700", "-p", parent])
        export = a.execute([a.test_binary, "-test.run=^TestExportWitnessNetworkFixture$", "-test.count=1", "-test.v"],
                           {"OMESH_WITNESS_EXPORT_PARENT": parent}).stdout.decode()
        matches = re.findall(r"witness_fixture_path=(\S+)", export)
        require(len(matches) == 1, "test fixture export missing")
        fixture = matches[0]
        self.public = json.loads(a.execute(["cat", fixture + "/public.json"]).stdout)
        self.scope = digest_id(self.public["scope_id"])
        require(self.public["opaque_result_is_not_custody_proof"] is True, "fixture misrepresented result evidence")
        for h in self.hosts.values():
            h.write("scope", a.execute(["cat", fixture + "/scope"]).stdout)
        for i in range(4):
            h = self.hosts["a" if i < 2 else "b"]
            for source, target in (("sign.seed", "sign-"), ("transport.seed", "transport-")):
                h.write(target + str(i), a.execute(["cat", fixture + "/" + str(i) + "/" + source]).stdout)
        for name in self.public["commands"]:
            a.write(name, a.execute(["cat", fixture + "/" + name]).stdout)
        a.write("client.seed", a.execute(["cat", fixture + "/client.seed"]).stdout)
        self.members = [Member(self, i) for i in range(4)]
        try:
            for member in self.members:
                member.create()
                member.start()
        except BaseException:
            for member in self.members:
                try:
                    member.stop()
                except (AcceptanceError, OSError):
                    pass  # stop always closes its supervisor in finally
            raise

    def call(self, member, command=None, cert=None, before=None, fail=False):
        a = self.hosts["a"]
        p = dict(before or member.pin)
        nonce = uuid.uuid4().hex
        request, response = "request-" + nonce, "response-" + nonce
        args = [PREFIX + "-request", "--scope", a.root + "/scope", "--scope-id", self.scope,
                "--expected-sequence", str(p["sequence"]), "--expected-head", p["head"], "--nonce", hashlib.sha256(nonce.encode()).hexdigest(),
                "--out", a.root + "/" + request]
        if p["pending"] != ZERO:
            args += ["--pending-id", p["pending"]]
        if command:
            args += ["--kind", "vote", "--command", a.root + "/" + command,
                     "--command-id", self.public["commands"][command]]
        else:
            args += ["--kind", "commit", "--certificate", a.root + "/" + cert["file"], "--certificate-id", cert["id"]]
        rid = review(a, args)
        published = once(a, args + ["--mode", "publish", "--expected-review-id", rid], "custody_witness_artifact")
        call = [PREFIX + "-call", "--scope", a.root + "/scope", "--scope-id", self.scope,
                "--witness-public-key", member.metadata["signing_public_key"], "--request", a.root + "/" + request,
                "--request-id", published["request_id"], "--transport-key", a.root + "/client.seed",
                "--transport-public-key", self.public["client_public_key"],
                "--server-transport-public-key", member.metadata["transport_public_key"],
                "--peer", member.address, "--timeout", "2s", "--out", a.root + "/" + response]
        approved = review(a, call)
        # Retain the full exact request and before pin independently before RPC.
        self.events.append({"member": member.index, "before": p, "request_id": published["request_id"],
                            "command": command, "certificate": cert["id"] if cert else None, "completed": False})
        a.write("attempt-" + nonce + ".json", json.dumps(self.events[-1], sort_keys=True).encode())
        result = once(a, call + ["--mode", "exchange", "--expected-review-id", approved], check=False)
        if fail:
            require(result.returncode != 0 and b"unconfirmed" in result.stderr, "request was not refused through the selected endpoint")
            self.events[-1]["refused"] = True
            return None
        require(result.returncode == 0, "witness call failed: " + result.stderr.decode()[-2048:])
        record = fields(result.stdout.decode(), "custody_witness_artifact")
        pin = response_pin(a.read(response), self.scope, member.metadata["signing_public_key"], published["request_id"])
        member.pin = {key: pin[key] for key in ("sequence", "head", "pending")}
        self.events[-1].update(completed=True, after=pin, response_sha256=hashlib.sha256(a.read(response)).hexdigest())
        return {"request": a.root + "/" + request, "response": a.root + "/" + response,
                "artifact_id": record["artifact_id"], "pin": pin}

    def quorum(self, command, replies, fail=False):
        a = self.hosts["a"]
        nonce = uuid.uuid4().hex
        pairs = "pairs-" + nonce
        a.write(pairs, json.dumps([{k: r[k] for k in ("request", "response")} for r in replies]).encode())
        args = [PREFIX + "-quorum", "--scope", a.root + "/scope", "--scope-id", self.scope,
                "--pairs", a.root + "/" + pairs, "--command-id", self.public["commands"][command]]
        if fail:
            require(once(a, args, check=False).returncode != 0, "insufficient/duplicate witness set formed a quorum")
            return None
        rid = review(a, args)
        output = "certificate-" + nonce
        record = once(a, args + ["--mode", "publish", "--expected-review-id", rid, "--out", a.root + "/" + output], "custody_witness_artifact")
        return {"file": output, "id": digest_id(record["artifact_id"])}

    def run(self):
        members = self.members
        initial = dict(members[0].pin)
        members[0].stop()
        members[1].stop()
        pair = [self.call(members[i], command="claim") for i in (2, 3)]
        self.quorum("claim", pair, fail=True)
        # One host's two logical members are unavailable. Two votes cannot
        # become a grant; one returning member restores the 3/4 quorum.
        members[0].start()
        third = self.call(members[0], command="claim")
        self.quorum("claim", [pair[0], pair[0], third], fail=True)
        claim = self.quorum("claim", pair + [third])
        for i in (0, 2, 3):
            before = dict(members[i].pin)
            self.call(members[i], cert=claim)
            self.call(members[i], cert=claim, before=before)  # exact transition retry
        members[1].start()
        self.call(members[1], cert=claim)  # minority catches up only by a quorum
        unknown = self.quorum("unknown", [self.call(members[i], command="unknown") for i in (0, 1, 2)])
        for member in members:
            self.call(member, cert=unknown)
        members[2].stop(kill=True)
        old = once(members[2].h, members[2].args(initial), check=False)
        require(old.returncode != 0, "cold restart adopted a stale position")
        observed = members[2].inspect()
        require(observed["phase"] == 2 and observed["held"] and observed["sequence"] == 2, "unknown outcome did not survive kill")
        members[2].start()
        self.call(members[2], command="claim", before=initial, fail=True)
        self.call(members[2], command="conflict", before=initial, fail=True)
        result = self.quorum("result", [self.call(members[i], command="result") for i in (0, 2, 3)])
        for member in members:
            self.call(member, cert=result)
        for member in members:
            member.stop()
        final = [member.inspect() for member in members]
        report = {"schema_version": 1, "scope_id": self.scope, "members": 4, "threshold": 3,
                  "logical_members_per_host": [2, 2], "observed_kernel_boot_sha256": self.provenance,
                  "source_manifest": self.config["source_manifest"], "binaries": self.config["expected_binaries"],
                  "two_member_outage_refused": True, "duplicate_member_refused": True,
                  "one_member_outage_quorum_passed": True, "commit_exact_retries": 3,
                  "unknown_sigkill_retained": True, "stale_cold_pin_refused": True,
                  "late_claim_refused": True, "unclaimed_close_after_unknown_refused": True,
                  "final": final, "events": self.events, "result_commitment_is_opaque": True,
                  "commands": self.public["commands"], "certificates": {"claim": claim["id"], "unknown": unknown["id"], "result": result["id"]},
                  "current_custody_source_acceptance_checked": False, "independent_four_host_deployment": False,
                  "controller_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "passed": True}
        validate(report)
        return report


def validate(report):
    require(report["schema_version"] == 1 and report["members"] == 4 and report["threshold"] == 3 and
            report["logical_members_per_host"] == [2, 2] and report["passed"] is True, "wrong witness campaign")
    digest_id(report["scope_id"])
    require(set(report["observed_kernel_boot_sha256"]) == {"a", "b"} and
            digest_id(report["observed_kernel_boot_sha256"]["a"]) != digest_id(report["observed_kernel_boot_sha256"]["b"]), "two observed kernels required")
    for field in ("two_member_outage_refused", "duplicate_member_refused", "one_member_outage_quorum_passed",
                  "unknown_sigkill_retained", "stale_cold_pin_refused", "late_claim_refused", "unclaimed_close_after_unknown_refused"):
        require(report[field] is True, "witness gate missing: " + field)
    require(report["commit_exact_retries"] == 3 and report["result_commitment_is_opaque"] is True and
            report["current_custody_source_acceptance_checked"] is False and report["independent_four_host_deployment"] is False,
            "wire acceptance claimed a stronger deployment/result boundary")
    require(len(report["final"]) == 4, "member outcome missing")
    heads = set()
    for state in report["final"]:
        require(state["sequence"] == 3 and state["phase"] == 3 and state["held"] is True and state["pending"] == ZERO,
                "result released obligation or lost a member's history")
        heads.add(digest_id(state["head"]))
    require(len(heads) == 1, "members ended on different certified histories")
    commands, certificates = report["commands"], report["certificates"]
    require(set(commands) == {"claim", "unknown", "result", "conflict"} and
            set(certificates) == {"claim", "unknown", "result"}, "missing independently selected command/certificate pins")
    for value in list(commands.values()) + list(certificates.values()):
        digest_id(value)
    require(len(set(commands.values())) == 4 and len(set(certificates.values())) == 3, "mixed transition pins")
    tracked = [{"sequence": 0, "head": report["scope_id"], "pending": ZERO} for _ in range(4)]
    completed, refused, retries = 0, 0, 0
    request_ids = set()
    for event in report["events"]:
        member = event["member"]
        require(isinstance(member, int) and 0 <= member < 4, "wrong member in event history")
        current, before = tracked[member], event["before"]
        request_id = digest_id(event["request_id"])
        require(request_id not in request_ids, "request event counted twice")
        request_ids.add(request_id)
        if not event["completed"]:
            require(event.get("refused") is True and event["command"] in ("claim", "conflict") and
                    before == {"sequence": 0, "head": report["scope_id"], "pending": ZERO} and
                    current["sequence"] == 2 and current["head"] == commands["unknown"], "unexplained or incorrectly scoped refusal")
            refused += 1
            continue
        completed += 1
        after = event["after"]
        digest_id(event["request_id"])
        digest_id(event["response_sha256"])
        if event["command"]:
            name = event["command"]
            require(name in ("claim", "unknown", "result") and before == current and
                    after["sequence"] == before["sequence"] and after["head"] == before["head"] and
                    after["pending"] == commands[name], "vote changed committed history or used another pending proposal")
        else:
            names = [name for name, pin in certificates.items() if pin == event["certificate"]]
            require(len(names) == 1, "unknown committed certificate")
            name = names[0]
            sequence = {"claim": 1, "unknown": 2, "result": 3}[name]
            require(after["sequence"] == sequence and after["head"] == commands[name] and
                    after["pending"] == ZERO and after["held"] is True, "commit lost immutable result or remaining hold")
            if before != current:
                require(current["sequence"] == sequence and current["head"] == commands[name] and
                        before["sequence"] == sequence - 1 and before["pending"] == commands[name], "unexpected historical retry")
                retries += 1
        tracked[member] = {key: after[key] for key in ("sequence", "head", "pending")}
    require(completed == 24 and refused == 2 and retries == 3 and
            all(state["sequence"] == 3 and state["head"] == commands["result"] and state["pending"] == ZERO for state in tracked),
            "incomplete member transition/retry evidence")
    return {"members": 4, "kernel_count": 2, "final_sequence": 3, "obligations_held": 4, "passed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    controller = Controller(json.loads(args.config.read_text()))
    try:
        report = controller.run()
        publish_report(args.out, report)
        print(json.dumps(validate(report), sort_keys=True))
    finally:
        for member in controller.members:
            member.stop()


if __name__ == "__main__":
    try:
        main()
    except (AcceptanceError, OSError, ValueError, KeyError) as exc:
        raise SystemExit("witness acceptance failed: " + str(exc)) from exc
