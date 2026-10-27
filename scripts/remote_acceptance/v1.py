#!/usr/bin/env python3
"""Single-assignment V1 CLI acceptance over two original local owners.

The controller distributes public artifacts, never live journals or A's owner.
Private test fixtures contain never-started role keys and immutable archive data.
SSH authentication stays outside configuration. Every effect is explicit.
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
import time
import uuid

from run import AcceptanceError, Host, Supervisor, ZERO, digest_id, fields, require


PREFIX = "work-archive-custody-remote-"
SCENARIOS = ("healthy", "partition-before", "loss-delay", "a-restart-before-data",
             "a-restart-after-data", "b-restart-before-result", "b-restart-after-result",
             "seal-reply-loss", "expired-cache", "unseen-seal", "soak")
PLACEMENT_SCENARIOS = {"healthy", "partition-before", "loss-delay", "a-restart-before-data", "a-restart-after-data", "soak"}


def close_supervisor(supervisor):
    active = sys.exc_info()[1]
    try:
        supervisor.close()
    except (AcceptanceError, OSError) as exc:
        detail = supervisor.process.stderr.read(65536).decode("utf-8", "replace") if supervisor.process.poll() is not None else ""
        if active is not None:
            print("remote_v1_cleanup_error %s %s" % (exc, detail[-4096:]), flush=True)
        else:
            raise AcceptanceError("%s %s" % (exc, detail[-4096:])) from exc


def publish_report(path, report):
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        require(os.write(fd, encoded) == len(encoded), "short report write")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(Path(path).parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def full_remote_review(supervisor):
    supervisor.rpc("send", name="audit", line="review")
    result = supervisor.rpc("until", name="audit", terminator="remote_custody_scope_end\n", timeout=40)
    lines = result["lines"]
    require(result.get("complete") is True and len(lines) > 3 and lines[1] == "scope:\n" and
            lines[-1] == "remote_custody_scope_end\n", "truncated remote review")
    header = fields(lines[0], "remote_custody_review")
    digest_id(header["review_id"])
    return json.loads("".join(lines[2:-1]))


def validate_success(a, b, cycle, identities=None):
    require(a["assignment_id"] == b["assignment_id"], "participants selected different assignments")
    require(a["confirmed_sequence"] == 6 * cycle and a["pending_operations"] == 0 and
            not a["pending_attempt"] and not a["active_remote"], "authority did not close both exact tickets")
    require(a["journal_sequence"] == b["journal_sequence"] == cycle, "source sequence did not advance exactly once")
    for key in ("journal_head_id", "current_receipt_id", "proof_id", "responded_at"):
        require(a[key] == b[key], "participants disagree on original " + key)
    require(b["worker_stage"] == 4 and b["worker_pending"] == 0 and b["disposition"] == 3 and
            b["result_id"] == a["journal_head_id"], "worker did not retain the accepted exact result")
    if identities:
        for role, state in (("a", a), ("b", b)):
            require(state["original_identities"] == identities[role], "original roots/locks changed during reuse")


class Role:
    def __init__(self, host, public):
        self.h, self.p = host, public
        self.n, self.ids = 0, {}
        self.placement_flags, self.placement_id = [], None

    def path(self, value):
        return self.h.root + "/" + value

    def op(self, name):
        return "operations/%03d/%s" % (self.n, name)

    def once(self, args, check=True):
        result = self.h.execute([self.h.binary] + args, check=check)
        return result.stdout.decode() if check else result

    def record(self, args, prefix):
        return fields(self.once(args), prefix)

    def policy(self):
        return ["--max-challenge-lifetime-seconds", str(self.p["Lifetime"]),
                "--max-proof-age-seconds", str(self.p["ProofAge"]),
                "--max-renewal-term-seconds", str(self.p["RenewalTerm"])]

    def archive(self):
        return ["--manifest", self.path("metadata/manifest"), "--receipt", self.path("metadata/initial")]

    def assignment(self):
        return ["--assignment", self.path("metadata/assignment"), "--assignment-id", self.ids["assignment"]]

    def common(self):
        return self.assignment() + self.archive() + self.policy() + [
            "--intent", self.path("intent/%03d" % self.n), "--intent-id", self.ids["intent"],
            "--previous-receipt", self.path(self.op("previous"))]

    def challenge(self):
        return ["--challenge", self.path(self.op("challenge")), "--challenge-id", self.ids["challenge"]]

    def plan(self):
        return ["--plan", self.path(self.op("plan")), "--plan-id", self.ids["plan"]]

    def begin(self):
        return ["--begin", self.path(self.op("begin")), "--begin-id", self.ids["begin"]]

    def owned(self, args, action):
        s = Supervisor(self.h, {"action": {"argv": [self.h.binary] + args + ["--mode", "control"]}})
        try:
            s.start("action", "work_archive_custody_command_ready")
            result = s.action("action", "work_archive_custody_command", action)
            s.stop("action")
            return result
        finally:
            close_supervisor(s)

    def apply(self, kind):
        args = [PREFIX + "admission-apply"] + self.common() + [
            "--purpose", kind, "--entry", self.path(self.op(kind)), "--entry-id", self.ids[kind],
            "--authority", self.path("authority"), "--authority-pins", self.path("authority-pins"),
            "--journal", self.path("journal")]
        if kind == "serve":
            args += self.challenge()
        result = self.owned(args, "apply")
        require(json.loads(result["commit"])["Appended"], "new admission was already applied")

    def session(self):
        value = {"cycle": self.n, "assignment_id": self.ids["assignment"],
                 "plan_id": self.ids["plan"], "begin_id": self.ids["begin"]}
        self.h.write(self.op("session.json"), json.dumps(value).encode())

    def inspect(self):
        result = self.h.execute([self.h.test_binary, "-test.run=^TestInspectRemoteV1Fixture$", "-test.count=1"],
                               {"OUTCOMEMESH_REMOTE_ROLE_ROOT": self.h.root,
                                "OMESH_REMOTE_GATE_ARGS": self.path(self.op("session.json"))})
        for line in result.stdout.decode().splitlines():
            if line.startswith("remote_v1_inspect "):
                return json.loads(line.split(" ", 1)[1])
        raise AcceptanceError("original V1 inspection missing")

    def runtime(self, role, peer="", drain="", terminal="", complete=""):
        args = [PREFIX + ("audit" if role == "a" else "serve")] + self.assignment() + self.archive() + self.policy()
        args += self.plan() + self.begin() + ["--previous-receipt", self.path(self.op("previous")),
                                             "--challenge", self.path(self.op("challenge")), "--journal", self.path("journal"),
                                             "--timeout", "10s", "--mode", "control"]
        if role == "b":
            return args + ["--worker", self.path("workers/%03d" % self.n), "--objects", self.path("objects"),
                           "--replica-key", self.path("keys/replica.seed"), "--control-key", self.path("keys/b-control.seed"),
                           "--key", self.path("keys/b-transport.seed"), "--listen", "/ip4/0.0.0.0/udp/43980/quic-v1"] + self.placement_flags
        args += ["--control-key", self.path("keys/a-control.seed"), "--key", self.path("keys/a-data.seed"),
                 "--listen", "/ip4/127.0.0.1/udp/43971/quic-v1", "--peer", peer,
                 "--authority", self.path("authority"), "--authority-pins", self.path("authority-pins"),
                 "--intent", self.path("intent/%03d" % self.n), "--intent-id", self.ids["intent"],
                 "--audit-admission", self.path(self.op("audit")), "--audit-ticket-id", self.ids["audit"],
                 "--artifacts", self.path("artifacts"), "--authority-key", self.path("keys/authority.seed"),
                 "--auditor-key", self.path("keys/auditor.seed"), "--drain", self.path(self.op("drain")),
                 "--terminal", self.path(self.op("terminal"))]
        if drain:
            args += ["--drain-id", drain]
        if terminal:
            args += ["--terminal-id", terminal]
        if complete:
            args += ["--complete-entry", self.path(self.op(complete)), "--complete-entry-id", self.ids[complete]]
        return args + self.placement_flags


class Case:
    def __init__(self, config, fixture):
        self.config = config
        self.roles = {}
        for name in ("a", "b"):
            source = fixture / ("role-" + name)
            for forbidden in ("authority", "authority-pins", "journal", "artifacts"):
                require(not (source / forbidden).exists(), "export contains a used owner/source")
            require(not (source / "metadata/assignment").exists(), "assignment must be created at destination")
            public = json.loads((source / "scope.json").read_text())
            require(public["version"] == 1 and public["role"] == name, "wrong fixture role")
            host = Host(config["hosts"][name])
            host.install(source)
            self.roles[name] = Role(host, public)
        self.a, self.b = self.roles["a"], self.roles["b"]
        require(self.a.p["public_keys"] == self.b.p["public_keys"] and
                self.a.p["incarnation_id"] == self.b.p["incarnation_id"], "fixture scopes diverge")
        require(self.a.h.sha256(self.a.h.binary) == self.b.h.sha256(self.b.h.binary), "installed normal binaries differ")
        require(self.a.h.sha256(self.a.h.test_binary) == self.b.h.sha256(self.b.h.test_binary), "installed CLI test binaries differ")
        expected = config["expected_binaries"]
        require(self.a.h.sha256(self.a.h.binary) == expected["omd"] and
                self.a.h.sha256(self.a.h.test_binary) == expected["omd.test"] and
                self.b.h.sha256(self.b.h.config["gate_binary"]) == expected["store.test"], "deployment differs from pinned build artifacts")
        clocks = {name: int(role.h.execute(["date", "+%s"]).stdout) for name, role in self.roles.items()}
        require(abs(clocks["a"] - clocks["b"]) <= 2, "host clocks differ; no clock adjustment is permitted")
        self.evidence = {"version": 1, "scope": "one original A authority and a separately bootstrapped B worker/source under the SAME V1 assignment",
                         "clock_observations": clocks, "normal_binary_sha256": self.a.h.sha256(self.a.h.binary),
                         "cli_test_binary_sha256": self.a.h.sha256(self.a.h.test_binary), "cycles": [], "copied_live_roots": False}
        self.evidence["gate_test_binary_sha256"] = self.b.h.sha256(self.b.h.config["gate_binary"])
        self.evidence["build_provenance"] = config["provenance"]
        self.evidence["placement_required"] = config.get("require_placement", False)
        if all(role.h.config["kind"] == "ssh" for role in (self.a, self.b)):
            boots = {name: hashlib.sha256(role.h.execute(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()).hexdigest()
                     for name, role in self.roles.items()}
            require(boots["a"] != boots["b"], "two SSH labels selected the same observed kernel boot")
            self.evidence["observed_kernel_boot_sha256"] = boots
        self.initialize()

    def transfer(self, source, dest, relative):
        dest.h.write(relative, source.h.read(relative))

    def initialize(self):
        a, b, k = self.a, self.b, self.a.p["public_keys"]
        members = sorted([(k["audit-consumer"], "audit+prune"), (k["serve-consumer"], "serve")])
        args = [PREFIX + "assignment"] + a.archive() + a.policy() + [
            "--incarnation-id", a.p["incarnation_id"], "--authority-public-key", k["authority"],
            "--auditor-public-keys", k["auditor"], "--consumers", ",".join(x + ":" + y for x, y in members),
            "--remote-control-public-key", k["b-control"], "--remote-transport-public-key", k["b-transport"],
            "--max-operations", str(a.p["MaximumOperations"]), "--max-pending", str(a.p["MaximumPending"])]
        aid = digest_id(a.record(args, "remote_custody_assignment")["assignment_id"])
        a.once(args + ["--mode", "publish", "--assignment-id", aid, "--out", a.path("metadata/assignment")])
        self.transfer(a, b, "metadata/assignment")
        self.evidence["assignment_id"] = aid
        for name, role in self.roles.items():
            role.ids["assignment"] = aid
            args = [PREFIX + "source"] + role.assignment() + role.archive() + role.policy() + [
                "--role", "audit" if name == "a" else "serve", "--journal", role.path("journal")]
            if name == "a":
                args += ["--artifacts", role.path("artifacts")]
            review = digest_id(role.record(args, "remote_custody_source")["review_id"])
            role.once(args + ["--mode", "create", "--expected-review-id", review])
        args = [PREFIX + "authority-bootstrap"] + a.assignment() + ["--authority", a.path("authority"), "--authority-pins", a.path("authority-pins")]
        review = digest_id(a.record(args, "remote_custody_authority_bootstrap")["review_id"])
        a.once(args + ["--mode", "create", "--expected-review-id", review])

    def sign(self, name, actor, key_name, extras):
        a, b = self.a, self.b
        def scope(role):
            args = [PREFIX + "command-sign"] + role.common() + extras(role)
            return args
        args = scope(actor)
        review = digest_id(actor.record(args, "remote_custody_signing")["review_id"])
        actor.once(args + ["--mode", "sign", "--expected-review-id", review, "--actor-key", actor.path("keys/" + key_name + ".seed"),
                           "--out", actor.path(actor.op(name + ".command"))])
        if actor is b:
            self.transfer(b, a, a.op(name + ".command"))
        args = scope(a)
        args[0] = PREFIX + "command-cosign"
        args += ["--command", a.path(a.op(name + ".command"))]
        review = digest_id(a.record(args, "remote_custody_signing")["review_id"])
        out = a.record(args + ["--mode", "sign", "--expected-review-id", review, "--authority-key", a.path("keys/authority.seed"),
                              "--out", a.path(a.op(name))], "remote_custody_signing")
        eid = digest_id(out["entry_id"])
        for role in (a, b):
            role.ids[name] = eid
        self.transfer(a, b, a.op(name))
        return eid

    def prepare(self, cycle):
        a, b, k = self.a, self.b, self.a.p["public_keys"]
        for role in (a, b):
            role.n = cycle
        previous = a.h.read("metadata/initial") if cycle == 1 else a.h.read("artifacts/cycle-%020d/receipt.omrr" % (cycle - 1))
        for role in (a, b):
            role.h.write(role.op("previous"), previous)
        if cycle == 1:
            prior_head, prior_receipt = ZERO, a.p["initial_receipt_id"]
        else:
            prior_head, prior_receipt = self.evidence["cycles"][-1]["final"]["a"]["journal_head_id"], self.evidence["cycles"][-1]["final"]["a"]["current_receipt_id"]
        issued = int(a.h.execute(["date", "+%s"]).stdout)
        args = ["work-archive-custody-audit-intent"] + a.assignment() + [
            "--intent", a.path("intent/%03d" % cycle), "--consumer-public-key", k["audit-consumer"],
            "--auditor-public-key", k["auditor"], "--replica-peer-id", k["b-peer"], "--prior-sequence", str(cycle - 1),
            "--prior-head-id", prior_head, "--prior-receipt-id", prior_receipt, "--issued-at", str(issued),
            "--expires-at", str(issued + a.p["Lifetime"]), "--renew-until", str(a.p["initial_retain_until"] + 60 * cycle),
            "--samples", "1", "--nonce-file", a.path("nonces/%03d-intent" % cycle)]
        iid = digest_id(a.record(args, "work_archive_custody_audit_intent")["intent_id"])
        a.once(args + ["--mode", "publish", "--intent-id", iid])
        self.transfer(a, b, "intent/%03d" % cycle)
        for role in (a, b):
            role.ids["intent"] = iid
        position = 6 * (cycle - 1)
        head = a.ids["assignment"] if cycle == 1 else self.evidence["cycles"][-1]["last_completion"]
        audit = self.sign("audit", a, "audit-consumer", lambda _: ["--kind", "admit", "--purpose", "audit", "--consumer-public-key", k["audit-consumer"], "--expected-sequence", str(position), "--expected-head", head])
        a.apply("audit")
        args = [PREFIX + "challenge"] + a.common() + ["--purpose", "audit", "--entry", a.path(a.op("audit")), "--entry-id", audit,
            "--authority", a.path("authority"), "--authority-pins", a.path("authority-pins"), "--journal", a.path("journal"),
            "--artifacts", a.path("artifacts"), "--auditor-key", a.path("keys/auditor.seed")]
        cid = digest_id(a.owned(args, "prepare")["challenge_id"])
        challenge = a.h.read("artifacts/cycle-%020d/challenge.omcc" % cycle)
        for role in (a, b):
            role.h.write(role.op("challenge"), challenge)
            role.ids["challenge"] = cid
        serve = self.sign("serve", b, "serve-consumer", lambda r: ["--kind", "admit", "--purpose", "serve", "--consumer-public-key", k["serve-consumer"], "--expected-sequence", str(position + 1), "--expected-head", audit] + r.challenge())
        a.apply("serve")
        args = [PREFIX + "plan"] + a.common() + a.challenge() + ["--admission", a.path(a.op("serve")), "--admission-id", serve,
            "--authority-transport-public-key", k["a-control"], "--audit-transport-public-key", k["a-data"], "--nonce-file", a.path("nonces/%03d-plan" % cycle)]
        pid = digest_id(a.record(args, "remote_custody_plan")["plan_id"])
        a.once(args + ["--mode", "publish", "--plan-id", pid, "--out", a.path(a.op("plan"))])
        self.transfer(a, b, a.op("plan"))
        for role in (a, b):
            role.ids["plan"] = pid
        self.sign("begin", b, "b-control", lambda r: ["--kind", "begin", "--purpose", "serve", "--expected-sequence", str(position + 2), "--expected-head", serve] + r.challenge() + r.plan())
        args = [PREFIX + "worker-prepare"] + b.common() + b.challenge() + b.plan() + b.begin() + ["--worker", b.path("workers/%03d" % cycle)]
        review = digest_id(b.record(args, "remote_custody_worker_prepare")["review_id"])
        b.once(args + ["--mode", "create", "--expected-review-id", review])
        for role in (a, b):
            role.session()
        placements = {}
        if self.config.get("require_placement"):
            for name, role in (("a", a), ("b", b)):
                if name == "b" or not role.placement_flags:
                    role.placement_flags = []
                    parent = role.path("placement-%03d" % cycle)
                    role.h.execute(["mkdir", "-m", "700", parent])
                    args = role.runtime(name)
                    args[args.index("--mode") + 1] = "placement-review"
                    args += ["--placement", parent + "/record"]
                    selected = digest_id(role.record(args, "remote_custody_placement")["placement_id"])
                    args[args.index("--mode") + 1] = "placement-create"
                    role.once(args + ["--placement-id", selected])
                    role.placement_flags = ["--placement", parent + "/record", "--placement-id", selected, "--require-placement=true"]
                    role.placement_id = selected
                placements[name] = role.placement_id
        return {"cycle": cycle, "intent_id": iid, "challenge_id": cid, "plan_id": pid, "begin_id": a.ids["begin"], "issued_at": issued,
                "placements": placements}

    def complete(self, cycle, peer, drain, terminal):
        a, b = self.a, self.b
        self.transfer(a, b, a.op("terminal"))
        state = a.record([PREFIX + "authority-bootstrap"] + a.assignment() + ["--mode", "verify", "--authority", a.path("authority"), "--authority-pins", a.path("authority-pins")], "remote_custody_authority_bootstrap")
        sequence, head = int(state["confirmed_sequence"]), state["confirmed_head"]
        for purpose, actor, key in (("audit", a, "audit-consumer"), ("serve", b, "serve-consumer")):
            name = "complete-" + purpose
            eid = self.sign(name, actor, key, lambda r: ["--kind", "complete", "--purpose", purpose, "--expected-sequence", str(sequence), "--expected-head", head,
                "--admission", r.path(r.op(purpose)), "--admission-id", r.ids[purpose], "--terminal", r.path(r.op("terminal")), "--terminal-id", terminal] + r.challenge() + r.plan() + r.begin())
            s = Supervisor(a.h, {"audit": {"argv": [a.h.binary] + a.runtime("a", peer, drain, terminal, name)}})
            try:
                s.start("audit", "remote_custody_ready")
                result = s.action("audit", "remote_custody", "apply-complete", "completed")
                require(result["entry_id"] == eid and result["appended"] == "true", "completion was not independently appended")
                s.stop("audit")
            finally:
                close_supervisor(s)
            sequence, head = sequence + 1, eid
        require(sequence == 6 * cycle, "unexpected final position")
        return head


def paused_server(case, stage):
    b = case.b
    b.h.execute([b.h.test_binary, "-test.run=^TestPrepareRemoteV1GateConfig$", "-test.count=1"],
                {"OUTCOMEMESH_REMOTE_ROLE_ROOT": b.h.root, "OMESH_REMOTE_GATE_ARGS": b.path(b.op("session.json"))})
    cfg = dict(b.h.config)
    cfg["test_binary"] = cfg["gate_binary"]
    host = Host(cfg)
    return Supervisor(host, {"serve": {"argv": [host.test_binary, "-test.run=^TestRemoteCustodyNetworkProcessHelper$", "-test.count=1"],
                     "env": {"OMESH_REMOTE_NETWORK_PROCESS_CONFIG": b.path(b.op(stage + ".json"))}}})


def wait_gate(case, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = case.b.h.execute(["test", "-f", case.b.path(case.b.op("gate.marker"))], check=False)
        if r.returncode == 0:
            return
        time.sleep(0.05)
    raise AcceptanceError("B did not reach the exact owned effect boundary")


def kill(s, name):
    s.rpc("kill", name=name)
    require(s.rpc("wait", name=name, timeout=30)["returncode"] not in (None, 0), "process was not killed")


def run_cycle(case, cycle, scenario):
    a, b = case.a, case.b
    evidence = case.prepare(cycle)
    stage = {"b-restart-before-result": "remote-data-admitted", "b-restart-after-result": "remote-data-before-response-write",
             "expired-cache": "remote-data-before-response-write", "seal-reply-loss": "remote-control-drained-before-response-write"}.get(scenario)
    server = paused_server(case, stage) if stage else Supervisor(b.h, {"serve": {"argv": [b.h.binary] + b.runtime("b")}})
    auditor = None
    try:
        ready = server.start("serve", "remote_custody_process_ready" if stage else "remote_custody_ready")
        if not stage:
            ready = server.action("serve", "remote_custody", "serve", "serving")
        address = ready.get("address", ready.get("listen", "")).split(",")[0]
        suffix = address.split("/p2p/")[-1]
        require(suffix != address, "B did not expose its pinned transport identity")
        peer = "/ip4/127.0.0.1/udp/43972/quic-v1/p2p/" + suffix
        relay = {"front": ["127.0.0.1", 43972], "allowed_client": ["127.0.0.1", 43971], "upstream": [case.config["hosts"]["b"]["public_ip"], 43980]}
        auditor = Supervisor(a.h, {"audit": {"argv": [a.h.binary] + a.runtime("a", peer)}}, relay)
        auditor.rpc("relay.start")
        if scenario == "loss-delay":
            auditor.rpc("relay.policy", mode="pass", drop_every=13, delay_ms=20)
        auditor.start("audit", "remote_custody_ready")
        auditor.action("audit", "remote_custody", "prepare", "prepared")
        auditor.action("audit", "remote_custody", "begin", "begun")
        if scenario == "a-restart-before-data":
            kill(auditor, "audit")
            state = a.inspect()
            require(state["active_remote"] and state["confirmed_sequence"] == 6 * (cycle - 1) + 3 and state["journal_sequence"] == cycle - 1, "A restart lost its hold")
            evidence["after_a_death"] = state
            auditor.start("audit", "remote_custody_ready")
        if scenario in ("partition-before", "unseen-seal"):
            auditor.rpc("relay.policy", mode="drop")
        if scenario in ("b-restart-before-result", "b-restart-after-result", "expired-cache"):
            token = auditor.review("audit", "remote_custody")
            auditor.rpc("send", name="audit", line="execute " + token)
            wait_gate(case)
            kill(server, "serve")
            auditor.expect_failure("audit")
            before = {"a": a.inspect(), "b": b.inspect()}
            require(before["a"]["active_remote"] and before["a"]["pending_operations"] == 2 and before["a"]["journal_sequence"] == cycle - 1, "failed exchange released A or accepted unseen data")
            expected_b = cycle - 1 if scenario == "b-restart-before-result" else cycle
            require(before["b"]["journal_sequence"] == expected_b and before["b"]["worker_stage"] == 2, "B death retained the wrong branch")
            evidence["after_b_death"] = before
            server.close()
            server = Supervisor(b.h, {"serve": {"argv": [b.h.binary] + b.runtime("b")}})
            server.start("serve", "remote_custody_ready")
            server.action("serve", "remote_custody", "serve", "serving")
            if scenario == "expired-cache":
                deadline = before["b"]["responded_at"] + b.p["ProofAge"] + 2
                while True:
                    remaining = deadline - int(a.h.execute(["date", "+%s"]).stdout)
                    if remaining <= 0:
                        break
                    print("remote_v1_wait original_proof_expiry_seconds=%d" % remaining, flush=True)
                    time.sleep(min(5, remaining))
            auditor.start("audit", "remote_custody_ready")
            if scenario in ("b-restart-before-result", "expired-cache"):
                token = auditor.review("audit", "remote_custody")
                auditor.rpc("send", name="audit", line="execute " + token)
                auditor.expect_failure("audit")
                auditor.start("audit", "remote_custody_ready")
                evidence["fresh_restart_rejected"] = True
            else:
                evidence["recovered"] = auditor.action("audit", "remote_custody", "execute", "executed")
        elif scenario in ("partition-before", "unseen-seal"):
            token = auditor.review("audit", "remote_custody")
            auditor.rpc("send", name="audit", line="execute " + token)
            auditor.expect_failure("audit")
            hold = a.inspect()
            require(hold["active_remote"] and hold["pending_operations"] == 2 and hold["journal_sequence"] == cycle - 1, "partition cleared A's obligation")
            evidence["after_partition"] = hold
            auditor.rpc("relay.policy", mode="pass")
            auditor.start("audit", "remote_custody_ready")
            if scenario == "partition-before":
                evidence["executed"] = auditor.action("audit", "remote_custody", "execute", "executed")
        else:
            evidence["executed"] = auditor.action("audit", "remote_custody", "execute", "executed")
        if scenario == "a-restart-after-data":
            kill(auditor, "audit")
            state = a.inspect()
            require(state["active_remote"] and state["journal_sequence"] == cycle, "accepted result or hold lost on A death")
            evidence["after_a_death"] = state
            auditor.start("audit", "remote_custody_ready")
        if scenario == "seal-reply-loss":
            token = auditor.review("audit", "remote_custody")
            auditor.rpc("send", name="audit", line="seal " + token)
            wait_gate(case)
            kill(server, "serve")
            auditor.expect_failure("audit")
            before = {"a": a.inspect(), "b": b.inspect()}
            require(before["a"]["active_remote"] and before["b"]["worker_stage"] == 4, "lost drain reply fabricated A confirmation")
            evidence["lost_seal_reply"] = before
            server.close()
            server = Supervisor(b.h, {"serve": {"argv": [b.h.binary] + b.runtime("b")}})
            server.start("serve", "remote_custody_ready")
            server.action("serve", "remote_custody", "serve", "serving")
            auditor.start("audit", "remote_custody_ready")
            reconciliation = auditor.action("audit", "remote_custody", "reconcile", "metadata")
            observed = full_remote_review(auditor)
            require(observed["ConfirmedSequence"] == 6 * (cycle - 1) + 3 and observed["ActiveBegin"] == a.ids["begin"],
                    "metadata reconciliation implicitly confirmed A's drain")
            evidence["metadata_only_reconciliation"] = {"drain_id": digest_id(reconciliation["drain_id"]),
                                                         "confirmed_sequence": observed["ConfirmedSequence"]}
        metadata = auditor.action("audit", "remote_custody", "seal", "metadata")
        drain = digest_id(metadata["drain_id"])
        if "metadata_only_reconciliation" in evidence:
            require(drain == evidence["metadata_only_reconciliation"]["drain_id"], "reconciliation changed the retained drain artifact")
        negative = scenario in ("b-restart-before-result", "expired-cache", "unseen-seal")
        if negative:
            token = auditor.review("audit", "remote_custody")
            auditor.rpc("send", name="audit", line="capture " + token)
            auditor.expect_failure("audit")
            require(a.h.execute(["test", "-e", a.path(a.op("terminal"))], check=False).returncode != 0, "unknown outcome created a success terminal")
            evidence["success_capture_rejected"] = True
        else:
            terminal = digest_id(auditor.action("audit", "remote_custody", "capture", "captured")["terminal_id"])
            auditor.stop("audit")
        session = {"cycle": cycle, "assignment_id": a.ids["assignment"], "plan_id": a.ids["plan"],
                   "begin_id": a.ids["begin"], "peer": peer}
        a.h.write(a.op("late-start.json"), json.dumps(session).encode())
        probe = a.h.execute([a.h.test_binary, "-test.run=^TestRemoteV1LateStart$", "-test.count=1"],
                            {"OUTCOMEMESH_REMOTE_ROLE_ROOT": a.h.root, "OMESH_REMOTE_GATE_ARGS": a.path(a.op("late-start.json"))})
        late = fields(probe.stdout.decode(), "remote_v1_late_start")
        require(late.get("authenticated") == "true" and late.get("confirmed") == "false" and late.get("transport_timeout") == "false",
                "delayed Start was not rejected on an authenticated live route")
        evidence["delayed_start_rejected"] = True
        server.stop("serve")
        final_before_complete = {"a": a.inspect(), "b": b.inspect()}
        if negative:
            require(final_before_complete["a"]["pending_operations"] == 2 and not final_before_complete["a"]["active_remote"] and
                    final_before_complete["a"]["confirmed_sequence"] == 6 * (cycle - 1) + 4, "negative drain completed ordinary tickets")
            expected = 1 if scenario == "unseen-seal" else (2 if scenario == "b-restart-before-result" else 3)
            require(final_before_complete["b"]["disposition"] == expected, "negative disposition was relabelled")
            require(final_before_complete["a"]["journal_sequence"] == cycle - 1 and
                    final_before_complete["b"]["worker_pending"] == 0, "negative branch accepted a success or left an unconfirmed seal")
            if "after_b_death" in evidence:
                before = evidence["after_b_death"]
                for role in ("a", "b"):
                    for key in ("journal_sequence", "journal_head_id", "current_receipt_id"):
                        require(before[role][key] == final_before_complete[role][key], "failed retry changed the original source")
                if scenario == "expired-cache":
                    for key in ("proof_id", "responded_at"):
                        require(before["b"][key] == final_before_complete["b"][key], "expired cache was refreshed")
            evidence["final"] = final_before_complete
            evidence["ordinary_tickets_retained"] = True
        else:
            evidence["last_completion"] = case.complete(cycle, peer, drain, terminal)
            evidence["final"] = {"a": a.inspect(), "b": b.inspect()}
            baseline = None if not case.evidence["cycles"] else {name: case.evidence["cycles"][0]["final"][name]["original_identities"] for name in ("a", "b")}
            validate_success(evidence["final"]["a"], evidence["final"]["b"], cycle, baseline)
            if "after_b_death" in evidence:
                for key in ("journal_head_id", "current_receipt_id", "proof_id", "responded_at"):
                    require(evidence["after_b_death"]["b"][key] == evidence["final"]["b"][key], "cached retry minted another result")
        evidence["relay"] = auditor.rpc("relay.stats")
        evidence["passed"] = True
        return evidence
    finally:
        # EOF drains normal children; paused fault children are explicitly killed
        # above. Retained directories/evidence are never removed or repaired.
        if auditor:
            close_supervisor(auditor)
        close_supervisor(server)


def run(config, fixture, scenario, cycles, checkpoint=None):
    require(scenario in SCENARIOS and 1 <= cycles <= 64, "invalid scenario or bounded cycle count")
    require(cycles == 1 or scenario == "soak", "multiple cycles require the explicit soak scenario")
    require(not config.get("require_placement") or scenario in PLACEMENT_SCENARIOS,
            "private pause helpers do not supply placement enforcement; choose a normal-CLI placement scenario")
    case = Case(config, fixture)
    for cycle in range(1, cycles + 1):
        print("remote_v1_step scenario=%s cycle=%d/%d" % (scenario, cycle, cycles), flush=True)
        case.evidence["cycles"].append(run_cycle(case, cycle, "loss-delay" if scenario == "soak" and cycle % 4 == 0 else ("healthy" if scenario == "soak" else scenario)))
        if checkpoint:
            checkpoint(cycle, case.evidence)
    case.evidence.update(scenario=scenario, cycle_count=cycles, passed=True)
    for role in (case.a, case.b):
        role.h.hashes.clear()
        require(role.h.sha256(role.h.binary) == config["expected_binaries"]["omd"] and
                role.h.sha256(role.h.test_binary) == config["expected_binaries"]["omd.test"], "binary changed during acceptance")
    require(case.b.h.sha256(case.b.h.config["gate_binary"]) == config["expected_binaries"]["store.test"], "gate binary changed during acceptance")
    case.evidence["binaries_unchanged_after_run"] = True
    case.evidence["controller_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return case.evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--cycles", type=int, default=1)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out)
    require(out.parent.is_dir() and not out.exists(), "report requires an existing private parent and new output")
    report = run(json.loads(Path(args.config).read_text()), Path(args.fixture), args.scenario, args.cycles,
                 lambda cycle, report: publish_report(str(out) + ".cycle-%03d.json" % cycle, report))
    publish_report(out, report)
    print("remote_v1_acceptance scenario=%s cycles=%d passed=true report=%s" % (args.scenario, args.cycles, out), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (AcceptanceError, OSError, ValueError) as exc:
        print("remote_v1_acceptance_failed " + str(exc), flush=True)
        raise SystemExit(1)
