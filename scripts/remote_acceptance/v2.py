#!/usr/bin/env python3
"""Witness-mandatory custody V2 acceptance across two explicit test hosts.

Only fresh fixture sources and public deterministic test keys are distributed.
Normal CLI commands sign jobs, collect quorums, execute and accept. The opaque
UDP relay changes delivery only; no clock, firewall or production owner changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import time
import uuid

from run import AcceptanceError, Host, Supervisor, ZERO, fields, require
from v1 import close_supervisor, publish_report

CLI = "work-archive-custody-v2"
WITNESS = "work-archive-custody-witness"
SCENARIOS = ("lost-result", "lost-session", "expired-result")


def digest(domain, raw):
    return hashlib.sha256(domain.encode() + raw).hexdigest()


def artifact(raw):
    return digest("OMESH/custody/v2/artifact/id", raw)


def command_id(raw):
    require(raw[:10] == b"OMCFCM00\0\1", "wrong V1 command header")
    return digest("OMESH/custody-fence/command/id/v1", raw)


def response_pin(raw, scope, member, request):
    # The normal witness CLI verifies every signature before retaining this file.
    # Decode its explicit V1 layout only to retain independent before/after pins.
    require(raw[:10] == b"OMCFWS00\0\1" and len(raw) >= 351, "wrong V1 witness response")
    obs = raw[10:350]
    require(obs[:10] == b"OMCFOB00\0\1" and obs[10:42].hex() == request and
            obs[42:74].hex() == member and obs[74:106].hex() == scope, "witness binding changed")
    return {"sequence": struct.unpack(">Q", obs[106:114])[0], "head": obs[114:146].hex(),
            "pending": obs[146:178].hex(), "phase": obs[178], "held": obs[243] == 1,
            "session": obs[244:276].hex()}


def once(host, args, prefix=None, check=True):
    result = host.execute([host.binary] + args, timeout=40, check=check)
    return fields(result.stdout.decode(), prefix) if prefix else result


def reviewed(host, args, witness=False, mode="run"):
    prefix = "custody_witness_review" if witness else "custody_v2_review"
    record = once(host, args, prefix)
    require(record["keys_loaded"] == "false", "review loaded private keys")
    return args + ["--mode", mode, "--expected-review-id", record["review_id"]]


def transfer(source, destination, name):
    destination.write(name, source.read(name))


def install_fresh(export_host, source, host):
    # This is a never-started fixture only: no V2 owner may be transferred.
    script = ("import io,os,sys,tarfile\n"
              "assert not os.path.exists(sys.argv[1]+'/owner')\n"
              "with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as t:t.add(sys.argv[1],arcname='.')\n")
    raw = export_host.execute(["python3", "-c", script, source]).stdout
    extract = ("import io,os,sys,tarfile\n"
               "os.makedirs(os.path.dirname(sys.argv[1]),mode=0o700,exist_ok=True);os.mkdir(sys.argv[1],0o700)\n"
               "with tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())) as t:\n"
               " m=t.getmembers();assert len(m)<=128\n"
               " for p in m:assert (p.isfile() or p.isdir()) and not p.name.startswith('/') and '..' not in p.name.split('/') and not p.name.startswith('./owner')\n"
               " t.extractall(sys.argv[1])\n"
               "os.chmod(sys.argv[1],0o700)\n")
    host.execute(["python3", "-c", extract, host.root], input_bytes=raw)


class Member:
    def __init__(self, case, index):
        self.case, self.index = case, index
        self.h = case.a if index < 2 else case.b
        self.pin = {"sequence": 0, "head": case.scope, "pending": ZERO}
        self.metadata = case.public["Members"][index]
        self.server, self.address = None, None

    def args(self, pin=None):
        p = self.pin if pin is None else pin
        args = [WITNESS, "--scope", self.h.root + "/scope", "--scope-id", self.case.scope,
                "--root", self.h.root + "/witness-" + str(self.index),
                "--witness-public-key", self.metadata["signing_public_key"],
                "--expected-sequence", str(p["sequence"]), "--expected-head", p["head"],
                "--sign-key", self.h.root + "/keys/witness-%d.seed" % self.index,
                "--transport-key", self.h.root + "/keys/witness-transport-%d.seed" % self.index,
                "--transport-public-key", self.metadata["transport_public_key"],
                "--clients", self.case.public["Keys"]["client-peer"], "--timeout", "5s",
                "--listen", "/ip4/0.0.0.0/udp/%d/quic-v1" % (self.case.config["witness_port"] + self.index)]
        if p["pending"] != ZERO:
            args += ["--pending-id", p["pending"]]
        return args

    def create(self):
        args = self.args() + ["--mode", "create-review"]
        record = once(self.h, args, "custody_witness_review")
        once(self.h, self.args() + ["--mode", "create", "--expected-review-id", record["review_id"]])

    def start(self):
        args = reviewed(self.h, self.args(), witness=True, mode="serve")
        self.server = Supervisor(self.h, {"witness": {"argv": [self.h.binary] + args}})
        record = self.server.start("witness", "custody_witness_serving")
        require(record["scope_id"] == self.case.scope, "witness started another scope")
        self.address = "/ip4/%s/udp/%d/quic-v1/p2p/%s" % (
            self.h.config["public_ip"], self.case.config["witness_port"] + self.index,
            record["address"].rsplit("/p2p/", 1)[1])

    def stop(self, kill=False):
        server, self.server = self.server, None
        if server is None:
            return
        try:
            if kill:
                server.rpc("kill", name="witness")
                require(server.rpc("wait", name="witness", timeout=15)["returncode"] == -9, "witness SIGKILL not observed")
            else:
                server.stop("witness")
        finally:
            close_supervisor(server)

    def inspect(self):
        text = once(self.h, self.args()).stdout.decode()
        value = json.loads(text.split("\nscope:\n", 1)[1])["Context"]["Snapshot"]
        return {"sequence": value["Position"]["Sequence"], "head": bytes(value["Position"]["HeadID"]).hex(),
                "phase": value["Phase"], "held": value["ObligationHeld"],
                "session": bytes(value["SessionID"]).hex() if "SessionID" in value else ZERO}


class Case:
    def __init__(self, config, scenario):
        self.config, self.scenario = config, scenario
        self.events, self.checks, self.targets, self.members = [], {}, {}, []
        self.relay, self.cleanup_complete = None, False
        nonce = uuid.uuid4().hex
        self.nonce = nonce
        self.hosts = {}
        for name in ("a", "b"):
            selected = dict(config["hosts"][name]); selected["root"] += "/" + nonce + "-" + scenario
            self.hosts[name] = Host(selected)
        self.a, self.b = self.hosts["a"], self.hosts["b"]
        self.boots = {}
        for name, h in self.hosts.items():
            for path, expected in ((h.binary, config["expected_binaries"]["omd"]),
                                   (h.test_binary, config["expected_binaries"]["omd.test"])):
                require(h.sha256(path) == expected, "native binary pin changed")
            require(h.sha256(h.config["support"]) == config["support_sha256"], "support source pin changed")
            self.boots[name] = hashlib.sha256(h.execute(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()).hexdigest()
        require(self.boots["a"] != self.boots["b"], "two observed kernels required")
        parent = config["export_parent"] + "/" + nonce
        self.a.execute(["mkdir", "-m", "700", "-p", parent])
        output = self.a.execute([self.a.test_binary, "-test.run=^TestExportCustodyV2WANFixture$", "-test.count=1", "-test.v"],
                                {"OUTCOMEMESH_REMOTE_FIXTURE_OUT": parent, "OMESH_V2_SCENARIO": scenario}).stdout.decode()
        matches = re.findall(r"custody_v2_fixture root=(\S+)", output)
        require(len(matches) == 1, "missing fresh V2 export")
        fixture = matches[0]
        install_fresh(self.a, fixture + "/a", self.a)
        install_fresh(self.a, fixture + "/b", self.b)
        clone_config = dict(self.b.config); clone_config["root"] += "-clone"
        self.clone = Host(clone_config)
        install_fresh(self.a, fixture + "/clone", self.clone)
        self.public = json.loads(self.a.read("public.json")); self.scope = self.public["ScopeID"]
        require(not self.public["OriginalOwnersCreated"] and self.public["Scenario"] == scenario, "fixture exported an active owner")
        self.prepare_context()
        self.checks["sources_initially_zero"] = all(self.inspect(h)["source_sequence"] == 0 for h in (self.a, self.b, self.clone))
        for h in (self.b, self.clone):
            self.act(h, "create-target", ["--root", h.root + "/owner", "--journal", h.root + "/journal", "--objects", h.root + "/objects"])
        self.act(self.a, "create-acceptor", ["--root", self.a.root + "/owner", "--journal", self.a.root + "/journal"])
        self.identities = {name: self.inspect(h)["original_identities_sha256"] for name, h in self.hosts.items()}

    def args(self, h, action, extra=()):
        return [CLI, "--action", action, "--context", h.root + "/context", "--context-id", self.public["ContextID"], "--scope-id", self.scope] + list(extra)

    def act(self, h, action, extra=(), fail=False):
        args = self.args(h, action, extra)
        if fail:
            result = once(h, args, check=False)
            require(result.returncode != 0, "invalid offline V2 input accepted")
            return result
        return once(h, reviewed(h, args), "custody_v2_artifact" if action not in ("create-target", "create-acceptor") else "custody_v2_created")

    def prepare_context(self):
        a, b = self.a, self.b
        for role, key, source, target in (("audit", "audit", "draft.json", "draft-audit.json"),
                                          ("authority", "authority", "draft-audit.json", "draft-authority.json")):
            args = [CLI, "--action", "draft-sign", "--draft", a.root + "/" + source, "--sign-role", role,
                    "--sign-key", a.root + "/keys/" + key + ".seed", "--out", a.root + "/" + target]
            once(a, reviewed(a, args))
        transfer(a, b, "draft-authority.json")
        args = [CLI, "--action", "draft-sign", "--draft", b.root + "/draft-authority.json", "--sign-role", "serve",
                "--sign-key", b.root + "/keys/serve.seed", "--out", b.root + "/draft-signed.json"]
        once(b, reviewed(b, args)); transfer(b, a, "draft-signed.json")
        args = [CLI, "--action", "context", "--draft", a.root + "/draft-signed.json", "--out", a.root + "/context"]
        once(a, reviewed(a, args)); require(a.read("context") == a.read("expected-context"), "CLI changed signed job")
        for h in (b, self.clone): transfer(a, h, "context")
        self.act(a, "scope", ["--out", a.root + "/scope"])
        transfer(a, b, "scope")

    def inspect(self, h):
        raw = h.execute([h.test_binary, "-test.run=^TestInspectCustodyV2WANFixture$", "-test.count=1", "-test.v"],
                        {"OUTCOMEMESH_REMOTE_ROLE_ROOT": h.root}).stdout.decode()
        record = next((line for line in raw.splitlines() if line.startswith("custody_v2_inspect ")), None)
        require(record is not None, "missing original-source observation")
        value = json.loads(record.split(" ", 1)[1]); require(value["context_id"] == self.public["ContextID"], "inspection selected another job")
        return value

    def start_target(self, h, clone=False):
        port = self.config["target_port"] + int(clone)
        args = self.args(h, "serve-target", ["--root", h.root + "/owner", "--journal", h.root + "/journal", "--objects", h.root + "/objects",
                 "--sign-key", h.root + "/keys/control.seed", "--replica-key", h.root + "/keys/replica.seed", "--transport-key", h.root + "/keys/transport.seed",
                 "--listen", "/ip4/0.0.0.0/udp/%d/quic-v1" % port, "--timeout", "15s"])
        server = Supervisor(h, {"target": {"argv": [h.binary] + reviewed(h, args)}})
        self.targets[h.root] = server
        ready = server.start("target", "custody_v2_serving")
        require(ready["scope_id"] == self.scope and ready["execution_started"] == "false", "startup executed work")
        route = "/ip4/%s/udp/%d/quic-v1/p2p/%s" % (h.config["public_ip"], port, ready["address"].rsplit("/p2p/", 1)[1])
        if not clone: self.direct_peer = route
        return route

    def stop_target(self, h, kill=False):
        server = self.targets.pop(h.root, None)
        if server is None: return
        try:
            if kill:
                server.rpc("kill", name="target")
                require(server.rpc("wait", name="target", timeout=15)["returncode"] == -9, "target SIGKILL not observed")
            else: server.stop("target")
        finally: close_supervisor(server)

    def start_relay(self):
        args = self.args(self.a, "scope", ["--out", self.a.root + "/unused-relay-view"])
        self.relay = Supervisor(self.a, {"view": {"argv": [self.a.binary] + args}}, relay={
            "front": ["127.0.0.1", self.config["relay_port"]], "allowed_client": ["127.0.0.1", self.config["client_port"]],
            "upstream": [self.b.config["public_ip"], self.config["target_port"]]})
        self.relay.rpc("relay.start")
        self.peer = "/ip4/127.0.0.1/udp/%d/quic-v1/p2p/%s" % (self.config["relay_port"], self.direct_peer.rsplit("/p2p/", 1)[1])

    def request(self, operation, unknown=False):
        name = "request-" + uuid.uuid4().hex
        args = ["--operation", operation, "--nonce", hashlib.sha256(name.encode()).hexdigest(), "--out", self.a.root + "/" + name]
        if operation != "prepare": args += ["--claim", self.a.root + "/claim.qc", "--claim-id", artifact(self.a.read("claim.qc"))]
        if unknown: args += ["--unknown", self.a.root + "/unknown.qc", "--unknown-id", artifact(self.a.read("unknown.qc"))]
        self.act(self.a, "request", args)
        raw = self.a.read(name)
        return {"file": name, "id": digest("OMESH/custody/v2/request/id", raw), "operation": operation}

    def call_args(self, request, output, direct=None):
        extra = ["--in", self.a.root + "/" + request["file"], "--in-id", artifact(self.a.read(request["file"])),
                 "--transport-key", self.a.root + "/keys/client.seed", "--peer", direct or self.peer,
                 "--listen", "/ip4/0.0.0.0/udp/0/quic-v1" if direct else "/ip4/127.0.0.1/udp/%d/quic-v1" % self.config["client_port"],
                 "--timeout", "12s", "--out", self.a.root + "/" + output]
        return reviewed(self.a, self.args(self.a, "call", extra))

    def call(self, request, fail=False, direct=None):
        output = "response-" + uuid.uuid4().hex
        args = self.call_args(request, output, direct)
        self.events.append({"kind": "target", "operation": request["operation"], "request_id": request["id"], "completed": False})
        self.a.write("attempt-" + uuid.uuid4().hex + ".json", json.dumps(self.events[-1]).encode())
        result = once(self.a, args, check=False)
        require((result.returncode != 0) if fail else result.returncode == 0, "target call outcome changed: " + result.stderr.decode()[-1024:])
        self.events[-1].update(completed=not fail, refused=fail)
        if not fail: self.events[-1]["response_sha256"] = hashlib.sha256(self.a.read(output)).hexdigest()
        return output

    def extract(self, request, response, part, output):
        self.act(self.a, "extract", ["--in", self.a.root + "/" + response, "--in-id", artifact(self.a.read(response)),
                 "--request", self.a.root + "/" + request["file"], "--request-id", request["id"], "--part", part, "--out", self.a.root + "/" + output])

    def wcall(self, member, command=None, certificate=None, before=None, replay=None, fail=False):
        a = self.a; p = dict(member.pin if before is None else before)
        if replay:
            request, rid = replay["request"], replay["request_id"]
        else:
            request = "wrequest-" + uuid.uuid4().hex
            args = [WITNESS + "-request", "--scope", a.root + "/scope", "--scope-id", self.scope,
                    "--expected-sequence", str(p["sequence"]), "--expected-head", p["head"],
                    "--nonce", hashlib.sha256(request.encode()).hexdigest(), "--out", a.root + "/" + request]
            if p["pending"] != ZERO: args += ["--pending-id", p["pending"]]
            if command: args += ["--kind", "vote", "--command", a.root + "/" + command, "--command-id", command_id(a.read(command))]
            else: args += ["--kind", "commit", "--certificate", a.root + "/" + certificate,
                           "--certificate-id", digest("OMESH/custody-fence/certificate/artifact/id/v0", a.read(certificate))]
            result = once(a, reviewed(a, args, witness=True, mode="publish"), "custody_witness_artifact"); rid = result["request_id"]
        output = "wresponse-" + uuid.uuid4().hex
        args = [WITNESS + "-call", "--scope", a.root + "/scope", "--scope-id", self.scope, "--witness-public-key", member.metadata["signing_public_key"],
                "--request", a.root + "/" + request, "--request-id", rid, "--transport-key", a.root + "/keys/client.seed", "--transport-public-key", self.public["Keys"]["client"],
                "--server-transport-public-key", member.metadata["transport_public_key"], "--peer", member.address, "--timeout", "3s", "--out", a.root + "/" + output]
        event = {"kind": "witness", "member": member.index, "before": p, "request_id": rid,
                 "command_id": command_id(a.read(command)) if command else replay.get("command_id") if replay else None, "certificate": certificate, "completed": False}
        self.events.append(event); a.write("attempt-" + uuid.uuid4().hex + ".json", json.dumps(event).encode())
        result = once(a, reviewed(a, args, witness=True, mode="exchange"), check=False)
        require(result.returncode != 0 if fail else result.returncode == 0, "witness RPC outcome changed: " + result.stderr.decode()[-1024:])
        if fail: event["refused"] = True; return None
        raw = a.read(output); pin = response_pin(raw, self.scope, member.metadata["signing_public_key"], rid)
        member.pin = {key: pin[key] for key in ("sequence", "head", "pending")}; event.update(completed=True, after=pin, response_sha256=hashlib.sha256(raw).hexdigest())
        return {"request": request, "request_id": rid, "response": output, "pin": pin, "command_id": event["command_id"]}

    def quorum(self, command, replies, name=None, fail=False):
        pairs = "pairs-" + uuid.uuid4().hex
        self.a.write(pairs, json.dumps([{"request": self.a.root + "/" + r["request"], "response": self.a.root + "/" + r["response"]} for r in replies]).encode())
        args = [WITNESS + "-quorum", "--scope", self.a.root + "/scope", "--scope-id", self.scope,
                "--pairs", self.a.root + "/" + pairs, "--command-id", command_id(self.a.read(command))]
        if fail: require(once(self.a, args, check=False).returncode != 0, "invalid quorum assembled"); return None
        once(self.a, reviewed(self.a, args + ["--out", self.a.root + "/" + name], witness=True, mode="publish"))
        return name

    def certify(self, command, name):
        replies = [self.wcall(self.members[i], command=command) for i in (0, 2, 3)]
        cert = self.quorum(command, replies, name)
        for member in self.members: self.wcall(member, certificate=cert)
        return cert

    def unknown(self):
        observation = json.dumps({"scope_id": self.scope, "events": self.events}, sort_keys=True).encode()
        self.a.write("unknown-observation.json", observation)
        self.act(self.a, "sign-unknown", ["--claim", self.a.root + "/claim.qc", "--claim-id", artifact(self.a.read("claim.qc")),
                 "--evidence-id", hashlib.sha256(observation).hexdigest(), "--sign-key", self.a.root + "/keys/authority.seed", "--out", self.a.root + "/unknown-command"])
        self.certify("unknown-command", "unknown.qc")

    def probe(self, kind):
        name = "probe-" + uuid.uuid4().hex + ".json"
        # The fixed test helper reads one independently retained probe selection.
        self.a.write(name, json.dumps({"Kind": kind, "Peer": self.direct_peer}).encode())
        self.a.execute(["python3", "-c", "import os,sys; os.link(sys.argv[1],sys.argv[2])", self.a.root + "/" + name, self.a.root + "/probe.json"])
        try:
            text = self.a.execute([self.a.test_binary, "-test.run=^TestCustodyV2WANProbe$", "-test.count=1", "-test.v"],
                                  {"OUTCOMEMESH_REMOTE_ROLE_ROOT": self.a.root}).stdout.decode()
            require(fields(text, "custody_v2_probe")["refused"] == "true", "probe not refused")
        finally: self.a.execute(["rm", self.a.root + "/probe.json"])
        self.checks["probe_" + kind + "_refused"] = True

    def marker(self, host, name):
        text = host.execute(["python3", "-c", "import os,sys; print(int(os.path.isfile(sys.argv[1])))", host.root + "/owner/" + name]).stdout.decode()
        return text.strip() == "1"

    def setup_network(self):
        self.start_target(self.b); self.start_relay()
        for i in range(4):
            member = Member(self, i); self.members.append(member); member.create(); member.start()
        request = self.request("prepare"); response = self.call(request); self.extract(request, response, "claim", "claim-command")
        self.members[0].stop(); self.members[1].stop()
        pair = [self.wcall(self.members[i], command="claim-command") for i in (2, 3)]
        self.quorum("claim-command", pair, fail=True); self.checks["two_witnesses_not_quorum"] = True
        self.members[0].start(); third = self.wcall(self.members[0], command="claim-command")
        self.quorum("claim-command", [pair[0], pair[0], third], fail=True); self.checks["duplicate_member_not_quorum"] = True
        self.quorum("claim-command", pair + [third], "claim.qc")
        member = self.members[3]; before = dict(member.pin); member.stop(kill=True)
        stale = dict(before, pending=ZERO)
        require(once(member.h, member.args(stale), check=False).returncode != 0, "cold witness adopted missing pending pin")
        member.start(); replay = self.wcall(member, before=before, replay=pair[1])
        require(self.a.read(replay["response"]) == self.a.read(pair[1]["response"]), "cold vote replay changed signed evidence")
        self.checks["witness_sigkill_exact_vote_recovered"] = True
        for i in (0, 2, 3): self.wcall(self.members[i], certificate="claim.qc")
        self.members[1].start(); self.wcall(self.members[1], certificate="claim.qc")
        transfer(self.a, self.b, "claim.qc"); transfer(self.a, self.clone, "claim.qc")
        self.checks["no_effect_before_claim"] = not self.marker(self.b, "consumed")

    def run(self):
        try:
            self.setup_network()
            if self.scenario == "lost-session": return self.lost_session()
            for kind in ("weak", "wrong-scope", "legacy"): self.probe(kind)
            require(not self.marker(self.b, "consumed"), "hostile packet consumed a grant")
            request = self.request("execute")
            if self.scenario == "lost-result":
                response = self.lose_result(request)
            else: response = self.call(request)
            if self.scenario == "lost-result":
                self.unknown(); request = self.request("recover", unknown=True); response = self.call(request)
            self.extract(request, response, "result", "result")
            self.extract(request, response, "result-command", "result-command")
            self.certify("result-command", "result.qc")
            extra = ["--in", self.a.root + "/result", "--in-id", artifact(self.a.read("result")),
                     "--claim", self.a.root + "/claim.qc", "--claim-id", artifact(self.a.read("claim.qc")),
                     "--result-certificate", self.a.root + "/result.qc", "--result-certificate-id", artifact(self.a.read("result.qc")), "--out", self.a.root + "/bundle"]
            if self.scenario == "lost-result": extra += ["--unknown", self.a.root + "/unknown.qc", "--unknown-id", artifact(self.a.read("unknown.qc"))]
            self.run_action_bundle(extra)
            self.stop_target(self.b); b = self.inspect(self.b)
            require(b["source_sequence"] == 1 and b["result"] and self.a.read("result") == self.b.read("owner/result"), "B did not retain the exact original result")
            self.checks["exact_result_bytes_retained"] = True
            if self.scenario == "expired-result":
                while int(self.a.execute(["date", "+%s"]).stdout) <= b["responded_at"] + self.public["ProofAge"]:
                    time.sleep(.2)
                args = self.accept_args("accepted-expired")
                require(once(self.a, reviewed(self.a, args), check=False).returncode != 0, "expired proof advanced A")
                a = self.inspect(self.a); require(a["source_sequence"] == 0 and not a["accepted"] and not self.marker(self.a, "pending"), "expired result left acceptance state")
                self.checks["expired_result_not_accepted"] = True
            else:
                args = reviewed(self.a, self.accept_args("accepted-output-lost"))
                script = ("import json,os,subprocess,sys\n"
                          "r,w=os.pipe();os.close(r)\n"
                          "try:p=subprocess.run(sys.argv[1:],stdout=w,stderr=subprocess.PIPE,timeout=30);print(json.dumps({'returncode':p.returncode}))\n"
                          "finally:os.close(w)\n")
                broken = json.loads(self.a.execute(["python3", "-c", script, self.a.binary] + args).stdout)
                require(broken["returncode"] != 0 and self.marker(self.a, "accepted"), "broken output lost acceptance receipt")
                a = self.inspect(self.a); require(a["source_sequence"] == 1 and a["accepted"] and a["source_head"] == b["source_head"], "original A did not accept exactly once")
                self.act(self.a, "receipt", ["--root", self.a.root + "/owner", "--journal", self.a.root + "/journal", "--sign-key", self.a.root + "/keys/authority.seed", "--out", self.a.root + "/accepted-recovered"])
                require(self.a.read("accepted-recovered") == self.a.read("owner/accepted"), "receipt recovery changed bytes")
                self.checks["a_lost_output_receipt_recovered"] = True
            self.start_target(self.b); self.call(self.request("execute"), fail=True); self.probe("late")
            clone_peer = self.start_target(self.clone, clone=True)
            self.call(self.request("execute"), fail=True, direct=clone_peer); self.stop_target(self.clone)
            clone = self.inspect(self.clone); require(clone["source_sequence"] == 0 and not clone["consumed"], "copied persistent participant reused another session")
            self.checks["copied_persistent_keys_old_claim_refused"] = True
            recovered_request = self.request("recover", unknown=self.scenario == "lost-result"); recovered = self.call(recovered_request)
            self.extract(recovered_request, recovered, "result", "result-recovered")
            require(self.a.read("result") == self.a.read("result-recovered"), "cold recovery refreshed result")
            self.stop_target(self.b); after = self.inspect(self.b); require(after["source_sequence"] == 1 and after["responded_at"] == b["responded_at"], "late replay advanced B")
            self.checks["late_execution_refused"] = True
            return self.report(a, after, clone)
        finally: self.cleanup()

    def run_action_bundle(self, extra):
        self.act(self.a, "bundle", extra)

    def accept_args(self, output):
        return self.args(self.a, "accept", ["--root", self.a.root + "/owner", "--journal", self.a.root + "/journal", "--sign-key", self.a.root + "/keys/authority.seed",
                       "--in", self.a.root + "/bundle", "--in-id", artifact(self.a.read("bundle")), "--out", self.a.root + "/" + output])

    def lose_result(self, request):
        output = "lost-result-" + uuid.uuid4().hex; args = self.call_args(request, output)
        self.relay.rpc("relay.policy", delay_ms=1000)
        client = Supervisor(self.a, {"call": {"argv": [self.a.binary] + args}})
        event={"kind":"target","operation":"execute","request_id":request["id"],"completed":False,"response_lost":True}
        self.events.append(event);self.a.write("attempt-"+uuid.uuid4().hex+".json",json.dumps(event).encode())
        try:
            client.rpc("start", name="call")
            deadline = time.monotonic() + 10
            while not self.marker(self.b, "result"):
                require(time.monotonic() < deadline, "B did not retain result before controlled response cut")
                time.sleep(.03)
            self.relay.rpc("relay.policy", mode="drop-reverse")
            require(client.rpc("wait", name="call", timeout=20)["returncode"] != 0, "response escaped controlled network cut")
            require(not self.a.execute(["python3", "-c", "import os,sys; print(int(os.path.exists(sys.argv[1])))", self.a.root + "/" + output]).stdout.strip() == b"1", "client retained a supposedly lost response")
            stats = self.relay.rpc("relay.stats"); require(stats["counters"].get("reverse_partition_drops", 0) > 0 or stats["counters"].get("policy_queue_drops", 0) > 0, "no reverse packets were dropped")
            self.checks["result_reply_cut_after_durable_b"] = True; self.relay_cut_stats = stats
        finally: close_supervisor(client)
        self.stop_target(self.b, kill=True); state = self.inspect(self.b); require(state["source_sequence"] == 1 and state["result"], "SIGKILL lost retained B result")
        self.checks["target_sigkill_result_retained"] = True
        self.start_target(self.b); self.relay.rpc("relay.policy")
        self.call(request, fail=True)
        return None

    def lost_session(self):
        self.stop_target(self.b, kill=True); before = self.inspect(self.b); require(before["source_sequence"] == 0 and not before["consumed"], "pre-execution kill had an effect")
        self.start_target(self.b); self.call(self.request("execute"), fail=True)
        request = self.request("prepare"); response = self.call(request); self.extract(request, response, "claim", "new-session-command")
        require(command_id(self.a.read("new-session-command")) != command_id(self.a.read("claim-command")), "new process reused old volatile session")
        self.wcall(self.members[0], command="new-session-command", before={"sequence": 0, "head": self.scope, "pending": ZERO}, fail=True)
        self.unknown(); self.call(self.request("recover", unknown=True), fail=True)
        self.stop_target(self.b); b = self.inspect(self.b); a = self.inspect(self.a)
        require(a["source_sequence"] == b["source_sequence"] == 0 and not b["consumed"] and not b["result"], "lost session fabricated a result")
        self.checks.update(target_sigkill_before_effect=True, old_live_session_claim_refused=True, unknown_without_result_held=True)
        return self.report(a, b, self.inspect(self.clone))

    def report(self, a, b, clone):
        for member in self.members: member.stop()
        final = [member.inspect() for member in self.members]
        phase = 2 if self.scenario == "lost-session" else 3
        sequence = phase if self.scenario != "expired-result" else 2
        require(all(s["phase"] == phase and s["sequence"] == sequence and s["held"] and s["session"] != ZERO for s in final), "witness history lost its obligation/session")
        require(all(self.inspect(self.hosts[name])["original_identities_sha256"] == identity for name, identity in self.identities.items()), "original root/lock identity changed")
        self.checks["original_owner_identities_preserved"] = True
        return {"scenario": self.scenario, "scope_id": self.scope, "context_id": self.public["ContextID"], "checks": self.checks,
                "observed_kernel_boot_sha256": self.boots, "original_identity_pins": self.identities, "a": a, "b": b, "clone": clone, "witnesses": final,
                "events": self.events, "relay_cut": getattr(self, "relay_cut_stats", None), "passed": True,
                "independent_four_domain_deployment": False, "serve_resolved": False}

    def cleanup(self):
        errors = []
        for h in (self.b, self.clone):
            try: self.stop_target(h)
            except (AcceptanceError, OSError) as e: errors.append(str(e))
        for member in self.members:
            try: member.stop()
            except (AcceptanceError, OSError) as e: errors.append(str(e))
        if self.relay is not None:
            relay, self.relay = self.relay, None
            try: relay.rpc("relay.stop")
            except (AcceptanceError, OSError) as e: errors.append(str(e))
            try: close_supervisor(relay)
            except (AcceptanceError, OSError) as e: errors.append(str(e))
        self.cleanup_complete = not errors
        require(not errors, "V2 cleanup failed: " + "; ".join(errors))


def validate(report):
    require(report.get("schema_version") == 1 and report.get("passed") is True, "incomplete V2 WAN campaign")
    cases = report.get("cases", [])
    require(len(cases) == 3 and {c["scenario"] for c in cases} == set(SCENARIOS), "missing V2 failure class")
    require(len({c["scope_id"] for c in cases}) == 3, "a failed scope was reinitialized")
    for c in cases:
        require(c["passed"] and not c["independent_four_domain_deployment"] and not c["serve_resolved"], "campaign overstated its guarantees")
        require(c["observed_kernel_boot_sha256"]["a"] != c["observed_kernel_boot_sha256"]["b"], "same kernel used twice")
        required={"sources_initially_zero","two_witnesses_not_quorum","duplicate_member_not_quorum","witness_sigkill_exact_vote_recovered","no_effect_before_claim","original_owner_identities_preserved"}
        if c["scenario"]=="lost-session":required|={"target_sigkill_before_effect","old_live_session_claim_refused","unknown_without_result_held"}
        else:required|={"probe_weak_refused","probe_wrong-scope_refused","probe_legacy_refused","probe_late_refused","exact_result_bytes_retained","copied_persistent_keys_old_claim_refused","late_execution_refused"}
        if c["scenario"]=="lost-result":required|={"result_reply_cut_after_durable_b","target_sigkill_result_retained","a_lost_output_receipt_recovered"}
        if c["scenario"]=="expired-result":required.add("expired_result_not_accepted")
        require(required<=set(c["checks"]),"missing required scenario evidence")
        require(all(c["checks"].values()) and len(c["witnesses"]) == 4 and all(w["held"] for w in c["witnesses"]), "missing check or retained obligation")
        require(c["checks"].get("two_witnesses_not_quorum") and c["checks"].get("duplicate_member_not_quorum") and c["checks"].get("witness_sigkill_exact_vote_recovered"), "missing quorum/restart evidence")
        phase=2 if c["scenario"]=="lost-session" else 3
        sequence=3 if c["scenario"]=="lost-result" else 2
        require(all(w["phase"]==phase and w["sequence"]==sequence and w["session"]!=ZERO for w in c["witnesses"]),"wrong final witness phase")
        require(len({w["session"] for w in c["witnesses"]})==len({w["head"] for w in c["witnesses"]})==1,"witnesses disagree on selected session/history")
        pins=[{"sequence":0,"head":c["scope_id"],"pending":ZERO} for _ in range(4)]
        count=0
        for e in c["events"]:
            require(e.get("kind") in ("witness","target") and re.fullmatch("[0-9a-f]{64}",e["request_id"]) is not None,"invalid event")
            if e["kind"]!="witness":continue
            i=e["member"];require(type(i) is int and 0<=i<4,"invalid member")
            if not e["completed"]:require(e.get("refused") is True,"unclassified witness outcome");continue
            require(e["before"]==pins[i],"witness before pin changed")
            after=e["after"]
            if e.get("command_id"):
                require(after["sequence"]==pins[i]["sequence"] and after["head"]==pins[i]["head"] and after["pending"]==e["command_id"],"invalid vote advance")
            else:
                require(e.get("certificate") and after["sequence"]==pins[i]["sequence"]+1 and after["pending"]==ZERO,"invalid certificate advance")
            pins[i]={k:after[k] for k in ("sequence","head","pending")};count+=1
        require(count >= (22 if c["scenario"] == "lost-result" else 15),"incomplete witness transcript")
        require(all(pins[i]["sequence"]==w["sequence"] and pins[i]["head"]==w["head"] and pins[i]["pending"]==ZERO for i,w in enumerate(c["witnesses"])),"final witness state lacks transcript")
        require(all(c[name]["original_identities_sha256"]==pin for name,pin in c["original_identity_pins"].items()) and set(c["original_identity_pins"])=={"a","b"},"original identity pin changed")
        expected = 0 if c["scenario"] == "lost-session" else 1
        require(c["b"]["source_sequence"] == expected and c["clone"]["source_sequence"] == 0, "unexpected execution count")
        require(c["a"]["source_sequence"] == int(c["scenario"] == "lost-result"), "unexpected original source acceptance")
        if c["scenario"] == "lost-result": require(c["a"]["source_head"] == c["b"]["source_head"] and c["a"]["accepted"], "accepted result not shared")
    return {"scenarios": 3, "joint_hosts": 2, "logical_witnesses": 4, "serve_obligations_released": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--config", required=True); parser.add_argument("--out", required=True)
    args = parser.parse_args(); config = json.loads(Path(args.config).read_text()); cases = []
    for scenario in SCENARIOS:
        print("custody_v2_wan_start " + scenario, flush=True)
        case = Case(config, scenario)
        try:
            result = case.run(); require(case.cleanup_complete, "incomplete cleanup"); cases.append(result)
        except BaseException as exc:
            publish_report(args.out+".failed-"+uuid.uuid4().hex,{"schema_version":1,"passed":False,"failed_scenario":scenario,"scope_id":case.scope,"completed_cases":cases,"cleanup_complete":case.cleanup_complete,"error":str(exc)})
            raise
        print("custody_v2_wan_pass " + scenario, flush=True)
    report = {"schema_version": 1, "passed": True, "cases": cases, "source_manifest": config["source_manifest"], "binaries": config["expected_binaries"]}
    report["summary"] = validate(report); publish_report(args.out, report)
    print("custody_v2_wan_complete " + json.dumps(report["summary"], sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
