#!/usr/bin/env python3
"""Drive an explicit acceptance fixture over local/SSH dedicated pipes.

Configuration contains existing SSH argv (keys/agent/control sockets), never a
password. Each role receives its own fresh bootstrap and local authority domain.
This is a test runner, not a distributed authority or a production daemon.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import subprocess
import sys
import time
import uuid


ZERO = "0" * 64
MAX_OUTPUT = 4 * 1024 * 1024


class AcceptanceError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise AcceptanceError(message)


def fields(text, prefix):
    for line in text.splitlines():
        if line.startswith(prefix + " "):
            return dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
    raise AcceptanceError("missing output record: " + prefix)


def digest_id(value):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) and value != ZERO,
            "missing canonical nonzero content ID")
    return value


def interpolate(argv, values):
    def item(text):
        for key, value in values.items():
            text = text.replace("{" + key + "}", value)
        require(re.search(r"\{[A-Z_]+\}", text) is None, "unresolved command placeholder")
        require("\x00" not in text and "\n" not in text and "\r" not in text,
                "invalid command argument")
        return text
    return [item(text) for text in argv]


def archive_command(source):
    # Do not use the platform tar producer: macOS may add AppleDouble entries
    # for filesystem attributes. Those extra files correctly invalidate an
    # existing-only journal. Transfer the fixture's actual paths and bytes only.
    script = ("import sys,tarfile\n"
              "with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:\n"
              " archive.add(sys.argv[1],arcname='.')\n")
    return [sys.executable, "-c", script, str(source)]


class Host:
    def __init__(self, config):
        self.config = dict(config)
        self.local = config["kind"] == "local"
        require(self.local or config["kind"] == "ssh", "unsupported host kind")
        for key in ("root", "binary", "test_binary", "support"):
            require(os.path.isabs(config[key]), "host paths must be absolute")
            if self.local:
                self.config[key] = os.path.realpath(config[key])
        self.root = self.config["root"]
        self.binary = self.config["binary"]
        self.test_binary = self.config["test_binary"]
        self.hashes = {}

    def command(self, argv, env=None):
        if env:
            argv = ["env"] + [key + "=" + value for key, value in env.items()] + list(argv)
        if self.local:
            return argv
        return list(self.config["ssh"]) + [shlex.join(argv)]

    def execute(self, argv, env=None, input_bytes=None, timeout=45, check=True):
        result = subprocess.run(self.command(list(argv), env), input=input_bytes,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        require(len(result.stdout) + len(result.stderr) <= MAX_OUTPUT, "command output exceeds bound")
        if check and result.returncode:
            raise AcceptanceError("remote command failed (%d): %s" %
                                  (result.returncode, result.stderr.decode("utf-8", "replace")[-4096:]))
        return result

    def install(self, source):
        # Copy only the never-started export. Live owners must not be copied.
        for name in ("authority", "authority-pins"):
            require(not (source / name).exists(), "fixture contains an active authority root")
        if self.local:
            Path(self.root).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copytree(source, self.root)
            os.chmod(self.root, 0o700)
            return
        self.execute(["python3", "-c", "import os,sys; os.makedirs(os.path.dirname(sys.argv[1]),mode=0o700,exist_ok=True); os.mkdir(sys.argv[1],0o700)", self.root])
        archive = subprocess.Popen(archive_command(source), stdout=subprocess.PIPE)
        try:
            result = subprocess.run(self.command(["tar", "--no-same-owner", "-xf", "-", "-C", self.root]),
                                    stdin=archive.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
            archive.stdout.close()
            require(archive.wait(timeout=45) == 0 and result.returncode == 0, "fixture transfer failed")
        finally:
            if archive.poll() is None:
                archive.kill()
                archive.wait()

    def read(self, relative):
        path = self.root + "/" + relative
        return self.execute(["python3", "-c", "import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())", path]).stdout

    def write(self, relative, data):
        path = self.root + "/" + relative
        script = ("import os,sys; p=sys.argv[1]; f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); "
                  "b=sys.stdin.buffer.read(); n=os.write(f,b); assert n==len(b); os.fsync(f); os.close(f); "
                  "d=os.open(os.path.dirname(p),os.O_RDONLY); os.fsync(d); os.close(d)")
        self.execute(["python3", "-c", script, path], input_bytes=data)

    def sha256(self, path):
        if path not in self.hashes:
            script = "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())"
            self.hashes[path] = self.execute(["python3", "-c", script, path]).stdout.decode().strip()
        return self.hashes[path]

    def inspect(self):
        out = self.execute([self.test_binary, "-test.run=^TestInspectRemoteCustodyFixture$", "-test.count=1"],
                           {"OUTCOMEMESH_REMOTE_ROLE_ROOT": self.root}).stdout.decode()
        for line in out.splitlines():
            if line.startswith("remote_custody_inspect "):
                return json.loads(line.split(" ", 1)[1])
        raise AcceptanceError("inspection did not produce a retained state")


class Supervisor:
    def __init__(self, host, commands, relay=None):
        self.host, self.request_id, self.closed = host, 0, False
        spec = {"version": 1, "root": host.root, "binary": host.binary,
                "binary_sha256": host.sha256(host.binary), "test_binary": host.test_binary,
                "test_binary_sha256": host.sha256(host.test_binary), "commands": commands}
        if relay is not None:
            spec["relay"] = relay
        name = "supervisor-" + uuid.uuid4().hex + ".json"
        host.write(name, json.dumps(spec, sort_keys=True).encode())
        self.process = subprocess.Popen(host.command(["python3", host.config["support"], "--spec", host.root + "/" + name]),
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        bufsize=0, close_fds=True)
        self.buffer = bytearray()

    def rpc(self, method, **params):
        self.request_id += 1
        request = {"id": self.request_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(request).encode() + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 50
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and select.select([self.process.stdout], [], [], remaining)[0], "supervisor response timed out")
            chunk = os.read(self.process.stdout.fileno(), 65536)
            require(chunk, "supervisor closed its response pipe")
            self.buffer.extend(chunk)
            require(len(self.buffer) <= MAX_OUTPUT, "supervisor response exceeds bound")
        line, _, self.buffer = self.buffer.partition(b"\n")
        response = json.loads(line)
        require(response.get("id") == self.request_id, "supervisor response ID changed")
        if not response.get("ok"):
            raise AcceptanceError("supervisor %s failed: %s" % (method, response.get("error")))
        return response["result"]

    def line(self, name):
        result = self.rpc("next", name=name, timeout=40)
        if result["eof"]:
            raise AcceptanceError("child output closed before its result: " + str(self.rpc("status", name=name)))
        return result["line"]

    def start(self, name, prefix):
        self.rpc("start", name=name)
        return fields(self.line(name), prefix)

    def review(self, name, prefix):
        self.rpc("send", name=name, line="review")
        report = self.rpc("until", name=name, terminator=prefix + "_scope_end\n", timeout=40)
        require(report.get("complete") is True and report["lines"][-1] == prefix + "_scope_end\n",
                "review report was not consumed completely")
        header = fields(report["lines"][0], prefix + "_review")
        require(header.get("owners_retained") == "true", "review lost its original owner")
        return digest_id(header["review_id"])

    def action(self, name, prefix, action, result_suffix="result"):
        token = self.review(name, prefix)
        self.rpc("send", name=name, line=action + " " + token)
        result = fields(self.line(name), prefix + "_" + result_suffix)
        require(result.get("expected_review_id") == token, "action result changed the reviewed token")
        return result

    def stop(self, name):
        self.rpc("send", name=name, line="close")
        require(self.rpc("wait", name=name, timeout=30)["returncode"] == 0, "child close failed")

    def expect_failure(self, name):
        status = self.rpc("wait", name=name, timeout=40)
        require(status["returncode"] not in (None, 0), "partitioned action unexpectedly succeeded")
        return status["returncode"]

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.process.stdin.close()
        try:
            self.process.wait(timeout=35)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
        require(self.process.returncode == 0, "supervisor cleanup failed")


class Role:
    def __init__(self, host, fixture):
        self.host = host
        self.scope = json.loads((fixture / "scope.json").read_text())
        self.commands = json.loads((fixture / "commands.json").read_text())
        self.values = {"ROOT": host.root, "AUDIT_LISTEN": "/ip4/127.0.0.1/udp/43871/quic-v1",
                       "LISTEN": "/ip4/0.0.0.0/udp/43880/quic-v1"}

    def argv(self, name):
        return [self.host.binary] + interpolate(self.commands[name], self.values)

    def once(self, name):
        print("remote_acceptance_step purpose=%s command=%s" % (self.scope["purpose"], name), flush=True)
        return self.host.execute(self.argv(name)).stdout.decode()

    def owned(self, command, action, suffix="result", prefix="work_archive_custody_command"):
        print("remote_acceptance_step purpose=%s command=%s action=%s" % (self.scope["purpose"], command, action), flush=True)
        s = Supervisor(self.host, {"action": {"argv": self.argv(command)}})
        try:
            ready = s.start("action", prefix + "_ready")
            require(ready.get("owners_retained") == "true", "action did not retain owners")
            result = s.action("action", prefix, action, suffix)
            s.stop("action")
            return result
        finally:
            s.close()

    def sign_apply(self, phase):
        header = "work_archive_custody_signing"
        self.values["CONSUMER_REVIEW_ID"] = digest_id(fields(self.once(phase + "-consumer-review"), header)["review_id"])
        self.once(phase + "-consumer-sign")
        self.values["AUTHORITY_REVIEW_ID"] = digest_id(fields(self.once(phase + "-authority-review"), header)["review_id"])
        entry = fields(self.once(phase + "-authority-sign"), header)
        self.values["ADMISSION_ID" if phase == "admit" else "COMPLETION_ID"] = digest_id(entry["entry_id"])
        result = self.owned(phase + "-apply-control", "apply")
        commit = json.loads(result["commit"])
        require(commit["Appended"], "new entry was already applied")

    def complete(self):
        captured = self.owned("terminal-control", "capture")
        require(captured.get("completion_submitted") == "false", "capture implicitly completed ticket")
        self.values["TERMINAL_ID"] = digest_id(captured["terminal_id"])
        self.sign_apply("complete")


def assert_state(a, b, sequence, completed=False):
    for state in (a, b):
        require(not state["pending_attempt"], "authority contains an uncertain attempt")
        require(state["journal_sequence"] == sequence, "unexpected journal sequence")
        require(state["authority_sequence"] == (2 if completed else 1), "unexpected authority transition")
        require(state["phase"] == "accepting" and len(state["operations"]) == 1, "unexpected operation lifecycle")
        operation = state["operations"][0]
        require((operation["completion_id"] != ZERO) == completed, "implicit or missing completion")
    if sequence:
        for key in ("journal_head_id", "current_receipt_id", "head_proof_id", "responded_at", "challenge_id"):
            require(a[key] == b[key], "participants disagree on committed " + key)


def run(config, fixture, scenario):
    a, b = Role(Host(config["hosts"]["a"]), fixture / "role-a"), Role(Host(config["hosts"]["b"]), fixture / "role-b")
    require(a.scope["assignment_id"] != b.scope["assignment_id"] and
            a.scope["authority_public_key"] != b.scope["authority_public_key"] and
            a.scope["consumer_public_key"] != b.scope["consumer_public_key"], "roles share an authority domain")
    for role, directory in ((a, "role-a"), (b, "role-b")):
        role.host.install(fixture / directory)
        role.once("authority-review")
        role.once("authority-create")
        role.once("authority-verify")
    a.sign_apply("admit")
    prepared = a.owned("prepare-control", "prepare", "prepared", "work_archive_custody_managed_audit")
    challenge_id = digest_id(prepared["challenge_id"])
    for role in (a, b):
        role.values["CHALLENGE_ID"] = challenge_id
    b.host.write(b.scope["paths"]["challenge"], a.host.read(a.scope["paths"]["challenge"]))
    b.sign_apply("admit")

    gate = scenario in ("partition-after-replica", "expired-proof")
    gate_args = b.argv("serve")[1:]
    b.host.write("gate-args.json", json.dumps(gate_args).encode())
    server = Supervisor(b.host, {
        "serve": {"argv": b.argv("serve")},
        "gate": {"argv": [b.host.test_binary, "-test.run=^TestRemoteCustodyGatedServeHelper$", "-test.count=1"],
                 "env": {"OMESH_REMOTE_GATE_ARGS": b.host.root + "/gate-args.json"}}})
    auditor = None
    evidence = {"version": 1, "scenario": scenario, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "scope": "independent local Audit and Serve authorities over actual QUIC; no distributed freshness or physical-independence claim",
                "assignment_a": a.scope["assignment_id"], "assignment_b": b.scope["assignment_id"], "challenge_id": challenge_id,
                "binary_a_sha256": a.host.sha256(a.host.binary), "binary_b_sha256": b.host.sha256(b.host.binary),
                "test_binary_a_sha256": a.host.sha256(a.host.test_binary), "test_binary_b_sha256": b.host.sha256(b.host.test_binary)}
    try:
        server_name = "gate" if gate else "serve"
        ready = server.start(server_name, "remote_custody_gate_ready" if gate else "work_archive_custody_managed_serve_ready")
        suffix = ready["listen"].split(",")[0].split("/p2p/")[-1]
        require(suffix != ready["listen"], "server did not advertise authenticated identity")
        a.values["PEER"] = "/ip4/127.0.0.1/udp/43872/quic-v1/p2p/" + suffix
        relay = {"front": ["127.0.0.1", 43872], "allowed_client": ["127.0.0.1", 43871],
                 "upstream": [config["hosts"]["b"]["public_ip"], 43880]}
        auditor = Supervisor(a.host, {"audit": {"argv": a.argv("audit-control")}}, relay)
        auditor.rpc("relay.start")
        if scenario == "loss-delay":
            auditor.rpc("relay.policy", mode="pass", drop_every=7, delay_ms=40)
        elif scenario == "partition-before":
            auditor.rpc("relay.policy", mode="drop")
        auditor.start("audit", "work_archive_custody_managed_audit_ready")
        token = auditor.review("audit", "work_archive_custody_managed_audit")
        auditor.rpc("send", name="audit", line="audit " + token)
        if gate:
            marker = fields(server.line("gate"), "remote_custody_gate")
            require(marker.get("journal_committed") == "true", "fault gate preceded replica commit")
            auditor.rpc("relay.policy", mode="drop")
            server.rpc("send", name="gate", line="release")
        if scenario in ("partition-before", "partition-after-replica", "expired-proof"):
            evidence["partition_exit"] = auditor.expect_failure("audit")
            if gate:
                server.rpc("kill", name="gate")
                require(server.rpc("wait", name="gate", timeout=30)["returncode"] not in (None, 0), "replica was not killed")
            else:
                server.stop("serve")
            before_a, before_b = a.host.inspect(), b.host.inspect()
            evidence["after_partition"] = {"a": before_a, "b": before_b}
            require(before_a["journal_sequence"] == 0 and before_b["journal_sequence"] == (1 if gate else 0), "partition committed wrong journals")
            for state in (before_a, before_b):
                require(state["authority_sequence"] == 1 and state["operations"][0]["completion_id"] == ZERO,
                        "failed exchange changed authority")
            if scenario == "expired-proof":
                deadline = before_b["responded_at"] + b.scope["maximum_proof_age_seconds"] + 2
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    print("waiting_for_original_proof_expiry seconds=%d" % remaining, flush=True)
                    time.sleep(min(15, remaining))
            server.start("serve", "work_archive_custody_managed_serve_ready")
            auditor.rpc("relay.policy", mode="pass")
            auditor.start("audit", "work_archive_custody_managed_audit_ready")
            if scenario == "expired-proof":
                token = auditor.review("audit", "work_archive_custody_managed_audit")
                auditor.rpc("send", name="audit", line="audit " + token)
                auditor.expect_failure("audit")
                server.stop("serve")
                final_a, final_b = a.host.inspect(), b.host.inspect()
                require(final_a == before_a and final_b == before_b, "expired retry refreshed or changed retained evidence")
                evidence["expired_retry_rejected"] = True
                evidence["final"] = {"a": final_a, "b": final_b}
                evidence["relay"] = auditor.rpc("relay.stats")
                evidence["passed"] = True
                return evidence
            result = auditor.action("audit", "work_archive_custody_managed_audit", "audit")
        else:
            result = fields(auditor.line("audit"), "work_archive_custody_managed_audit_result")
            require(result.get("expected_review_id") == token, "audit changed reviewed token")
        require(result.get("sequence") == "1" and result.get("completion_submitted") == "false", "invalid accepted audit")
        auditor.stop("audit")
        server.stop("serve" if scenario in ("partition-before", "partition-after-replica") else server_name)
        after_a, after_b = a.host.inspect(), b.host.inspect()
        assert_state(after_a, after_b, 1)
        if gate:
            for key in ("journal_head_id", "head_proof_id", "responded_at", "current_receipt_id"):
                require(after_b[key] == evidence["after_partition"]["b"][key], "recovery minted a new response")
        evidence["accepted"] = {"a": after_a, "b": after_b}
        evidence["relay"] = auditor.rpc("relay.stats")
        # Remove the route itself: teardown retransmissions cannot be mistaken
        # for new recovery traffic, and recovery must succeed without a peer.
        auditor.rpc("relay.stop")
        auditor.start("audit", "work_archive_custody_managed_audit_ready")
        recovered = auditor.action("audit", "work_archive_custody_managed_audit", "recover")
        auditor.stop("audit")
        require(recovered.get("recovered") == "true" and recovered["proof_id"] == result["proof_id"], "offline recovery changed result")
        a.complete()
        b.complete()
        final_a, final_b = a.host.inspect(), b.host.inspect()
        assert_state(final_a, final_b, 1, True)
        retry = a.owned("complete-apply-control", "apply")
        require(json.loads(retry["commit"])["Appended"] is False, "exact completion retry appended again")
        evidence["final"] = {"a": final_a, "b": final_b}
        evidence["offline_recovery"] = True
        evidence["offline_route_removed"] = True
        evidence["passed"] = True
        return evidence
    finally:
        if auditor is not None:
            auditor.close()
        server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--scenario", choices=("healthy", "partition-before", "partition-after-replica", "loss-delay", "expired-proof"), required=True)
    args = parser.parse_args()
    started = time.monotonic()
    try:
        result = run(json.loads(Path(args.config).read_text()), Path(args.fixture), args.scenario)
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as target:
            json.dump(result, target, indent=2, sort_keys=True)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        print("remote_acceptance scenario=%s passed=true report=%s" % (args.scenario, args.out))
    except Exception as error:
        print("remote_acceptance scenario=%s passed=false error=%s" % (args.scenario, error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
