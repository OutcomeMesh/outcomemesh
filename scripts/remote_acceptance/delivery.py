#!/usr/bin/env python3
"""Deliver required admission proofs between two hosts before owner creation.

The receiver retains proof only. A lost sender output, offline receiver and cold
receiver restart recover the same signed acknowledgement through immutable
outboxes. The required execution/Serve/accounting fault matrix follows normally.
Fixture/operator copies are retained; the original B owner explicitly consumes
the binding exported from the delivered inbox. No legacy owner is migrated.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

from run import Supervisor, ZERO, fields, require
from v1 import close_supervisor, publish_report
from v2 import artifact, digest, once, transfer
from serve import broken
import required


CLI = "work-archive-custody-v2-delivery"
PROTOCOL = "/outcomemesh/custody/v2/admission-delivery"
DOMAIN = "OMESH/custody/v2/required/admission-delivery"
CHECKS = {"inbox_enrolled_before_receive", "outbox_durable_before_dispatch",
          "sender_stdout_lost_after_confirmation", "cold_outbox_receipt_exact",
          "receiver_sigkill_same_enrollment_reopened", "offline_send_stays_unresolved",
          "exact_intent_retry_original_receipt", "received_binding_export_exact",
          "original_sources_unchanged_by_delivery", "no_owner_or_session_created_by_delivery",
          "wrong_delivery_pin_refused", "required_target_uses_received_binding"}


def public_id(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) and value != ZERO


def decode_enrollment(raw):
    require(type(raw) is bytes and len(raw) == 267 and raw[:10] == b"OMCVDEN2\0\2", "wrong delivery enrollment framing")
    names = ("context_id", "scope_id", "binding_id", "sender_peer_id", "recipient_peer_id", "placement_id", "nonce")
    out = {name: raw[10 + 32 * i:42 + 32 * i].hex() for i, name in enumerate(names)}
    require(all(public_id(value) for value in out.values()) and out["sender_peer_id"] != out["recipient_peer_id"] and raw[234] in (1, 2), "invalid enrollment identity or role")
    out.update(role=raw[234], receipt_public_key=raw[235:267].hex(), enrollment_id=digest(DOMAIN + "/enrollment/id", raw))
    require(public_id(out["receipt_public_key"]), "missing receipt role key")
    return out


def decode_receipt(raw):
    # Normal Go sender/receiver CLI verifies the signature and complete proof.
    # This strict decoder records the exact public IDs independently.
    require(type(raw) is bytes and len(raw) == 235 and raw[:10] == b"OMCVDAR2\0\2", "wrong delivery receipt framing")
    names = ("delivery_id", "enrollment_id", "context_id", "scope_id", "binding_id")
    out = {name: raw[10 + 32 * i:42 + 32 * i].hex() for i, name in enumerate(names)}
    require(all(public_id(value) for value in out.values()) and raw[170] in (1, 2) and any(raw[171:]), "missing receipt identity/signature")
    out.update(role=raw[170], receipt_id=digest(DOMAIN + "/receipt/id", raw), sha256=hashlib.sha256(raw).hexdigest())
    return out


def reviewed(host, args):
    record = once(host, args, "custody_v2_delivery_review")
    require(record["keys_loaded"] == record["stores_opened"] == record["execution_granted"] == "false" and record["proof_only"] == "true", "delivery review crossed a private/effect boundary")
    return args + ["--mode", "run", "--expected-review-id", record["review_id"]]


def unchanged(before, after):
    return {role: {k: v for k, v in value.items() if k != "now"} for role, value in before.items()} == \
           {role: {k: v for k, v in value.items() if k != "now"} for role, value in after.items()}


class DeliveryCase(required.RequiredCase):
    def prepare_context(self):
        super().prepare_context()
        self.delivery_server = None
        self.delivery_checks, self.delivery_artifacts = {}, []
        port = self.config.get("delivery_port")
        occupied = {self.config[name] for name in ("relay_port", "client_port", "target_port")}
        occupied |= {self.config["target_port"] + 1} | set(range(self.config["witness_port"], self.config["witness_port"] + 4))
        require(type(port) is int and 1024 <= port <= 65535 and port not in occupied, "delivery_port must be an explicit distinct test UDP port")
        self.delivery_port = port
        self.delivery_before = {role: self.inspect(h) for role, h in (("a", self.a), ("b", self.b), ("clone", self.clone))}
        try:
            self.deliver_binding()
        finally:
            self.stop_delivery()
        self.delivery_after = {role: self.inspect(h) for role, h in (("a", self.a), ("b", self.b), ("clone", self.clone))}
        require(unchanged(self.delivery_before, self.delivery_after), "delivery altered an original source or owner")
        require(all(value["source_sequence"] == 0 and not value["consumed"] and not value["result"] and not value["accepted"] for value in self.delivery_after.values()), "delivery crossed the execution boundary")
        for h in (self.a, self.b, self.clone):
            exists = h.execute(["python3", "-c", "import os,sys;print(int(os.path.exists(sys.argv[1])))", h.root + "/owner"]).stdout.strip()
            require(exists == b"0", "delivery created a runtime owner")
        self.delivery_checks["original_sources_unchanged_by_delivery"] = True
        self.delivery_checks["no_owner_or_session_created_by_delivery"] = True

    def delivery_args(self, h, action, extra=()):
        return [CLI, "--action", action, "--context", h.root + "/context", "--context-id", self.public["ContextID"],
                "--scope-id", self.scope, "--binding-id", self.binding_id] + list(extra)

    def delivery_act(self, h, action, extra=(), lose=False, fail=False):
        args = self.delivery_args(h, action, extra)
        args = reviewed(h, args)
        if lose:
            broken(h, args)
        else:
            result = once(h, args, check=not fail)
            if fail:
                require(result.returncode != 0, "failed delivery attempt was confirmed")
                return result
            prefix = "custody_v2_delivery_created" if action == "outbox-create" else "custody_v2_delivery_artifact"
            record = fields(result.stdout.decode(), prefix)
            require(record["execution_granted"] == "false", "delivery granted execution")
        if "--out" in extra:
            name = extra[list(extra).index("--out") + 1]
            self.track(h, name[len(h.root) + 1:])

    def track(self, h, name):
        self.delivery_artifacts.append({"host": "a" if h.root == self.a.root else "b", "path": h.root + "/" + name,
                                        "sha256": hashlib.sha256(h.read(name)).hexdigest()})

    def inbox(self):
        return ["--root", self.b.root + "/delivery-inbox", "--journal", self.b.root + "/journal", "--objects", self.b.root + "/objects",
                "--enrollment", self.b.root + "/delivery-enrollment", "--enrollment-id", self.enrollment["enrollment_id"],
                "--sign-key", self.b.root + "/keys/control.seed"]

    def outbox(self, name):
        return ["--root", self.a.root + "/" + name, "--delivery", self.a.root + "/delivery-intent", "--delivery-id", self.delivery_id,
                "--address", self.delivery_address]

    def start_delivery(self):
        args = self.delivery_args(self.b, "inbox-serve", self.inbox() + ["--transport-key", self.b.root + "/keys/transport.seed",
                   "--listen", "/ip4/0.0.0.0/udp/%d/quic-v1" % self.delivery_port, "--timeout", "15s"])
        self.delivery_server = Supervisor(self.b, {"delivery": {"argv": [self.b.binary] + reviewed(self.b, args)}})
        record = self.delivery_server.start("delivery", "custody_v2_delivery_serving")
        require(record["enrollment_id"] == self.enrollment["enrollment_id"] and record["peer_id"] == self.enrollment["recipient_peer_id"] and
                record["execution_granted"] == "false" and record["proof_only"] == "true", "delivery service changed enrollment or permission")
        return "/ip4/%s/udp/%d/quic-v1/p2p/%s" % (self.b.config["public_ip"], self.delivery_port, record["address"].rsplit("/p2p/", 1)[1])

    def stop_delivery(self, kill=False):
        server, self.delivery_server = self.delivery_server, None
        if server is None:
            return
        try:
            if kill:
                server.rpc("kill", name="delivery")
                require(server.rpc("wait", name="delivery", timeout=15)["returncode"] == -9, "delivery receiver SIGKILL was not observed")
            else:
                server.stop("delivery")
        finally:
            close_supervisor(server)

    def deliver_binding(self):
        a, b = self.a, self.b
        peer = digest("OMESH/p2p/ed25519/v0", bytes.fromhex(self.public["Keys"]["transport"]))
        self.delivery_act(b, "inbox-create", ["--root", b.root + "/delivery-inbox", "--role", "target", "--journal", b.root + "/journal",
                          "--objects", b.root + "/objects", "--recipient-peer-id", peer, "--out", b.root + "/delivery-enrollment"])
        self.enrollment = decode_enrollment(b.read("delivery-enrollment"))
        require(self.enrollment["context_id"] == self.public["ContextID"] and self.enrollment["scope_id"] == self.scope and
                self.enrollment["binding_id"] == self.binding_id and self.enrollment["recipient_peer_id"] == peer and
                self.enrollment["sender_peer_id"] == self.public["Keys"]["client-peer"] and self.enrollment["role"] == 2 and
                self.enrollment["receipt_public_key"] == self.public["Keys"]["control"], "enrollment selected another job or role")
        self.delivery_checks["inbox_enrolled_before_receive"] = True
        transfer(b, a, "delivery-enrollment")
        self.delivery_act(a, "delivery", ["--binding", a.root + "/required-binding", "--enrollment", a.root + "/delivery-enrollment",
                          "--enrollment-id", self.enrollment["enrollment_id"], "--out", a.root + "/delivery-intent"])
        self.delivery_id = digest(DOMAIN + "/id", a.read("delivery-intent"))
        self.delivery_address = self.start_delivery()
        wrong = self.delivery_args(a, "outbox-create", ["--root", a.root + "/delivery-wrong-pin", "--delivery", a.root + "/delivery-intent",
                                   "--delivery-id", "f" * 64, "--address", self.delivery_address])
        require(once(a, wrong, check=False).returncode != 0, "wrong delivery semantic pin was accepted")
        self.delivery_checks["wrong_delivery_pin_refused"] = True
        self.delivery_act(a, "outbox-create", self.outbox("delivery-outbox"))
        self.delivery_checks["outbox_durable_before_dispatch"] = True
        send = ["--transport-key", a.root + "/keys/client.seed", "--listen", "/ip4/0.0.0.0/udp/0/quic-v1", "--timeout", "15s"]
        self.delivery_act(a, "outbox-send", self.outbox("delivery-outbox") + send + ["--out", a.root + "/delivery-sender-first"], lose=True)
        first = a.read("delivery-sender-first")
        self.delivery_receipt = decode_receipt(first)
        self.delivery_checks["sender_stdout_lost_after_confirmation"] = True
        self.delivery_act(a, "outbox-receipt", self.outbox("delivery-outbox") + ["--out", a.root + "/delivery-sender-cold"])
        require(a.read("delivery-sender-cold") == first, "cold sender readback changed receipt")
        self.delivery_checks["cold_outbox_receipt_exact"] = True
        self.stop_delivery(kill=True)
        self.delivery_act(b, "inbox-receipt", self.inbox() + ["--out", b.root + "/delivery-receiver-cold"])
        self.delivery_act(b, "inbox-binding", self.inbox() + ["--out", b.root + "/received-binding"])
        require(b.read("delivery-receiver-cold") == first and b.read("received-binding") == a.read("required-binding"), "cold receiver changed retained proof or receipt")
        self.delivery_checks["receiver_sigkill_same_enrollment_reopened"] = True
        self.delivery_checks["received_binding_export_exact"] = True
        # A fresh local proof-delivery outbox is allowed, but it must carry the
        # same immutable delivery. Its failed offline send remains unresolved.
        self.delivery_act(a, "outbox-create", self.outbox("delivery-retry-outbox"))
        offline = ["--transport-key", a.root + "/keys/client.seed", "--listen", "/ip4/0.0.0.0/udp/0/quic-v1", "--timeout", "750ms"]
        self.delivery_act(a, "outbox-send", self.outbox("delivery-retry-outbox") + offline + ["--out", a.root + "/delivery-offline-absent"], fail=True)
        self.delivery_act(a, "outbox-receipt", self.outbox("delivery-retry-outbox") + ["--out", a.root + "/delivery-offline-no-receipt"], fail=True)
        self.delivery_checks["offline_send_stays_unresolved"] = True
        require(self.start_delivery() == self.delivery_address, "cold receiver changed its reviewed route")
        self.delivery_act(a, "outbox-send", self.outbox("delivery-retry-outbox") + send + ["--out", a.root + "/delivery-sender-retry"])
        require(a.read("delivery-sender-retry") == first, "exact retry fabricated another receiver acknowledgement")
        self.delivery_checks["exact_intent_retry_original_receipt"] = True
        self.track(b, "delivery-inbox/delivery")
        self.track(b, "delivery-inbox/receipt")
        for name in ("delivery-outbox/receipt", "delivery-retry-outbox/receipt"):
            self.track(a, name)

    def args(self, h, action, extra=()):
        args = super().args(h, action, extra)
        if action in required.OWNER_ACTIONS and h.root == self.b.root:
            args[args.index("--binding") + 1] = h.root + "/received-binding"
        return args

    def create_owners(self):
        super().create_owners()
        require(self.b.read("owner/admission") == self.b.read("received-binding"), "original target did not retain delivered binding")
        self.delivery_checks["required_target_uses_received_binding"] = True

    def delivery_report(self):
        return {"proof_only": True, "execution_granted": False, "runtime_owner_created_by_delivery": False,
                "protocol": PROTOCOL, "context_id": self.public["ContextID"], "scope_id": self.scope, "binding_id": self.binding_id,
                "enrollment": self.enrollment, "delivery_id": self.delivery_id, "receipt": self.delivery_receipt,
                "route_sha256": hashlib.sha256(self.delivery_address.encode()).hexdigest(), "network_attempts": 3,
                "outboxes": 2, "receivers": 1, "checks": copy.deepcopy(self.delivery_checks), "sources_before": self.delivery_before,
                "sources_after": self.delivery_after, "artifacts": copy.deepcopy(self.delivery_artifacts),
                "observed_kernel_boot_sha256": copy.deepcopy(self.boots), "cleanup_complete": self.delivery_server is None}


def validate(report):
    summary = required.validate(report)
    require(report.get("durable_admission_delivery") is True, "campaign omitted durable delivery")
    enrollments, deliveries = set(), set()
    for case in report["cases"]:
        d = case.get("delivery", {})
        require(d.get("proof_only") is True and d.get("execution_granted") is False and d.get("runtime_owner_created_by_delivery") is False and
                d.get("cleanup_complete") is True and d.get("protocol") == PROTOCOL, "delivery overstated execution/currentness or left receiver active")
        require(d.get("context_id") == case["context_id"] and d.get("scope_id") == case["scope_id"] and d.get("binding_id") == case["binding_id"], "delivery selected another admitted job")
        require(CHECKS <= d.get("checks", {}).keys() and all(value is True for value in d["checks"].values()), "missing delivery fault check")
        require(d.get("network_attempts") == 3 and d.get("outboxes") == 2 and d.get("receivers") == 1, "delivery attempt/receiver provenance changed")
        e, r = d.get("enrollment", {}), d.get("receipt", {})
        for key in ("context_id", "scope_id", "binding_id"):
            require(e.get(key) == r.get(key) == case[key], "delivery enrollment/receipt job binding changed")
        for value in (d.get("delivery_id"), d.get("route_sha256"), e.get("enrollment_id"), e.get("sender_peer_id"), e.get("recipient_peer_id"),
                      e.get("placement_id"), e.get("nonce"), e.get("receipt_public_key"), r.get("receipt_id"), r.get("sha256")):
            require(public_id(value), "missing delivery public identity")
        require(e["sender_peer_id"] != e["recipient_peer_id"] and e.get("role") == r.get("role") == 2 and
                e["enrollment_id"] == r.get("enrollment_id") and d["delivery_id"] == r.get("delivery_id"), "receipt/enrollment role or exact intent changed")
        require(d.get("observed_kernel_boot_sha256") == case["execution"]["observed_kernel_boot_sha256"], "delivery did not use the observed two hosts")
        require(unchanged(d.get("sources_before", {}), d.get("sources_after", {})) and set(d.get("sources_before", {})) == {"a", "b", "clone"}, "delivery changed original source state")
        require(all(value["source_sequence"] == 0 and not value["consumed"] and not value["result"] and not value["accepted"] for value in d["sources_after"].values()), "delivery produced a custody effect")
        artifacts = d.get("artifacts", [])
        require(len(artifacts) >= 10 and {a.get("host") for a in artifacts} == {"a", "b"} and all(public_id(a.get("sha256")) and type(a.get("path")) is str for a in artifacts), "delivery transcript lacks exact public artifacts")
        enrollments.add(e["enrollment_id"]); deliveries.add(d["delivery_id"])
    require(len(enrollments) == len(deliveries) == 2, "fresh jobs reused delivery enrollment or intent")
    return dict(summary, durable_proof_deliveries=2, proof_delivery_network_attempts=6,
                delivery_source_appends=0, delivery_execution_granted=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True); parser.add_argument("--out", required=True)
    args = parser.parse_args(); config = json.loads(Path(args.config).read_text()); cases = []
    for scenario in required.SCENARIOS:
        print("custody_delivery_start " + scenario, flush=True)
        case = DeliveryCase(config, scenario)
        try:
            execution = case.run(); case.binding_after_job()
            service = required.RequiredServe(case); states = service.close() if scenario == "lost-result" else service.held()
            ledger = required.accounting_final(case, scenario == "lost-result")
            source_after = {role: case.inspect(h) for role, h in (("a", case.a), ("b", case.b), ("clone", case.clone))}
            require(unchanged(source_after, {role: execution[role] for role in source_after}), "accounting changed original source history")
            case.required_checks["accounting_does_not_change_source"] = True
        finally:
            case.stop_delivery()
            case.cleanup()
        case.admission_report["cleanup_complete"] = case.cleanup_complete
        cases.append({"scenario": scenario, "scope_id": case.scope, "context_id": case.public["ContextID"], "plan_id": case.public["PlanID"],
                      "genesis_id": case.admission.gid, "binding_id": case.binding_id, "binding_artifact_id": artifact(case.a.read("required-binding")),
                      "checks": case.required_checks, "admission_before_runtime": case.admission_report, "execution": execution,
                      "serve": service.report(scenario, states), "accounting_final": ledger, "sources_after_accounting": source_after,
                      "delivery": case.delivery_report(), "roots": {"a": case.a.root, "b": case.b.root}, "cleanup_complete": case.cleanup_complete,
                      "runtime_admission_enforced": True, "legacy_v1_migrated": False, "independent_four_domain_deployment": False, "passed": True})
        publish_report(args.out + ".checkpoint-" + case.nonce, {"schema_version": 1, "passed": False, "completed_cases": cases})
        print("custody_delivery_pass " + scenario, flush=True)
    report = {"schema_version": 1, "passed": True, "durable_admission_delivery": True, "cases": cases,
              "source_manifest": config["source_manifest"], "binaries": config["expected_binaries"]}
    report["summary"] = validate(report); publish_report(args.out, report)
    print("custody_delivery_complete " + json.dumps(report["summary"], sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
