#!/usr/bin/env python3
"""Exercise fresh ordinary devnet ledgers over direct authenticated QUIC.

Use the Host configuration from run.py with fresh, dedicated roots. Optional
top-level chain_roots={"a": "/new/root/a", "b": "/new/root/b"} overrides only
those roots while retaining the configured transports and pinned executables.
No live ledger, authority root, wallet seed, or transport seed is copied.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time

from run import AcceptanceError, Host, Supervisor, digest_id, fields, require


NETWORK = 20261027
GENESIS_TIMESTAMP = 1700000000
HISTORY_BYTES = 64 * 1024 * 1024
PORT = 43884
SYNC_SECONDS = 40
STATUS_KEYS = ("network", "height", "tip", "state", "cumulative_work",
               "resources", "history_bytes", "history_limit")


def _stdout(supervisor, name):
    lines = []
    for _ in range(64):
        result = supervisor.rpc("next", name=name, timeout=5)
        if result["eof"]:
            return "".join(lines)
        lines.append(result["line"])
    raise AcceptanceError("ordinary command emitted too many output lines")


def _terminate(supervisor, name, crash=False):
    require(supervisor.rpc("status", name=name)["running"],
            "selected owned child already stopped")
    supervisor.rpc("kill" if crash else "terminate", name=name)
    try:
        stopped = supervisor.rpc("wait", name=name, timeout=15)
    except AcceptanceError:
        if supervisor.rpc("status", name=name)["running"]:
            supervisor.rpc("kill", name=name)
            supervisor.rpc("wait", name=name, timeout=5)
        raise
    require(stopped["returncode"] is not None, "owned child did not stop")
    if crash:
        require(stopped["returncode"] != 0, "crashed server reported normal exit")
    else:
        require(stopped["returncode"] == 0, "ordinary server did not drain on SIGTERM")
    return stopped["returncode"]


def _command(supervisor, name, timeout=20, success=True):
    """Bound the actual remote child, rather than timing out just its SSH pipe."""
    supervisor.rpc("start", name=name)
    began = time.monotonic()
    timed_out = False
    try:
        stopped = supervisor.rpc("wait", name=name, timeout=timeout)
    except AcceptanceError:
        status = supervisor.rpc("status", name=name)
        require(status["running"] and time.monotonic() - began >= timeout - 1,
                "owned command wait failed before its execution deadline")
        timed_out = True
        supervisor.rpc("kill", name=name)
        stopped = supervisor.rpc("wait", name=name, timeout=5)
    output = _stdout(supervisor, name)
    code = stopped["returncode"]
    require(code is not None, "owned command was not reaped")
    if success:
        require(not timed_out and code == 0, "ordinary devnet command failed")
    else:
        require(timed_out or code != 0, "disconnected synchronization unexpectedly succeeded")
    return {"stdout": output, "returncode": code, "timed_out": timed_out,
            "duration_seconds": round(time.monotonic() - began, 3)}


def _status(supervisor):
    output = _command(supervisor, "status")["stdout"]
    record = None
    for line in output.splitlines():
        if line.startswith("data="):
            record = dict(part.split("=", 1) for part in line.split() if "=" in part)
    require(record is not None and set(STATUS_KEYS) <= set(record), "incomplete ledger status")
    public = {key: record[key] for key in STATUS_KEYS}
    for key in ("network", "height", "resources", "history_bytes", "history_limit"):
        require(re.fullmatch(r"0|[1-9][0-9]*", public[key]) is not None,
                "ledger status contains a noncanonical integer")
        public[key] = int(public[key])
    digest_id(public["tip"])
    digest_id(public["state"])
    require(re.fullmatch(r"(?:[0-9a-f]{2})*", public["cumulative_work"]) is not None,
            "ledger status contains invalid cumulative work")
    require(public["network"] == NETWORK and public["history_limit"] == HISTORY_BYTES,
            "ledger left its explicit devnet/storage configuration")
    return public


def _verify(supervisor, status):
    verified = fields(_command(supervisor, "verify")["stdout"], "verified")
    require(verified.get("height") == str(status["height"]) and
            verified.get("tip") == status["tip"] and verified.get("state") == status["state"],
            "full ledger replay differs from the observed tip/state")


def _converged(a, b, height):
    require(a["height"] == height and b["height"] == height,
            "participants did not reach the expected height")
    for key in ("tip", "state", "cumulative_work", "resources"):
        require(a[key] == b[key], "participants disagree on selected " + key)


def _mine(supervisor, name, start, count):
    output = _command(supervisor, name)["stdout"]
    blocks = []
    for line in output.splitlines():
        if line.startswith("mined "):
            value = fields(line, "mined")
            require(value.get("height") == str(start + len(blocks) + 1),
                    "mining skipped or repeated a height")
            blocks.append({"height": int(value["height"]), "id": digest_id(value["id"]),
                           "state": digest_id(value["state"])})
    require(len(blocks) == count, "mining returned an incomplete block sequence")
    return blocks


def _base_commands(host):
    data = host.root + "/data"
    argv = lambda *args: {"argv": [host.binary] + list(args)}
    return {
        "init": argv("init", "--data", data, "--network", str(NETWORK),
                     "--timestamp", str(GENESIS_TIMESTAMP), "--difficulty-bits", "0",
                     "--max-history-bytes", str(HISTORY_BYTES)),
        "transport-keygen": argv("keygen", "--out", host.root + "/transport.seed"),
        "miner-keygen": argv("keygen", "--out", host.root + "/miner.seed"),
        "status": argv("status", "--data", data),
        "verify": argv("verify", "--data", data),
    }


def _create_root(host):
    # mkdir is deliberately exclusive; no fixture installer, recursive create,
    # deletion, resume or reuse of an existing acceptance root is permitted.
    script = ("import os,sys; p=sys.argv[1]; os.mkdir(p,0o700); "
              "d=os.open(os.path.dirname(p),os.O_RDONLY); os.fsync(d); os.close(d)")
    host.execute(["python3", "-c", script, host.root])


def _bootstrap(host):
    _create_root(host)
    supervisor = Supervisor(host, _base_commands(host))
    try:
        initialized = fields(_command(supervisor, "init")["stdout"], "initialized")
        genesis = digest_id(initialized["genesis"])
        transport_address = fields(_command(supervisor, "transport-keygen")["stdout"], "created")["address"]
        miner = fields(_command(supervisor, "miner-keygen")["stdout"], "created")["address"]
        digest_id(transport_address)
        digest_id(miner)
        require(miner != transport_address, "miner and transport reuse a key")
        state = _status(supervisor)
        require(state["height"] == 0 and state["tip"] == genesis,
                "fresh initialization did not start at the retained genesis")
        _verify(supervisor, state)
        return {"genesis": genesis, "miner": miner, "transport_address": transport_address,
                "status": state}
    finally:
        supervisor.close()


def _sync(supervisor, expected, success=True):
    result = _command(supervisor, "sync", SYNC_SECONDS, success)
    if success:
        synced = fields(result["stdout"], "synced_quic")
        require(synced.get("height") == str(expected["height"]) and
                synced.get("tip") == expected["tip"] and
                synced.get("cumulative_work") == expected["cumulative_work"],
                "synchronization did not acknowledge the exact expected chain")
    return {key: result[key] for key in ("returncode", "timed_out", "duration_seconds")}


def _hosts(config):
    overrides = config.get("chain_roots", {})
    require(isinstance(overrides, dict) and not set(overrides) - {"a", "b"},
            "chain_roots accepts only the two explicit roles")
    values = []
    for role in ("a", "b"):
        value = dict(config["hosts"][role])
        if role in overrides:
            value["root"] = overrides[role]
        values.append(Host(value))
    a, b = values
    same_configured_host = ((a.local and b.local) or
                            (not a.local and not b.local and a.config["ssh"] == b.config["ssh"]))
    if same_configured_host:
        require(os.path.commonpath((a.root, b.root)) not in (a.root, b.root),
                "same-host chain roles require disjoint fresh roots")
    remote_ip = ipaddress.ip_address(config["hosts"]["b"]["public_ip"])
    require(not remote_ip.is_unspecified and not remote_ip.is_multicast,
            "replica requires an explicit reachable IP endpoint")
    a_ip = config["hosts"]["a"].get("public_ip")
    distinct_hosts = False
    if a_ip is not None:
        local_ip = ipaddress.ip_address(a_ip)
        distinct_hosts = (not same_configured_host and local_ip != remote_ip and
                          not local_ip.is_loopback and not remote_ip.is_loopback)
    return a, b, remote_ip, distinct_hosts


def run_chain(config):
    began = time.monotonic()
    a, b, peer_ip, distinct_hosts = _hosts(config)
    boot_a, boot_b = _bootstrap(a), _bootstrap(b)
    require(boot_a["genesis"] == boot_b["genesis"], "fresh participants initialized different genesis documents")
    require(boot_a["miner"] != boot_b["miner"] and
            len({boot_a["miner"], boot_b["miner"], boot_a["transport_address"], boot_b["transport_address"]}) == 4,
            "fresh participants share wallet/transport roles")
    _converged(boot_a["status"], boot_b["status"], 0)
    family, bind = ("ip4", "0.0.0.0") if peer_ip.version == 4 else ("ip6", "::")
    commands_b = _base_commands(b)
    commands_b["mine-initial"] = {"argv": [b.binary, "mine", "--data", b.root + "/data",
                                           "--miner", boot_b["miner"], "--count", "3"]}
    commands_b["mine-fork"] = {"argv": [b.binary, "mine", "--data", b.root + "/data",
                                        "--miner", boot_b["miner"], "--count", "4"]}
    commands_b["serve"] = {"argv": [b.binary, "serve-quic", "--data", b.root + "/data",
                                    "--key", b.root + "/transport.seed", "--listen",
                                    "/%s/%s/udp/%d/quic-v1" % (family, bind, PORT),
                                    "--max-connections", "8", "--max-streams-per-peer", "2"]}
    server = Supervisor(b, commands_b)
    client = None
    starts = 0
    peer_identity = None

    def start_server():
        nonlocal starts, peer_identity
        ready = server.start("serve", "serving_quic")
        peer = digest_id(ready["peer_id"])
        libp2p_id = ready["libp2p_id"]
        require(re.fullmatch(r"[A-Za-z0-9]+", libp2p_id) is not None and
                ready.get("network") == str(NETWORK), "server readiness changed its authenticated scope")
        identity = (peer, libp2p_id)
        if peer_identity is not None:
            require(identity == peer_identity, "server transport identity changed across restart")
        peer_identity = identity
        starts += 1
        return peer, libp2p_id

    report = {"version": 1, "scenario": "ordinary-devnet-direct-quic-restart-partition-reorg",
              "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "scope": ("direct WAN QUIC between the two configured hosts" if distinct_hosts else
                        "direct QUIC between configured processes; distinct WAN hosts not established"),
              "host_separation_source": "operator configuration; no physical-independence claim",
              "configured_distinct_hosts": distinct_hosts, "network": NETWORK,
              "genesis_timestamp": GENESIS_TIMESTAMP, "difficulty_bits": 0,
              "genesis_id": boot_a["genesis"], "binary_a_sha256": a.sha256(a.binary),
              "binary_b_sha256": b.sha256(b.binary), "initial": {"a": boot_a["status"], "b": boot_b["status"]},
              "miner_a": boot_a["miner"], "miner_b": boot_b["miner"],
              "partition_model": "owned server process outage and independent fork mining; no firewall changes",
              "monetary_scope": "isolated development genesis; no monetary-value claim"}
    try:
        _mine(server, "mine-initial", 0, 3)
        source = _status(server)
        _verify(server, source)
        peer, libp2p_id = start_server()
        commands_a = _base_commands(a)
        commands_a["mine-fork"] = {"argv": [a.binary, "mine", "--data", a.root + "/data",
                                            "--miner", boot_a["miner"], "--count", "2"]}
        commands_a["sync"] = {"argv": [a.binary, "sync-quic", "--data", a.root + "/data",
                                       "--key", a.root + "/transport.seed", "--peer",
                                       "/%s/%s/udp/%d/quic-v1/p2p/%s" % (family, peer_ip, PORT, libp2p_id),
                                       "--peer-id", peer]}
        client = Supervisor(a, commands_a)
        first_sync = _sync(client, source)
        # Ordinary serve holds the database. Drain it before independently
        # replaying B's ledger; a cached pre-serve tip is not used as that proof.
        _terminate(server, "serve")
        initial_a, initial_b = _status(client), _status(server)
        _converged(initial_a, initial_b, 3)
        _verify(client, initial_a)
        _verify(server, initial_b)
        report["first_sync"] = {"process": first_sync, "a": initial_a, "b": initial_b,
                                "both_full_replay_verified": True}

        start_server()
        first_crash = _terminate(server, "serve", crash=True)
        before_outage = _status(client)
        failed_sync = _sync(client, source, success=False)
        after_outage = _status(client)
        require(after_outage == before_outage, "disconnected synchronization changed A's retained ledger history")
        start_server()
        healed_sync = _sync(client, source)
        _terminate(server, "serve")
        healed_a, healed_b = _status(client), _status(server)
        _converged(healed_a, healed_b, 3)
        _verify(client, healed_a)
        _verify(server, healed_b)
        report["server_outage"] = {"crash_returncode": first_crash, "failed_sync": failed_sync,
                                   "before_a": before_outage, "after_a": after_outage,
                                   "history_unchanged": True, "healed_sync": healed_sync,
                                   "healed": {"a": healed_a, "b": healed_b}}

        branch_a = _mine(client, "mine-fork", 3, 2)
        branch_b = _mine(server, "mine-fork", 3, 4)
        require(branch_a[0]["id"] != branch_b[0]["id"], "partition mining did not create distinct first branch blocks")
        fork_a, fork_b = _status(client), _status(server)
        require(fork_a["height"] == 5 and fork_b["height"] == 7 and fork_a["tip"] != fork_b["tip"],
                "partition did not retain two divergent branches")
        require(int(fork_b["cumulative_work"] or "0", 16) > int(fork_a["cumulative_work"] or "0", 16),
                "the seven-block source does not have greater cumulative work")
        _verify(client, fork_a)
        _verify(server, fork_b)
        start_server()
        reorg_sync = _sync(client, fork_b)
        _terminate(server, "serve")
        selected_a, selected_b = _status(client), _status(server)
        _converged(selected_a, selected_b, 7)
        require(selected_a["tip"] != fork_a["tip"], "healed synchronization did not replace A's losing tip")
        _verify(client, selected_a)
        _verify(server, selected_b)
        report["partition_forks"] = {"first_block_a": branch_a[0]["id"], "first_block_b": branch_b[0]["id"],
                                     "before": {"a": fork_a, "b": fork_b}, "healed_sync": reorg_sync,
                                     "after": {"a": selected_a, "b": selected_b},
                                     "both_full_replay_verified": True}

        start_server()
        second_crash = _terminate(server, "serve", crash=True)
        start_server()
        duplicate_sync = _sync(client, selected_b)
        _terminate(server, "serve")
        final_a, final_b = _status(client), _status(server)
        _converged(final_a, final_b, 7)
        require(final_a == selected_a and final_b == selected_b,
                "exact synchronization after source restart changed retained ledger history")
        _verify(client, final_a)
        _verify(server, final_b)
        report["restart_idempotence"] = {"crash_returncode": second_crash, "sync": duplicate_sync,
                                         "history_unchanged": True}
        report["transport_peer_id_b"] = peer_identity[0]
        report["server_starts"] = starts
        report["server_crashes"] = 2
        report["final"] = {"a": final_a, "b": final_b}
        report["duration_seconds"] = round(time.monotonic() - began, 3)
        report["passed"] = True
        return report
    finally:
        try:
            if client is not None:
                client.close()
        finally:
            server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    try:
        require(not os.path.lexists(args.out) and Path(args.out).resolve().parent.is_dir(),
                "report requires a new destination in an existing directory")
        report = run_chain(json.loads(Path(args.config).read_text()))
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(report, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        directory = os.open(str(Path(args.out).resolve().parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        print("remote_chain_acceptance passed=true report=%s" % args.out)
        return 0
    except Exception as error:
        # Host/Supervisor diagnostics can include private routes and paths.
        # Keep those out of the public report and this concise result line.
        print("remote_chain_acceptance passed=false error_type=%s" % type(error).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
