"""Standard-library tests; no SSH, credentials, Go build, or external service."""

import hashlib
import json
import os
from pathlib import Path
import queue
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import support


FAKE = r'''
import json, os, sys, time
mode = sys.argv[1]
if mode == "line-overflow":
    os.write(1, b"x" * (256 * 1024 + 1))
    time.sleep(30)
elif mode == "buffer-overflow":
    for _ in range(1100):
        os.write(1, b"x" * 4095 + b"\n")
    time.sleep(30)
elif mode == "stderr":
    data = b"e" * 100000 + b"TAIL"
    offset = 0
    while offset < len(data):
        offset += os.write(2, data[offset:])
    print("done", flush=True)
elif mode == "env":
    print(json.dumps({k:v for k,v in os.environ.items() if k.startswith(("OUTCOMEMESH_REMOTE_", "OMESH_REMOTE_"))}), flush=True)
elif mode == "partial":
    os.write(1, b"review_id=incomplete")
elif mode in ("partial-scope", "slow-scope", "large-scope"):
    print("ready", flush=True)
    for line in sys.stdin:
        with open(os.path.join(os.path.dirname(__file__), "controls.log"), "ab") as log:
            log.write(line.encode())
        print("review review_id=" + "a" * 64, flush=True)
        if mode == "partial-scope":
            break
        if mode == "slow-scope":
            time.sleep(1)
        if mode == "large-scope":
            for _ in range(17):
                sys.stdout.write("x" * 65535 + "\n")
            sys.stdout.flush()
        print("scope_end", flush=True)
else:
    print("ready", flush=True)
    for line in sys.stdin:
        with open(os.path.join(os.path.dirname(__file__), "controls.log"), "ab") as log:
            log.write(line.encode())
        if line == "close\n":
            break
        if line == "review\n":
            print("review review_id=" + "a" * 64, flush=True)
            print("scope:", flush=True)
            print('{"selected":"same-session"}', flush=True)
            print("scope_end", flush=True)
        else:
            sys.stdout.write("  caf\u00e9 " + line)
            sys.stdout.flush()
'''


def eventually(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("condition deadline expired")


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="outcomemesh-support-")
        self.addCleanup(self.directory.cleanup)
        self.root = os.path.realpath(self.directory.name)
        self.python = os.path.realpath(sys.executable)
        self.digest = hashlib.sha256(Path(self.python).read_bytes()).hexdigest()
        self.fake = str(Path(self.root, "fake.py"))
        Path(self.fake).write_text(FAKE, encoding="utf-8")
        self.supervisors = []

    def spec(self, mode="echo", env=None):
        command = {"argv": [self.python, "-u", self.fake, mode]}
        if env is not None:
            command["env"] = env
        return {"version": 1, "root": self.root, "binary": self.python,
                "binary_sha256": self.digest, "test_binary": self.python,
                "test_binary_sha256": self.digest, "commands": {"task": command}}

    def supervisor(self, mode="echo", env=None):
        supervisor = support.Supervisor(self.spec(mode, env))
        self.supervisors.append(supervisor)
        self.addCleanup(supervisor.close)
        return supervisor

    def test_dedicated_pipe_lines_review_timeout_and_explicit_restart(self):
        supervisor = self.supervisor()
        started = supervisor.dispatch("start", {"name": "task"})
        self.assertTrue(started["running"])
        self.assertEqual(supervisor.dispatch("next", {"name": "task"})["line"], "ready\n")
        with self.assertRaises(support.SupportError) as error:
            supervisor.dispatch("start", {"name": "task"})
        self.assertEqual(error.exception.code, "busy")
        with self.assertRaises(support.SupportError) as error:
            supervisor.dispatch("next", {"name": "task", "timeout": 0.01})
        self.assertEqual(error.exception.code, "timeout")
        self.assertTrue(supervisor.dispatch("status", {"name": "task"})["running"])
        self.assertEqual(supervisor.dispatch("send", {"name": "task", "line": "review"})["bytes_written"], 7)
        lines = [supervisor.dispatch("next", {"name": "task"})["line"] for _ in range(4)]
        self.assertEqual(lines, ["review review_id=" + "a" * 64 + "\n", "scope:\n",
                                 '{"selected":"same-session"}\n', "scope_end\n"])
        # Reading a review never sends or replays any action.
        with self.assertRaises(support.SupportError):
            supervisor.dispatch("next", {"name": "task", "timeout": 0.01})
        supervisor.dispatch("send", {"name": "task", "line": "explicit"})
        self.assertEqual(supervisor.dispatch("next", {"name": "task"})["line"], "  caf\u00e9 explicit\n")
        for line in ("review\n", "review\r", "x\x00", "x" * 96):
            with self.assertRaises(support.SupportError):
                supervisor.dispatch("send", {"name": "task", "line": line})
        with self.assertRaises(support.SupportError):
            supervisor.dispatch("wait", {"name": "task", "timeout": 46})
        supervisor.dispatch("eof", {"name": "task"})
        self.assertEqual(supervisor.dispatch("wait", {"name": "task", "timeout": 2})["returncode"], 0)
        self.assertTrue(supervisor.dispatch("next", {"name": "task"})["eof"])
        restarted = supervisor.dispatch("start", {"name": "task"})
        self.assertNotEqual(restarted["pid"], started["pid"])
        self.assertEqual(supervisor.dispatch("next", {"name": "task"})["line"], "ready\n")

    def test_fixed_executable_hash_and_unknown_request_cannot_start(self):
        binary = Path(self.root, "pinned-executable")
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o700)
        data = self.spec()
        data["binary"] = str(binary)
        data["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        data["commands"]["task"]["argv"] = [str(binary)]
        supervisor = support.Supervisor(data)
        self.addCleanup(supervisor.close)
        binary.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        with self.assertRaises(support.SupportError) as error:
            supervisor.dispatch("start", {"name": "task"})
        self.assertEqual(error.exception.code, "changed")
        self.assertFalse(supervisor.children)
        for method, params in (("start", {"name": "unknown"}), ("start", {"name": "task", "argv": ["sh"]}),
                               ("arbitrary.exec", {})):
            with self.assertRaises(support.SupportError):
                supervisor.dispatch(method, params)

    def test_until_returns_only_the_complete_exact_review_without_sending_actions(self):
        supervisor = self.supervisor()
        supervisor.dispatch("start", {"name": "task"})
        supervisor.dispatch("next", {"name": "task"})
        supervisor.dispatch("send", {"name": "task", "line": "review"})
        result = supervisor.dispatch("until", {"name": "task", "terminator": "scope_end\n", "timeout": 2})
        self.assertEqual(result, {"name": "task", "complete": True, "lines": [
            "review review_id=" + "a" * 64 + "\n", "scope:\n",
            '{"selected":"same-session"}\n', "scope_end\n"]})
        self.assertEqual(Path(self.root, "controls.log").read_bytes(), b"review\n")
        self.assertTrue(supervisor.dispatch("status", {"name": "task"})["running"])
        with self.assertRaises(support.SupportError) as error:
            supervisor.dispatch("next", {"name": "task", "timeout": 0.01})
        self.assertEqual(error.exception.code, "timeout")
        for params in ({"terminator": "scope_end"}, {"terminator": "scope_end\n", "max_lines": 8193},
                       {"terminator": "scope_end\n", "timeout": 46}):
            with self.assertRaises(support.SupportError) as error:
                supervisor.dispatch("until", dict(params, name="task"))
            self.assertEqual(error.exception.code, "invalid")
        self.assertTrue(supervisor.dispatch("status", {"name": "task"})["running"])

    def test_until_partial_scope_deadline_and_caps_cancel_without_action_replay(self):
        for mode, params, code in (
            ("partial-scope", {}, "stdout"),
            ("slow-scope", {"timeout": 0.05}, "timeout"),
            ("large-scope", {}, "limit"),
            ("echo", {"max_lines": 3}, "limit"),
        ):
            with self.subTest(mode=mode):
                Path(self.root, "controls.log").unlink(missing_ok=True)
                supervisor = self.supervisor(mode)
                supervisor.dispatch("start", {"name": "task"})
                supervisor.dispatch("next", {"name": "task"})
                supervisor.dispatch("send", {"name": "task", "line": "review"})
                began = time.monotonic()
                with self.assertRaises(support.SupportError) as error:
                    supervisor.dispatch("until", dict({"name": "task", "terminator": "scope_end\n", "timeout": 2}, **params))
                self.assertEqual(error.exception.code, code)
                self.assertLess(time.monotonic() - began, 1)
                supervisor.dispatch("wait", {"name": "task", "timeout": 2})
                status = supervisor.dispatch("status", {"name": "task"})
                self.assertTrue(status["stdin_closed"])
                self.assertIsNotNone(status["stdout_error"])
                self.assertEqual(status["stdout_buffered_bytes"], 0)
                self.assertEqual(Path(self.root, "controls.log").read_bytes(), b"review\n")

    def test_role_environment_is_fixed_private_and_rechecked(self):
        role = Path(self.root, "role")
        role.mkdir()
        env = {"OUTCOMEMESH_REMOTE_ROLE_ROOT": str(role),
               "OMESH_REMOTE_GATE_ARGS": str(Path(self.root, "gate.json")),
               "OUTCOMEMESH_REMOTE_FIXTURE_OUT": str(Path(self.root, "new-fixture"))}
        with mock.patch.dict(os.environ, {"OUTCOMEMESH_REMOTE_UNDECLARED": "secret",
                                         "OMESH_REMOTE_UNDECLARED": "secret"}):
            supervisor = self.supervisor("env", env)
            supervisor.dispatch("start", {"name": "task"})
            received = json.loads(supervisor.dispatch("next", {"name": "task"})["line"])
        self.assertEqual(received, env)
        for bad in ({"LD_PRELOAD": str(role)}, {"OUTCOMEMESH_REMOTE_ROLE_ROOT": "/tmp"}):
            with self.assertRaises(support.SupportError):
                support.Spec(self.spec("env", bad))
        production = self.spec("env", env)
        del production["test_binary"]
        del production["test_binary_sha256"]
        with self.assertRaises(support.SupportError):
            support.Spec(production)
        pending = self.supervisor("env", {"OUTCOMEMESH_REMOTE_ROLE_ROOT": str(role)})
        role.rmdir()
        with tempfile.TemporaryDirectory() as external:
            role.symlink_to(external, target_is_directory=True)
            with self.assertRaises(support.SupportError):
                pending.dispatch("start", {"name": "task"})
            self.assertFalse(pending.children)

    def test_stdout_bounds_fail_closed_without_dropping_review_tokens(self):
        for mode in ("line-overflow", "buffer-overflow", "partial"):
            with self.subTest(mode=mode):
                supervisor = self.supervisor(mode)
                supervisor.dispatch("start", {"name": "task"})
                eventually(lambda: supervisor.dispatch("status", {"name": "task"})["stdout_error"])
                with self.assertRaises(support.SupportError) as error:
                    supervisor.dispatch("next", {"name": "task"})
                self.assertEqual(error.exception.code, "stdout")
                self.assertEqual(supervisor.dispatch("status", {"name": "task"})["stdout_buffered_bytes"], 0)
                supervisor.dispatch("wait", {"name": "task", "timeout": 2})

    def test_stderr_tail_is_bounded_and_fully_drained(self):
        supervisor = self.supervisor("stderr")
        supervisor.dispatch("start", {"name": "task"})
        self.assertEqual(supervisor.dispatch("next", {"name": "task"})["line"], "done\n")
        supervisor.dispatch("wait", {"name": "task", "timeout": 2})
        status = supervisor.dispatch("status", {"name": "task"})
        self.assertTrue(status["stderr_tail"].endswith("TAIL"))
        self.assertEqual(len(status["stderr_tail"].encode("utf-8")), support.MAX_STDERR)
        self.assertEqual(status["stderr_truncated_bytes"], 100004 - support.MAX_STDERR)

    def test_cleanup_only_owns_recorded_child(self):
        outsider = subprocess.Popen([self.python, "-c", "import time;time.sleep(30)"], close_fds=True)
        self.addCleanup(lambda: (outsider.kill(), outsider.wait()) if outsider.poll() is None else None)
        supervisor = self.supervisor()
        supervisor.dispatch("start", {"name": "task"})
        supervisor.dispatch("next", {"name": "task"})
        child = supervisor.children["task"].process
        supervisor.close()
        self.assertEqual(child.poll(), 0)
        self.assertIsNone(outsider.poll())

    def test_stdio_rpc_eof_interrupts_pending_next_and_drains_child(self):
        spec = Path(self.root, "spec.json")
        spec.write_text(json.dumps(self.spec()), encoding="utf-8")
        process = subprocess.Popen([self.python, str(Path(support.__file__).resolve()), "--spec", str(spec)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0, close_fds=True)
        self.addCleanup(lambda: (process.kill(), process.wait()) if process.poll() is None else None)

        def request(request_id, method, params):
            process.stdin.write((json.dumps({"id": request_id, "method": method, "params": params}) + "\n").encode())
            process.stdin.flush()
            self.assertTrue(select.select([process.stdout], [], [], 3)[0], "missing RPC response")
            return json.loads(process.stdout.readline())

        invalid = request(0, "unknown", {})
        self.assertEqual(invalid["id"], 0)
        self.assertFalse(invalid["ok"])
        started = request(1, "start", {"name": "task"})
        self.assertTrue(started["ok"])
        pid = started["result"]["pid"]
        self.assertEqual(request(2, "next", {"name": "task"})["result"]["line"], "ready\n")
        self.assertTrue(request(3, "send", {"name": "task", "line": "review"})["ok"])
        framed = request(4, "until", {"name": "task", "terminator": "scope_end\n", "timeout": 2})
        self.assertTrue(framed["result"]["complete"])
        self.assertEqual(framed["result"]["lines"][-1], "scope_end\n")
        process.stdin.write((json.dumps({"id": 5, "method": "next", "params": {"name": "task", "timeout": 45}}) + "\n").encode())
        process.stdin.close()
        self.assertEqual(process.wait(timeout=5), 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        process.stdout.close()
        process.stderr.close()


class EchoUDP:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.endpoint = list(self.socket.getsockname())
        self.received = queue.Queue()
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.closed.is_set():
            if select.select([self.socket], [], [], 0.02)[0]:
                payload, address = self.socket.recvfrom(65536)
                self.received.put(payload)
                self.socket.sendto(payload, address)

    def close(self):
        self.closed.set()
        self.thread.join(1)
        self.socket.close()


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.server = EchoUDP()
        self.addCleanup(self.server.close)
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client.bind(("127.0.0.1", 0))
        self.client.settimeout(1)
        self.addCleanup(self.client.close)
        self.config = {"front": ["127.0.0.1", 0], "allowed_client": list(self.client.getsockname()),
                       "upstream": self.server.endpoint}
        self.relay = support.FaultRelay(self.config)
        self.addCleanup(self.relay.close)
        self.front = tuple(self.relay.stats()["front"])

    def send(self, payload):
        self.client.sendto(payload, self.front)

    def silence(self, timeout=0.12):
        previous = self.client.gettimeout()
        self.client.settimeout(timeout)
        try:
            with self.assertRaises(socket.timeout):
                self.client.recvfrom(65536)
        finally:
            self.client.settimeout(previous)

    def test_exact_opaque_bidirectional_flow_and_foreign_source_rejection(self):
        payload = b"QUIC\x00\xff\x80opaque"
        self.send(payload)
        self.assertEqual(self.client.recvfrom(65536)[0], payload)
        self.assertEqual(self.server.received.get(timeout=1), payload)
        foreign = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(foreign.close)
        foreign.bind(("127.0.0.1", 0))
        foreign.sendto(b"foreign", self.front)
        eventually(lambda: self.relay.stats()["counters"].get("foreign_source_drops") == 1)
        self.assertTrue(self.server.received.empty())
        stats = self.relay.stats()
        self.assertEqual(stats["counters"]["forward_sent_bytes"], len(payload))
        self.assertEqual(stats["counters"]["reverse_sent_bytes"], len(payload))
        self.assertEqual(stats["allowed_client"], self.config["allowed_client"])

    def test_partition_each_direction_and_deterministic_pattern(self):
        for mode in ("drop", "drop-forward", "drop-reverse"):
            self.relay.policy(mode=mode)
            self.send(mode.encode())
            self.silence()
            if mode == "drop-reverse":
                self.assertEqual(self.server.received.get(timeout=1), mode.encode())
            else:
                self.assertTrue(self.server.received.empty())
        self.relay.policy(drop_every=2)
        for index in range(1, 6):
            self.send(str(index).encode())
            if index in (1, 5):
                self.assertEqual(self.client.recvfrom(65536)[0], str(index).encode())
            else:
                self.silence()
        stats = self.relay.stats()["counters"]
        self.assertEqual(stats["forward_pattern_drops"], 2)
        self.assertEqual(stats["reverse_pattern_drops"], 1)

    def test_delay_queue_is_bounded_and_policy_change_cannot_replay_old_packets(self):
        self.relay.policy(delay_ms=100)
        began = time.monotonic()
        self.send(b"delayed")
        self.assertEqual(self.client.recvfrom(65536)[0], b"delayed")
        self.assertGreaterEqual(time.monotonic() - began, 0.18)
        self.assertEqual(self.server.received.get(timeout=1), b"delayed")
        self.relay.policy(delay_ms=5000)
        self.relay.MAX_PACKETS = 2
        for index in range(5):
            self.send(str(index).encode())
        eventually(lambda: self.relay.stats()["counters"].get("forward_queue_drops", 0) == 3)
        stats = self.relay.policy(mode="drop")
        self.assertEqual(stats["queued_packets"], 0)
        self.assertEqual(stats["queued_bytes"], 0)
        self.assertEqual(stats["counters"]["policy_queue_drops"], 2)
        self.silence(0.22)
        self.assertTrue(self.server.received.empty())
        self.relay.policy()
        self.send(b"fresh")
        self.assertEqual(self.client.recvfrom(65536)[0], b"fresh")

    def test_only_numeric_task_endpoints_and_valid_fault_caps(self):
        for key, value in (("front", ["0.0.0.0", 43872]), ("allowed_client", ["127.0.0.1", 0]),
                           ("allowed_client", ["8.8.8.8", 43871]), ("upstream", ["example.com", 43880]),
                           ("upstream", ["0.0.0.0", 43880])):
            config = dict(self.config)
            config[key] = value
            with self.assertRaises(support.SupportError):
                support.validate_relay(config)
        for policy in ({"mode": "unknown"}, {"drop_every": -1}, {"delay_ms": 5001}, {"drop_every": True}):
            with self.assertRaises(support.SupportError):
                self.relay.policy(**policy)


if __name__ == "__main__":
    unittest.main()
