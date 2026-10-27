#!/usr/bin/env python3
"""Task-private stdio supervisor and opaque UDP fault relay for acceptance runs.

There is no network administration endpoint, shell execution, SSH implementation,
automatic review action, or control-command replay. The caller supplies a private
fixed spec and drives every process through its dedicated pipes. JSONL request
shape: {"id": ..., "method": "start", "params": {"name": "audit"}}.
"""

import argparse
import collections
import hashlib
import heapq
import ipaddress
import json
import os
import queue
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time


MAX_LINE = 256 * 1024
MAX_STDOUT = 4 * 1024 * 1024
MAX_STDERR = 64 * 1024
MAX_FRAME = 1024 * 1024
MAX_REQUEST = 64 * 1024
MAX_SPEC = 1024 * 1024
MAX_CHILDREN = 16
MAX_CONTROL = 96  # Native CLI bound, including mandatory LF.
ENV_PATHS = frozenset({
    "OUTCOMEMESH_REMOTE_ROLE_ROOT", "OMESH_REMOTE_GATE_ARGS",
    "OUTCOMEMESH_REMOTE_FIXTURE_OUT",
    "OMESH_REMOTE_NETWORK_PROCESS_CONFIG",
})


class SupportError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def checked_keys(value, required=(), optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise SupportError("invalid", "missing or unknown fields")
    return value


def number(value, minimum, maximum, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
        raise SupportError("invalid", "%s is outside its bound" % label)
    return value


def integer(value, minimum, maximum, label):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SupportError("invalid", "%s is outside its integer bound" % label)
    return value


def json_loads(value):
    def invalid_constant(_):
        raise SupportError("invalid", "non-finite JSON number")
    return json.loads(value, parse_constant=invalid_constant)


def private_root(path):
    if not isinstance(path, str) or not os.path.isabs(path) or os.path.realpath(path) != path:
        raise SupportError("invalid", "root must be an existing absolute canonical directory")
    info = os.stat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise SupportError("invalid", "root must belong to this user and deny group/other access")
    return path


def contained_path(root, path):
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path or os.path.normpath(path) != path:
        raise SupportError("invalid", "environment path must be absolute canonical task placement")
    resolved = os.path.realpath(path)
    if os.path.commonpath((root, resolved)) != root:
        raise SupportError("invalid", "environment path escapes the private task root")
    return path


def verify_binary(path, expected):
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path or os.path.realpath(path) != path:
        raise SupportError("invalid", "binary must be an absolute canonical regular executable")
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise SupportError("invalid", "binary requires its exact lowercase SHA256")
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or not os.access(path, os.X_OK):
        raise SupportError("invalid", "binary must be a regular executable")
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        opened = os.fstat(source.fileno())
        if not os.path.samestat(before, opened):
            raise SupportError("changed", "binary identity changed")
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    after = os.lstat(path)
    if not os.path.samestat(before, after) or before.st_size != after.st_size or digest.hexdigest() != expected:
        raise SupportError("changed", "binary differs from its pinned SHA256")


class Spec:
    def __init__(self, data):
        checked_keys(data, ("version", "root", "binary", "binary_sha256", "commands"),
                     ("test_binary", "test_binary_sha256", "relay"))
        if isinstance(data["version"], bool) or data["version"] != 1:
            raise SupportError("invalid", "unsupported spec version")
        self.root = private_root(data["root"])
        if not isinstance(data["binary"], str):
            raise SupportError("invalid", "binary path must be text")
        self.binaries = {data["binary"]: data["binary_sha256"]}
        self.test_binary = data.get("test_binary")
        if (self.test_binary is None) != ("test_binary_sha256" not in data):
            raise SupportError("invalid", "test binary requires path and SHA256 together")
        if self.test_binary is not None:
            if not isinstance(self.test_binary, str):
                raise SupportError("invalid", "test binary path must be text")
            self.binaries[self.test_binary] = data["test_binary_sha256"]
        for path, digest in self.binaries.items():
            verify_binary(path, digest)
        commands = data["commands"]
        if not isinstance(commands, dict) or not 1 <= len(commands) <= 128:
            raise SupportError("invalid", "spec requires a bounded named command set")
        self.commands = {}
        for name, command in commands.items():
            if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) is None:
                raise SupportError("invalid", "invalid fixed command name")
            checked_keys(command, ("argv",), ("env",))
            argv = command["argv"]
            if not isinstance(argv, list) or not 1 <= len(argv) <= 512 or any(
                not isinstance(arg, str) or "\x00" in arg or "\n" in arg or "\r" in arg for arg in argv
            ) or sum(len(arg.encode("utf-8")) for arg in argv) > MAX_SPEC:
                raise SupportError("invalid", "fixed argv exceeds its shape or size bound")
            if argv[0] not in self.binaries:
                raise SupportError("invalid", "argv executable is not a pinned spec binary")
            env = command.get("env", {})
            if not isinstance(env, dict) or set(env) - ENV_PATHS or (env and argv[0] != self.test_binary):
                raise SupportError("invalid", "only fixed test-binary role path environment is allowed")
            for value in env.values():
                contained_path(self.root, value)
            self.commands[name] = {"argv": tuple(argv), "env": dict(env)}
        self.relay = data.get("relay")
        if self.relay is not None:
            validate_relay(self.relay)

    def command(self, name):
        if not isinstance(name, str) or name not in self.commands:
            raise SupportError("invalid", "unknown fixed command name")
        command = self.commands[name]
        verify_binary(command["argv"][0], self.binaries[command["argv"][0]])
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("OUTCOMEMESH_REMOTE_", "OMESH_REMOTE_"))}
        for key, value in command["env"].items():
            env[key] = contained_path(self.root, value)
        return command["argv"], env


class Child:
    def __init__(self, name, argv, cwd, env, shutdown):
        self.name, self.shutdown = name, shutdown
        self.condition = threading.Condition()
        self.input_lock = threading.Lock()
        self.stop_readers = threading.Event()
        self.lines = collections.deque()
        self.buffered = 0
        self.stdout_eof = False
        self.stdout_error = None
        self.stderr = bytearray()
        self.stderr_truncated = 0
        self.stdin_closed = False
        self.process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        bufsize=0, close_fds=True, start_new_session=True)
        os.set_blocking(self.process.stdin.fileno(), False)
        self.readers = [threading.Thread(target=self._stdout, daemon=True),
                        threading.Thread(target=self._stderr, daemon=True)]
        for reader in self.readers:
            reader.start()

    def _blocks(self, stream):
        fd = stream.fileno()
        os.set_blocking(fd, False)
        while not self.stop_readers.is_set():
            try:
                ready, _, _ = select.select([fd], [], [], 0.05)
                if not ready:
                    continue
                block = os.read(fd, 8192)
            except BlockingIOError:
                continue
            except (OSError, ValueError):
                if self.stop_readers.is_set():
                    return
                raise
            if not block:
                return
            yield block

    def _fail_stdout(self, message):
        with self.condition:
            self.stdout_error = message
            self.lines.clear()
            self.buffered = 0
            self.condition.notify_all()
        self.eof()
        if self.process.poll() is None:
            self.process.terminate()

    def _stdout(self):
        partial = bytearray()
        try:
            for block in self._blocks(self.process.stdout):
                partial.extend(block)
                while b"\n" in partial:
                    offset = partial.index(b"\n") + 1
                    if offset > MAX_LINE:
                        self._fail_stdout("stdout line exceeds 256 KiB")
                        return
                    encoded = bytes(partial[:offset])
                    del partial[:offset]
                    try:
                        line = encoded.decode("utf-8")
                    except UnicodeDecodeError:
                        self._fail_stdout("stdout is not UTF-8")
                        return
                    with self.condition:
                        if self.stdout_error is not None:
                            return
                        if self.buffered + len(encoded) > MAX_STDOUT:
                            overflow = True
                        else:
                            overflow = False
                            self.lines.append((line, len(encoded)))
                            self.buffered += len(encoded)
                            self.condition.notify_all()
                    if overflow:
                        self._fail_stdout("stdout buffer exceeds 4 MiB")
                        return
                if len(partial) > MAX_LINE:
                    self._fail_stdout("stdout line exceeds 256 KiB")
                    return
                with self.condition:
                    overflow = self.buffered + len(partial) > MAX_STDOUT
                if overflow:
                    self._fail_stdout("stdout buffer exceeds 4 MiB")
                    return
            if partial and not self.stop_readers.is_set():
                self._fail_stdout("stdout ended with an unterminated line")
        except (OSError, ValueError) as error:
            self._fail_stdout("stdout capture failed: %s" % error)
        finally:
            with self.condition:
                self.stdout_eof = True
                self.condition.notify_all()

    def _stderr(self):
        try:
            for block in self._blocks(self.process.stderr):
                with self.condition:
                    self.stderr.extend(block)
                    excess = max(0, len(self.stderr) - MAX_STDERR)
                    if excess:
                        del self.stderr[:excess]
                        self.stderr_truncated += excess
        except (OSError, ValueError) as error:
            self._fail_stdout("stderr capture failed: %s" % error)

    def status(self):
        with self.condition:
            returncode = self.process.poll()
            return {"name": self.name, "pid": self.process.pid, "running": returncode is None,
                    "returncode": returncode, "stdin_closed": self.stdin_closed,
                    "stdout_buffered_bytes": self.buffered, "stdout_error": self.stdout_error,
                    "stderr_tail": bytes(self.stderr).decode("utf-8", errors="replace"),
                    "stderr_truncated_bytes": self.stderr_truncated}

    def next(self, timeout):
        deadline = time.monotonic() + number(timeout, 0, 45, "timeout")
        with self.condition:
            while True:
                if self.shutdown.is_set():
                    raise SupportError("closed", "supervisor is closing")
                if self.stdout_error is not None:
                    raise SupportError("stdout", self.stdout_error)
                if self.lines:
                    line, size = self.lines.popleft()
                    self.buffered -= size
                    return {"name": self.name, "line": line, "eof": False}
                if self.stdout_eof:
                    return {"name": self.name, "line": None, "eof": True,
                            "returncode": self.process.poll()}
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SupportError("timeout", "stdout line deadline expired")
                self.condition.wait(min(remaining, 0.05))

    def send(self, line):
        if not isinstance(line, str) or any(c in line for c in "\x00\r\n"):
            raise SupportError("invalid", "send requires one complete control line without LF/CR/NUL")
        encoded = (line + "\n").encode("utf-8")
        if len(encoded) > MAX_CONTROL:
            raise SupportError("invalid", "control line exceeds native 96-byte LF-inclusive bound")
        with self.input_lock:
            if self.stdin_closed or self.process.poll() is not None:
                raise SupportError("closed", "child stdin is closed")
            fd, offset, deadline = self.process.stdin.fileno(), 0, time.monotonic() + 5
            while offset < len(encoded):
                if self.shutdown.is_set():
                    raise SupportError("closed", "supervisor is closing")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SupportError("timeout", "control pipe write deadline expired")
                _, ready, _ = select.select([], [fd], [], min(remaining, 0.05))
                if ready:
                    try:
                        offset += os.write(fd, encoded[offset:])
                    except BlockingIOError:
                        continue
                    except OSError as error:
                        raise SupportError("closed", "control pipe write failed: %s" % error)
        result = self.status()
        result["bytes_written"] = len(encoded)
        return result

    def until(self, terminator, max_lines=4096, timeout=10):
        if not isinstance(terminator, str) or not terminator.endswith("\n") or terminator.count("\n") != 1 or len(terminator.encode("utf-8")) > MAX_LINE:
            raise SupportError("invalid", "terminator must be one bounded exact LF-terminated line")
        integer(max_lines, 1, 8192, "max_lines")
        deadline = time.monotonic() + number(timeout, 0, 45, "timeout")
        lines, size = [], 0
        try:
            while len(lines) < max_lines:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SupportError("timeout", "framed stdout deadline expired")
                result = self.next(remaining)
                if result["eof"]:
                    raise SupportError("stdout", "stdout ended before the exact frame terminator")
                line = result["line"]
                size += len(line.encode("utf-8"))
                if size > MAX_FRAME:
                    raise SupportError("limit", "framed stdout exceeds 1 MiB")
                lines.append(line)
                if line == terminator:
                    return {"name": self.name, "lines": lines, "complete": True}
            raise SupportError("limit", "framed stdout exceeds its line count")
        except SupportError as error:
            # A partial review is not a reusable result. Cancel this exact
            # owned child and discard queued tokens; never send/replay a verb.
            self._fail_stdout("framed stdout read failed: %s" % error)
            raise

    def eof(self):
        with self.input_lock:
            if not self.stdin_closed:
                self.stdin_closed = True
                self.process.stdin.close()
        return self.status()

    def wait(self, timeout):
        deadline = time.monotonic() + number(timeout, 0, 45, "timeout")
        while self.process.poll() is None:
            if self.shutdown.is_set():
                raise SupportError("closed", "supervisor is closing")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SupportError("timeout", "child wait deadline expired")
            self.shutdown.wait(min(remaining, 0.05))
        # Exit and pipe EOF are distinct observations. Drain final diagnostics
        # before reporting a failed/successful child; stdout stays queued for next.
        for reader in self.readers:
            while reader.is_alive():
                if self.shutdown.is_set():
                    raise SupportError("closed", "supervisor is closing")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SupportError("timeout", "child output drain deadline expired")
                reader.join(min(remaining, 0.05))
        return self.status()

    def signal(self, kill=False):
        if self.process.poll() is None:
            if kill:
                self.process.kill()
            else:
                self.process.terminate()
        return self.status()

    def close_readers(self):
        self.stop_readers.set()
        with self.condition:
            self.condition.notify_all()
        for reader in self.readers:
            reader.join(1)
        self.process.stdout.close()
        self.process.stderr.close()


def endpoint(value, zero_port=False):
    if not isinstance(value, list) or len(value) != 2 or not isinstance(value[0], str):
        raise SupportError("invalid", "endpoint requires [numeric IP, port]")
    try:
        ip = ipaddress.ip_address(value[0])
    except ValueError:
        raise SupportError("invalid", "endpoint requires a numeric IP, never DNS")
    port = integer(value[1], 0 if zero_port else 1, 65535, "endpoint port")
    if ip.is_multicast:
        raise SupportError("invalid", "multicast endpoint is forbidden")
    return str(ip), port


def validate_relay(config):
    checked_keys(config, ("front", "allowed_client", "upstream"))
    front, client, upstream = endpoint(config["front"], True), endpoint(config["allowed_client"]), endpoint(config["upstream"])
    if not ipaddress.ip_address(front[0]).is_loopback or not ipaddress.ip_address(client[0]).is_loopback:
        raise SupportError("invalid", "fault relay front and exact allowed client must be loopback endpoints")
    if ipaddress.ip_address(front[0]).version != ipaddress.ip_address(client[0]).version or ipaddress.ip_address(upstream[0]).is_unspecified:
        raise SupportError("invalid", "relay endpoint families or upstream address are invalid")
    return front, client, upstream


class FaultRelay:
    MAX_PACKETS = 256
    MAX_BYTES = 1024 * 1024

    def __init__(self, config):
        front, self.allowed_client, self.upstream = validate_relay(config)
        self.lock = threading.Lock()
        self.closed = threading.Event()
        self.front = socket.socket(socket.AF_INET6 if ":" in front[0] else socket.AF_INET, socket.SOCK_DGRAM)
        self.back = socket.socket(socket.AF_INET6 if ":" in self.upstream[0] else socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.front.bind(front)
            self.back.connect(self.upstream)
            self.front.setblocking(False)
            self.back.setblocking(False)
        except BaseException:
            self.front.close()
            self.back.close()
            raise
        self.mode, self.drop_every, self.delay_ms, self.epoch = "pass", 0, 0, 0
        self.pending, self.pending_bytes, self.serial = [], 0, 0
        self.sequence = {"forward": 0, "reverse": 0}
        self.counters = collections.Counter()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stats(self):
        with self.lock:
            return {"front": list(self.front.getsockname()[:2]), "allowed_client": list(self.allowed_client),
                    "upstream": list(self.upstream), "back": list(self.back.getsockname()[:2]),
                    "running": self.thread.is_alive(),
                    "mode": self.mode, "drop_every": self.drop_every, "delay_ms": self.delay_ms,
                    "epoch": self.epoch, "queued_packets": len(self.pending),
                    "queued_bytes": self.pending_bytes, "counters": dict(self.counters)}

    def policy(self, mode="pass", drop_every=0, delay_ms=0):
        if mode not in ("pass", "drop", "drop-forward", "drop-reverse"):
            raise SupportError("invalid", "unknown fault mode")
        integer(drop_every, 0, 1000000, "drop_every")
        integer(delay_ms, 0, 5000, "delay_ms")
        with self.lock:
            self.counters["policy_queue_drops"] += len(self.pending)
            self.pending.clear()
            self.pending_bytes = 0
            self.mode, self.drop_every, self.delay_ms = mode, drop_every, delay_ms
            self.epoch += 1
            self.sequence = {"forward": 0, "reverse": 0}
        return self.stats()

    def _send(self, direction, payload):
        try:
            count = self.back.send(payload) if direction == "forward" else self.front.sendto(payload, self.allowed_client)
            if count != len(payload):
                self.counters[direction + "_io_drops"] += 1
                return
            self.counters[direction + "_sent_packets"] += 1
            self.counters[direction + "_sent_bytes"] += count
        except OSError:
            self.counters[direction + "_io_drops"] += 1

    def _receive(self, direction, payload, address):
        with self.lock:
            if direction == "forward" and address[:2] != self.allowed_client:
                self.counters["foreign_source_drops"] += 1
                return
            self.counters[direction + "_received_packets"] += 1
            self.counters[direction + "_received_bytes"] += len(payload)
            self.sequence[direction] += 1
            if len(payload) > 65507:
                self.counters[direction + "_oversize_drops"] += 1
                return
            if self.mode == "drop" or self.mode == "drop-" + direction:
                self.counters[direction + "_partition_drops"] += 1
                return
            if self.drop_every and self.sequence[direction] % self.drop_every == 0:
                self.counters[direction + "_pattern_drops"] += 1
                return
            if self.delay_ms:
                if len(self.pending) >= self.MAX_PACKETS or self.pending_bytes + len(payload) > self.MAX_BYTES:
                    self.counters[direction + "_queue_drops"] += 1
                    return
                self.serial += 1
                heapq.heappush(self.pending, (time.monotonic() + self.delay_ms / 1000, self.serial, direction, payload))
                self.pending_bytes += len(payload)
            else:
                self._send(direction, payload)

    def _run(self):
        while not self.closed.is_set():
            try:
                ready, _, _ = select.select([self.front, self.back], [], [], 0.01)
            except (OSError, ValueError):
                break
            for source in ready:
                try:
                    payload, address = source.recvfrom(65536)
                except BlockingIOError:
                    continue
                except OSError:
                    with self.lock:
                        self.counters["socket_receive_errors"] += 1
                    continue
                self._receive("forward" if source is self.front else "reverse", payload, address)
            with self.lock:
                now = time.monotonic()
                while self.pending and self.pending[0][0] <= now:
                    _, _, direction, payload = heapq.heappop(self.pending)
                    self.pending_bytes -= len(payload)
                    self._send(direction, payload)

    def close(self):
        self.closed.set()
        self.thread.join(1)
        self.front.close()
        self.back.close()


class Supervisor:
    def __init__(self, spec):
        self.spec = spec if isinstance(spec, Spec) else Spec(spec)
        self.shutdown = threading.Event()
        self.children = {}
        self.relay = None

    def _child(self, params):
        name = params["name"]
        if not isinstance(name, str) or name not in self.children:
            raise SupportError("invalid", "process name has not been started")
        return self.children[name]

    def dispatch(self, method, params):
        if self.shutdown.is_set():
            raise SupportError("closed", "supervisor is closing")
        if method == "start":
            checked_keys(params, ("name",))
            name = params["name"]
            argv, env = self.spec.command(name)
            previous = self.children.get(name)
            if previous is not None:
                if previous.process.poll() is None:
                    raise SupportError("busy", "named child is still running")
                previous.eof()
                previous.close_readers()
            elif len(self.children) >= MAX_CHILDREN:
                raise SupportError("limit", "task child count limit reached")
            child = Child(name, argv, self.spec.root, env, self.shutdown)
            self.children[name] = child
            return {"name": name, "pid": child.process.pid, "running": True}
        if method in ("next", "wait"):
            checked_keys(params, ("name",), ("timeout",))
            child = self._child(params)
            return getattr(child, method)(params.get("timeout", 10))
        if method == "until":
            checked_keys(params, ("name", "terminator"), ("max_lines", "timeout"))
            return self._child(params).until(params["terminator"], params.get("max_lines", 4096), params.get("timeout", 10))
        if method == "send":
            checked_keys(params, ("name", "line"))
            return self._child(params).send(params["line"])
        if method in ("status", "eof", "terminate", "kill"):
            checked_keys(params, ("name",))
            child = self._child(params)
            if method in ("terminate", "kill"):
                return child.signal(method == "kill")
            return getattr(child, method)()
        if method == "relay.start":
            checked_keys(params)
            if self.relay is not None:
                raise SupportError("busy", "task relay is already running")
            if self.spec.relay is None:
                raise SupportError("invalid", "spec declares no task relay")
            self.relay = FaultRelay(self.spec.relay)
            return self.relay.stats()
        if method in ("relay.policy", "relay.stats", "relay.stop"):
            if self.relay is None:
                raise SupportError("closed", "task relay is not running")
            if method == "relay.policy":
                checked_keys(params, (), ("mode", "drop_every", "delay_ms"))
                return self.relay.policy(**params)
            checked_keys(params)
            result = self.relay.stats()
            if method == "relay.stop":
                self.relay.close()
                self.relay = None
            return result
        raise SupportError("invalid", "unknown task support method")

    def close(self):
        self.shutdown.set()
        children = list(self.children.values())
        for child in children:
            child.eof()
        for seconds, kill in ((0.5, False), (1, True), (1, None)):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline and any(child.process.poll() is None for child in children):
                time.sleep(0.01)
            if kill is not None:
                for child in children:
                    child.signal(kill)
        for child in children:
            child.close_readers()
        if self.relay is not None:
            self.relay.close()
            self.relay = None


def serve_stdio(supervisor, input_fd=0, output_fd=1):
    requests = queue.Queue(maxsize=16)
    os.set_blocking(input_fd, False)
    os.set_blocking(output_fd, False)

    def read_requests():
        partial = bytearray()
        while not supervisor.shutdown.is_set():
            try:
                ready, _, _ = select.select([input_fd], [], [], 0.05)
                if not ready:
                    continue
                block = os.read(input_fd, 8192)
            except BlockingIOError:
                continue
            except (OSError, ValueError):
                supervisor.shutdown.set()
                return
            if not block:
                supervisor.shutdown.set()
                return
            partial.extend(block)
            while b"\n" in partial:
                offset = partial.index(b"\n") + 1
                if offset > MAX_REQUEST:
                    supervisor.shutdown.set()
                    return
                line = bytes(partial[:offset])
                del partial[:offset]
                try:
                    requests.put_nowait(line)
                except queue.Full:
                    supervisor.shutdown.set()
                    return
            if len(partial) > MAX_REQUEST:
                supervisor.shutdown.set()
                return

    reader = threading.Thread(target=read_requests, daemon=True)
    reader.start()
    try:
        while not supervisor.shutdown.is_set():
            try:
                line = requests.get(timeout=0.05)
            except queue.Empty:
                continue
            request_id = None
            try:
                request = json_loads(line.decode("utf-8"))
                checked_keys(request, ("id", "method"), ("params",))
                request_id = request["id"]
                if isinstance(request_id, bool) or not isinstance(request_id, (str, int)) or len(str(request_id)) > 64:
                    raise SupportError("invalid", "request id must be a bounded string or integer")
                if not isinstance(request["method"], str):
                    raise SupportError("invalid", "method must be text")
                result = supervisor.dispatch(request["method"], request.get("params", {}))
                response = {"id": request_id, "ok": True, "result": result}
            except (SupportError, OSError, ValueError, TypeError, UnicodeError, RecursionError) as error:
                response = {"id": request_id, "ok": False, "error": {
                    "code": getattr(error, "code", "invalid"), "message": str(error)}}
            encoded = (json.dumps(response, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
            offset, deadline = 0, time.monotonic() + 5
            while offset < len(encoded) and not supervisor.shutdown.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    supervisor.shutdown.set()
                    break
                _, ready, _ = select.select([], [output_fd], [], min(remaining, 0.05))
                if ready:
                    try:
                        offset += os.write(output_fd, encoded[offset:])
                    except BlockingIOError:
                        continue
    except (OSError, ValueError):
        supervisor.shutdown.set()
    finally:
        supervisor.close()
        reader.join(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, help="existing private task spec JSON")
    args = parser.parse_args()
    with open(args.spec, "rb") as source:
        data = source.read(MAX_SPEC + 1)
    if len(data) > MAX_SPEC:
        raise SupportError("invalid", "spec exceeds 1 MiB")
    supervisor = Supervisor(json_loads(data.decode("utf-8")))
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, lambda _number, _frame: supervisor.shutdown.set())
    serve_stdio(supervisor)


if __name__ == "__main__":
    try:
        main()
    except (SupportError, OSError, ValueError) as error:
        print("remote acceptance support: %s" % error, file=sys.stderr)
        sys.exit(1)
