"""Disposable guard deployment across two authorized SSH hosts.

Config contains ssh_a/ssh_b argv, binary, fixtures, root, uid, and three ports.
No credentials are accepted. Existing authenticated SSH control sockets are
required. Only the fresh root and forwards created by this run are modified.
The guard survives only for this bounded campaign; original evidence is retained.
"""
import json
import hashlib
import pathlib
import re
import shlex
import subprocess
import sys
import time
import zlib


def run(config):
    root = config["root"]
    if not re.fullmatch(r"/var/tmp/omesh-guard-[a-zA-Z0-9-]+", root):
        raise ValueError("fresh dedicated root required")
    uid = int(config["uid"])
    if uid <= 0 or uid == 65534:
        raise ValueError("guard needs a separate non-root UID")
    a, b = config["ssh_a"], config["ssh_b"]
    fixtures = pathlib.Path(config["fixtures"])
    gp, lp, bp = (int(config[k]) for k in ("guard_port", "local_port", "client_port"))
    for p in (gp, lp, bp):
        if not 1024 <= p <= 65535:
            raise ValueError("unprivileged explicit ports required")
    forwards = []
    started = False

    def ssh(host, command, data=None, check=True):
        return subprocess.run(host + [command], input=data, capture_output=True, check=check, timeout=300)

    def write(host, path, data, mode=0o644):
        # Exclusive publication with file + directory fsync, no secret data.
        program = "import os,sys,zlib; p=sys.argv[1]; f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,int(sys.argv[2])); b=zlib.decompress(sys.stdin.buffer.read()); fobj=os.fdopen(f,'wb'); fobj.write(b); os.fchmod(fobj.fileno(),int(sys.argv[2])); fobj.flush(); os.fsync(fobj.fileno()); fobj.close(); d=os.open(os.path.dirname(p),os.O_RDONLY); os.fsync(d); os.close(d)"
        ssh(host, shlex.join(["python3", "-c", program, path, str(mode)]), zlib.compress(data))

    def reviewed(args, execute=True):
        command = shlex.join(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", root + "/omd", "work-archive-custody-guard"] + args)
        output = ssh(a, command).stdout.decode()
        pin = re.search(r"review_id=([0-9a-f]{64})", output).group(1)
        prepared = command + " --mode run --expected-review-id " + pin
        return ssh(a, prepared) if execute else prepared

    def forward(host, spec, direction, add):
        subprocess.run(host[:-1] + ["-O", "forward" if add else "cancel", direction, spec, host[-1]], check=True, capture_output=True, timeout=15)

    def stop():
        nonlocal started
        if started:
            program = "import os,signal,sys; p=int(open(sys.argv[1]+'/pid').read()); cmd=open('/proc/%s/cmdline'%p,'rb').read(); assert (sys.argv[1]+'/omd').encode() in cmd; os.kill(p,signal.SIGKILL)"
            ssh(a, shlex.join(["python3", "-c", program, root]), check=False)
            started = False

    def start(position, number):
        nonlocal started
        command = reviewed(["--action", "serve", "--root", root + "/private/store", "--identity", root + "/public/identity.json", "--position", position, "--listen", f"127.0.0.1:{gp}"], False)
        log = root + f"/log-{number}"
        ssh(a, "nohup " + command + " >" + shlex.quote(log) + " 2>&1 </dev/null & echo $! >" + shlex.quote(root + "/pid"))
        started = True
        for _ in range(30):
            if b"custody_guard_ready" in ssh(a, "cat " + shlex.quote(log)).stdout:
                return log
            time.sleep(0.1)
        raise RuntimeError("guard did not become ready")

    def request(name, output, expected=200):
        command = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "curl", "--noproxy", "*", "--silent", "--show-error", "--max-time", "3", "--output", output, "--write-out", "%{http_code}", "--data-binary", "@" + root + "/" + name + ".bin", f"http://127.0.0.1:{bp}/outcomemesh/custody-guard/1"]
        response = ssh(b, shlex.join(command), check=False)
        if expected is not None:
            assert response.returncode == 0 and response.stdout.decode() == str(expected), response.stderr.decode()
        return response

    try:
        for host in (a, b):
            ssh(host, "mkdir " + shlex.quote(root) + " && chmod 755 " + shlex.quote(root))
        ssh(a, f"! getent passwd {uid} >/dev/null")
        binary = pathlib.Path(config["binary"]).read_bytes()
        digest = hashlib.sha256(binary).hexdigest()
        if config.get("binary_cache"):
            cache = config["binary_cache"]
            if not re.fullmatch(r"/var/tmp/omesh-guard-[a-zA-Z0-9-]+/omd", cache):
                raise ValueError("unexpected binary cache path")
            actual = ssh(a, "sha256sum " + shlex.quote(cache)).stdout.decode().split()[0]
            assert actual == digest, "cached binary differs"
            ssh(a, "cp --reflink=auto " + shlex.quote(cache) + " " + shlex.quote(root + "/omd"))
        else:
            write(a, root + "/omd", binary, 0o755)
        ssh(a, f"mkdir {root}/private {root}/public && chown {uid}:{uid} {root}/private {root}/public && chmod 700 {root}/private && chmod 755 {root}/public")
        for name in ("config.json", "position.json"):
            write(a, root + "/public/" + name, (fixtures / name).read_bytes())
        reviewed(["--action", "create", "--root", root + "/private/store", "--config", root + "/public/config.json", "--out", root + "/public/identity.json"])
        identity = ssh(a, "cat " + root + "/public/identity.json").stdout
        write(b, root + "/identity.json", identity)
        (fixtures / "identity.json").write_bytes(identity)
        write(b, root + "/verify", (fixtures / "verify").read_bytes(), 0o755)
        for name in ("first", "conflict", "next"):
            write(b, root + "/" + name + ".bin", (fixtures / (name + ".bin")).read_bytes())
        ssh(b, f"mkdir {root}/client && chown 65534:65534 {root}/client && chmod 700 {root}/client")
        ssh(a, f"test -s {root}/private/store/key")
        isolation = ssh(a, f"setpriv --reuid=65534 --regid=65534 --clear-groups cat {root}/private/store/key", check=False)
        assert isolation.returncode != 0
        log = start(root + "/public/position.json", 1)
        specs = [(a, f"127.0.0.1:{lp}:127.0.0.1:{gp}", "-L"), (b, f"127.0.0.1:{bp}:127.0.0.1:{lp}", "-R")]
        for host, spec, direction in specs:
            forward(host, spec, direction, True)
            forwards.append((host, spec, direction))
        request("first", root + "/client/first.seal")
        ssh(b, f"setpriv --reuid=65534 --regid=65534 --clear-groups {root}/verify verify {root}/identity.json {root}/first.bin {root}/client/first.seal")
        request("conflict", root + "/client/conflict.reply", 409)
        journal = ssh(a, "cat " + log).stdout
        position = [json.loads(line)["Position"] for line in journal.splitlines() if line.startswith(b'{')][-1]
        assert position["Sequence"] == 1
        write(b, root + "/position-1.json", json.dumps(position).encode(), 0o600)
        # A tunnel cut cannot generate a seal or advance the guard.
        host, spec, direction = forwards.pop()
        forward(host, spec, direction, False)
        assert request("next", root + "/client/cut.reply", None).returncode != 0
        forward(host, spec, direction, True)
        forwards.append((host, spec, direction))
        stop()
        stale = reviewed(["--action", "serve", "--root", root + "/private/store", "--identity", root + "/public/identity.json", "--position", root + "/public/position.json", "--listen", f"127.0.0.1:{gp}"], False)
        assert ssh(a, stale, check=False).returncode != 0
        retained = ssh(b, "cat " + root + "/position-1.json").stdout
        write(a, root + "/public/position-1.json", retained)
        log = start(root + "/public/position-1.json", 2)
        request("first", root + "/client/retry.seal")
        ssh(b, f"cmp {root}/client/first.seal {root}/client/retry.seal")
        request("conflict", root + "/client/cold-conflict.reply", 409)
        request("next", root + "/client/next.seal")
        ssh(b, f"setpriv --reuid=65534 --regid=65534 --clear-groups {root}/verify verify {root}/identity.json {root}/next.bin {root}/client/next.seal")
        journal = ssh(a, "cat " + log).stdout
        position = [json.loads(line)["Position"] for line in journal.splitlines() if line.startswith(b'{')][-1]
        assert position["Sequence"] == 2
        write(b, root + "/position-2.json", json.dumps(position).encode(), 0o600)
        report = {"binary_sha256": digest, "guard_uid": uid, "participant_uid": 65534, "choices": 2, "conflicting_choices_refused": 2, "stale_restart_refused": True, "exact_reply_preserved": True, "tunnel_cut_refused": True, "participant_cannot_read_guard": True, "external_cursor_retained_on_b": True, "independent_operator": False, "transport": "SSH via operator workstation"}
        (fixtures / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        stop()
        for host, spec, direction in reversed(forwards):
            try:
                forward(host, spec, direction, False)
            except subprocess.SubprocessError:
                pass


if __name__ == "__main__":
    print(json.dumps(run(json.loads(pathlib.Path(sys.argv[1]).read_text())), indent=2))
