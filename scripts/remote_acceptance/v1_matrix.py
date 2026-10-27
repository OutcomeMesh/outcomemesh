#!/usr/bin/env python3
"""Export fresh, never-started fixtures and run an explicit V1 WAN matrix."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import uuid

from run import AcceptanceError, Host, fields, require
import v1


def export_fixture(host, parent, destination):
    host.execute(["python3", "-c", "import os,sys; os.makedirs(sys.argv[1],mode=0o700,exist_ok=True)", parent])
    output = host.execute([host.test_binary, "-test.run=^TestExportRemoteV1Fixture$", "-test.count=1"],
                          {"OUTCOMEMESH_REMOTE_FIXTURE_OUT": parent}).stdout.decode()
    exported = fields(output, "remote_v1_fixture")["root"]
    require(exported.startswith(parent + "/v1-fixture-"), "export escaped its selected parent")
    script = ("import sys,tarfile\n"
              "with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive: archive.add(sys.argv[1],arcname='fixture')\n")
    data = host.execute(["python3", "-c", script, exported]).stdout
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = archive.getmembers()
        require(len(members) <= 4096, "export contains too many entries")
        for entry in members:
            require(not entry.name.startswith("/") and ".." not in Path(entry.name).parts and
                    (entry.isfile() or entry.isdir()), "export contains a link or unsafe path")
        archive.extractall(destination)
    # Python's data extraction filter may intentionally discard directory
    # modes. Restore privacy before this never-started export is installed.
    for path in destination.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    return destination / "fixture", hashlib.sha256(data).hexdigest()


def run_matrix(config, out, scenarios, cycles):
    require(out.is_dir() and out.stat().st_mode & 0o077 == 0, "existing private output directory required")
    require(1 <= cycles <= 64 and scenarios and all(x in v1.SCENARIOS for x in scenarios), "invalid explicit matrix")
    exporter = Host(config["hosts"]["a"])
    completed = []
    for scenario in scenarios:
        name = scenario + "-" + uuid.uuid4().hex[:12]
        directory = out / name
        directory.mkdir(mode=0o700)
        fixture, fixture_hash = export_fixture(exporter, config["export_parent"], directory / "export")
        selected = json.loads(json.dumps(config))
        for role in ("a", "b"):
            selected["hosts"][role]["root"] += "-" + name
        private_config = directory / "hosts.json"
        v1.publish_report(private_config, selected)
        report = directory / "report.json"
        log = directory / "controller.log"
        argv = [sys.executable, str(Path(__file__).with_name("v1.py")), "--config", str(private_config),
                "--fixture", str(fixture), "--scenario", scenario, "--cycles", str(cycles if scenario == "soak" else 1), "--out", str(report)]
        print("remote_v1_matrix_start scenario=%s private_log=%s" % (scenario, log), flush=True)
        with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            status = process.wait()
        require(status == 0 and report.exists(), "scenario failed; retained evidence: " + str(directory))
        value = json.loads(report.read_text())
        require(value.get("passed") is True, "scenario did not pass")
        completed.append({"scenario": scenario, "cycles": value["cycle_count"], "report": str(report),
                          "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(), "fixture_archive_sha256": fixture_hash})
        v1.publish_report(directory / "provenance.json", completed[-1])
        print("remote_v1_matrix_pass scenario=%s cycles=%d assignment=%s" % (scenario, value["cycle_count"], value["assignment_id"]), flush=True)
    v1.publish_report(out / ("matrix-" + uuid.uuid4().hex + ".json"), {"version": 1, "completed": completed, "passed": True})
    return completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--scenarios", default=",".join(v1.SCENARIOS))
    parser.add_argument("--soak-cycles", type=int, default=32)
    args = parser.parse_args()
    run_matrix(json.loads(Path(args.config).read_text()), Path(args.out_dir), args.scenarios.split(","), args.soak_cycles)


if __name__ == "__main__":
    try:
        main()
    except (AcceptanceError, OSError, ValueError) as exc:
        print("remote_v1_matrix_failed " + str(exc), flush=True)
        raise SystemExit(1)
