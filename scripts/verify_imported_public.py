#!/usr/bin/env python3
"""Replay the public accounting import corpus against a separately trusted manifest.

This verifies historical accounting and selection. It opens no owner, loads no
seed and does not establish that old signers or copied machines are fenced.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

NAMES = {"proposal", "genesis", "registry", "selection", "selection-certificate",
         "enrollment", "context", "admission-entry", "admission-certificate",
         "accounting-history", "initial-accounting.json", "historical-accounting.json"}
MAXIMUM = (32 << 20) + 4298


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_manifest(path):
    path = Path(path)
    if path.stat().st_size > 256 << 10:
        raise ValueError("manifest exceeds the public fixture bound")
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def verify(binary, corpus, manifest):
    document = read_manifest(manifest)
    if document["format"] != "outcomemesh-custody-import-public-v1":
        raise ValueError("unsupported corpus manifest")
    corpus = Path(corpus).resolve(strict=True)
    files = document["files"]
    if len(files) != len(NAMES):
        raise ValueError("incomplete or extra corpus declarations")
    seen = set()
    for item in files:
        name = item["name"]
        if name not in NAMES or name in seen:
            raise ValueError("duplicate or unsafe corpus name")
        seen.add(name)
        path = corpus / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("corpus entry must be a regular file")
        if type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAXIMUM:
            raise ValueError("invalid bounded size")
        if path.stat().st_size != item["bytes"]:
            raise ValueError("artifact size differs")
        raw = path.read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("artifact differs: " + name)
    if {p.name for p in corpus.iterdir()} != NAMES:
        raise ValueError("unlisted corpus files")
    pin = document["pins"]
    for key, value in pin.items():
        if key == "retired_sequence":
            if type(value) is not int or not 1 <= value <= 642:
                raise ValueError("invalid retirement sequence")
        elif not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid independent pin")
    binary = str(Path(binary).resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix="omesh-import-public-") as temporary:
        temporary = Path(temporary)

        def reviewed(command, flags, name):
            output = temporary / name
            args = [binary, command] + flags + ["--out", str(output)]
            result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)
            fields = dict(field.split("=", 1) for field in result.stdout.splitlines()[0].split()[1:])
            if fields.get("keys_loaded") != "false" or fields.get("execution_granted") != "false":
                raise ValueError("CLI did not produce a disabled public review")
            if fields.get("owners_opened", fields.get("stores_opened")) != "false":
                raise ValueError("public review opened an owner")
            subprocess.run(args + ["--mode", "run", "--expected-review-id", fields["review_id"]],
                           check=True, capture_output=True, text=True, timeout=30)
            return output.read_bytes()

        genesis = reviewed("work-archive-custody-cutover-review", [
            "--action", "import-genesis", "--proposal", str(corpus / "proposal"),
            "--proposal-id", pin["proposal_id"], "--anchor-id", pin["registry_id"],
            "--descriptor-id", pin["registry_descriptor_id"], "--legacy-id", pin["legacy_id"],
            "--retired-sequence", str(pin["retired_sequence"]), "--retired-head", pin["retired_head"]], "genesis")
        if genesis != (corpus / "genesis").read_bytes():
            raise ValueError("derived imported genesis differs")
        enrollment = reviewed("work-archive-custody-registry", [
            "--action", "import-enrollment", "--registry", str(corpus / "registry"),
            "--registry-id", pin["registry_id"], "--registry-descriptor-id", pin["registry_descriptor_id"],
            "--in", str(corpus / "selection-certificate"), "--in-id", pin["selection_certificate_artifact_id"]], "enrollment")
        if enrollment != (corpus / "enrollment").read_bytes():
            raise ValueError("derived imported selection binding differs")
        common = ["--genesis", str(corpus / "genesis"), "--genesis-id", pin["genesis_id"],
                  "--genesis-descriptor-id", pin["genesis_descriptor_id"],
                  "--enrollment", str(corpus / "enrollment"), "--enrollment-id", pin["enrollment_artifact_id"]]
        for action, name, extra in [
            ("inspect-genesis", "initial-accounting.json", []),
            ("inspect-history", "historical-accounting.json", ["--in", str(corpus / "accounting-history"),
                                                               "--in-id", pin["history_artifact_id"]])]:
            actual = json.loads(reviewed("work-archive-custody-v2-admission", ["--action", action] + common + extra, name))
            if actual != json.loads((corpus / name).read_text()) or actual["ExecutionGranted"] or not actual["HistoricalOnly"]:
                raise ValueError("historical accounting replay differs")
        state = actual["Snapshot"]
    return {"verified_files": len(seen), "spent": state["SpentOperations"],
            "pending": state["PendingOperations"], "source_sequence": state["SourceSequence"],
            "execution_granted": False, "global_old_copy_exclusion_proven": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--omd", required=True)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.omd, args.corpus, args.manifest), sort_keys=True))


if __name__ == "__main__":
    main()
