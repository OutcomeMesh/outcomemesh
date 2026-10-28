#!/usr/bin/env python3
"""Verify a separately trusted cutover fixture manifest with the actual omd CLI.

The manifest is a historical test corpus, not enrollment or activation evidence.
Extract its archive into a new directory before calling this script.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def verify(binary, corpus, manifest):
    manifest = Path(manifest)
    if manifest.stat().st_size > 256 << 10:
        raise ValueError("manifest exceeds the public fixture bound")
    document = json.loads(manifest.read_text())
    if document["format"] != "outcomemesh-cutover-review-public-v1":
        raise ValueError("unsupported corpus manifest")
    corpus = Path(corpus).resolve(strict=True)
    if len(document["files"]) != 7:
        raise ValueError("incomplete or extra corpus file declarations")
    names = set()
    for item in document["files"]:
        name = item["name"]
        if name in names or Path(name).name != name or name in (".", ".."):
            raise ValueError("duplicate or unsafe corpus name")
        names.add(name)
        path = corpus / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("corpus entry is not an original regular file")
        if not 0 <= item["bytes"] <= (32 << 20) + 4278 or path.stat().st_size != item["bytes"]:
            raise ValueError("corpus artifact exceeds its declared bounded size")
        raw = path.read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("corpus artifact differs: " + name)
    if names != {"evidence", "anchor", "a-observation", "b-observation", "proposal", "assessment.json", "bridge.json"}:
        raise ValueError("incomplete or extra corpus files")
    if {p.name for p in corpus.iterdir()} != names:
        raise ValueError("unlisted corpus files")
    pin = document["pins"]
    with tempfile.TemporaryDirectory(prefix="omesh-cutover-public-") as temporary:
        output = Path(temporary) / "verified-bridge.json"
        args = [str(Path(binary).resolve(strict=True)), "work-archive-custody-cutover-review",
                "--action", "verify-proposal", "--proposal", str(corpus / "proposal"),
                "--legacy-id", pin["legacy_id"], "--retired-sequence", str(pin["retired_sequence"]),
                "--retired-head", pin["retired_head"], "--anchor-id", pin["anchor_id"],
                "--descriptor-id", pin["descriptor_id"], "--out", str(output)]
        review = subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)
        fields = dict(field.split("=", 1) for field in review.stdout.splitlines()[0].split()[1:])
        if fields.get("execution_granted") != "false" or fields.get("stores_opened") != "false":
            raise ValueError("CLI did not produce a disabled public review")
        subprocess.run(args + ["--mode", "run", "--expected-review-id", fields["review_id"]],
                       check=True, capture_output=True, text=True, timeout=30)
        actual = json.loads(output.read_text())
        if actual != document["bridge"] or actual["ActivationAllowed"]:
            raise ValueError("CLI bridge does not match the separately trusted manifest")
    return {"verified_files": len(names), "spent": actual["Spent"], "authorized": actual["Authorized"],
            "whole_jobs": actual["WholeJobs"], "execution_granted": False, "activation_allowed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--omd", required=True)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.omd, args.corpus, args.manifest), sort_keys=True))


if __name__ == "__main__":
    main()
