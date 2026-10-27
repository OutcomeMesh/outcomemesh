"""Acceptance assertions and portable archive regressions; no servers or keys."""

import copy
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

import run


class ControllerTests(unittest.TestCase):
    def test_archive_transfers_exact_fixture_paths_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "journal").mkdir(mode=0o700)
            path = root / "journal" / "header.omcj"
            path.write_bytes(b"canonical fixture bytes")
            path.chmod(0o600)
            if hasattr(os, "setxattr"):
                try:
                    os.setxattr(path, "com.apple.metadata:acceptance" if os.uname().sysname == "Darwin" else "user.acceptance", b"filesystem only")
                except OSError:
                    pass
            encoded = subprocess.check_output(run.archive_command(root))
            with tarfile.open(fileobj=io.BytesIO(encoded)) as archive:
                self.assertEqual(set(archive.getnames()), {".", "./journal", "./journal/header.omcj"})
                self.assertEqual(archive.extractfile("./journal/header.omcj").read(), path.read_bytes())
                self.assertEqual(archive.getmember("./journal/header.omcj").mode, 0o600)

    def test_fixed_command_requires_all_pins_and_rejects_control_injection(self):
        self.assertEqual(run.interpolate(["--entry-id", "{ENTRY}"], {"ENTRY": "ab" * 32}), ["--entry-id", "ab" * 32])
        for value in ({}, {"ENTRY": "review\napply"}, {"ENTRY": "bad\x00path"}):
            with self.assertRaises(run.AcceptanceError):
                run.interpolate(["{ENTRY}"], value)
        for value in (run.ZERO, "A" * 64, "a" * 63, "a" * 65):
            with self.assertRaises(run.AcceptanceError):
                run.digest_id(value)

    def test_convergence_rejects_different_proof_or_implicit_completion(self):
        state = {"pending_attempt": False, "journal_sequence": 1, "authority_sequence": 1,
                 "phase": "accepting", "operations": [{"completion_id": run.ZERO}],
                 "journal_head_id": "1" * 64, "current_receipt_id": "2" * 64,
                 "head_proof_id": "3" * 64, "responded_at": 123, "challenge_id": "4" * 64}
        run.assert_state(state, copy.deepcopy(state), 1)
        for key, value in (("head_proof_id", "5" * 64), ("responded_at", 124),
                           ("journal_sequence", 2), ("authority_sequence", 2), ("pending_attempt", True)):
            altered = copy.deepcopy(state)
            altered[key] = value
            with self.assertRaises(run.AcceptanceError):
                run.assert_state(state, altered, 1)
        altered = copy.deepcopy(state)
        altered["operations"][0]["completion_id"] = "6" * 64
        with self.assertRaises(run.AcceptanceError):
            run.assert_state(state, altered, 1)


if __name__ == "__main__":
    unittest.main()
