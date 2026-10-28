"""Corrupt public corpus inputs must refuse before starting any verifier binary."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

REPOSITORY = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_cutover_public", REPOSITORY / "scripts/verify_cutover_public.py")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class CutoverPublicCorpusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.manifest = self.root / "manifest.json"
        document = json.loads((REPOSITORY / "docs/evidence/custody-cutover-review-public-20261028.json").read_text())
        archive = REPOSITORY / "docs/evidence" / document["archive"]
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), document["archive_sha256"])
        with tarfile.open(archive) as source:
            for member in source:
                self.assertTrue(member.isfile())
                self.assertEqual(Path(member.name).name, member.name)
                (self.corpus / member.name).write_bytes(source.extractfile(member).read())
        self.document = document
        self.manifest.write_text(json.dumps(document))

    def refuse(self, document=None):
        if document is not None:
            self.manifest.write_text(json.dumps(document))
        # Any attempted binary execution raises FileNotFoundError instead of the
        # expected ValueError, so the check proves these inputs refuse first.
        with self.assertRaises(ValueError):
            VERIFIER.verify(self.root / "must-not-execute", self.corpus, self.manifest)

    def test_changed_signed_packet_refuses_before_binary(self):
        path = self.corpus / "proposal"
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
        self.refuse()

    def test_duplicate_or_unsafe_manifest_member_refuses_before_binary(self):
        for name in (self.document["files"][1]["name"], "../outside", "/absolute", ".."):
            with self.subTest(name=name):
                changed = copy.deepcopy(self.document)
                changed["files"][0]["name"] = name
                self.refuse(changed)

    def test_symlink_cannot_substitute_a_manifest_member(self):
        path = self.corpus / "proposal"
        other = self.root / "same-public-packet"
        path.rename(other)
        path.symlink_to(other)
        self.refuse()

    def test_extra_file_or_missing_declaration_refuses_before_binary(self):
        extra = self.corpus / "unexpected"
        extra.write_text("retained unexpected file")
        self.refuse()
        extra.unlink()
        changed = copy.deepcopy(self.document)
        changed["files"].pop()
        self.refuse(changed)

    def test_large_sparse_packet_cannot_trigger_an_unbounded_read(self):
        path = self.corpus / "proposal"
        size = (32 << 20) + 4279
        with path.open("wb") as output:
            output.truncate(size)
        changed = copy.deepcopy(self.document)
        item = next(item for item in changed["files"] if item["name"] == "proposal")
        item["bytes"] = size
        self.refuse(changed)
