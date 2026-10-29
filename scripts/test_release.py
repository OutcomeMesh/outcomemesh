import gzip
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('release', Path(__file__).with_name('release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseArtifacts(unittest.TestCase):
    def test_version_rejects_paths_shell_and_ambiguous_tags(self):
        for version in ('v0.1.0-alpha.1', 'v1.2.3', 'v2.0.0-rc.1'):
            self.assertEqual(release.validate_version(version), version)
        for version in ('', '../v1.0.0', 'v1.0.0;id', 'v1.0.0\n', 'v1.0', '1.2.3', 'v01.2.3', 'v1.0.0/rc', '$(id)'):
            with self.assertRaises(ValueError):
                release.validate_version(version)

    def test_archives_are_reproducible_and_keep_executable_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            a, b = Path(temporary) / 'a.tar.gz', Path(temporary) / 'b.tar.gz'
            entries = {'omd': (b'binary', 0o755), 'LICENSE': (b'notice', 0o644)}
            release.archive(a, 'outcomemesh-v0.1.0-linux-amd64', entries, 1234567890)
            release.archive(b, 'outcomemesh-v0.1.0-linux-amd64', dict(reversed(list(entries.items()))), 1234567890)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with tarfile.open(fileobj=io.BytesIO(gzip.decompress(a.read_bytes()))) as tar:
                members = tar.getmembers()
                self.assertEqual([m.name for m in members], ['outcomemesh-v0.1.0-linux-amd64/LICENSE', 'outcomemesh-v0.1.0-linux-amd64/omd'])
                self.assertEqual(members[1].mode, 0o755)
                self.assertEqual(members[1].uid, 0)
                self.assertEqual(members[1].mtime, 1234567890)
            with self.assertRaises(FileExistsError):
                release.archive(a, 'release', entries, 1234567890)

    def test_archive_refuses_parent_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                release.archive(Path(temporary) / 'bad.tar.gz', 'release', {'../escape': (b'x', 0o644)}, 1)


if __name__ == '__main__':
    unittest.main()
