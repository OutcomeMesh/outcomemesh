import gzip
import zipfile
import version as versions
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location('release', Path(__file__).with_name('release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseArtifacts(unittest.TestCase):
    def test_version_rejects_paths_shell_and_ambiguous_tags(self):
        for version in ('v0.2.0', 'v1.2.3', 'v2.0.0'):
            self.assertEqual(release.validate_version(version), version)
        for version in ('', '../v1.0.0', 'v1.0.0;id', 'v1.0.0\n', 'v1.0', '1.2.3', 'v01.2.3', 'v1.0.0/rc', '$(id)', 'v0.1.0-alpha.1', 'v1.2.3-rc.1'):
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

    def test_zip_is_deterministic_extractable_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            a, b = Path(temporary) / 'a.zip', Path(temporary) / 'b.zip'
            entries = {'omd.exe': (b'MZbinary', 0o755), 'LICENSE': (b'notice', 0o644)}
            release.archive(a, 'windows', entries, 1234567890)
            release.archive(b, 'windows', dict(reversed(list(entries.items()))), 1234567890)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with zipfile.ZipFile(a) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.namelist(), ['windows/LICENSE', 'windows/omd.exe'])
                self.assertEqual(archive.read('windows/omd.exe'), b'MZbinary')
                self.assertEqual(archive.getinfo('windows/omd.exe').external_attr >> 16, 0o100755)
            with self.assertRaises(FileExistsError):
                release.archive(a, 'windows', entries, 1234567890)
            for entry in ('../escape', '/absolute', r'..\escape', 'C:stream', './dot', ''):
                with self.assertRaises(ValueError):
                    release.archive(Path(temporary) / 'bad.zip', 'windows', {entry: (b'x', 0o644)}, 1)

    def test_version_source_tag_and_progression_agree(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'VERSION'
            path.write_text('0.2.0\n')
            self.assertEqual(versions.require_version(temporary, 'v0.2.0'), 'v0.2.0')
            with self.assertRaises(ValueError):
                versions.require_version(temporary, 'v0.3.0')
            for bad in ('0.2.0', '0.2.0\n\n', '00.2.0\n', '0.2.0-alpha.1\n'):
                path.write_text(bad)
                with self.assertRaises(ValueError):
                    versions.source_version(temporary)
        versions.require_progression('v0.2.0', ['v0.1.0-alpha.1', 'v0.1.0-alpha.2', 'v0.2.0'])
        for previous in ('v0.2.1', 'v0.3.0', 'v1.0.0'):
            with self.assertRaises(ValueError):
                versions.require_progression('v0.2.0', [previous])

    def test_packaging_rejects_changed_or_replaced_source_commit(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(release, 'ROOT', Path(temporary)):
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=temporary, stderr=subprocess.DEVNULL)
            git('init', '--quiet')
            source = Path(temporary) / 'source.go'
            source.write_text('original source')
            git('add', 'source.go')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'original')
            commit = git('rev-parse', 'HEAD').decode().strip()
            manifest = release.source_manifest()
            release.require_source(commit, manifest)
            source.write_text('changed source')
            with self.assertRaises(ValueError):
                release.require_source(commit, manifest)
            git('add', 'source.go')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'changed')
            with self.assertRaises(ValueError):
                release.require_source(commit, manifest)

    def test_archive_refuses_parent_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                release.archive(Path(temporary) / 'bad.tar.gz', 'release', {'../escape': (b'x', 0o644)}, 1)


if __name__ == '__main__':
    unittest.main()
