"""Regression tests for verified directory restore and rollback.

Synthetic, isolated local vaults only; never reads a real owner's archive.
The historical v2.2 overwrite path deleted the old tree before decryption.
"""
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidTag
from sealed_core import SealedCore


SECRET = "synthetic-owner-passphrase-only-for-directory-tests"


class SafeDirectoryRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-directory-integrity-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "photos"
        (self.source / "nested").mkdir(parents=True)
        (self.source / "one.txt").write_bytes(b"verified new tree")
        (self.source / "nested" / "two.bin").write_bytes(b"verified nested file")
        self.restore_root = self.root / "restore"
        self.target = self.restore_root / "photos"
        self.target.mkdir(parents=True)
        (self.target / "important.txt").write_bytes(b"ORIGINAL KEEP ME")
        self.core = SealedCore(SECRET, storage_dir=str(self.root / "store"))
        self.addCleanup(self.core.close)
        self.record = self.core.seal_directory(str(self.source))
        self.object_id = self.record["object_id"]

    def assert_old_intact(self):
        self.assertEqual((self.target / "important.txt").read_bytes(), b"ORIGINAL KEEP ME")
        self.assertEqual(sorted(x.name for x in self.target.iterdir()), ["important.txt"])

    def assert_clean(self):
        self.assertEqual(list(self.restore_root.glob(".photos.sealed-restore-*")), [])
        self.assertEqual(list(self.restore_root.glob(".photos.sealed-backup-*")), [])

    def _seal_custom_archive(self, content: bytes) -> str:
        archive = self.root / "custom.tar.gz"
        archive.write_bytes(content)
        info = self.core._seal_file_like(
            source=archive,
            kind="directory",
            source_path=str(self.source),
            label="synthetic bad archive",
            metadata=None,
        )
        return info["object_id"]

    def test_missing_chunk_cannot_delete_old_tree(self):
        self.core._chunk_path(self.object_id, 0).unlink()
        with self.assertRaises(FileNotFoundError):
            self.core.restore_directory(self.object_id, str(self.restore_root), overwrite=True)
        self.assert_old_intact()
        self.assert_clean()

    def test_bad_cipher_cannot_delete_old_tree(self):
        path = self.core._chunk_path(self.object_id, 0)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["cipher_hex"] = "00" * (len(data["cipher_hex"]) // 2)
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(InvalidTag):
            self.core.restore_directory(self.object_id, str(self.restore_root), overwrite=True)
        self.assert_old_intact()
        self.assert_clean()

    def test_authenticated_but_invalid_tar_preserves_old_tree(self):
        object_id = self._seal_custom_archive(b"corrupt tar content, valid encrypted vault")
        with self.assertRaises((tarfile.TarError, OSError, EOFError)):
            self.core.restore_directory(object_id, str(self.restore_root), overwrite=True)
        self.assert_old_intact()
        self.assert_clean()

    def test_tar_traversal_is_rejected_before_publication(self):
        archive = self.root / "traversal.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            payload = b"escape attempt"
            member = tarfile.TarInfo("photos/../escaped.txt")
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
        object_id = self._seal_custom_archive(archive.read_bytes())
        with self.assertRaises(ValueError):
            self.core.restore_directory(object_id, str(self.restore_root), overwrite=True)
        self.assert_old_intact()
        self.assertFalse((self.restore_root / "escaped.txt").exists())
        self.assert_clean()

    def test_failed_publication_rolls_back_previous_tree(self):
        actual_replace = os.replace

        def fail_promote(source, destination):
            if (Path(source).name == "photos"
                    and Path(source).parent.name == "extracted"
                    and Path(destination) == self.target):
                raise OSError("injected publication failure")
            return actual_replace(source, destination)

        with mock.patch("sealed_core.os.replace", side_effect=fail_promote):
            with self.assertRaisesRegex(OSError, "injected publication failure"):
                self.core.restore_directory(self.object_id, str(self.restore_root), overwrite=True)
        self.assert_old_intact()
        self.assert_clean()

    def test_unrecoverable_rollback_keeps_original_backup(self):
        actual_replace = os.replace

        def fail_both(source, destination):
            source = Path(source)
            if Path(destination) == self.target and (
                source.parent.name == "extracted" or ".sealed-backup-" in source.name
            ):
                raise OSError("injected failed rename")
            return actual_replace(source, destination)

        with mock.patch("sealed_core.os.replace", side_effect=fail_both):
            with self.assertRaisesRegex(RuntimeError, "preserved at"):
                self.core.restore_directory(self.object_id, str(self.restore_root), overwrite=True)
        backups = list(self.restore_root.glob(".photos.sealed-backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "important.txt").read_bytes(), b"ORIGINAL KEEP ME")
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.restore_root.glob(".photos.sealed-restore-*")), [])

    def test_successful_overwrite_is_complete(self):
        restored = Path(self.core.restore_directory(self.object_id, str(self.restore_root), overwrite=True))
        self.assertEqual(restored, self.target)
        self.assertFalse((restored / "important.txt").exists())
        self.assertEqual((restored / "one.txt").read_bytes(), b"verified new tree")
        self.assertEqual((restored / "nested" / "two.bin").read_bytes(), b"verified nested file")
        self.assert_clean()

    def test_default_no_overwrite_preserves_previous_tree(self):
        with self.assertRaises(FileExistsError):
            self.core.restore_directory(self.object_id, str(self.restore_root))
        self.assert_old_intact()
        self.assert_clean()

    def test_fresh_directory_restores_complete_tree(self):
        fresh_root = self.root / "fresh"
        target = Path(self.core.restore_directory(self.object_id, str(fresh_root)))
        self.assertEqual((target / "one.txt").read_bytes(), b"verified new tree")
        self.assertEqual((target / "nested" / "two.bin").read_bytes(), b"verified nested file")
        self.assertFalse(list(fresh_root.glob(".photos.sealed-restore-*")))


if __name__ == "__main__":
    unittest.main()
