"""Local-only file restore integrity and overwrite safety regression tests.

The archived v2.2 implementation opened the final path with wb *before*
verifying every encrypted chunk, destroying an existing file on failure.
These tests use temporary stores and no network or user data.
"""
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

from sealed_core import SealedCore


SECRET = "test-owner-passphrase-only-for-isolated-vault-tests"


class VerifiedRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sealed-verified-restore-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "input.bin"
        self.source.write_bytes(b"new verified contents " * 100)
        self.destination = self.root / "existing.bin"
        self.destination.write_bytes(b"PREVIOUS VALUABLE CONTENT")
        self.core = SealedCore(SECRET, storage_dir=str(self.root / "storage"))
        self.addCleanup(self.core.close)
        self.record = self.core.seal_file(str(self.source))
        self.object_id = self.record["object_id"]

    def assert_no_staged_files(self):
        self.assertFalse(list(self.root.glob(".existing.bin.sealed-*.tmp")))

    def test_corrupt_cipher_does_not_destroy_existing_file(self):
        part = self.core._chunk_path(self.object_id, 0)
        payload = json.loads(part.read_text(encoding="utf-8"))
        payload["cipher_hex"] = "00" * (len(payload["cipher_hex"]) // 2)
        part.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(InvalidTag):
            self.core.unseal_file(self.object_id, output_path=str(self.destination), overwrite=True)

        self.assertEqual(self.destination.read_bytes(), b"PREVIOUS VALUABLE CONTENT")
        self.assert_no_staged_files()

    def test_missing_chunk_does_not_destroy_existing_file(self):
        self.core._chunk_path(self.object_id, 0).unlink()

        with self.assertRaises(FileNotFoundError):
            self.core.unseal_file(self.object_id, output_path=str(self.destination), overwrite=True)

        self.assertEqual(self.destination.read_bytes(), b"PREVIOUS VALUABLE CONTENT")
        self.assert_no_staged_files()

    def test_corrupt_object_never_exposes_partial_new_file(self):
        part = self.core._chunk_path(self.object_id, 0)
        part.unlink()
        new_path = self.root / "new-destination.bin"

        with self.assertRaises(FileNotFoundError):
            self.core.unseal_file(self.object_id, output_path=str(new_path))

        self.assertFalse(new_path.exists())
        self.assertFalse(list(self.root.glob(".new-destination.bin.sealed-*.tmp")))

    def test_verified_overwrite_replaces_entire_file(self):
        self.core.unseal_file(self.object_id, output_path=str(self.destination), overwrite=True)
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        self.assert_no_staged_files()

    def test_default_no_overwrite_preserves_existing_file(self):
        with self.assertRaises(FileExistsError):
            self.core.unseal_file(self.object_id, output_path=str(self.destination))
        self.assertEqual(self.destination.read_bytes(), b"PREVIOUS VALUABLE CONTENT")
        self.assert_no_staged_files()

    def test_verified_new_file_is_complete(self):
        new_path = self.root / "new-destination.bin"
        restored = self.core.unseal_file(self.object_id, output_path=str(new_path))
        self.assertEqual(Path(restored).read_bytes(), self.source.read_bytes())
        self.assertFalse(list(self.root.glob(".new-destination.bin.sealed-*.tmp")))


if __name__ == "__main__":
    unittest.main()
