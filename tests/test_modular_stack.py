import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sealed_core import SealedCore


class ModularSmokeTests(unittest.TestCase):
    def test_imports(self):
        importlib.import_module("sealed_core")
        importlib.import_module("gatekeeper_v2_2")
        importlib.import_module("sealed_snapshot")


class VaultTests(unittest.TestCase):
    def test_seal_unseal_file(self):
        with tempfile.TemporaryDirectory(prefix="sealed-vault-file-") as temp_root:
            root = Path(temp_root)
            source = root / "input.bin"
            restored = root / "restored.bin"
            source.write_bytes(b"hello sealed vault\n" * 2000)

            with SealedCore("self-test-owner-passphrase-32-chars", storage_dir=str(root / "storage")) as core:
                result = core.seal_file(str(source), label="test-file", metadata={"scope": "unit"})
                self.assertEqual(result["kind"], "file")
                self.assertGreaterEqual(result["chunk_count"], 1)
                path = core.unseal_file(result["object_id"], output_path=str(restored))
                self.assertEqual(Path(path).read_bytes(), source.read_bytes())

    def test_seal_restore_directory(self):
        with tempfile.TemporaryDirectory(prefix="sealed-vault-dir-") as temp_root:
            root = Path(temp_root)
            source_dir = root / "docs"
            (source_dir / "nested").mkdir(parents=True, exist_ok=True)
            (source_dir / "a.txt").write_text("alpha", encoding="utf-8")
            (source_dir / "nested" / "b.txt").write_text("bravo", encoding="utf-8")
            restore_root = root / "restore"

            with SealedCore("self-test-owner-passphrase-32-chars", storage_dir=str(root / "storage")) as core:
                result = core.seal_directory(str(source_dir), label="docs")
                restored_path = Path(core.restore_directory(result["object_id"], str(restore_root)))
                self.assertTrue((restored_path / "a.txt").is_file())
                self.assertEqual((restored_path / "a.txt").read_text(encoding="utf-8"), "alpha")
                self.assertEqual((restored_path / "nested" / "b.txt").read_text(encoding="utf-8"), "bravo")

    def test_helper_vault_listing_redaction(self):
        with tempfile.TemporaryDirectory(prefix="sealed-vault-helper-") as temp_root:
            root = Path(temp_root)
            source = root / "secret.txt"
            source.write_text("secret", encoding="utf-8")
            storage = root / "storage"

            with SealedCore("self-test-owner-passphrase-32-chars", storage_dir=str(storage)) as owner:
                result = owner.seal_file(str(source), label="private", metadata={"sensitive": True})
                self.assertIn("source_path", owner.list_vault_summary()[0])
                object_id = result["object_id"]

            with SealedCore("self-test-owner-passphrase-32-chars", mode="HELPER", storage_dir=str(storage)) as helper:
                items = helper.list_vault_summary()
                self.assertEqual(items[0]["object_id"], object_id)
                self.assertNotIn("source_path", items[0])
                self.assertNotIn("metadata", items[0])


class CliTests(unittest.TestCase):
    def _run(self, *args, env=None):
        repo_root = Path(__file__).resolve().parents[1]
        cmd = [sys.executable, str(repo_root / "sealed_core.py"), *args]
        return subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, capture_output=True, check=False)

    def test_cli_help_when_no_mode(self):
        result = self._run()
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())

    def test_cli_watchdog_and_diagnostic(self):
        with tempfile.TemporaryDirectory(prefix="sealed-cli-") as temp_root:
            env = os.environ.copy()
            env["SEALED_OWNER_SECRET"] = "self-test-owner-passphrase-32-chars"
            result = self._run("--watchdog", "--diagnostic", "--storage-dir", str(Path(temp_root) / "storage"), env=env)
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            merged = "\n".join(lines)
            self.assertIn("warnings_created", merged)
            self.assertIn('"schema": "SEALED_STATE_V2_2"', merged)


if __name__ == "__main__":
    unittest.main()
