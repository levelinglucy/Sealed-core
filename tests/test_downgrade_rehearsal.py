"""Copy-only historical downgrade rehearsal for Sealed-core draft PR #8.

Development summary (2026-11-06)
--------------------------------
Purpose: show how the last merged Gatekeeper treats encrypted PENDING after a
linked ticket commit and after an interruption before core execution.
Historical predecessor: main at 6f6e9c67 (PR #7 merge), not an invented model.
Latest: execute that exact old source only on isolated synthetic store copies.
Next: owner-reviewed operational reconciliation; never downgrade live stores.
See GATEKEEPER_RECOVERY.md. No user data or network operations are involved.

Git history is required to fetch the pinned old code; in CI checkout full
history. On non-Git source distributions these tests skip, not simulate old
semantics. No subprocess may access the original synthetic store.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatekeeper_v2_2 import (
    GatekeeperV22, build_signed_request, inspect_pending_evidence_local,
    sign_request,
)
from sealed_core import SealedCore

ROOT = Path(__file__).resolve().parents[1]
OLD_MAIN = "6f6e9c67349934ed129a84edcc650219b2311675"
OWNER_SECRET = "synthetic-downgrade-owner-2026"
CLIENT_SECRET = "synthetic-downgrade-client-2026"
PRINCIPAL = "creator-alpha"
REGISTRY = {
    PRINCIPAL: {"role": "EXTERNAL_CREATE", "secret": CLIENT_SECRET, "scope_id": "alpha"}
}
PAYLOAD = {"subject": "synthetic downgrade rehearsal", "body": "no user data"}

# Executed only in a new interpreter with cwd set to historical source,
# and the storage path forced to a private copy of temporary synthetic data.
OLD_RETRY = r"""
import json
import os
import sys
from gatekeeper_v2_2 import GatekeeperV22, build_signed_request, sign_request
from sealed_core import SealedCore

copy_path, business_key, nonce = sys.argv[1:]
request = build_signed_request(
    "creator-alpha", os.environ["SYNTHETIC_CLIENT_SECRET"],
    "NEW_TICKET", payload={"subject": "synthetic downgrade rehearsal",
                           "body": "no user data"}, idempotency_key=business_key,
)
request["nonce"] = nonce
request["signature"] = sign_request(request, os.environ["SYNTHETIC_CLIENT_SECRET"])
gate = GatekeeperV22(storage_dir=copy_path)
try:
    result = gate.request(request)
finally:
    gate.close()
with SealedCore(os.environ["SEALED_OWNER_SECRET"], storage_dir=copy_path) as core:
    count = len(core.list_open_summary())
print(json.dumps({"ok": result["ok"], "tickets": count}))
"""


@unittest.skipUnless(shutil.which("git"), "Git history required for pinned historical rehearsal")
class CopyOnlyDowngradeRehearsal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Never download remote source in a security-sensitive test. Resolve
        # only a previously inspected and pinned, locally available Git object.
        if subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", OLD_MAIN + "^{commit}"],
            capture_output=True, timeout=15, check=False,
        ).returncode:
            raise unittest.SkipTest("pinned old main unavailable locally")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-downgrade-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original = self.root / "original-synthetic"
        self.old_code = self.root / "pinned-old-code"
        self.old_code.mkdir()
        self.env_patch = patch.dict(os.environ, {
            "SEALED_OWNER_SECRET": OWNER_SECRET,
            "SYNTHETIC_CLIENT_SECRET": CLIENT_SECRET,
            "SEALED_PRINCIPALS_JSON": json.dumps(REGISTRY),
        })
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

        # Independent historical Gatekeeper AND core: don't accidentally load
        # the draft core while claiming to have tested an older installation.
        for name in ("gatekeeper_v2_2.py", "sealed_core.py"):
            show = subprocess.run(
                ["git", "-C", str(ROOT), "show", OLD_MAIN + ":" + name],
                capture_output=True, text=True, timeout=15, check=True,
            )
            (self.old_code / name).write_text(show.stdout, encoding="utf-8")

    @staticmethod
    def request(key, nonce):
        req = build_signed_request(
            PRINCIPAL, CLIENT_SECRET, "NEW_TICKET", payload=dict(PAYLOAD),
            idempotency_key=key,
        )
        req["nonce"] = nonce
        req["signature"] = sign_request(req, CLIENT_SECRET)
        return req

    def _create_pending(self, key, *, after_commit):
        gate = GatekeeperV22(storage_dir=str(self.original))
        try:
            req = self.request(key, "rehearsal-initial-nonce-0001")
            if after_commit:
                with patch.object(gate.state, "record_idempotent_result",
                                  side_effect=RuntimeError("synthetic lost completion")):
                    result = gate.request(req)
            else:
                with patch.object(gate, "_execute",
                                  side_effect=RuntimeError("synthetic precommit stop")):
                    result = gate.request(req)
            self.assertEqual(result, {"ok": False, "error": "INTERNAL_ERROR"})
        finally:
            gate.close()

    def _ticket_count(self, path):
        with SealedCore(OWNER_SECRET, storage_dir=str(path)) as core:
            return len(core.list_open_summary())

    @staticmethod
    def _sealed_bytes(path):
        # Encrypted originals must be byte-for-byte untouched by old code run.
        return {p.name: p.read_bytes() for p in (
            path / "gatekeeper_state.json", path / "state.json"
        ) if p.exists()}

    def _rehearse_old_retry_on_copy(self, key):
        sentinel = self.original / "representative-output.bin"
        sentinel.write_bytes(b"synthetic-output-must-not-change")
        originals = self._sealed_bytes(self.original)
        before = self._ticket_count(self.original)
        snapshot = self.root / "historical-rehearsal-COPY"
        shutil.copytree(self.original, snapshot)
        run = subprocess.run(
            [sys.executable, "-c", OLD_RETRY, str(snapshot), key,
             "rehearsal-new-nonce-0002"],
            cwd=str(self.old_code), env=os.environ.copy(),
            capture_output=True, text=True, timeout=35, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr[-1200:])
        result = json.loads(run.stdout.strip().splitlines()[-1])
        self.assertTrue(result["ok"], result)
        self.assertEqual(self._sealed_bytes(self.original), originals)
        self.assertEqual(self._ticket_count(self.original), before)
        self.assertEqual(sentinel.read_bytes(), b"synthetic-output-must-not-change")
        self.assertEqual((snapshot / sentinel.name).read_bytes(), sentinel.read_bytes())
        return before, result["tickets"]

    def test_old_binary_duplicates_a_proven_committed_ticket_on_copy(self):
        key = "downgrade-linked-key-0001"
        self._create_pending(key, after_commit=True)
        rows = inspect_pending_evidence_local(str(self.original))
        self.assertEqual(rows[0]["core_evidence"], "CORE_TICKET_RECEIPT_PRESENT")
        # This asserts the DANGEROUS historical behaviour, not an expected
        # behaviour of the current candidate. Never run old code on live data.
        self.assertEqual(self._rehearse_old_retry_on_copy(key), (1, 2))

    def test_old_binary_blindly_executes_an_uncommitted_pending_on_copy(self):
        key = "downgrade-unlinked-key-0001"
        self._create_pending(key, after_commit=False)
        rows = inspect_pending_evidence_local(str(self.original))
        self.assertEqual(rows[0]["core_evidence"], "NO_CORE_RECEIPT_UNKNOWN")
        self.assertEqual(self._rehearse_old_retry_on_copy(key), (0, 1))


if __name__ == "__main__":
    unittest.main()
