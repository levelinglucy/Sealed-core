"""Owner-local, non-mutating Gatekeeper recovery-inspection tests.

Credentials, payloads and storage are synthetic. No user vault or network I/O.
"""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatekeeper_v2_2 import (
    GatekeeperV22, build_signed_request, inspect_pending_local, sign_request,
)
from sealed_core import _StoreFileLock


OWNER_SECRET = "synthetic-owner-secret-for-pending-inspection"
PRINCIPAL_SECRET = "synthetic-principal-secret-for-inspection"


class PendingInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-pending-inspect-")
        self.storage_dir = str(Path(self.temp.name) / "encrypted-state")
        self.env = patch.dict(os.environ, {
            "SEALED_OWNER_SECRET": OWNER_SECRET,
            "SEALED_PRINCIPALS_JSON": json.dumps({
                "owner-local": {
                    "role": "OWNER",
                    "secret": PRINCIPAL_SECRET,
                    "scope_id": "owner",
                },
            }),
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def signed(self, key, nonce, subject="synthetic private subject"):
        request = build_signed_request(
            "owner-local", PRINCIPAL_SECRET, "NEW_TICKET",
            payload={"subject": subject}, idempotency_key=key,
        )
        request["nonce"] = nonce
        request["signature"] = sign_request(request, PRINCIPAL_SECRET)
        return request

    def test_pending_has_stable_id_and_inspector_cannot_modify_state(self):
        key = "local-pending-key-001"
        first = self.signed(key, "local-pending-nonce-001")
        gate = GatekeeperV22(storage_dir=self.storage_dir)
        try:
            gate._execute = lambda *_: (_ for _ in ()).throw(
                RuntimeError("synthetic precommit interruption")
            )
            self.assertEqual(
                gate.request(first), {"ok": False, "error": "INTERNAL_ERROR"}
            )
        finally:
            gate.close()

        state_path = Path(self.storage_dir) / "gatekeeper_state.json"
        original = state_path.read_bytes()
        inspected = inspect_pending_local(self.storage_dir)
        self.assertEqual(state_path.read_bytes(), original)
        self.assertEqual(len(inspected), 1)
        record = inspected[0]
        expected_key_ref = "owner-local:" + key
        self.assertEqual(
            record["key_ref_sha256"],
            hashlib.sha256(expected_key_ref.encode()).hexdigest(),
        )
        self.assertRegex(record["operation_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(record["status"], "PENDING")
        self.assertEqual(len(record["request_hash"]), 64)
        serialized = json.dumps(record)
        for sensitive in (key, "owner-local", "local-pending-nonce-001",
                          "synthetic private subject", OWNER_SECRET,
                          PRINCIPAL_SECRET):
            self.assertNotIn(sensitive, serialized)

        retry = self.signed(key, "local-pending-nonce-002")
        gate = GatekeeperV22(storage_dir=self.storage_dir)
        try:
            self.assertEqual(
                gate.request(retry),
                {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
            )
        finally:
            gate.close()
        self.assertEqual(
            inspect_pending_local(self.storage_dir)[0]["operation_id"],
            record["operation_id"],
        )

    def test_completed_receipts_excluded_and_legacy_pending_visible(self):
        gate = GatekeeperV22(storage_dir=self.storage_dir)
        try:
            gate._execute = lambda *_: {"ticket_id": "synthetic-complete"}
            success = gate.request(
                self.signed("complete-key-0001", "complete-nonce-00001")
            )
            self.assertTrue(success["ok"], success)

            with _StoreFileLock(gate.state.lock_path):
                state = gate.state._load_locked()
                state["idempotency"]["owner-local:old-pending-key"] = {
                    "request_hash": "legacy-hash",
                    "created_at": "2020-01-01T00:00:00Z",
                    "status": "PENDING",
                }
                finished = state["idempotency"]["owner-local:complete-key-0001"]
                self.assertRegex(finished["operation_id"], r"^[0-9a-f]{32}$")
                self.assertIn("result", finished)
                gate.state._save_locked(state)
        finally:
            gate.close()

        pending = inspect_pending_local(self.storage_dir)
        self.assertEqual(len(pending), 1)
        self.assertIsNone(pending[0]["operation_id"])
        self.assertEqual(pending[0]["request_hash"], "legacy-hash")

    def test_inspection_is_not_a_signed_policy_action(self):
        gate = GatekeeperV22(storage_dir=self.storage_dir)
        try:
            request = build_signed_request(
                "owner-local", PRINCIPAL_SECRET, "INSPECT_PENDING", payload={}
            )
            self.assertEqual(
                gate.request(request), {"ok": False, "error": "UNKNOWN_ACTION"}
            )
        finally:
            gate.close()

    def test_missing_owner_secret_fails_closed(self):
        with patch.dict(os.environ, {"SEALED_OWNER_SECRET": ""}):
            with self.assertRaises(RuntimeError):
                inspect_pending_local(self.storage_dir)


if __name__ == "__main__":
    unittest.main()
