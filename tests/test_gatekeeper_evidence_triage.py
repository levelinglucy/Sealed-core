"""Read-only owner-local Gatekeeper PENDING/core evidence triage regression tests.

Development summary
-------------------
Purpose: distinguish a core-linked ticket receipt from legacy and uncertain
PENDING records without changing encrypted state or authorizing a retry.
Predecessor: inspect_pending_local() and signed NEW_TICKET atomic receipts.
Next: operator-reviewed reconciliation policy and safe downgrade rehearsal.
All keys, payloads and stores are synthetic; no user data or network calls.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatekeeper_v2_2 import (
    GatekeeperV22, build_signed_request,
    inspect_pending_evidence_local, sign_request,
)
from sealed_core import _StoreFileLock

OWNER_SECRET = "synthetic-owner-secret-triage-2026"
PRINCIPAL_SECRET = "synthetic-principal-secret-triage-2026"


class PendingEvidenceTriageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-triage-")
        self.storage = str(Path(self.temp.name) / "storage")
        self.env = patch.dict(os.environ, {
            "SEALED_OWNER_SECRET": OWNER_SECRET,
            "SEALED_PRINCIPALS_JSON": json.dumps({
                "local-owner": {
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

    @staticmethod
    def signed(key, nonce):
        req = build_signed_request(
            "local-owner", PRINCIPAL_SECRET, "NEW_TICKET",
            payload={"subject": "private synthetic subject", "body": "no user data"},
            idempotency_key=key,
        )
        req["nonce"] = nonce
        req["signature"] = sign_request(req, PRINCIPAL_SECRET)
        return req

    def test_precommit_pending_has_no_proof_and_is_never_cleared(self):
        gate = GatekeeperV22(self.storage)
        try:
            gate._execute = lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("synthetic precommit failure")
            )
            self.assertEqual(
                gate.request(self.signed("precommit-key-0001", "precommit-nonce-00001")),
                {"ok": False, "error": "INTERNAL_ERROR"},
            )
        finally:
            gate.close()
        gate_path = Path(self.storage) / "gatekeeper_state.json"
        before = gate_path.read_bytes()
        rows = inspect_pending_evidence_local(self.storage)
        self.assertEqual(gate_path.read_bytes(), before)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["core_evidence"], "NO_CORE_RECEIPT_UNKNOWN")
        self.assertFalse(rows[0]["authorizes_retry_or_clear"])
        self.assertFalse(rows[0]["current_scope_verified"])
        self.assertFalse((Path(self.storage) / "state.json").exists())
        self.assertNotIn("private synthetic subject", json.dumps(rows))

    def test_core_committed_receipt_is_reported_but_not_authorized(self):
        gate = GatekeeperV22(self.storage)
        try:
            with patch.object(gate.state, "record_idempotent_result",
                              side_effect=RuntimeError("synthetic postcommit failure")):
                self.assertEqual(
                    gate.request(self.signed("committed-key-0001", "committed-nonce-0001")),
                    {"ok": False, "error": "INTERNAL_ERROR"},
                )
        finally:
            gate.close()
        gate_path = Path(self.storage) / "gatekeeper_state.json"
        core_path = Path(self.storage) / "state.json"
        before = (gate_path.read_bytes(), core_path.read_bytes())
        rows = inspect_pending_evidence_local(self.storage)
        self.assertEqual((gate_path.read_bytes(), core_path.read_bytes()), before)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["core_evidence"], "CORE_TICKET_RECEIPT_PRESENT")
        self.assertFalse(rows[0]["authorizes_retry_or_clear"])
        self.assertFalse(rows[0]["current_scope_verified"])
        self.assertRegex(rows[0]["operation_id"], r"^[0-9a-f]{32}$")
        exposed = json.dumps(rows)
        for secret in ("committed-key-0001", "local-owner", "committed-nonce-0001",
                       "private synthetic subject", OWNER_SECRET, PRINCIPAL_SECRET,
                       "owner_email", "ticket_id"):
            self.assertNotIn(secret, exposed)

    def test_conflicting_hash_and_legacy_reservation_remain_unresolved(self):
        gate = GatekeeperV22(self.storage)
        try:
            with patch.object(gate.state, "record_idempotent_result",
                              side_effect=RuntimeError("synthetic write failure")):
                self.assertFalse(
                    gate.request(self.signed("conflict-key-0001", "conflict-nonce-0001"))["ok"]
                )
            with _StoreFileLock(gate.state.lock_path):
                state = gate.state._load_locked()
                state["idempotency"]["local-owner:conflict-key-0001"]["request_hash"] = "b" * 64
                state["idempotency"]["local-owner:legacy-key-0001"] = {
                    "created_at": "2020-01-01T00:00:00Z",
                    "request_hash": "historic-hash",
                    "status": "PENDING",
                }
                gate.state._save_locked(state)
        finally:
            gate.close()
        gate_path = Path(self.storage) / "gatekeeper_state.json"
        core_path = Path(self.storage) / "state.json"
        before = (gate_path.read_bytes(), core_path.read_bytes())
        rows = inspect_pending_evidence_local(self.storage)
        self.assertEqual((gate_path.read_bytes(), core_path.read_bytes()), before)
        self.assertEqual(
            {row["core_evidence"] for row in rows},
            {"CORE_RECEIPT_CONFLICT", "LEGACY_UNLINKED_UNKNOWN"},
        )
        self.assertTrue(all(not row["authorizes_retry_or_clear"] for row in rows))

    def test_wrong_secret_or_missing_secret_fails_closed(self):
        gate = GatekeeperV22(self.storage)
        gate.close()
        with patch.dict(os.environ, {"SEALED_OWNER_SECRET": ""}):
            with self.assertRaises(RuntimeError):
                inspect_pending_evidence_local(self.storage)
        # No pending records were present: require a real encrypted state to
        # verify that changing the secret cannot produce a misleading report.
        with patch.dict(os.environ, {"SEALED_OWNER_SECRET": "wrong-secret"}):
            with self.assertRaises(Exception):
                inspect_pending_evidence_local(self.storage)

    def test_evidence_triage_is_not_an_authenticated_gatekeeper_action(self):
        gate = GatekeeperV22(self.storage)
        try:
            req = build_signed_request(
                "local-owner", PRINCIPAL_SECRET,
                "INSPECT_PENDING_EVIDENCE", payload={}
            )
            self.assertEqual(
                gate.request(req), {"ok": False, "error": "UNKNOWN_ACTION"}
            )
        finally:
            gate.close()


if __name__ == "__main__":
    unittest.main()
