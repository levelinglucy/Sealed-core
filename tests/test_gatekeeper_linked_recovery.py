"""Signed local Gatekeeper/core recovery contract (draft candidate).

Purpose: show evidence-linked ticket recovery without blind reexecution.
Predecessor: test_core_gatekeeper_operation.py's isolated core receipts.
Latest: signed HMAC/role/scope linkage, fail-closed ambiguous/legacy inputs.
Next: owner-only audit/reconciliation design; power-cut and mobile testing.
Synthetic secrets and temporary stores only; never user vault material.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatekeeper_v2_2 import (
    GatekeeperV22, build_signed_request, sign_request,
)
from sealed_core import SealedCore, _StoreFileLock


OWNER_SECRET = "synthetic-owner-secret-linked-recovery-2026"
CREATOR_SECRET = "synthetic-creator-secret-linked-recovery"
ACK_SECRET = "synthetic-acknowledger-secret-linked-recovery"
REGISTRY = {
    "creator-alpha": {
        "role": "EXTERNAL_CREATE",
        "secret": CREATOR_SECRET,
        "scope_id": "alpha",
    },
    "ack-beta": {
        "role": "EXTERNAL_ACK",
        "secret": ACK_SECRET,
        "scope_id": "beta",
    },
}


class SignedTicketRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-linked-")
        self.dir = str(Path(self.temp.name) / "encrypted")
        self.env = patch.dict(os.environ, {
            "SEALED_OWNER_SECRET": OWNER_SECRET,
            "SEALED_PRINCIPALS_JSON": json.dumps(REGISTRY),
        })
        self.env.start()
        self.one = GatekeeperV22(self.dir)
        self.two = GatekeeperV22(self.dir)

    def tearDown(self):
        self.one.close()
        self.two.close()
        self.env.stop()
        self.temp.cleanup()

    @staticmethod
    def signed(key, nonce, subject="synthetic signed receipt"):
        req = build_signed_request(
            "creator-alpha", CREATOR_SECRET, "NEW_TICKET",
            payload={"subject": subject, "body": "not sensitive"},
            idempotency_key=key,
        )
        req["nonce"] = nonce
        req["signature"] = sign_request(req, CREATOR_SECRET)
        return req

    def tickets(self):
        with SealedCore(OWNER_SECRET, storage_dir=self.dir) as core:
            return core.list_open_summary()

    def pending(self, key):
        with _StoreFileLock(self.one.state.lock_path):
            state = self.one.state._load_locked()
        return state["idempotency"]["creator-alpha:" + key]

    def test_signed_retry_reconstructs_exact_committed_receipt(self):
        key = "linked-after-receipt-error-001"
        req = self.signed(key, "linked-initial-nonce-00001")
        with patch.object(self.one.state, "record_idempotent_result",
                          side_effect=RuntimeError("synthetic receipt failure")):
            self.assertEqual(
                self.one.request(req), {"ok": False, "error": "INTERNAL_ERROR"}
            )
        ids = [item["ticket_id"] for item in self.tickets()]
        self.assertEqual(len(ids), 1)
        reservation = self.pending(key)
        self.assertEqual(reservation["status"], "PENDING")
        self.assertRegex(reservation["operation_id"], r"^[0-9a-f]{32}$")

        # The core alone provides proof, not subject/date similarity.
        with SealedCore(OWNER_SECRET, storage_dir=self.dir) as core:
            core_receipt = core.get_gatekeeper_ticket_receipt(
                reservation["operation_id"], self.one._business_hash(req), "alpha"
            )
        self.assertEqual(core_receipt["ticket_id"], ids[0])

        recovered = self.two.request(self.signed(key, "linked-retry-nonce-000002"))
        self.assertTrue(recovered["ok"], recovered)
        self.assertEqual(recovered["data"]["ticket_id"], ids[0])
        self.assertEqual(self.two.state.ticket_scope(ids[0]), "alpha")
        self.assertEqual(len(self.tickets()), 1)
        self.assertEqual(
            recovered,
            self.one.request(self.signed(key, "linked-retry-nonce-000003"))
        )

    def test_changed_authorized_scope_cannot_rebind_committed_ticket(self):
        key = "linked-scope-identity-0001"
        with patch.object(self.one.state, "bind_ticket_scope",
                          side_effect=RuntimeError("synthetic postcommit crash")):
            self.assertEqual(
                self.one.request(self.signed(key, "linked-scope-nonce-00001")),
                {"ok": False, "error": "INTERNAL_ERROR"},
            )
        ticket_id = self.tickets()[0]["ticket_id"]
        self.assertIsNone(self.two.state.ticket_scope(ticket_id))
        self.two.registry["creator-alpha"]["scope_id"] = "beta"
        mismatch = self.two.request(self.signed(key, "linked-scope-nonce-00002"))
        self.assertEqual(mismatch, {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"})
        self.assertIsNone(self.two.state.ticket_scope(ticket_id))
        self.two.registry["creator-alpha"]["scope_id"] = "alpha"
        recovered = self.two.request(self.signed(key, "linked-scope-nonce-00003"))
        self.assertEqual(recovered["data"]["ticket_id"], ticket_id)
        self.assertEqual(self.two.state.ticket_scope(ticket_id), "alpha")
        self.assertEqual(len(self.tickets()), 1)

        foreign = build_signed_request(
            "ack-beta", ACK_SECRET, "GET_TICKET_DETAIL",
            payload={"ticket_id": ticket_id},
        )
        self.assertEqual(
            self.two.request(foreign),
            {"ok": False, "error": "SCOPE_NOT_ALLOWED"},
        )

    def test_pending_identifier_mismatch_never_guesses_from_ticket(self):
        key = "linked-mismatch-operation-001"
        with patch.object(self.one.state, "bind_ticket_scope",
                          side_effect=RuntimeError("synthetic bind interruption")):
            self.assertEqual(
                self.one.request(self.signed(key, "linked-mismatch-nonce-001")),
                {"ok": False, "error": "INTERNAL_ERROR"},
            )
        original = self.pending(key)["operation_id"]
        with _StoreFileLock(self.one.state.lock_path):
            state = self.one.state._load_locked()
            state["idempotency"]["creator-alpha:" + key]["operation_id"] = "f" * 32
            self.one.state._save_locked(state)

        self.assertEqual(
            self.two.request(self.signed(key, "linked-mismatch-nonce-002")),
            {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
        )
        self.assertEqual(len(self.tickets()), 1)

        with _StoreFileLock(self.one.state.lock_path):
            state = self.one.state._load_locked()
            state["idempotency"]["creator-alpha:" + key]["operation_id"] = original
            self.one.state._save_locked(state)
        self.assertTrue(
            self.two.request(self.signed(key, "linked-mismatch-nonce-003"))["ok"]
        )

    def test_legacy_unlinked_pending_cannot_replay_or_infer_success(self):
        key = "legacy-unlinked-pending-0001"
        req = self.signed(key, "legacy-unlinked-nonce-0001")
        with SealedCore(OWNER_SECRET, storage_dir=self.dir) as core:
            core.handle({"subject": "looks similar to old operation"})
        before = [item["ticket_id"] for item in self.tickets()]
        with _StoreFileLock(self.one.state.lock_path):
            state = self.one.state._load_locked()
            state["idempotency"]["creator-alpha:" + key] = {
                "request_hash": self.one._business_hash(req),
                "created_at": "2026-11-06T18:00:00Z",
                "status": "PENDING",
            }
            self.one.state._save_locked(state)

        self.assertEqual(
            self.two.request(req),
            {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
        )
        self.assertEqual([item["ticket_id"] for item in self.tickets()], before)

    def test_bad_signature_cannot_recover_authenticated_core_receipt(self):
        key = "linked-invalid-signature-0001"
        with patch.object(self.one.state, "bind_ticket_scope",
                          side_effect=RuntimeError("synthetic postcommit error")):
            self.assertEqual(
                self.one.request(self.signed(key, "linked-signed-nonce-0001")),
                {"ok": False, "error": "INTERNAL_ERROR"},
            )
        ticket_id = self.tickets()[0]["ticket_id"]
        invalid = self.signed(key, "linked-signed-nonce-0002")
        invalid["signature"] = "0" * 64
        self.assertEqual(
            self.two.request(invalid), {"ok": False, "error": "UNAUTHORIZED"}
        )
        self.assertIsNone(self.two.state.ticket_scope(ticket_id))
        self.assertTrue(
            self.two.request(self.signed(key, "linked-signed-nonce-0003"))["ok"]
        )
        self.assertEqual(len(self.tickets()), 1)


if __name__ == "__main__":
    unittest.main()
