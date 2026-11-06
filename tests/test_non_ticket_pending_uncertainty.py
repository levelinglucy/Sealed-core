"""Non-ticket PENDING ambiguity: a terminal core status is not a recovery receipt.

Development summary
-------------------
Purpose: test whether an owner could reconcile interrupted CLOSE_TICKET from
a ticket's current status alone. Two distinct execution histories deliberately
produce the same visible CLOSED state and the same unresolved evidence class.
Predecessor: read-only owner PENDING/core triage and synthetic crash tests.
Next: keep unlinked/non-ticket outcomes blocked unless attributable, durable
operation evidence is implemented and tested. No real data or network use.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatekeeper_v2_2 import (
    GatekeeperV22, build_signed_request, inspect_pending_evidence_local,
)
from sealed_core import SealedCore

OWNER_SECRET = "synthetic-owner-uncertainty-2026"
SIGN_SECRET = "synthetic-signer-uncertainty-2026"


class NonTicketUncertaintyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-uncertain-close-")
        self.environment = patch.dict(os.environ, {
            "SEALED_OWNER_SECRET": OWNER_SECRET,
            "SEALED_PRINCIPALS_JSON": json.dumps({
                "owner-local": {
                    "role": "OWNER", "secret": SIGN_SECRET, "scope_id": "owner",
                },
            }),
        })
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temp.cleanup()

    def case(self, label, *, did_execute):
        storage = str(Path(self.temp.name) / label)
        with SealedCore(OWNER_SECRET, storage_dir=storage) as core:
            ticket_id = core.handle({
                "source": "test", "subject": "synthetic closed ticket",
                "body": "fictional fixture only",
            })["ticket_id"]
            self.assertTrue(core.close_ticket(ticket_id))
            self.assertEqual(core.store.get_ticket(ticket_id)["status"], "CLOSED")

        gate = GatekeeperV22(storage)
        try:
            key = f"close-uncertain-{label}-0001"
            payload = {"ticket_id": ticket_id}
            first = build_signed_request(
                "owner-local", SIGN_SECRET, "CLOSE_TICKET",
                payload=payload, idempotency_key=key,
            )
            if did_execute:
                # The real core handler completes; only Gatekeeper's *later*
                # completion receipt write fails.
                with patch.object(gate, "_execute", wraps=gate._execute) as executed:
                    with patch.object(
                        gate.state, "record_idempotent_result",
                        side_effect=RuntimeError("synthetic lost completion"),
                    ):
                        result = gate.request(first)
                    self.assertEqual(executed.call_count, 1)
            else:
                # The operation never reaches the core.
                with patch.object(
                    gate, "_execute",
                    side_effect=RuntimeError("synthetic precommit interruption"),
                ) as intercepted:
                    result = gate.request(first)
                self.assertEqual(intercepted.call_count, 1)
            self.assertEqual(result, {"ok": False, "error": "INTERNAL_ERROR"})

            core_file = Path(storage) / "state.json"
            gate_file = Path(storage) / "gatekeeper_state.json"
            before = (core_file.read_bytes(), gate_file.read_bytes())
            triage = inspect_pending_evidence_local(storage)
            self.assertEqual(
                (core_file.read_bytes(), gate_file.read_bytes()), before,
                "owner-only inspection must not alter encrypted evidence",
            )
            self.assertEqual(len(triage), 1)
            self.assertEqual(triage[0]["core_evidence"], "NO_CORE_RECEIPT_UNKNOWN")
            self.assertFalse(triage[0]["authorizes_retry_or_clear"])
            self.assertFalse(triage[0]["current_scope_verified"])
            self.assertNotIn(ticket_id, json.dumps(triage))

            retry = build_signed_request(
                "owner-local", SIGN_SECRET, "CLOSE_TICKET",
                payload=payload, idempotency_key=key,
            )
            # A new signed nonce is NOT proof or permission to re-execute.
            self.assertNotEqual(first["nonce"], retry["nonce"])
            self.assertEqual(
                gate.request(retry),
                {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
            )
            with SealedCore(OWNER_SECRET, storage_dir=storage) as core:
                self.assertEqual(core.store.get_ticket(ticket_id)["status"], "CLOSED")
            return triage[0]["core_evidence"]
        finally:
            gate.close()

    def test_closed_ticket_cannot_prove_pending_close_executed(self):
        """A pending CLOSE can be unexecuted or executed; both look CLOSED.

        Even a real terminal core state is not tied to the pending operation
        ID, so a reviewer must not infer success or clear a reservation.
        """
        pre = self.case("precommit", did_execute=False)
        post = self.case("postcommit", did_execute=True)
        self.assertEqual(pre, post)


if __name__ == "__main__":
    unittest.main()
