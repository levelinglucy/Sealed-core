"""Synthetic Gatekeeper replay/idempotency regression cases.

No real vault data, credentials or network calls are used. The concurrent
test isolates the request transaction boundary by replacing only _execute.
"""

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from gatekeeper_v2_2 import GatekeeperV22, build_signed_request, sign_request


OWNER_SECRET = "synthetic-owner-secret-for-regression-2026"
PRINCIPAL_SECRET = "synthetic-principal-hmac-secret-for-regression"
EXTERNAL_SECRET = "synthetic-external-hmac-secret-for-regression"


class GatekeeperIdempotencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-gate-idem-")
        self.env = patch.dict(os.environ, {
            "SEALED_OWNER_SECRET": OWNER_SECRET,
            "SEALED_PRINCIPALS_JSON": json.dumps({
                "owner-local": {
                    "role": "OWNER",
                    "secret": PRINCIPAL_SECRET,
                    "scope_id": "owner",
                },
                "creator-alpha": {
                    "role": "EXTERNAL_CREATE",
                    "secret": EXTERNAL_SECRET,
                    "scope_id": "alpha",
                },
                "ack-alpha": {
                    "role": "EXTERNAL_ACK",
                    "secret": EXTERNAL_SECRET,
                    "scope_id": "alpha",
                },
                "ack-beta": {
                    "role": "EXTERNAL_ACK",
                    "secret": EXTERNAL_SECRET,
                    "scope_id": "beta",
                },
            }),
        })
        self.env.start()
        storage = str(Path(self.temp.name) / "storage")
        # Independent Gatekeeper objects model separate callers/processes
        # using the same encrypted on-disk state.
        self.gate_one = GatekeeperV22(storage_dir=storage)
        self.gate_two = GatekeeperV22(storage_dir=storage)

    def tearDown(self):
        self.gate_one.close()
        self.gate_two.close()
        self.env.stop()
        self.temp.cleanup()

    @staticmethod
    def signed(action, key, nonce, payload=None, principal_id="owner-local",
               secret=PRINCIPAL_SECRET):
        request = build_signed_request(
            principal_id, secret, action,
            payload=payload or {}, idempotency_key=key,
        )
        request["nonce"] = nonce
        request["signature"] = sign_request(request, secret)
        return request

    def test_parallel_retry_with_distinct_nonces_executes_once(self):
        """Same business identity must not create two side effects."""
        first_entered = threading.Event()
        second_started = threading.Event()
        release_first = threading.Event()
        mutex = threading.Lock()
        invocations = []
        replies = [None, None]
        failures = []

        def synthetic_write(action, principal, payload):
            with mutex:
                invocations.append(1)
                sequence = len(invocations)
            if sequence == 1:
                first_entered.set()
                # Keep the first mutation in flight while the retry arrives.
                release_first.wait(timeout=4)
            return {"synthetic_ticket": "ticket-" + str(sequence)}

        self.gate_one._execute = synthetic_write
        self.gate_two._execute = synthetic_write
        requests = [
            self.signed("NEW_TICKET", "shared-key-12345678",
                        "parallel-nonce-000001", {"subject": "same"}),
            self.signed("NEW_TICKET", "shared-key-12345678",
                        "parallel-nonce-000002", {"subject": "same"}),
        ]

        def call(index, gate):
            try:
                if index == 1:
                    second_started.set()
                replies[index] = gate.request(requests[index])
            except BaseException as exc:
                failures.append(exc)

        first = threading.Thread(target=call, args=(0, self.gate_one))
        second = threading.Thread(target=call, args=(1, self.gate_two))
        try:
            first.start()
            self.assertTrue(first_entered.wait(timeout=5))
            second.start()
            self.assertTrue(second_started.wait(timeout=5))
            time.sleep(0.25)
        finally:
            release_first.set()
            first.join(timeout=6)
            if second.ident is not None:
                second.join(timeout=6)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(invocations), 1, "concurrent idempotent retry duplicated the write")
        self.assertEqual(replies[0], replies[1])
        self.assertTrue(replies[0]["ok"])

    def test_new_nonce_reuses_cached_result_and_mismatched_payload_is_rejected(self):
        invocations = []
        self.gate_one._execute = lambda *_: invocations.append(1) or {"ticket": "synthetic-1"}
        self.gate_two._execute = self.gate_one._execute
        req1 = self.signed("NEW_TICKET", "receipt-key-12345",
                           "receipt-nonce-000001", {"subject": "original"})
        req2 = self.signed("NEW_TICKET", "receipt-key-12345",
                           "receipt-nonce-000002", {"subject": "original"})
        req3 = self.signed("NEW_TICKET", "receipt-key-12345",
                           "receipt-nonce-000003", {"subject": "different"})

        original = self.gate_one.request(req1)
        self.assertEqual(original, self.gate_two.request(req2))
        self.assertEqual(len(invocations), 1)
        self.assertEqual(
            self.gate_two.request(req3)["error"],
            "IDEMPOTENCY_KEY_REUSED_FOR_DIFFERENT_REQUEST",
        )
        self.assertEqual(len(invocations), 1)
        self.assertEqual(
            self.gate_one.request(req1)["error"], "REPLAYED_NONCE"
        )


    def test_external_ack_is_limited_to_its_ticket_scope(self):
        """The persisted scope binding controls reads and acknowledgements."""
        creation = self.gate_one.request(self.signed(
            "NEW_TICKET", "create-alpha-0001", "scope-create-nonce-00001",
            {"subject": "synthetic scope test", "body": "local-only fixture",
             "from_email": "synthetic@example.test"},
            principal_id="creator-alpha", secret=EXTERNAL_SECRET,
        ))
        self.assertTrue(creation["ok"], creation)
        ticket_id = creation["data"]["ticket_id"]

        foreign_detail = self.gate_two.request(self.signed(
            "GET_TICKET_DETAIL", None, "scope-beta-detail-00001",
            {"ticket_id": ticket_id},
            principal_id="ack-beta", secret=EXTERNAL_SECRET,
        ))
        self.assertEqual(foreign_detail, {"ok": False, "error": "SCOPE_NOT_ALLOWED"})

        foreign_ack = self.gate_two.request(self.signed(
            "ACK_TICKET", "ack-beta-0000001", "scope-beta-ack-0000001",
            {"ticket_id": ticket_id},
            principal_id="ack-beta", secret=EXTERNAL_SECRET,
        ))
        self.assertEqual(foreign_ack, {"ok": False, "error": "SCOPE_NOT_ALLOWED"})

        foreign_list = self.gate_two.request(self.signed(
            "LIST_OPEN_SUMMARY", None, "scope-beta-list-0000001",
            principal_id="ack-beta", secret=EXTERNAL_SECRET,
        ))
        self.assertTrue(foreign_list["ok"], foreign_list)
        self.assertEqual(foreign_list["data"]["open"], [])

        same_scope = self.gate_one.request(self.signed(
            "LIST_OPEN_SUMMARY", None, "scope-alpha-list-00001",
            principal_id="ack-alpha", secret=EXTERNAL_SECRET,
        ))
        self.assertTrue(same_scope["ok"], same_scope)
        self.assertIn(ticket_id, [x["ticket_id"] for x in same_scope["data"]["open"]])

        valid_ack = self.gate_one.request(self.signed(
            "ACK_TICKET", "ack-alpha-000001", "scope-alpha-ack-00001",
            {"ticket_id": ticket_id},
            principal_id="ack-alpha", secret=EXTERNAL_SECRET,
        ))
        self.assertTrue(valid_ack["ok"], valid_ack)
        self.assertTrue(valid_ack["data"]["changed"])


    def _open_tickets(self):
        # Core is reopened from the encrypted synthetic fixture, not mocked.
        from sealed_core import SealedCore
        with SealedCore(OWNER_SECRET, storage_dir=self.gate_one.storage_dir) as core:
            return core.list_open_summary()

    def test_failed_scope_bind_does_not_blindly_retry_committed_ticket(self):
        """The core may commit before Gatekeeper persists the ticket scope."""
        first = self.signed(
            "NEW_TICKET", "crash-scope-key-0001", "crash-scope-nonce-0001",
            {"subject": "synthetic interrupted bind", "body": "local-only"},
            principal_id="creator-alpha", secret=EXTERNAL_SECRET,
        )
        with patch.object(self.gate_one.state, "bind_ticket_scope",
                          side_effect=RuntimeError("injected interruption after core commit")):
            self.assertEqual(
                self.gate_one.request(first), {"ok": False, "error": "INTERNAL_ERROR"}
            )
        created = self._open_tickets()
        self.assertEqual(len(created), 1, created)
        self.assertIsNone(self.gate_one.state.ticket_scope(created[0]["ticket_id"]))

        second = self.signed(
            "NEW_TICKET", "crash-scope-key-0001", "crash-scope-nonce-0002",
            {"subject": "synthetic interrupted bind", "body": "local-only"},
            principal_id="creator-alpha", secret=EXTERNAL_SECRET,
        )
        self.assertEqual(
            self.gate_two.request(second),
            {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
        )
        self.assertEqual(len(self._open_tickets()), 1)

    def test_failed_receipt_write_does_not_blindly_retry_committed_ticket(self):
        """A committed ticket + scope might lack its idempotency receipt."""
        first = self.signed(
            "NEW_TICKET", "crash-receipt-key-01", "crash-receipt-nonce-0001",
            {"subject": "synthetic interrupted receipt", "body": "local-only"},
            principal_id="creator-alpha", secret=EXTERNAL_SECRET,
        )
        with patch.object(self.gate_one.state, "record_idempotent_result",
                          side_effect=RuntimeError("injected interruption before receipt")):
            self.assertEqual(
                self.gate_one.request(first), {"ok": False, "error": "INTERNAL_ERROR"}
            )
        created = self._open_tickets()
        self.assertEqual(len(created), 1, created)
        self.assertEqual(
            self.gate_one.state.ticket_scope(created[0]["ticket_id"]), "alpha"
        )

        second = self.signed(
            "NEW_TICKET", "crash-receipt-key-01", "crash-receipt-nonce-0002",
            {"subject": "synthetic interrupted receipt", "body": "local-only"},
            principal_id="creator-alpha", secret=EXTERNAL_SECRET,
        )
        self.assertEqual(
            self.gate_two.request(second),
            {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
        )
        self.assertEqual(len(self._open_tickets()), 1)

    def test_pending_reservation_is_retained_during_bounded_receipt_prune(self):
        """An uncertain result must not be silently discarded to save space."""
        state = self.gate_one.state._new_state()
        state["idempotency"] = {
            "pending": {
                "request_hash": "a", "created_at": "2020-01-01T00:00:00Z",
                "status": "PENDING",
            },
            **{
                f"completed-{i}": {
                    "request_hash": "b", "created_at": f"2026-11-06T12:00:0{i}Z",
                    "result": {"ok": True},
                }
                for i in range(4)
            },
        }
        with patch("gatekeeper_v2_2.MAX_IDEMPOTENCY", 3):
            self.gate_one.state._prune(state)
        self.assertIn("pending", state["idempotency"])
        self.assertLessEqual(len(state["idempotency"]), 3)


    def test_precommit_error_is_conservatively_uncertain(self):
        """Without a core-linked commit marker, even no-op failure is ambiguous."""
        invocations = []
        def interrupted_execute(*_args):
            invocations.append(1)
            raise RuntimeError("synthetic precommit error")
        self.gate_one._execute = interrupted_execute
        self.gate_two._execute = interrupted_execute

        first = self.signed(
            "NEW_TICKET", "precommit-key-000001", "precommit-nonce-0001",
            {"subject": "precommit"},
        )
        second = self.signed(
            "NEW_TICKET", "precommit-key-000001", "precommit-nonce-0002",
            {"subject": "precommit"},
        )
        self.assertEqual(
            self.gate_one.request(first), {"ok": False, "error": "INTERNAL_ERROR"}
        )
        self.assertEqual(
            self.gate_two.request(second),
            {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
        )
        self.assertEqual(len(invocations), 1)

    def test_pending_capacity_exhaustion_rejects_fresh_write(self):
        """Never delete uncertain reservations to admit another local write."""
        self.gate_one._execute = lambda *_: (_ for _ in ()).throw(
            RuntimeError("synthetic interrupted write")
        )
        self.gate_two._execute = lambda *_: {"unexpected": "executed"}
        with patch("gatekeeper_v2_2.MAX_IDEMPOTENCY", 1):
            self.assertEqual(
                self.gate_one.request(self.signed(
                    "NEW_TICKET", "capacity-key-00001", "capacity-nonce-000001"
                ))["error"],
                "INTERNAL_ERROR",
            )
            self.assertEqual(
                self.gate_two.request(self.signed(
                    "NEW_TICKET", "capacity-key-00002", "capacity-nonce-000002"
                ))["error"],
                "IDEMPOTENCY_CAPACITY_REACHED",
            )
            self.assertEqual(
                self.gate_two.request(self.signed(
                    "NEW_TICKET", "capacity-key-00001", "capacity-nonce-000003"
                ))["error"],
                "OPERATION_OUTCOME_UNKNOWN",
            )


if __name__ == "__main__":
    unittest.main()
