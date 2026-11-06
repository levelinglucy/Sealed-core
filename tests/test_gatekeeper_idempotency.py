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
                }
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
    def signed(action, key, nonce, payload=None):
        request = build_signed_request(
            "owner-local", PRINCIPAL_SECRET, action,
            payload=payload or {}, idempotency_key=key,
        )
        request["nonce"] = nonce
        request["signature"] = sign_request(request, PRINCIPAL_SECRET)
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


if __name__ == "__main__":
    unittest.main()
