"""Atomic core-linked NEW_TICKET operation evidence, synthetic and local-only.

Development summary (2026-11-06)
---------------------------------
Purpose: prove a ticket, its two intents, metric and opaque operation receipt
commit together. Predecessor: Gatekeeper draft PENDING marker/inspection.
Next: bind an authenticated Gatekeeper reservation to this core primitive,
test signed retry after a hard exit, and retain unlinked legacy ambiguity.
No live vaults, external services or production keys are used.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sealed_core import SealedCore, _StoreFileLock

ROOT = Path(__file__).resolve().parents[1]
SECRET = "synthetic-core-operation-secret"
OPERATION_ID = "a" * 32
REQUEST_HASH = "b" * 64
SCOPE = "synthetic-scope-alpha"
EVENT = {"source": "test", "subject": "synthetic linked ticket",
         "body": "no live data", "from_email": "synthetic@example.invalid"}

CHILD = r"""
import os, sys
from sealed_core import SealedCore

mode, storage = sys.argv[1:]
with SealedCore("synthetic-core-operation-secret", storage_dir=storage) as core:
    if mode == "precommit":
        # The outer transaction has prepared data but has NOT committed any
        # encrypted generation. A hard exit at persist leaves no receipt/ticket.
        core.store._persist_state_locked = lambda: os._exit(74)
    core.handle_with_gatekeeper_operation(
        {"source": "test", "subject": "synthetic linked ticket",
         "body": "no live data", "from_email": "synthetic@example.invalid"},
        operation_id="a"*32, request_hash="b"*64,
        scope_id="synthetic-scope-alpha",
    )
    if mode == "committed":
        os._exit(73)
raise AssertionError("child did not terminate as expected")
"""


class AtomicGatekeeperCoreReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-core-linked-")
        self.storage = str(Path(self.temp.name) / "storage")

    def tearDown(self):
        self.temp.cleanup()

    def _snapshot(self):
        with SealedCore(SECRET, storage_dir=self.storage) as core:
            with _StoreFileLock(core.store.lock_path):
                return core.store._load_state_locked()

    def test_same_id_reopen_reuses_exact_ticket_without_extra_intents(self):
        with SealedCore(SECRET, storage_dir=self.storage) as core:
            receipt = core.handle_with_gatekeeper_operation(
                EVENT, operation_id=OPERATION_ID,
                request_hash=REQUEST_HASH, scope_id=SCOPE)
            self.assertEqual(receipt, core.get_gatekeeper_ticket_receipt(
                OPERATION_ID, REQUEST_HASH, SCOPE))
        with SealedCore(SECRET, storage_dir=self.storage) as reopened:
            self.assertEqual(
                receipt, reopened.handle_with_gatekeeper_operation(
                    EVENT, operation_id=OPERATION_ID,
                    request_hash=REQUEST_HASH, scope_id=SCOPE))
        state = self._snapshot()
        self.assertEqual(len(state["tickets"]), 1)
        self.assertEqual(len(state["metrics"]), 1)
        self.assertEqual(len(state["intents"]), 2)
        self.assertEqual(len(state["gatekeeper_ticket_operations"]), 1)
        operation = state["gatekeeper_ticket_operations"][OPERATION_ID]
        self.assertEqual(operation["receipt"], receipt)
        self.assertNotIn("body", operation)
        self.assertNotIn("subject", operation)

    def test_existing_id_with_mismatched_hash_or_scope_rejected(self):
        with SealedCore(SECRET, storage_dir=self.storage) as core:
            core.handle_with_gatekeeper_operation(
                EVENT, operation_id=OPERATION_ID,
                request_hash=REQUEST_HASH, scope_id=SCOPE)
            with self.assertRaisesRegex(ValueError, "GATEKEEPER_OPERATION_MISMATCH"):
                core.handle_with_gatekeeper_operation(
                    EVENT, operation_id=OPERATION_ID,
                    request_hash="c"*64, scope_id=SCOPE)
            with self.assertRaisesRegex(ValueError, "GATEKEEPER_OPERATION_MISMATCH"):
                core.get_gatekeeper_ticket_receipt(
                    OPERATION_ID, REQUEST_HASH, "other-scope")
            with self.assertRaisesRegex(ValueError, "INVALID_GATEKEEPER_OPERATION_ID"):
                core.get_gatekeeper_ticket_receipt("bad", REQUEST_HASH, SCOPE)
        self.assertEqual(len(self._snapshot()["tickets"]), 1)

    def test_old_unlinked_ticket_state_remains_compatible(self):
        with SealedCore(SECRET, storage_dir=self.storage) as core:
            first = core.handle(dict(EVENT))
            self.assertIsNone(core.get_gatekeeper_ticket_receipt(
                OPERATION_ID, REQUEST_HASH, SCOPE))
            second = core.handle_with_gatekeeper_operation(
                EVENT, operation_id=OPERATION_ID,
                request_hash=REQUEST_HASH, scope_id=SCOPE)
            self.assertNotEqual(first["ticket_id"], second["ticket_id"])
        self.assertEqual(len(self._snapshot()["tickets"]), 2)

    def test_failed_persist_rolls_back_ticket_and_operation(self):
        with SealedCore(SECRET, storage_dir=self.storage) as core:
            # A store persist failure cannot publish ticket alone.
            with patch.object(core.store, "_persist_state_locked",
                              side_effect=RuntimeError("synthetic disk failure")):
                with self.assertRaisesRegex(RuntimeError, "synthetic disk"):
                    core.handle_with_gatekeeper_operation(
                        EVENT, operation_id=OPERATION_ID,
                        request_hash=REQUEST_HASH, scope_id=SCOPE)
        state = self._snapshot()
        self.assertEqual(state["tickets"], {})
        self.assertEqual(state["gatekeeper_ticket_operations"], {})
        self.assertEqual(state["metrics"], [])
        self.assertEqual(state["intents"], [])

    def test_precommit_vs_committed_process_exit(self):
        for mode, exit_code, tickets in (
            ("precommit", 74, 0), ("committed", 73, 1),
        ):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory(prefix="sealed-linked-child-") as directory:
                    child = subprocess.run(
                        [sys.executable, "-c", CHILD, mode, directory],
                        cwd=str(ROOT), capture_output=True, text=True,
                        timeout=40, check=False,
                    )
                    self.assertEqual(child.returncode, exit_code,
                                     msg=child.stderr[-1000:])
                    with SealedCore(SECRET, storage_dir=directory) as core:
                        actual = core.list_open_summary()
                        self.assertEqual(len(actual), tickets)
                        linked = core.get_gatekeeper_ticket_receipt(
                            OPERATION_ID, REQUEST_HASH, SCOPE)
                        if mode == "committed":
                            self.assertEqual(linked["ticket_id"], actual[0]["ticket_id"])
                            self.assertEqual(
                                core.handle_with_gatekeeper_operation(
                                    EVENT, operation_id=OPERATION_ID,
                                    request_hash=REQUEST_HASH, scope_id=SCOPE),
                                linked)
                            self.assertEqual(len(core.list_open_summary()), 1)
                        else:
                            self.assertIsNone(linked)


if __name__ == "__main__":
    unittest.main()
