"""Cross-process hard-exit coverage for a draft Gatekeeper crash-window fix.

Development summary (2026-11-06)
---------------------------------
Purpose: verify that an encrypted PENDING reservation survives os._exit()
and prevents a second signed execution after the first child disappears.
Predecessor: synthetic exception-injection tests in test_gatekeeper_idempotency.
Current stage: draft PR #8 only; not a released recovery contract.
Next: core-linked operation identity and explicit owner-local reconciliation.
See GATEKEEPER_RECOVERY.md and DEV_NOTES.md for limitations.

Children use synthetic secrets, a temporary local store, and no networking.
os._exit bypasses Python finally blocks, but is not power-loss simulation.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gatekeeper_v2_2 import GatekeeperV22, build_signed_request, sign_request
from sealed_core import SealedCore, _StoreFileLock

ROOT = Path(__file__).resolve().parents[1]
OWNER_SECRET = "synthetic-owner-secret-for-hard-exit-tests"
CLIENT_SECRET = "synthetic-client-secret-for-hard-exit-tests"
PRINCIPAL = "creator-alpha"
BUSINESS_KEY = "hard-exit-business-0001"
PAYLOAD = {"subject": "synthetic hard exit", "body": "local-only test"}
REGISTRY = {
    PRINCIPAL: {
        "role": "EXTERNAL_CREATE",
        "secret": CLIENT_SECRET,
        "scope_id": "alpha",
    },
}

# A genuinely separate interpreter, not a mocked exception in the caller.
# after_commit exits once the original _execute returns: the core and scope
# have persisted, but Gatekeeper has not saved a completed receipt.
# before_commit exits at the _execute boundary, after PENDING is persisted.
CHILD = r"""
import os
import sys
from gatekeeper_v2_2 import GatekeeperV22, build_signed_request, sign_request

mode, store, key = sys.argv[1:]
gate = GatekeeperV22(storage_dir=store)
original = gate._execute

def interrupted_execute(*args):
    if mode == "after_commit":
        original(*args)
        os._exit(73)
    if mode == "before_commit":
        os._exit(74)
    raise AssertionError("unexpected mode")

gate._execute = interrupted_execute
request = build_signed_request(
    "creator-alpha", os.environ["SYNTHETIC_CLIENT_SECRET"], "NEW_TICKET",
    payload={"subject": "synthetic hard exit", "body": "local-only test"},
    idempotency_key=key,
)
request["nonce"] = "hard-exit-first-nonce-0001"
request["signature"] = sign_request(request, os.environ["SYNTHETIC_CLIENT_SECRET"])
gate.request(request)
raise AssertionError("child returned instead of hard-exiting")
"""


class GatekeeperHardExitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-hard-exit-")
        self.store = str(Path(self.temp.name) / "storage")
        self.patch_env = patch.dict(os.environ, {
            "SEALED_OWNER_SECRET": OWNER_SECRET,
            "SEALED_PRINCIPALS_JSON": json.dumps(REGISTRY),
            "SYNTHETIC_CLIENT_SECRET": CLIENT_SECRET,
        })
        self.patch_env.start()

    def tearDown(self):
        self.patch_env.stop()
        self.temp.cleanup()

    def _kill_child(self, mode, expected_exit):
        child = subprocess.run(
            [sys.executable, "-c", CHILD, mode, self.store, BUSINESS_KEY],
            cwd=str(ROOT),
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=40,
            check=False,
        )
        self.assertEqual(
            child.returncode, expected_exit,
            "child failed before target exit; stdout={!r} stderr={!r}".format(
                child.stdout[-1000:], child.stderr[-1000:]
            ),
        )

    def _ticket_ids(self):
        with SealedCore(OWNER_SECRET, storage_dir=self.store) as core:
            return [item["ticket_id"] for item in core.list_open_summary()]

    def _assert_persisted_pending(self):
        gate = GatekeeperV22(storage_dir=self.store)
        try:
            # Read and decrypt the persisted envelope; do not mutate it.
            with _StoreFileLock(gate.state.lock_path):
                state = gate.state._load_locked()
            marker = state["idempotency"][PRINCIPAL + ":" + BUSINESS_KEY]
            self.assertEqual(marker["status"], "PENDING")
            self.assertNotIn("result", marker)
            return gate
        except BaseException:
            gate.close()
            raise

    @staticmethod
    def _fresh_retry():
        req = build_signed_request(
            PRINCIPAL, CLIENT_SECRET, "NEW_TICKET",
            payload=dict(PAYLOAD), idempotency_key=BUSINESS_KEY,
        )
        req["nonce"] = "hard-exit-second-nonce-0002"
        req["signature"] = sign_request(req, CLIENT_SECRET)
        return req

    def test_hard_exit_after_commit_does_not_duplicate_ticket(self):
        self._kill_child("after_commit", 73)
        before = self._ticket_ids()
        self.assertEqual(len(before), 1, before)
        gate = self._assert_persisted_pending()
        try:
            self.assertEqual(
                gate.request(self._fresh_retry()),
                {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
            )
        finally:
            gate.close()
        self.assertEqual(self._ticket_ids(), before)

    def test_hard_exit_before_commit_remains_uncertain(self):
        self._kill_child("before_commit", 74)
        self.assertEqual(self._ticket_ids(), [])
        gate = self._assert_persisted_pending()
        try:
            self.assertEqual(
                gate.request(self._fresh_retry()),
                {"ok": False, "error": "OPERATION_OUTCOME_UNKNOWN"},
            )
        finally:
            gate.close()
        # Failure before the core starts cannot be safely inferred from the
        # missing ticket: an equivalent operation could have committed unseen.
        self.assertEqual(self._ticket_ids(), [])


if __name__ == "__main__":
    unittest.main()
