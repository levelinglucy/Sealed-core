# Gatekeeper uncertain-outcome recovery (draft candidate)

**Status:** [PR #8](https://github.com/levelinglucy/Sealed-core/pull/8) is a local-only development candidate, **not merged or released**. Its *linked* signed NEW_TICKET behaviour is different from the stable main branch. Read this before retrying.

## Meaning of a pending outcome

A valid, freshly signed same-key NEW_TICKET retry can now return the original receipt **only when** the Gatekeeper's encrypted PENDING ID, verified request hash and current authorized registry scope exactly match a core operation receipt committed atomically with that ticket. It then restores the matching ticket scope binding and completed Gatekeeper receipt. A missing receipt, mismatch or legacy unlinked PENDING record still returns `OPERATION_OUTCOME_UNKNOWN`; that **does not** prove an operation did not execute.

Non-ticket writes (ACK/CLOSE, vault sealing, unsealing, directory restores) continue to return `OPERATION_OUTCOME_UNKNOWN` after interruption because their filesystem/core side effects are not linked to an atomic operation map. A new idempotency key is a *new operation*, not a safe retry.

Never delete or hand-edit `gatekeeper_state.json` or encrypted `state.json`. Do not downgrade to older code that ignores PENDING or linked core receipts and then retry, as duplicate side effects can result. Save offline backups of both encrypted stores before any owner review; keep the original host binding.

## Evidence and owner-local inspection

`inspect_pending_local(storage_dir)` is a read-only Python helper requiring the local owner secret. It exposes only a hashed compound key reference, request hash, timestamp, PENDING status and optional random operation ID; no raw signed payloads, keys, nonces or secrets. It is **not** a signed action, network endpoint, permission to clear PENDING or an automatic repair API.

```python
from gatekeeper_v2_2 import inspect_pending_local
for item in inspect_pending_local("sealed_storage"):  # trusted local host only
    print(item)
```

### Cross-store evidence triage (owner-local, read-only)

A second helper compares PENDING markers with **one authenticated encrypted core-state generation**, without clearing markers, issuing requests or copying ticket contents. On the original trusted host, with the usual owner secret:

```python
from gatekeeper_v2_2 import inspect_pending_evidence_local
for row in inspect_pending_evidence_local("sealed_storage"):
    print(row["key_ref_sha256"], row["core_evidence"])
```

- `CORE_TICKET_RECEIPT_PRESENT`: a matching operation ID and request hash reference an internally consistent ticket receipt in encrypted core state. **Current registry scope and signed request have not been authenticated by this helper**. This is not permission to clear PENDING, create a new key, or grant external access. Actual recovery still requires a fresh signed same-key request with matching authorized scope.
- `NO_CORE_RECEIPT_UNKNOWN`: no corresponding core receipt is visible; this **does not prove the write never happened**.
- `LEGACY_UNLINKED_UNKNOWN` or `INVALID_ID_UNKNOWN`: historical/unusable correlation, never infer success from similar-looking tickets.
- `CORE_RECEIPT_CONFLICT` or `CORE_RECEIPT_INCOMPLETE`: inconsistent or incomplete evidence; stop, preserve both encrypted originals and inspect offline on a copy. Never repair it by hand-editing stores.

Every row explicitly reports `authorizes_retry_or_clear=False` and `current_scope_verified=False`; it includes only redacted identifiers/hashes and diagnostic status, not the principal, original key, scope, signed payload or ticket. The helper requires the **local owner secret** and uses the existing request lock. Encrypted state files are not rewritten, although local lock files/working directories may be created. Do not expose its output outside a trusted owner workstation.

A new linked ticket's operation ID is present in both encrypted stores only after the core transaction commits. The core's `get_gatekeeper_ticket_receipt()` validates exact ID/hash/scope without mutation, but does not independently authenticate callers. The **Gatekeeper's HMAC, nonce, role and registry-scope validation must happen first**. Operation IDs on their own are not a proof of execution or entitlement, and a missing core record must not be used to reset state.

## Owner response when outcome is still unknown

1. Stop automatic retries of the affected business action and preserve the original principal, action, idempotency-key reference, request business identity, local timestamps and redacted error, **not** signing secrets.
2. Back up the encrypted Gatekeeper and core state, relevant vault/file outputs and local recovery metadata. Avoid copying decrypted information to logs.
3. Use trusted owner-local inspection to determine whether there is exact core-linked evidence; never infer from a similar-looking ticket or an old unlinked ID. If scope changed, resolve the principal registry discrepancy offline; don't bind a ticket to a new scope.
4. For unlinked/legacy/non-ticket operations or ambiguous evidence, **leave PENDING intact** and seek deliberate owner reconciliation; no automatic reset or manual deletion is provided.
5. For a genuinely new business request, use a different key only under normal owner controls; it is not automatic recovery of the earlier request.

A ticket may have committed before its external-ack scope binding and be temporarily invisible to external acknowledgers. A matching signed ticket retry restores that binding only with exact atomic core evidence and matching scope; other scopes remain forbidden.

## Rollback, validation and limits

The draft adds an encrypted `PENDING` reservation and core operation ledger, while preserving old completed receipts without a status field. The completed cache remains bounded; PENDING entries are not silently pruned and can exhaust capacity. Historic unrelated direct `core.handle()` operations have no linked identity. Do not run earlier code against these stores expecting safe retry; code rollback is not state rollback.

[Pre-documentation CI 42288153350](https://github.com/levelinglucy/Sealed-core/actions/runs/42288153350) passed **53/53 Python unit tests plus 9/9 self-tests on each Python 3.11 and 3.12**, using synthetic temporary stores, injected commit/receipt failures and child-interpreter `os._exit` after core commit and before execution. It is **not** a power-cut test, real SIGKILL test, trusted iPhone/Pythonista filesystem check, or proof of general exactly-once delivery. No new listener or external network access was added. The draft must remain reviewable until an audited owner-only recovery/rollback plan covers older PENDING, non-ticket writes and platform constraints.
