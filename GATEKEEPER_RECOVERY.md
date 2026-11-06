# Gatekeeper uncertain-outcome recovery (draft candidate)

**Status:** local-only Gatekeeper v2.2 proposal in [PR #8](https://github.com/levelinglucy/Sealed-core/pull/8), **not merged or released**. This document describes the proposed `PENDING` idempotency reservation, not behavior in the current stable baseline.

## What the response means

`{"ok": false, "error": "OPERATION_OUTCOME_UNKNOWN"}` means a valid, freshly signed retry matched an earlier idempotency key for which the Gatekeeper has an encrypted **pending reservation but no committed reply**. The earlier request might have failed **before** any side effect, or it might have committed in Sealed Core, mutated an output directory, or bound a ticket scope before interruption. Gatekeeper cannot distinguish those cases using its two independent encrypted state files.

Do **not** automatically submit the operation again under a different idempotency key. That can duplicate tickets, vault objects or external filesystem changes. Do **not** delete, truncate or hand-edit `gatekeeper_state.json` or `state.json` to clear the error; either can be the only surviving evidence of an interrupted operation.

## Safe response for an operator

1. Stop automatic retries for the affected business operation and record its principal, action, key, payload identity, approximate time, and the redacted error response. Never record signing secrets.
2. Keep copies/backups of the original encrypted files and relevant local-only audit context before recovery work. Respect file permissions and retain the original machine binding.
3. Using authorized owner-local tools, inspect the actual Sealed Core state and any specific output path for evidence of a completed action. A similar-looking ticket is **not** proof it is the matching request; the core currently lacks a durable Gatekeeper operation identifier.
4. If an outcome remains uncertain, leave the pending reservation in place and treat the action as requiring human reconciliation, not a blind retry. The current candidate intentionally has **no automatic reset/repair endpoint**.
5. For a known-uncommitted operation, a new signed request with a new idempotency key is a deliberate *new* operation and must be approved through the caller's normal operational controls. This is not the same as proving a replay was safe.

An orphan ticket can exist in the core but remain invisible to an external acknowledger when scope binding failed; the owner must inspect it locally. Do not guess or invent a scope binding. No new remotely exposed interface is introduced.

## Compatibility and rollback cautions

The candidate extends existing encrypted Gatekeeper state values with `status: PENDING` before execution and `status: COMMITTED` after receipt storage. Old completed entries with only `result` remain valid. The envelope schema, secrets and signatures are unchanged. The number of stored idempotency entries is bounded. Pending entries are retained in preference to completed entries; exhausted pending capacity rejects new keyed requests with `IDEMPOTENCY_CAPACITY_REACHED` rather than discarding uncertain operations. Older completed receipts may still age out of this bounded cache.

Rolling back the code to a version that *ignores* pending records can re-enable duplicate execution on retry. Therefore **do not treat an older binary as a safe recovery tool for a store containing pending entries**. Keep this candidate on a reviewable branch until operator reconciliation and a compatible rollback procedure are designed. Rollback of source code alone is not equivalent to safe rollback of state.

## Validation and remaining work

All current tests use fake secrets and temporary local storage. Synthetic exceptions after core commit and after scope binding reproduce the missing-receipt window. Before the repair, matching signed retries created a second ticket; test-only CI failed on Python 3.11 and 3.12 ([red baseline](https://github.com/levelinglucy/Sealed-core/actions/runs/42242913268)). Initial candidate checks passed 29 unit tests and nine self-tests on each version ([green CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42243006070)). Additional compatibility and capacity tests were added later; see the current PR checks for their status.

An injected Python exception is **not** a simulated power cut, actual SIGKILL, or an end-to-end cross-filesystem durability test. A durable core-linked operation ledger and safe, audited resolution flow remain research milestones. Local-only access, ticket-scope boundaries, raw-data confidentiality and historical sources must remain intact.
