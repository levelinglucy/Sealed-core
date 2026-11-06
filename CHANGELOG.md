# Sealed-core changelog

## Draft core-side atomic ticket receipt candidate (2026-11-06; PR #8, unmerged)

**Components:** `sealed_core.py`, `tests/test_core_gatekeeper_operation.py`, README, engineering notes and roadmap. **Before:** a PENDING reservation had an opaque Gatekeeper-only ID with no independently verifiable corresponding core transaction; a separate receipt write would leave the same crash window.

**Change and reason:** add an opt-in local core method that stores the ticket result and bound request hash/scope/operation ID together with the ticket, metric and intents in one encrypted transaction. Exact-ID replay returns the original result; hash or scope mismatch rejects reuse. Preserve ordinary `handle()` and legacy state. Tests cover precommit and postcommit `os._exit`, synthetic failed persist, exact replay and collisions. **Validated code head:** [GitHub Actions 42270761333](https://github.com/levelinglucy/Sealed-core/actions/runs/42270761333) passed 43/43 Python unit tests and nine core self-tests on each of Python 3.11 and 3.12 at [`bf310cc9`](https://github.com/levelinglucy/Sealed-core/commit/bf310cc9cb2c97c90600f0637f6cc04d3e719a56). Five new tests cover readback, rejection, legacy data, failed persist and actual subprocess hard-exit. This is Linux CI only.

**Limitations:** no Gatekeeper wiring or owner-side pending reconciliation yet, so the reservation ID is still unlinked in actual signed requests. No automatic retry/resolution, stable tag, release or claim of power-cut/mobile verification. A source downgrade could ignore operation records; preserve the original encrypted store and code branch.



## Draft preparatory step — redacted owner-local PENDING inspection (2026-11-06; PR #8; unmerged)

**Components:** \`gatekeeper_v2_2.py\`, \`tests/test_gatekeeper_inspection.py\`, README, developer decisions, recovery guide and roadmap. **Before:** a pending marker could prevent duplicate execution but offered no local diagnostic beyond manually inspecting its encrypted state, and had no dedicated correlation identifier. No one could infer the exact core commit from that marker.

**Change:** add an opaque random ID to new encrypted PENDING reservations and preserve it on completion; provide a read-only local owner-secret helper that fingerprints the business-key reference and returns only the request hash, time, status and optional ID. It is *not* a policy action, network service or automatic reset facility. Historical pending records without IDs still appear as unlinked; completed receipts are omitted from the diagnostic. No core schema or transaction code changed.

**Why this limited approach:** it creates a traceable future linkage point and allows safe inspection without guessing from similar ticket details. A durable core commit mapping, owner-controlled reconciliation and safe downgrade remain unimplemented. The correlation ID is **not yet written to core** and alone proves nothing. The change is reviewable only; do not merge or publish as a release without validation of final head and a comprehensive recovery plan. New synthetic regression checks cover read-only operation, output redaction, stable IDs, legacy entries and API non-exposure; [Exact candidate CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42261063240) passed **38/38 unit tests + nine core self-tests on each Python 3.11 and 3.12**, including all four new cases.

## Draft test expansion — hard process-exit recovery checks (2026-11-06; PR #8; not merged)

**Components:** new `tests/test_gatekeeper_hard_exit.py` plus README, developer notes, recovery guide and roadmap. **Why:** previously only injected Python exceptions tested the gap after a core commit; these still run cleanup and do not represent a terminated interpreter.

**Observed:** two separate Python child processes used synthetic local-only secrets, a temporary encrypted store, and `os._exit` to bypass Python cleanup. A forced exit just after the core committed a ticket and persisted scope left one ticket and an encrypted pending marker; reopening Gatekeeper and retrying with a distinct valid nonce returned `OPERATION_OUTCOME_UNKNOWN` without creating another ticket. An exit after the marker but before core execution left zero tickets, yet correctly blocked the ambiguous retry. [Exact code-commit CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42252218491) passed **34/34 unit tests plus 9/9 core self-tests on each Python 3.11 and 3.12** at [`be1e8ae1`](https://github.com/levelinglucy/Sealed-core/commit/be1e8ae11c84b16cd0ca24bf73a06c0d8ae82223). All fixtures are synthetic.

**Trade-offs and limits:** even a known precommit interruption strands a pending reservation; the runtime cannot prove the outcome for arbitrary write actions. `os._exit` is not a power cut, SIGKILL, mobile filesystem durability test or exactly-once transaction guarantee. No automatic reset, new endpoint, data migration, PR merge or stable release. Resume by designing a core-linked durable operation identity and owner-only audited reconciliation/rollback, rather than guessing from similar ticket content.

## Draft candidate — fail-closed uncertain Gatekeeper outcomes (2026-11-06; PR #8; not merged)

**Components:** `gatekeeper_v2_2.py`, `tests/test_gatekeeper_idempotency.py`, README, developer notes, roadmap and `GATEKEEPER_RECOVERY.md`.

**Before:** a core commit that succeeded shortly before ticket-scope binding or idempotency receipt storage could lack a cached result. A later signed retry using the same business key with a new nonce executed the write a second time. Synthetic tests for both interrupted windows and pending-entry eviction were first committed as `9b53f0bb`; on Python 3.11 and 3.12, [expected-red CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42242913268) confirmed three failures.

**Draft change:** durably reserve each keyed operation as `PENDING` together with its nonce before executing it; a matching retry with no completed receipt returns `OPERATION_OUTCOME_UNKNOWN` instead of re-executing. Keep pending records during bounded cache pruning; reject new keyed operations rather than evict pending entries at full capacity; continue to replay historical completed receipts without migration. The code candidate `e389bdb4` passed 29/29 Python unit tests and nine core self-tests on each of Python 3.11 and 3.12 ([CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42243006070)). Additional synthetic capacity/precommit/legacy-compatibility tests and detailed recovery documentation followed; refer to the latest PR head for their validation.

**Compatibility:** no new public action, role, signature, network listener or encrypted envelope schema. The retry contract changes: uncertain operations are deliberately blocked pending manual reconciliation, even if no write occurred. A rollback to a previous Gatekeeper version with pending records may permit duplicates; do not automatically deploy older code against this state.

**Known limitations:** this is a **reviewable candidate only**, not a merged fix, stable release, or crash-atomic transaction. No audited operator reconciliation workflow exists. Power-cut/fault injection on iPhone, hard-kill recovery, external direct-core writes, indefinitely retained completed receipts, and portable lock semantics remain unverified. Details in [engineering decision](./DEV_NOTES.md) and [recovery guide](./GATEKEEPER_RECOVERY.md).

## Merged integrated candidate — concurrent Gatekeeper idempotency (2026-11-06; PR #6)

**Components:** `gatekeeper_v2_2.py`, `tests/test_gatekeeper_idempotency.py` and developer documentation.

**Previously:** two signed same-principal requests with the same idempotency key and different valid nonces could both consume their nonce, see no saved receipt and execute the side effect before either caller recorded its result. The standalone test-only commit `f063752b` reproduced two executions; [red CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234112137) on Python 3.11 and 3.12 documented the failure.

**Now:** a separate cooperating-process request file lock encloses authentication, side effects, scope binding and receipt storage. Retrying the same business action receives the cached result. Three synthetic tests cover concurrent same-key retries, replay/key-collision invariants and actual scoped-ticket isolation for external acknowledgers. Other historical integrity tests remain intact.

**Validation:** [Final PR CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234685983) and [merged-main CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234765405) passed 26/26 unit tests plus all nine core self-tests on each of Python 3.11 and 3.12. [PR #6](https://github.com/levelinglucy/Sealed-core/pull/6) was merged at [`9396f067`](https://github.com/levelinglucy/Sealed-core/commit/9396f067bf403fde4678850e7f69588437fb626e); **no stable tag/release**. Fixtures use fake local secrets and temp storage.

**Trade-offs:** cooperating local calls are serialized, including reads; no network or new role access. Crash between a successful core mutation and idempotency/scope persistence can still leave a committed action without a receipt, and later retry can repeat it. Cross-platform locking, non-cooperating writers and Pythonista/iPhone execution remain unverified. Revisit with a durable core-linked transaction protocol if crash recovery becomes a requirement.



## Integrated candidate — directory-restore rollback (2026-11-06; untagged)

**Scope:** `sealed_core.py` directory restoration / tar extraction, eleven synthetic integrity tests, README, engineering notes and roadmap.

**Before:** `restore_directory(overwrite=True)` deleted any existing tree before authenticating encrypted archive chunks or validating the tar. Missing/tampered chunks or malformed paths could destroy previously restored data.

**After:** verify encrypted chunks and whole-object hash, extract inside a sibling private staging directory with a single expected top-level tree and safe tar filtering, then move the old target to a recoverable sibling backup before publishing the staged tree. Roll back on ordinary publication failure; deliberately retain old backup if rollback fails. New tests cover missing and invalid ciphertext, malformed authenticated tar, path traversal and unexpected roots, older-Python link rejection, rollback successes/failures, overwrite and fresh restore round-trips, and no-overwrite.

**Validation:** [directory PR #4](https://github.com/levelinglucy/Sealed-core/pull/4) merged as [`7e647ed0`](https://github.com/levelinglucy/Sealed-core/commit/7e647ed06a8d19a0e28015a9729f801985db77a2). [PR CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42225523051) and [merged-main CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42225646052) each passed 23/23 unittest cases plus all nine original self-tests on both Python 3.11 and 3.12. All tests use synthetic fixtures and temporary storage; no trusted end-user vault or Pythonista device was touched.

**Limits and recovery:** this is not an atomic directory swap; sudden termination between renames may leave old content in `.NAME.sealed-backup-*` or expose a brief missing target. A failed rollback preserves the backup for manual restoration. Staging plaintext may persist after a hard crash. On Python without the tar data filter, archives with links/special files are rejected. No filesystem power-loss, concurrent-writer or Pythonista guarantee. No stable release/tag asserted.

## Unreleased — local-only file-restore integrity candidate (2026-11-06)

**Scope:** `sealed_core.py`, `tests/test_verified_restore.py`, README and developer docs.

**Before:** `_restore_vault_object_to_file()` opened the final destination with `wb` before reading and authenticating all chunks. If a chunk was absent or failed AES-GCM verification, an existing `overwrite=True` target had already been truncated and then deleted. New targets could briefly contain partial plaintext. No repository-local automated regression tested this failure mode.

**After:** decrypt to a private sibling staging file; verify all chunk authentication and aggregate SHA-256 before exposing output. Publish existing-file overwrites with `os.replace()`, or new-file restores with an exclusive `os.link()`. Remove staging files on ordinary failure. File-specific regression tests cover missing/corrupt ciphertext, intact original contents, successful replacement, no-overwrite behaviour, and successful new-file round trips.

**Validation:** [PR #2](https://github.com/levelinglucy/Sealed-core/pull/2) merged as [`385c4cd0`](https://github.com/levelinglucy/Sealed-core/commit/385c4cd0c4039ac76c268af96c8a688c0bd7e328). [PR CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42217418606) and [merged-main CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42217565879) each passed 12/12 unittest cases and all nine bundled core self-tests (Python 3.12). Tests use isolated temporary storage, synthetic secrets and no network. No trusted mobile-device test was performed.

**Compatibility and limits:** same vault format and public APIs; regular-file restore now requires a filesystem supporting hard links for non-overwrite publication and same-directory rename for overwrite. Temporary owner-readable plaintext can remain after hard process termination; a power loss is outside current validation. `restore_directory(overwrite=True)` still deletes an existing destination before archive authentication/extraction, and is a separate priority repair. No stable version tag or release is asserted.

Previous historical source files are retained. This changelog records portfolio-maintained changes, not reconstructed history.
