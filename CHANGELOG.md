# Sealed-core changelog

## Integrated candidate — concurrent Gatekeeper idempotency (2026-11-06; PR #6)

**Components:** `gatekeeper_v2_2.py`, `tests/test_gatekeeper_idempotency.py` and developer documentation.

**Previously:** two signed same-principal requests with the same idempotency key and different valid nonces could both consume their nonce, see no saved receipt and execute the side effect before either caller recorded its result. The standalone test-only commit `f063752b` reproduced two executions; [red CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234112137) on Python 3.11 and 3.12 documented the failure.

**Now:** a separate cooperating-process request file lock encloses authentication, side effects, scope binding and receipt storage. Retrying the same business action receives the cached result. Three synthetic tests cover concurrent same-key retries, replay/key-collision invariants and actual scoped-ticket isolation for external acknowledgers. Other historical integrity tests remain intact.

**Validation:** [PR candidate CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234410661) passed 26/26 unit tests plus all nine core self-tests on each of Python 3.11 and 3.12. PR merge and merged-main checks require separate verification; no stable tag/release. Fixtures use fake local secrets and temp storage.

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
