# Sealed-core developer notes

## Development summary

**Stage:** local-only v2.2 Gatekeeper idempotency transaction candidate in [PR #6](https://github.com/levelinglucy/Sealed-core/pull/6), after integrated file and directory recovery candidates; no stable tag.
**Goal:** signed concurrent retries should not execute the same side effect twice while local cooperating Gatekeeper callers are running.
**Latest:** first reproduced duplicate side effects under parallel same-key, distinct-nonce requests in [unpatched PR CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234112137). Added cross-process request serialization over authentication, core action and cached result. Tests also exercise nonce replay, changed-payload key collision and real ticket scope isolation.
**Evidence:** 26/26 tests and 9/9 core self-tests passed in [candidate CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234410661) on each of Python 3.11 and 3.12. Main-branch CI and final merge status must be verified separately.
**Next:** validate merged revision; investigate crash interruption between core and Gatekeeper state; trusted Pythonista/device checks.
**Limits:** operations are serialized through a local file lock, reducing simultaneous read throughput; a process crash after a side effect but before recording the receipt remains an unclosed exactly-once gap. Separate core writers, mobile file locking and power-loss behavior not proven.

[README](./README.md) · [Changelog](./CHANGELOG.md) · [Roadmap](./ROADMAP.md)

## Decision: serialize Gatekeeper request transactions (2026-11-06)

**Observed defect:** `consume_nonce_and_check_idempotency` persisted the nonce and checked for an existing result, but the business operation and `record_idempotent_result` happened later and outside any shared execution lock. Two valid signed requests from the same principal, with identical action/payload/idempotency key and distinct nonces, could both pass the check before either result existed. Isolated test-only PR SHA `f063752b` reproduced **2 side effects rather than 1** on Python 3.11 and 3.12, while sequential replay and key-collision checks passed. This is a local API concurrency defect, not a verified remote exploit.

**Options:** (a) nonce lock alone — insufficient; (b) in-memory per-key mutex — insufficient across cooperating processes; (c) separate process-shared request lock across authentication, execution and result write — simple and fits existing `_StoreFileLock` cross-process convention; (d) durable transaction journal in the core store — better for recovery but a substantial, riskier schema/API change. Selected **(c)** for bounded repair and preserve (d) for a later milestone.

**Implementation:** `GatekeeperState.request_lock_path` is distinct from `.gatekeeper.lock`; the entire `GatekeeperV22.request()` normal path, including signed auth, nonce check, ticket-scope binding, local core operation and result persistence, runs under the new lock. State/Core locks remain separate inside. This also prevents a cooperating scoped read from overtaking an in-progress ticket creation. No encryption format, signature or role policy was changed; original historical files remain untouched.

**Acceptance:** independent Gatekeeper instances share a synthetic storage root; a deliberately delayed first write receives a parallel same-key retry; one operation executes and the other receives the identical cached result. Sequential same-key retry, payload mismatch, reused nonce, and different-scope `EXTERNAL_ACK` denial/own-scope success are covered. [Candidate CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234410661) passed 26 unit tests plus nine self-tests on both versions. This validates cooperating file-lock behavior on Linux runners, not crash recovery or all platforms.

**Remaining gap and revisit:** this is *not* a single crash-atomic transaction across two encrypted state files. A hard termination after `core.handle` but before scope binding or cached result persistence can leave an orphan scoped ticket or duplicate the action on a retry; even under the process-shared lock a fresh process cannot infer the missing receipt. Investigate a durable intent/commit marker or core-level transaction link with safe migration and crash injection before claiming exactly-once semantics. Non-cooperating direct core writers bypass the request lock. Reads serialize as a deliberate safety/throughput trade-off; revisit if profiling shows an actual bottleneck.

## Decision: stage and roll back directory restoration (2026-11-06)

**Before:** `restore_directory(overwrite=True)` removed the destination with `rmtree` / `unlink` before even decrypting the archive. A missing vault chunk, altered AES-GCM ciphertext, invalid tar, extraction error or interrupted write could therefore destroy the only available prior output.

**Alternatives:** (a) decrypt and extract directly into the old destination — no safe failure isolation; (b) make a full copied backup before in-place extraction — more I/O, still exposes partial new content; (c) stage the verified extracted directory beside the destination, rename old to backup, then rename new into place, with rollback — bounded memory, additional disk space, distinct rollback path. Selected (c).

**Implementation:** validate the original directory name; create owner-private temporary storage inside the target root; reuse vault chunk authentication and full SHA-256 verification for the archive; use `tarfile`'s data filter when supported and enforce a single expected top-level root. On older Python without the filter, reject archive links and special entries rather than allowing potentially unsafe extraction. Keep previous content in `.NAME.sealed-backup-UUID` outside the auto-removed staging directory. Restore it if the second rename fails, and leave it untouched if rollback itself fails. Delete the old backup only after publishing new data; preserve historical source files and the local-only design.

**Trade-offs:** requires approximately a second full plaintext archive plus extracted tree during staging; no long-term API/schema changes. There is a short gap between moving the old tree and making the new one visible. Abrupt termination, storage failure, or an uncooperative concurrent writer is not a guaranteed recoverable transaction. A crash can leave backup folders or plaintext staging; do not blindly delete them. Symlink-containing archives on old Python may no longer restore (security-first compatibility restriction). Directory data and permissions were not power-loss fsynced exhaustively; not certified on iPhone or non-POSIX filesystems.

**Acceptance:** missing/corrupt chunks, authenticated invalid tar and traversal attempts preserve old content; injected failed promotion rolls back; if rollback itself fails old data remains in a recoverable sibling; successful overwrite and fresh restores preserve bytes; standard smoke tests pass. Revisit if an audited portable crash-atomic directory exchange or a safe cross-platform exclusive publication mechanism becomes available.

## Decision: verify before publishing restored file (2026-11-06)

**Problem and evidence:** `_restore_vault_object_to_file` called `target.open("wb")` before verifying any chunk. On `overwrite=True`, that truncates an existing target; the exception handler then unlinks it after a missing or tampered chunk. This is a direct source-level data-loss risk, not a claim of remote exploitability. Existing tests covered successful unseal only.

**Alternatives:** (a) load whole content into memory before writing — simple, unacceptable for large backups; (b) stream to original destination and restore a backup on failure — more write cycles and complicated interruption recovery; (c) stream to a sibling staging file and publish only after integrity verification — bounded memory with ordinary filesystem atomicity.

**Choice:** (c). Use `NamedTemporaryFile(delete=False)` in the target directory with 0600 permissions and fsync after writing. Verify AES-GCM tags and the recorded full-object SHA-256 before publishing. For `overwrite=True`, `os.replace` atomically changes the directory entry on supported filesystems. For default non-overwrite, `os.link` creates the destination only if absent, avoiding a concurrent creator being replaced between precheck and publication. The temp inode is unlinked after success, and cleaned on ordinary exception. The key bytearray is zeroed in finally.

**Trade-offs and uncertainty:** This approach uses extra temporary disk space approximately equal to restored plaintext. A hard process crash can strand a mode-0600 plaintext `.sealed-*.tmp` file; the operator should inspect and remove these from the chosen output directory when recovering from a crash. Hard links are not supported by every filesystem, and a hard-link failure surfaces as an exception rather than falling back to a risky overwrite. Filesystem failures and host power loss are not comprehensively simulated. The original `overwrite=False` destination precheck is retained for a friendly error, but the hard-link operation supplies the race-safe final guard. This does not harden directory restore, which has its own destructive prevalidation path.

**Acceptance:** corruption or missing chunks leave existing target bytes unchanged; no partial new target appears; successful overwrite and fresh restores contain exactly original bytes; no staging files remain after ordinary success/failure; new tests and historical smoke tests pass on supported Python CI. Revisit if device support requires another exclusive publication mechanism or if crash-cleanup architecture is added.

## Architecture and trust boundary

The active imports are `sealed_core.py`, `gatekeeper_v2_2.py`, and `sealed_snapshot.py`; historical named files must not be silently rewritten. Local-only function calls are not proof of absence of application-level authorization defects. No network service was introduced in this change. Use synthetic data and temporary storage for tests; do not load user vaults or secrets as test fixtures.
