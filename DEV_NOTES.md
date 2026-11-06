# Sealed-core developer notes

## Development summary

**Stage:** directory-restore integrity candidate merged via [PR #4](https://github.com/levelinglucy/Sealed-core/pull/4) at `7e647ed0`; no new stable tag or release.
**Goal:** prevent a corrupt or malformed encrypted directory archive from deleting existing restored content.
**Latest change:** stage verified archive and extracted tree, validate one expected top-level directory, then rename the previous destination to a recoverable sibling before publishing the new tree; roll back on ordinary failure.
**Checks:** 23/23 unit tests and 9/9 core self-tests passed for each Python 3.11/3.12 on the exact [PR revision](https://github.com/levelinglucy/Sealed-core/actions/runs/42225523051) and [merged main](https://github.com/levelinglucy/Sealed-core/actions/runs/42225646052). Eleven new directory cases cover both normal restoration and failure recovery.
**Next:** investigate gatekeeper consistency using isolated tests; consider crash-backup recovery tooling; obtain trusted Pythonista evidence.
**Blockers / known risk:** multi-rename publication is not crash-atomic; interrupted runs can leave `.NAME.sealed-backup-*` and private temporary plaintext. No guarantee against independent concurrent writers or power loss; old Python tar fallbacks decline links/special files.
[README](./README.md) · [Changelog](./CHANGELOG.md) · [Roadmap](./ROADMAP.md)

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
