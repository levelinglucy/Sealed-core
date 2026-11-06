# Sealed-core developer notes

## Development summary

**Current stage:** file-restore integrity candidate merged on main at `385c4cd0` (PR #2), without a stable tag or release.  
**Goal:** make corrupt, absent or failed-to-authenticate vault data incapable of truncating an existing restored file.  
**Latest change:** staged authenticated restoration with private sibling temp files, `os.replace()` for requested overwrite and exclusive `os.link()` for new files.  
**Validation:** 12/12 unittest cases and nine core self-tests passed in both PR and merged-main CI, Python 3.12. [PR run](https://github.com/levelinglucy/Sealed-core/actions/runs/42217418606) · [merged-main run](https://github.com/levelinglucy/Sealed-core/actions/runs/42217565879).  
**Next:** harden `restore_directory()` overwrite safely; investigate gatekeeper idempotency consistency across process crashes and concurrent requests.  
**Blockers:** directory overwrite still destructive prior to archive validation; power-loss and iPhone/Pythonista filesystems untested; no verified tagged stable release.  
[README](./README.md) · [Changelog](./CHANGELOG.md) · [Roadmap](./ROADMAP.md)

## Decision: verify before publishing restored file (2026-11-06)

**Problem and evidence:** `_restore_vault_object_to_file` called `target.open("wb")` before verifying any chunk. On `overwrite=True`, that truncates an existing target; the exception handler then unlinks it after a missing or tampered chunk. This is a direct source-level data-loss risk, not a claim of remote exploitability. Existing tests covered successful unseal only.

**Alternatives:** (a) load whole content into memory before writing — simple, unacceptable for large backups; (b) stream to original destination and restore a backup on failure — more write cycles and complicated interruption recovery; (c) stream to a sibling staging file and publish only after integrity verification — bounded memory with ordinary filesystem atomicity.

**Choice:** (c). Use `NamedTemporaryFile(delete=False)` in the target directory with 0600 permissions and fsync after writing. Verify AES-GCM tags and the recorded full-object SHA-256 before publishing. For `overwrite=True`, `os.replace` atomically changes the directory entry on supported filesystems. For default non-overwrite, `os.link` creates the destination only if absent, avoiding a concurrent creator being replaced between precheck and publication. The temp inode is unlinked after success, and cleaned on ordinary exception. The key bytearray is zeroed in finally.

**Trade-offs and uncertainty:** This approach uses extra temporary disk space approximately equal to restored plaintext. A hard process crash can strand a mode-0600 plaintext `.sealed-*.tmp` file; the operator should inspect and remove these from the chosen output directory when recovering from a crash. Hard links are not supported by every filesystem, and a hard-link failure surfaces as an exception rather than falling back to a risky overwrite. Filesystem failures and host power loss are not comprehensively simulated. The original `overwrite=False` destination precheck is retained for a friendly error, but the hard-link operation supplies the race-safe final guard. This does not harden directory restore, which has its own destructive prevalidation path.

**Acceptance:** corruption or missing chunks leave existing target bytes unchanged; no partial new target appears; successful overwrite and fresh restores contain exactly original bytes; no staging files remain after ordinary success/failure; new tests and historical smoke tests pass on supported Python CI. Revisit if device support requires another exclusive publication mechanism or if crash-cleanup architecture is added.

## Architecture and trust boundary

The active imports are `sealed_core.py`, `gatekeeper_v2_2.py`, and `sealed_snapshot.py`; historical named files must not be silently rewritten. Local-only function calls are not proof of absence of application-level authorization defects. No network service was introduced in this change. Use synthetic data and temporary storage for tests; do not load user vaults or secrets as test fixtures.
