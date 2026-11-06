# Sealed-core changelog

## Unreleased — local-only file-restore integrity candidate (2026-11-06)

**Scope:** `sealed_core.py`, `tests/test_verified_restore.py`, README and developer docs.

**Before:** `_restore_vault_object_to_file()` opened the final destination with `wb` before reading and authenticating all chunks. If a chunk was absent or failed AES-GCM verification, an existing `overwrite=True` target had already been truncated and then deleted. New targets could briefly contain partial plaintext. No repository-local automated regression tested this failure mode.

**After:** decrypt to a private sibling staging file; verify all chunk authentication and aggregate SHA-256 before exposing output. Publish existing-file overwrites with `os.replace()`, or new-file restores with an exclusive `os.link()`. Remove staging files on ordinary failure. File-specific regression tests cover missing/corrupt ciphertext, intact original contents, successful replacement, no-overwrite behaviour, and successful new-file round trips.

**Validation:** code and tests submitted for PR CI; final tested and merged statuses must be recorded only when observed. Tests use isolated temporary storage, synthetic secrets and no network.

**Compatibility and limits:** same vault format and public APIs; regular-file restore now requires a filesystem supporting hard links for non-overwrite publication and same-directory rename for overwrite. Temporary owner-readable plaintext can remain after hard process termination; a power loss is outside current validation. `restore_directory(overwrite=True)` still deletes an existing destination before archive authentication/extraction, and is a separate priority repair. No stable version tag or release is asserted.

Previous historical source files are retained. This changelog records portfolio-maintained changes, not reconstructed history.
