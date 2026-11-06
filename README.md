# Sealed-core

## Development summary

**Status:** local-only modular stack; file and directory restore integrity fixes prepared on a reviewable branch for the next candidate, **not a tagged stable release**. File restore PR #2 and its documentation PR #3 remain merged.
**Goal:** fail safely on encrypted vault corruption and extracted archive errors, without erasing existing restored data.
**Latest change (2026-11-06):** directory archives now decrypt and extract in a private sibling staging tree before any existing destination moves. Overwrite holds the old tree in a recoverable same-filesystem backup until publication succeeds; ordinary publish failures roll back. Path traversal, unexpected archive roots and unsafe link fallbacks are rejected.
**Validation:** nine new synthetic directory restore regression cases and existing file/core self-tests are included for CI; this candidate is not considered verified until the PR checks complete. See [developer notes](./DEV_NOTES.md) and [changelog](./CHANGELOG.md) for precise evidence.
**Next steps:** (1) verify candidate tests and merge if safe; (2) review gatekeeper nonce/idempotency and scope transaction boundaries; (3) gather trusted target-device evidence.
**Limitations:** directory promotion uses two renames, **not one atomic swap**: abrupt interruption can strand an old tree as `.NAME.sealed-backup-*` and may leave a visible gap before publication. After an ordinary failed rollback the backup is deliberately retained for manual recovery. Hard termination can also strand private plaintext staging; inspect output roots before deleting backups or staging. Older Python versions without `tarfile.data_filter` reject archived links/special files rather than using an unsafe extraction fallback. Concurrent non-cooperating writers and power-loss durability are not proven; avoid restoring into concurrently edited destinations. Pythonista/iPhone has not been tested.
[Changelog](./CHANGELOG.md) · [Engineering decisions](./DEV_NOTES.md) · [Roadmap](./ROADMAP.md)

## Modular stack wiring

This repository uses a local-only modular stack:

- `sealed_core.py` — core ticketing/storage module imported by other components.
- `gatekeeper_v2_2.py` — authenticated local policy wrapper over `SealedCore`.
- `sealed_snapshot.py` — small snapshot front door that imports `SealedCore`.

## Required environment variables

- `SEALED_OWNER_SECRET` (required): owner secret used by `SealedCore` key derivation.
- `SEALED_HOST_ID` (optional but recommended on VMs/containers): stable host identifier
  mixed into machine fingerprint derivation when hardware identity is less stable.
- `SEALED_PRINCIPALS_JSON` (required for `gatekeeper_v2_2.py`): JSON mapping
  principal IDs to `{role, secret, scope_id}` objects.

Example:

```bash
export SEALED_OWNER_SECRET='replace-with-a-long-random-secret'
export SEALED_PRINCIPALS_JSON='{
  "owner-local": {
    "role": "OWNER",
    "secret": "replace-with-a-long-random-principal-secret",
    "scope_id": "owner"
  }
}'
```

## Quick start (modular)

```bash
python -m pip install cryptography
export SEALED_OWNER_SECRET='replace-with-a-long-random-secret'
export SEALED_PRINCIPALS_JSON='{
  "owner-local": {
    "role": "OWNER",
    "secret": "replace-with-a-long-random-principal-secret",
    "scope_id": "owner"
  }
}'
python -c "import sealed_core, gatekeeper_v2_2, sealed_snapshot; print('imports-ok')"
```

## Vault examples

```bash
# Snapshot file or directory
python sealed_snapshot.py /path/to/item --label "My snapshot"
```

## Notes

- No network listener is required; imports are local Python module calls.
- Gatekeeper write actions are local-only and require signed requests plus
  idempotency keys as documented in `gatekeeper_v2_2.py`.