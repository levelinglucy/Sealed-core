# Sealed-core

## Development summary

**Stage:** local-only Sealed-core v2.2 integrity improvements **integrated candidates**, not a tagged or released stable version. [Directory-restore PR #4](https://github.com/levelinglucy/Sealed-core/pull/4) is merged; Gatekeeper concurrent idempotency work is in [PR #6](https://github.com/levelinglucy/Sealed-core/pull/6).
**Goal:** preserve encrypted data on restore failure and prevent one signed, idempotent write from executing twice during concurrent local retries.
**Latest change (2026-11-06):** Gatekeeper now holds a separate cooperating-process request lock from signed authentication through its side effect and encrypted idempotency result record. Synthetic regression first reproduced the duplicate execution on the old code ([red CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234112137)); the repaired candidate and an additional external-acknowledger scope test passed [CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42234410661).
**Validation:** 26/26 Python unit tests and the nine core self-tests passed on each of Python 3.11 and 3.12 for the candidate PR revision. Previous file and directory recovery checks remain included. GitHub merge/main verification is separate from candidate CI.
**Next priorities:** (1) verify PR merge and merged-main CI before integration is considered complete; (2) investigate crash-window recovery of write versus receipt/scope binding; (3) obtain trusted Pythonista/iPhone evidence when available.
**Limitations:** cooperating calls serialize even for reads, so throughput may decrease; interruption after the core commits but before receipt/scope persistence can still leave an uncertain write and permit another effect on retry. Local file-locking does not protect against uncooperative direct-core writers or platform-specific lock differences. Directory overwrite is not a crash-atomic exchange; a hard crash can strand `.NAME.sealed-backup-*` and private plaintext staging. No network service added; mobile and power-loss behavior remain unverified.

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