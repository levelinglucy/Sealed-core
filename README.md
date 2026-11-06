# Sealed-core

## Development summary

**Stage:** local-only v2.2 recovery integrity **draft candidate** in [PR #8](https://github.com/levelinglucy/Sealed-core/pull/8); **not merged or stable**. Earlier file/directory restore and cooperating Gatekeeper concurrency fixes are integrated into `main`.
**Goal:** prevent an automatic same-key retry from silently repeating a local write whose outcome became uncertain between the core commit, scope binding and idempotency receipt.
**Latest candidate (2026-11-06):** create an encrypted `PENDING` reservation *before* executing signed requests with idempotency keys. If the expected receipt is absent after an interruption, a matching newly signed retry returns `OPERATION_OUTCOME_UNKNOWN` rather than executing again. Preserve pending records during cache pruning. Existing completed receipts remain compatible.
**Evidence:** three synthetic crash-window/pruning tests first failed against the previous baseline ([red CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42242913268)); the initial repair passed 29/29 unit tests plus 9/9 core self-tests on Python 3.11/3.12 ([candidate CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42243006070)). The full draft's two additional **hard process-exit** tests confirmed that a committed ticket is not duplicated after `os._exit`, and that a precommit exit remains conservatively uncertain. [Python 3.11/3.12 CI](https://github.com/levelinglucy/Sealed-core/actions/runs/42252218491) passed 34/34 unit tests and nine core self-tests on each version at `be1e8ae1`. This is not a power-cut test.
**Next:** a read-only owner-secret diagnostic now shows redacted encrypted PENDING markers and newly generated *unlinked* correlation identifiers; the four accompanying synthetic tests are awaiting final CI verification. This cannot establish whether the core committed. Design an atomic core-linked proof and audited recovery before resolving any pending write. Keep this consequential retry-contract change in draft before any stable promotion. Obtain trusted Pythonista/iPhone evidence when available.
**Limits:** `OPERATION_OUTCOME_UNKNOWN` cannot tell whether the core operation committed; there is **no automatic repair or exactly-once guarantee**. A reservation may remain pending even when execution never began. Never blindly change the key and retry an uncertain operation. Completed idempotency receipts still have a bounded retention policy; external direct-core writers bypass Gatekeeper. Directory overwrite is not a crash-atomic exchange. Power-loss, cross-platform locking and target-device behaviour remain unverified.

[Uncertain-outcome recovery notes](./GATEKEEPER_RECOVERY.md) · [Changelog](./CHANGELOG.md) · [Engineering decisions](./DEV_NOTES.md) · [Roadmap](./ROADMAP.md)

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