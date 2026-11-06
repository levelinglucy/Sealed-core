# Sealed-core

## Development summary

**Stage:** local-only Gatekeeper v2.2 **draft recovery candidate** on [PR #8](https://github.com/levelinglucy/Sealed-core/pull/8); not merged, tagged, released, or verified on Pythonista. Earlier restore and concurrent-key repairs remain on `main`.

**Latest (2026-11-06):** Authenticated, role-authorized, signed `NEW_TICKET` requests now use their encrypted PENDING operation ID and verified business request hash in the core's **same encrypted ticket/metric/intent/receipt transaction**. A freshly signed same-key retry can recover the exact committed ticket receipt, rebuild its matching external scope binding, and save the Gatekeeper result without making another ticket. Scope/hash/ID mismatch, missing core evidence, precommit failure and older unlinked PENDING entries remain `OPERATION_OUTCOME_UNKNOWN`. Other write types remain conservatively blocked if their receipt is missing.

**Validation:** [code-and-tests CI 42280404380](https://github.com/levelinglucy/Sealed-core/actions/runs/42280404380) passed **48/48 Python unit tests plus 9/9 core self-tests on each Python 3.11 and 3.12**. Tests include real child `os._exit` after core commit versus before it, redacted local inspection, signed payload/role/scope checks, non-rebinding of another scope, legacy pending and tampered operation IDs. Synthetic secrets/stores only.

**Why this matters:** a failed Gatekeeper receipt write no longer forces a known committed ticket to remain indefinitely unresolved; the independently stored core record supplies precise commit evidence. Missing evidence does **not** authorize a replay, and the system is not generally exactly-once or crash-atomic.

**Next:** design an auditable owner-local process for unlinked/legacy reservations and non-ticket filesystem side effects; evaluate safe downgrade and recoverable backups. Test power-loss/device durability before stable promotion. Source rollback alone can resurrect duplicate writes; do not downgrade a store with pending/linked operations.

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