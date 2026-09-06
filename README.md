# Sealed-core

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