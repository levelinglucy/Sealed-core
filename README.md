# Sealed-core

## Development summary

**Status:** local-only modular stack; file-restore integrity repair under review on `noe/portfolio-restore-integrity` (no stable release/tag claimed).  
**Latest change (2026-11-06):** stage decrypted vault files beside the target, verify every AES-GCM chunk and the whole-object SHA-256, then publish by atomic replacement or exclusive hard link. A corrupt/missing chunk no longer truncates an existing file when `overwrite=True`.  
**Next steps:** (1) validate the exact PR and merged revision via Python CI; (2) fix directory restore's destructive pre-extraction overwrite in a separate bounded change; (3) review gatekeeper nonce/idempotency and scope transaction boundaries.  
**Known limitations:** ordinary file restore writes temporary plaintext with owner-only filesystem permissions; a hard process crash can leave a staging file that should be removed securely. File restoration uses same-directory atomic publication, but this is not proof of full power-loss durability on every filesystem. Directory overwrite is **not yet safe** when extraction fails; avoid `restore_directory(..., overwrite=True)` with valuable existing contents until its repair is validated.  
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