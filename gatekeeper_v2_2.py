#!/usr/bin/env python3
"""
gatekeeper_v2_2.py — local-only authenticated policy layer for SEALED Core v2.2

Design:
- caller supplies principal_id, never a trusted role;
- server-side principal registry binds principal -> role/scope;
- per-principal HMAC signatures over canonical JSON;
- timestamp skew + encrypted nonce registry blocks replay;
- write actions require idempotency keys;
- completed idempotent retries return the original result;
- uncertain keyed writes stay PENDING; authenticated NEW_TICKET retries can
  recover only a matching atomic core receipt (draft PR #8);
  all other missing/unlinked outcomes fail closed;
- external acknowledgers are constrained to their own ticket scope;
- explicit output allowlists; no raw-object passthrough;
- no network listener and no remote I/O.

Secrets:
    SEALED_OWNER_SECRET      required by sealed_core.py
    SEALED_PRINCIPALS_JSON   JSON object mapping principal IDs to config

Example SEALED_PRINCIPALS_JSON:
{
  "owner-local": {
    "role": "OWNER",
    "secret": "replace-with-a-long-random-secret",
    "scope_id": "owner"
  },
  "helper-local": {
    "role": "HELPER",
    "secret": "another-long-random-secret",
    "scope_id": "staff"
  }
}

Request shape:
{
  "principal_id": "owner-local",
  "timestamp": "2026-08-11T11:52:00Z",
  "nonce": "random-unique-string",
  "action": "LIST_OPEN_SUMMARY",
  "payload": {},
  "idempotency_key": null,
  "signature": "hex-hmac-sha256"
}
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from sealed_core import (
    SealedCore,
    _StoreFileLock,
    _atomic_json_write,
    _canonical_json_bytes,
    _decrypt_blob,
    _derive_master_key,
    _derive_subkey,
    _encrypt_blob,
    _format_utc,
    _get_machine_fingerprint,
    _parse_timestamp,
    _utc_now,
)


GATEKEEPER_SCHEMA = "SEALED_GATEKEEPER_STATE_V2_2"
MAX_CLOCK_SKEW_SECONDS = 300
NONCE_RETENTION_SECONDS = 3600
MAX_NONCES = 20_000
MAX_IDEMPOTENCY = 20_000
DEFAULT_STORAGE_DIR = "sealed_storage"

ROLES = {"OWNER", "HELPER", "EXTERNAL_CREATE", "EXTERNAL_ACK"}

POLICY = {
    "NEW_TICKET": {
        "roles": {"OWNER", "EXTERNAL_CREATE"},
        "write": True,
        "view": "receipt",
    },
    "ACK_TICKET": {
        "roles": {"OWNER", "EXTERNAL_ACK"},
        "write": True,
        "view": "redacted",
    },
    "CLOSE_TICKET": {
        "roles": {"OWNER"},
        "write": True,
        "view": "redacted",
    },
    "GET_TICKET_DETAIL": {
        "roles": {"OWNER", "HELPER", "EXTERNAL_ACK"},
        "write": False,
        "view": "role",
    },
    "LIST_OPEN_SUMMARY": {
        "roles": {"OWNER", "HELPER", "EXTERNAL_ACK"},
        "write": False,
        "view": "role",
    },
    "SEAL_FILE": {
        "roles": {"OWNER"},
        "write": True,
        "view": "vault_receipt",
    },
    "SEAL_DIR": {
        "roles": {"OWNER"},
        "write": True,
        "view": "vault_receipt",
    },
    "LIST_VAULT": {
        "roles": {"OWNER", "HELPER"},
        "write": False,
        "view": "role",
    },
    "UNSEAL_FILE": {
        "roles": {"OWNER"},
        "write": True,
        "view": "path_receipt",
    },
    "RESTORE_DIR": {
        "roles": {"OWNER"},
        "write": True,
        "view": "path_receipt",
    },
}


def _load_principal_registry() -> Dict[str, dict]:
    raw = os.environ.get("SEALED_PRINCIPALS_JSON")
    if not raw:
        raise RuntimeError("SEALED_PRINCIPALS_JSON environment variable required")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("SEALED_PRINCIPALS_JSON must be valid JSON") from exc
    if not isinstance(data, dict) or not data:
        raise RuntimeError("principal registry must be a non-empty object")

    normalized: Dict[str, dict] = {}
    for principal_id, cfg in data.items():
        if not isinstance(principal_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", principal_id):
            raise RuntimeError(f"invalid principal_id: {principal_id!r}")
        if not isinstance(cfg, dict):
            raise RuntimeError(f"principal {principal_id!r} config must be an object")
        role = str(cfg.get("role", "")).upper()
        secret = cfg.get("secret")
        scope_id = str(cfg.get("scope_id", principal_id))
        if role not in ROLES:
            raise RuntimeError(f"principal {principal_id!r} has invalid role")
        if not isinstance(secret, str) or len(secret) < 24:
            raise RuntimeError(f"principal {principal_id!r} secret must be at least 24 characters")
        if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", scope_id):
            raise RuntimeError(f"principal {principal_id!r} has invalid scope_id")
        normalized[principal_id] = {
            "role": role,
            "secret": secret,
            "scope_id": scope_id,
        }
    return normalized


def canonical_request_for_signing(request: dict) -> dict:
    return {
        "principal_id": request.get("principal_id"),
        "timestamp": request.get("timestamp"),
        "nonce": request.get("nonce"),
        "action": request.get("action"),
        "payload": request.get("payload", {}),
        "idempotency_key": request.get("idempotency_key"),
    }


def build_signed_request(
    principal_id: str,
    secret: str,
    action: str,
    payload: Optional[dict] = None,
    idempotency_key: Optional[str] = None,
) -> dict:
    request = {
        "principal_id": principal_id,
        "timestamp": _format_utc(_utc_now()),
        "nonce": secrets.token_urlsafe(24),
        "action": action.upper(),
        "payload": payload or {},
        "idempotency_key": idempotency_key,
    }
    request["signature"] = sign_request(request, secret)
    return request


def sign_request(request: dict, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        _canonical_json_bytes(canonical_request_for_signing(request)),
        hashlib.sha256,
    ).hexdigest()


class GatekeeperState:
    def __init__(self, owner_secret: str, storage_dir: str = DEFAULT_STORAGE_DIR):
        machine_fp = _get_machine_fingerprint()
        master = _derive_master_key(owner_secret, machine_fp)
        try:
            self.key = bytearray(_derive_subkey(master, "SEALED_GATEKEEPER_V2_2"))
        finally:
            for i in range(len(master)):
                master[i] = 0

        self.dir = Path(storage_dir).expanduser().resolve()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "gatekeeper_state.json"
        self.lock_path = self.dir / ".gatekeeper.lock"
        # Separate from the state mutex: one cooperating operation must finish
        # and record its result before a same-key retry can authenticate.
        self.request_lock_path = self.dir / ".gatekeeper-request.lock"

    @staticmethod
    def _new_state() -> dict:
        return {
            "schema": GATEKEEPER_SCHEMA,
            "updated_at": _format_utc(_utc_now()),
            "nonces": {},
            "idempotency": {},
            "ticket_scopes": {},
        }

    def _load_locked(self) -> dict:
        if not self.path.exists():
            return self._new_state()
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "enc" not in raw:
            raise ValueError("invalid gatekeeper state envelope")
        state = _decrypt_blob(self.key, raw["enc"])
        if not isinstance(state, dict) or state.get("schema") != GATEKEEPER_SCHEMA:
            raise ValueError("invalid gatekeeper state")
        state.setdefault("nonces", {})
        state.setdefault("idempotency", {})
        state.setdefault("ticket_scopes", {})
        return state

    def _save_locked(self, state: dict) -> None:
        state["schema"] = GATEKEEPER_SCHEMA
        state["updated_at"] = _format_utc(_utc_now())
        _atomic_json_write(self.path, {
            "schema": GATEKEEPER_SCHEMA,
            "enc": _encrypt_blob(self.key, state),
        })

    def _prune(self, state: dict) -> None:
        cutoff = _utc_now() - timedelta(seconds=NONCE_RETENTION_SECONDS)
        fresh = {}
        for key, ts in state.get("nonces", {}).items():
            try:
                if _parse_timestamp(ts) >= cutoff:
                    fresh[key] = ts
            except Exception:
                continue
        if len(fresh) > MAX_NONCES:
            ordered = sorted(fresh.items(), key=lambda kv: kv[1], reverse=True)[:MAX_NONCES]
            fresh = dict(ordered)
        state["nonces"] = fresh

        idem = state.get("idempotency", {})
        if len(idem) > MAX_IDEMPOTENCY:
            # Pending records mean a mutation might already have committed.
            # Never evict them for an older timestamp: the next retry must
            # fail closed rather than silently executing the operation again.
            pending = {key: item for key, item in idem.items() if "result" not in item}
            completed = sorted(
                ((key, item) for key, item in idem.items() if "result" in item),
                key=lambda kv: kv[1].get("created_at", ""), reverse=True,
            )
            remaining = max(0, MAX_IDEMPOTENCY - len(pending))
            state["idempotency"] = {**pending, **dict(completed[:remaining])}

    def consume_nonce_and_check_idempotency(
        self,
        principal_id: str,
        nonce: str,
        request_hash: str,
        idempotency_key: Optional[str],
        *,
        allow_ticket_recovery: bool = False,
    ) -> tuple[Optional[dict], Optional[str], bool]:
        nonce_key = f"{principal_id}:{nonce}"
        idem_key = f"{principal_id}:{idempotency_key}" if idempotency_key else None

        with _StoreFileLock(self.lock_path):
            state = self._load_locked()
            self._prune(state)

            if nonce_key in state["nonces"]:
                raise ValueError("REPLAYED_NONCE")
            state["nonces"][nonce_key] = _format_utc(_utc_now())

            prior = None
            if idem_key:
                prior = state["idempotency"].get(idem_key)
                if prior and prior.get("request_hash") != request_hash:
                    raise ValueError("IDEMPOTENCY_KEY_REUSED_FOR_DIFFERENT_REQUEST")

            if idem_key and prior is None:
                # Persist the reservation in the same encrypted write as the
                # nonce, *before* any action can mutate the independent core.
                # If the process dies later, a fresh signed retry cannot
                # mistake the missing receipt for permission to execute again.
                pending_count = sum(
                    "result" not in item
                    for item in state["idempotency"].values()
                )
                if pending_count >= MAX_IDEMPOTENCY:
                    raise ValueError("IDEMPOTENCY_CAPACITY_REACHED")
                state["idempotency"][idem_key] = {
                    "request_hash": request_hash,
                    "created_at": _format_utc(_utc_now()),
                    "status": "PENDING",
                    # Generated only after HMAC, role, nonce and business
                    # identity checks. Linked to the core on NEW_TICKET.
                    "operation_id": secrets.token_hex(16),
                }
                self._prune(state)

            self._save_locked(state)
            was_pending = prior is not None and "result" not in prior
            if was_pending and not allow_ticket_recovery:
                # Filesystem and non-ticket actions remain uncertain.
                raise ValueError("OPERATION_OUTCOME_UNKNOWN")
            reservation = state["idempotency"].get(idem_key) if idem_key else None
            operation_id = reservation.get("operation_id") if reservation else None
            return (
                copy.deepcopy(prior.get("result")) if prior and "result" in prior else None,
                operation_id,
                was_pending,
            )

    def record_idempotent_result(
        self,
        principal_id: str,
        idempotency_key: str,
        request_hash: str,
        result: dict,
    ) -> None:
        idem_key = f"{principal_id}:{idempotency_key}"
        with _StoreFileLock(self.lock_path):
            state = self._load_locked()
            previous = state["idempotency"].get(idem_key)
            if not isinstance(previous, dict) or previous.get("request_hash") != request_hash:
                raise ValueError("IDEMPOTENCY_RESERVATION_MISMATCH")
            state["idempotency"][idem_key] = {
                "request_hash": request_hash,
                "created_at": _format_utc(_utc_now()),
                "status": "COMMITTED",
                "result": copy.deepcopy(result),
                # Keep the correlation ID for future audit. Older completed
                # receipts without an ID remain readable.
                **({"operation_id": previous["operation_id"]}
                   if "operation_id" in previous else {}),
            }
            self._save_locked(state)

    def bind_ticket_scope(self, ticket_id: str, scope_id: str) -> None:
        with _StoreFileLock(self.lock_path):
            state = self._load_locked()
            existing = state["ticket_scopes"].get(ticket_id)
            if existing is not None and existing != scope_id:
                raise ValueError("SCOPE_BINDING_CONFLICT")
            if existing == scope_id:
                return
            state["ticket_scopes"][ticket_id] = scope_id
            self._save_locked(state)

    def ticket_scope(self, ticket_id: str) -> Optional[str]:
        with _StoreFileLock(self.lock_path):
            state = self._load_locked()
            return state["ticket_scopes"].get(ticket_id)

    def list_pending_local(self) -> list[dict]:
        """Read-only owner-local diagnostics; never clear uncertain writes.

        The stored composite key cannot be parsed reliably: both principal IDs
        and business keys may include ':'. Fingerprint it instead of exposing
        the original business key, principal, nonce, or payload.
        """
        with _StoreFileLock(self.lock_path):
            state = self._load_locked()
            pending = []
            for key_ref, item in state["idempotency"].items():
                if not isinstance(item, dict) or "result" in item:
                    continue
                pending.append({
                    "key_ref_sha256": hashlib.sha256(
                        key_ref.encode("utf-8")
                    ).hexdigest(),
                    "operation_id": item.get("operation_id"),
                    "request_hash": item.get("request_hash"),
                    "created_at": item.get("created_at"),
                    "status": "PENDING",
                })
            return sorted(
                pending,
                key=lambda item: (item["created_at"] or "",
                                  item["key_ref_sha256"]),
            )

    def close(self) -> None:
        for i in range(len(self.key)):
            self.key[i] = 0


class GatekeeperV22:
    def __init__(self, storage_dir: str = DEFAULT_STORAGE_DIR):
        self.owner_secret = os.environ.get("SEALED_OWNER_SECRET")
        if not self.owner_secret:
            raise RuntimeError("SEALED_OWNER_SECRET environment variable required")
        self.registry = _load_principal_registry()
        self.storage_dir = storage_dir
        self.state = GatekeeperState(self.owner_secret, storage_dir=storage_dir)

    @staticmethod
    def _business_hash(request: dict) -> str:
        # Nonce/timestamp are transport freshness, not business identity.
        operation = {
            "principal_id": request.get("principal_id"),
            "action": request.get("action"),
            "payload": request.get("payload", {}),
            "idempotency_key": request.get("idempotency_key"),
        }
        return hashlib.sha256(_canonical_json_bytes(operation)).hexdigest()

    @staticmethod
    def _validate_nonce(nonce: Any) -> str:
        if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]{16,256}", nonce):
            raise ValueError("INVALID_NONCE")
        return nonce

    @staticmethod
    def _validate_idempotency_key(value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]{8,256}", value):
            raise ValueError("INVALID_IDEMPOTENCY_KEY")
        return value

    def _authenticate(self, request: dict) -> tuple[str, dict, dict, str, Optional[str], Optional[dict]]:
        if not isinstance(request, dict):
            raise ValueError("INVALID_REQUEST")

        principal_id = request.get("principal_id")
        if not isinstance(principal_id, str) or principal_id not in self.registry:
            raise ValueError("UNAUTHORIZED")
        principal = self.registry[principal_id]

        timestamp = request.get("timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("INVALID_TIMESTAMP")
        request_time = _parse_timestamp(timestamp)
        if abs((_utc_now() - request_time).total_seconds()) > MAX_CLOCK_SKEW_SECONDS:
            raise ValueError("STALE_REQUEST")

        nonce = self._validate_nonce(request.get("nonce"))
        action = str(request.get("action", "")).upper()
        rule = POLICY.get(action)
        if not rule:
            raise ValueError("UNKNOWN_ACTION")
        if principal["role"] not in rule["roles"]:
            raise ValueError("ROLE_NOT_ALLOWED")

        payload = request.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("INVALID_PAYLOAD")

        signature = request.get("signature")
        if not isinstance(signature, str):
            raise ValueError("UNAUTHORIZED")
        expected = sign_request(request, principal["secret"])
        if not hmac.compare_digest(expected, signature):
            raise ValueError("UNAUTHORIZED")

        idempotency_key = self._validate_idempotency_key(request.get("idempotency_key"))
        if rule["write"] and not idempotency_key:
            raise ValueError("IDEMPOTENCY_KEY_REQUIRED")

        request_hash = self._business_hash(request)
        prior, operation_id, existing_pending = self.state.consume_nonce_and_check_idempotency(
            principal_id,
            nonce,
            request_hash,
            idempotency_key,
            allow_ticket_recovery=(action == "NEW_TICKET"),
        )
        return (action, principal, payload, request_hash, idempotency_key,
                prior, operation_id, existing_pending)

    def _core(self, principal: dict) -> SealedCore:
        mode = "OWNER" if principal["role"] == "OWNER" else "HELPER"
        return SealedCore(self.owner_secret, mode=mode, storage_dir=self.storage_dir)

    @staticmethod
    def _receipt(data: dict) -> dict:
        allowed = {"ticket_id", "route", "owner", "sla_deadline", "status"}
        return {key: copy.deepcopy(value) for key, value in data.items() if key in allowed}

    @staticmethod
    def _vault_receipt(data: dict) -> dict:
        allowed = {"object_id", "kind", "created_at", "size_bytes", "chunk_count", "sha256"}
        return {key: copy.deepcopy(value) for key, value in data.items() if key in allowed}

    @staticmethod
    def _path_receipt(path: str) -> dict:
        return {"restored_to": path}

    def _scope_check(self, principal: dict, ticket_id: str) -> None:
        if principal["role"] != "EXTERNAL_ACK":
            return
        scope = self.state.ticket_scope(ticket_id)
        if scope is None or scope != principal["scope_id"]:
            raise ValueError("SCOPE_NOT_ALLOWED")

    def _execute(self, action: str, principal: dict, payload: dict,
                 operation_id: Optional[str] = None,
                 request_hash: Optional[str] = None) -> dict:
        with self._core(principal) as core:
            if action == "NEW_TICKET":
                incoming = {
                    "source": payload.get("source", "external"),
                    "subject": payload.get("subject", ""),
                    "body": payload.get("body", ""),
                    "from_email": payload.get("from_email", "unknown@example.com"),
                    "timestamp": payload.get("timestamp"),
                }
                # Only the authenticated NEW_TICKET path supplies identity
                # from the already-persisted encrypted PENDING reservation.
                # Ticket and core receipt commit in the same generation.
                if operation_id is None or request_hash is None:
                    raise ValueError("MISSING_GATEKEEPER_OPERATION")
                result = core.handle_with_gatekeeper_operation(
                    incoming, operation_id=operation_id,
                    request_hash=request_hash, scope_id=principal["scope_id"],
                )
                self.state.bind_ticket_scope(result["ticket_id"], principal["scope_id"])
                return self._receipt(result)

            if action == "ACK_TICKET":
                ticket_id = str(payload.get("ticket_id", ""))
                self._scope_check(principal, ticket_id)
                changed = core.acknowledge_ticket(ticket_id)
                detail = core.get_ticket_detail(ticket_id)
                return {"changed": changed, "ticket": detail}

            if action == "CLOSE_TICKET":
                ticket_id = str(payload.get("ticket_id", ""))
                changed = core.close_ticket(ticket_id)
                detail = core.get_ticket_detail(ticket_id)
                return {"changed": changed, "ticket": detail}

            if action == "GET_TICKET_DETAIL":
                ticket_id = str(payload.get("ticket_id", ""))
                self._scope_check(principal, ticket_id)
                return {"ticket": core.get_ticket_detail(ticket_id)}

            if action == "LIST_OPEN_SUMMARY":
                items = core.list_open_summary()
                if principal["role"] == "EXTERNAL_ACK":
                    items = [
                        item for item in items
                        if self.state.ticket_scope(item.get("ticket_id", "")) == principal["scope_id"]
                    ]
                return {"open": items, "time": core.debug_snapshot()["timestamp"]}

            if action == "SEAL_FILE":
                result = core.seal_file(
                    payload.get("path", ""),
                    label=payload.get("label"),
                    metadata=payload.get("metadata"),
                )
                return self._vault_receipt(result)

            if action == "SEAL_DIR":
                result = core.seal_directory(
                    payload.get("path", ""),
                    label=payload.get("label"),
                    metadata=payload.get("metadata"),
                )
                return self._vault_receipt(result)

            if action == "LIST_VAULT":
                return {"items": core.list_vault_summary()}

            if action == "UNSEAL_FILE":
                restored = core.unseal_file(
                    str(payload.get("object_id", "")),
                    output_path=payload.get("out"),
                    overwrite=bool(payload.get("overwrite", False)),
                )
                return self._path_receipt(restored)

            if action == "RESTORE_DIR":
                restored = core.restore_directory(
                    str(payload.get("object_id", "")),
                    str(payload.get("out", "")),
                    overwrite=bool(payload.get("overwrite", False)),
                )
                return self._path_receipt(restored)

        raise ValueError("NOT_IMPLEMENTED")

    def request(self, request: dict) -> dict:
        try:
            # Nonce consumption alone does not reserve an idempotency key:
            # without this cross-process gate, simultaneous retries can both
            # mutate the core before either one records its result. Keep scoped
            # reads within the same boundary as ticket creation/scope binding.
            # NEW_TICKET now links a core-atomic receipt. Other actions are
            # still not crash-atomic across independent state/output files.
            with _StoreFileLock(self.state.request_lock_path):
                auth = self._authenticate(request)
                (action, principal, payload, request_hash, idempotency_key,
                 prior, operation_id, existing_pending) = auth
                if prior is not None:
                    return copy.deepcopy(prior)

                if action == "NEW_TICKET" and existing_pending:
                    # An authenticated retry may recover *only* exact
                    # core-committed evidence. Missing/old/mismatched receipts
                    # stay PENDING; never use absence to retry a mutation.
                    if not operation_id:
                        raise ValueError("OPERATION_OUTCOME_UNKNOWN")
                    with self._core(principal) as core:
                        try:
                            receipt = core.get_gatekeeper_ticket_receipt(
                                operation_id, request_hash, principal["scope_id"]
                            )
                        except ValueError as exc:
                            if str(exc) == "GATEKEEPER_OPERATION_MISMATCH":
                                raise ValueError("OPERATION_OUTCOME_UNKNOWN") from exc
                            raise
                    if receipt is None:
                        raise ValueError("OPERATION_OUTCOME_UNKNOWN")
                    self.state.bind_ticket_scope(
                        receipt["ticket_id"], principal["scope_id"]
                    )
                    result = {
                        "ok": True, "action": "NEW_TICKET",
                        "data": self._receipt(receipt),
                    }
                elif action == "NEW_TICKET":
                    result = {
                        "ok": True, "action": action,
                        "data": self._execute(
                            action, principal, payload, operation_id, request_hash
                        ),
                    }
                else:
                    result = {
                        "ok": True, "action": action,
                        "data": self._execute(action, principal, payload),
                    }
                if idempotency_key:
                    self.state.record_idempotent_result(
                        request["principal_id"],
                        idempotency_key,
                        request_hash,
                        result,
                    )
                return result
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        except NotImplementedError:
            return {"ok": False, "error": "NOT_IMPLEMENTED"}
        except PermissionError:
            return {"ok": False, "error": "FORBIDDEN"}
        except FileNotFoundError:
            return {"ok": False, "error": "NOT_FOUND"}
        except FileExistsError:
            return {"ok": False, "error": "ALREADY_EXISTS"}
        except Exception:
            # Deliberately avoid reflecting internal details to callers.
            return {"ok": False, "error": "INTERNAL_ERROR"}

    def close(self) -> None:
        self.state.close()


def inspect_pending_local(storage_dir: str = DEFAULT_STORAGE_DIR) -> list[dict]:
    """Read-only owner-secret recovery view, NOT a signed or network action.

    A pending correlation ID is not evidence that the core committed. Never
    auto-clear an uncertain reservation based on this diagnostic.
    """
    owner_secret = os.environ.get("SEALED_OWNER_SECRET")
    if not owner_secret:
        raise RuntimeError("SEALED_OWNER_SECRET environment variable required")
    state = GatekeeperState(owner_secret, storage_dir=storage_dir)
    try:
        # Avoid reporting a transient PENDING from an ordinary in-flight
        # cooperating request by acquiring the same outer operation lock.
        with _StoreFileLock(state.request_lock_path):
            return state.list_pending_local()
    finally:
        state.close()



def inspect_pending_evidence_local(storage_dir: str = DEFAULT_STORAGE_DIR) -> list[dict]:
    """Owner-local, read-only triage of PENDING against one encrypted core snapshot.

    This does not authenticate a fresh business request or verify the current
    principal registry scope. Even a matching atomic receipt is *not* authority
    to clear a marker, grant ticket access, or retry an uncertain write.
    No signing key, original principal, business key, scope or ticket is output.
    """
    owner_secret = os.environ.get("SEALED_OWNER_SECRET")
    if not owner_secret:
        raise RuntimeError("SEALED_OWNER_SECRET environment variable required")
    state = GatekeeperState(owner_secret, storage_dir=storage_dir)
    try:
        # Match the ordinary signed request's lock order. Take the core state
        # from one authenticated generation so multiple pending rows are not
        # compared to different core snapshots.
        with _StoreFileLock(state.request_lock_path):
            pending = state.list_pending_local()
            if not pending:
                return []
            with SealedCore(owner_secret, mode="OWNER",
                            storage_dir=storage_dir) as core:
                with _StoreFileLock(core.store.lock_path):
                    snapshot = core.store._load_state_locked()

            operations = snapshot.get("gatekeeper_ticket_operations", {})
            tickets = snapshot.get("tickets", {})
            for item in pending:
                operation_id = item.get("operation_id")
                if operation_id is None:
                    evidence = "LEGACY_UNLINKED_UNKNOWN"
                elif (not isinstance(operation_id, str)
                      or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None):
                    evidence = "INVALID_ID_UNKNOWN"
                else:
                    record = operations.get(operation_id)
                    if record is None:
                        evidence = "NO_CORE_RECEIPT_UNKNOWN"
                    elif (not isinstance(record, dict)
                          or record.get("kind") != "NEW_TICKET"
                          or record.get("request_hash") != item["request_hash"]
                          or not isinstance(record.get("scope_id"), str)
                          or not record["scope_id"]):
                        evidence = "CORE_RECEIPT_CONFLICT"
                    else:
                        receipt = record.get("receipt")
                        ticket_id = (receipt.get("ticket_id")
                                     if isinstance(receipt, dict) else None)
                        ticket = (tickets.get(ticket_id)
                                  if isinstance(ticket_id, str) else None)
                        if (not isinstance(ticket, dict)
                            or ticket.get("ticket_id") != ticket_id
                            or ticket.get("route") != receipt.get("route")):
                            evidence = "CORE_RECEIPT_INCOMPLETE"
                        else:
                            evidence = "CORE_TICKET_RECEIPT_PRESENT"
                item["core_evidence"] = evidence
                item["authorizes_retry_or_clear"] = False
                item["current_scope_verified"] = False
            return pending
    finally:
        state.close()


def gatekeeper_request(request: dict, storage_dir: str = DEFAULT_STORAGE_DIR) -> dict:
    gate = GatekeeperV22(storage_dir=storage_dir)
    try:
        return gate.request(request)
    finally:
        gate.close()


if __name__ == "__main__":
    print(
        "gatekeeper_v2_2.py is a local Python policy function, not a network server.\n"
        "Import gatekeeper_request() or GatekeeperV22 from a local process."
    )
