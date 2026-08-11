#!/usr/bin/env python3
"""
gatekeeper_v2_2.py — local-only authenticated policy layer for SEALED Core v2.2

Design:
- caller supplies principal_id, never a trusted role;
- server-side principal registry binds principal -> role/scope;
- per-principal HMAC signatures over canonical JSON;
- timestamp skew + encrypted nonce registry blocks replay;
- write actions require idempotency keys;
- idempotent retries return the original result;
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
            ordered = sorted(idem.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)[:MAX_IDEMPOTENCY]
            state["idempotency"] = dict(ordered)

    def consume_nonce_and_check_idempotency(
        self,
        principal_id: str,
        nonce: str,
        request_hash: str,
        idempotency_key: Optional[str],
    ) -> Optional[dict]:
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

            self._save_locked(state)
            return copy.deepcopy(prior.get("result")) if prior else None

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
            state["idempotency"][idem_key] = {
                "request_hash": request_hash,
                "created_at": _format_utc(_utc_now()),
                "result": copy.deepcopy(result),
            }
            self._save_locked(state)

    def bind_ticket_scope(self, ticket_id: str, scope_id: str) -> None:
        with _StoreFileLock(self.lock_path):
            state = self._load_locked()
            state["ticket_scopes"][ticket_id] = scope_id
            self._save_locked(state)

    def ticket_scope(self, ticket_id: str) -> Optional[str]:
        with _StoreFileLock(self.lock_path):
            state = self._load_locked()
            return state["ticket_scopes"].get(ticket_id)

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
        prior = self.state.consume_nonce_and_check_idempotency(
            principal_id,
            nonce,
            request_hash,
            idempotency_key,
        )
        return action, principal, payload, request_hash, idempotency_key, prior

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

    def _execute(self, action: str, principal: dict, payload: dict) -> dict:
        with self._core(principal) as core:
            if action == "NEW_TICKET":
                incoming = {
                    "source": payload.get("source", "external"),
                    "subject": payload.get("subject", ""),
                    "body": payload.get("body", ""),
                    "from_email": payload.get("from_email", "unknown@example.com"),
                    "timestamp": payload.get("timestamp"),
                }
                result = core.handle(incoming)
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
            auth = self._authenticate(request)
            action, principal, payload, request_hash, idempotency_key, prior = auth
            if prior is not None:
                return copy.deepcopy(prior)

            result = {
                "ok": True,
                "action": action,
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
        except Exception:
            # Deliberately avoid reflecting internal details to callers.
            return {"ok": False, "error": "INTERNAL_ERROR"}

    def close(self) -> None:
        self.state.close()


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
