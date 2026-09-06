#!/usr/bin/env python3
"""
sealed_core.py — SEALED Core v2.1 (complete reconstructed build)

Provenance
----------
Reconstructed from the public levelinglucy/Sealed-core lineage:
- complete V1 implementation: Sealed-core.py
- hardened but abbreviated V2 snapshot: Sealed core V2

This carries forward the V1 routing/private methods and applies the V2 changes
that are explicit in the public snapshot: 600k PBKDF2, V2 salt,
OWNER/HELPER modes, redaction, lifecycle methods, strict validation,
environment-secret support, filesystem permissions, enhanced fingerprinting,
and atomic persistence.

v2.1 hardening added during reconstruction
-------------------------------------------
- one encrypted state generation instead of independently-written tickets,
  metrics, and intents files;
- one transaction + one persist per logical mutation;
- same-directory tempfile + fsync + os.replace + directory fsync;
- advisory cross-process store lock;
- HELPER-specific intent redaction;
- normalized/validated timestamps and bounded input sizes;
- deduplicated near/breached SLA warnings;
- intent IDs and state schema/generation metadata;
- best-effort key/state memory clearing;
- built-in self-test.

No network code is present. Outbound actions are drafts stored as local intents.

Dependency:
    pip install cryptography

Environment (recommended):
    export SEALED_OWNER_SECRET='a long local passphrase'
    export SEALED_HOST_ID='optional-stable-host-id-for-VMs'

Run integrity/lifecycle tests:
    python sealed_core.py --self-test
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
import platform
import re
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


STATE_SCHEMA = "SEALED_STATE_V2_1"
ENVELOPE_SCHEMA = "SEALED_ENVELOPE_V2_1"
PBKDF2_ITERATIONS = 600_000
DEFAULT_STORAGE_DIR = "sealed_storage"

MAX_SUBJECT_CHARS = 500
MAX_BODY_CHARS = 100_000
MAX_EMAIL_CHARS = 320
MAX_SOURCE_CHARS = 80
MAX_TIMESTAMP_CHARS = 80
MAX_METRICS = 50_000
MAX_INTENTS = 50_000


def _safe_chmod(path: os.PathLike | str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except (OSError, AttributeError):
        pass


def _get_machine_fingerprint() -> str:
    parts: List[str] = []

    host = platform.node().strip()
    if host:
        parts.append("host=" + host)

    try:
        parts.append("uuidnode=" + format(uuid.getnode(), "012x"))
    except Exception:
        pass

    net_root = Path("/sys/class/net")
    if net_root.is_dir():
        macs: List[str] = []
        try:
            for iface in sorted(net_root.iterdir(), key=lambda p: p.name):
                try:
                    value = (iface / "address").read_text(encoding="utf-8").strip().lower()
                    if value:
                        macs.append(value)
                except OSError:
                    continue
        except OSError:
            pass
        if macs:
            parts.append("macs=" + ",".join(macs))

    host_id = os.environ.get("SEALED_HOST_ID", "").strip()
    if host_id:
        parts.append("host_id=" + host_id)

    if not parts:
        raise RuntimeError("Unable to derive a stable machine fingerprint")

    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _derive_master_key(owner_passphrase: str, machine_fp: str) -> bytearray:
    if not isinstance(owner_passphrase, str) or not owner_passphrase:
        raise ValueError("owner passphrase is required")
    if len(owner_passphrase) < 12:
        raise ValueError("owner passphrase must be at least 12 characters")

    salt = ("SEALED_CORE_STATIC_SALT_v2__" + machine_fp).encode("utf-8")
    key = hashlib.pbkdf2_hmac(
        "sha256",
        owner_passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return bytearray(key)


def _derive_subkey(master: bytearray | bytes, label: str) -> bytearray:
    if not isinstance(label, str) or not label:
        raise ValueError("label is required")
    return bytearray(hmac.new(bytes(master), label.encode("utf-8"), hashlib.sha256).digest())


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _encrypt_blob(key: bytearray | bytes, data: Any) -> dict:
    aesgcm = AESGCM(bytes(key))
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, _canonical_json_bytes(data), None)
    return {"nonce_hex": nonce.hex(), "cipher_hex": ciphertext.hex()}


def _decrypt_blob(key: bytearray | bytes, enc: dict) -> Any:
    if not isinstance(enc, dict):
        raise ValueError("encrypted envelope must be an object")

    if isinstance(enc.get("nonce_hex"), str) and isinstance(enc.get("cipher_hex"), str):
        nonce = bytes.fromhex(enc["nonce_hex"])
        cipher = bytes.fromhex(enc["cipher_hex"])
    elif isinstance(enc.get("nonce_b64"), str) and isinstance(enc.get("cipher_b64"), str):
        nonce = base64.b64decode(enc["nonce_b64"], validate=True)
        cipher = base64.b64decode(enc["cipher_b64"], validate=True)
    else:
        raise ValueError("encrypted envelope missing nonce/ciphertext")

    aesgcm = AESGCM(bytes(key))
    plaintext = aesgcm.decrypt(nonce, cipher, None)
    return json.loads(plaintext.decode("utf-8"))


def _hmac_sign(key: bytearray | bytes, data: Any) -> str:
    return hmac.new(bytes(key), _canonical_json_bytes(data), hashlib.sha256).hexdigest()


def _hmac_verify(key: bytearray | bytes, data: Any, signature: str) -> bool:
    return isinstance(signature, str) and hmac.compare_digest(_hmac_sign(key, data), signature)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if not text:
        return _utc_now()
    if len(text) > MAX_TIMESTAMP_CHARS:
        raise ValueError("timestamp too long")
    try:
        dt = datetime.fromisoformat(text[:-1] + "+00:00") if text.endswith("Z") else datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class _StoreFileLock:
    """Advisory lock for cooperating SEALED processes."""

    def __init__(self, path: Path):
        self.path = path
        self.handle = None
        self._backend = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "a+b")
        _safe_chmod(self.path, 0o600)

        try:
            import fcntl  # type: ignore
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
            self._backend = "fcntl"
        except ImportError:
            try:
                import msvcrt  # type: ignore
                self.handle.seek(0)
                if self.handle.read(1) == b"":
                    self.handle.write(b"0")
                    self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_LOCK, 1)
                self._backend = "msvcrt"
            except ImportError as exc:
                self.handle.close()
                self.handle = None
                raise RuntimeError("No supported local file-lock backend") from exc
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handle is None:
            return False
        try:
            if self._backend == "fcntl":
                import fcntl  # type: ignore
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            elif self._backend == "msvcrt":
                import msvcrt  # type: ignore
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self.handle.close()
            self.handle = None
        return False


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_json_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _safe_chmod(path.parent, 0o700)
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        _safe_chmod(temp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        _safe_chmod(path, 0o600)
        _fsync_directory(path.parent)
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


class SealedStore:
    """One encrypted logical state generation, with cross-process serialization."""

    def __init__(self, master_key: bytearray, storage_dir: str = DEFAULT_STORAGE_DIR):
        self.key = master_key
        self.dir = Path(storage_dir).expanduser().resolve()
        self.dir.mkdir(parents=True, exist_ok=True)
        _safe_chmod(self.dir, 0o700)
        self.state_path = self.dir / "state.json"
        self.lock_path = self.dir / ".sealed.lock"
        self._state: Dict[str, Any] = self._new_state()
        self._transaction_depth = 0

        with _StoreFileLock(self.lock_path):
            self._state = self._load_state_locked()

    def _new_state(self) -> Dict[str, Any]:
        now = _format_utc(_utc_now())
        return {
            "schema": STATE_SCHEMA,
            "generation": 0,
            "created_at": now,
            "updated_at": now,
            "tickets": {},
            "metrics": [],
            "intents": [],
        }

    def _validate_state(self, state: Any) -> Dict[str, Any]:
        if not isinstance(state, dict):
            raise ValueError("sealed state root must be an object")
        schema = state.get("schema")
        if schema not in (STATE_SCHEMA, None):
            raise ValueError(f"unsupported sealed state schema: {schema!r}")

        tickets = state.get("tickets", {})
        metrics = state.get("metrics", [])
        intents = state.get("intents", [])
        if not isinstance(tickets, dict):
            raise ValueError("state.tickets must be an object")
        if not isinstance(metrics, list):
            raise ValueError("state.metrics must be a list")
        if not isinstance(intents, list):
            raise ValueError("state.intents must be a list")

        normalized = dict(state)
        normalized["schema"] = STATE_SCHEMA
        normalized.setdefault("generation", 0)
        normalized.setdefault("created_at", _format_utc(_utc_now()))
        normalized.setdefault("updated_at", normalized["created_at"])
        normalized["tickets"] = tickets
        normalized["metrics"] = metrics[-MAX_METRICS:]
        normalized["intents"] = intents[-MAX_INTENTS:]
        return normalized

    def _decode_envelope(self, raw: Any) -> Any:
        if not isinstance(raw, dict) or "enc" not in raw or "sig" not in raw:
            raise ValueError("tampered or invalid sealed envelope")
        decrypted = _decrypt_blob(self.key, raw["enc"])
        if not _hmac_verify(self.key, decrypted, raw["sig"]):
            raise ValueError("integrity check failed: data may be tampered")
        return decrypted

    def _read_encrypted_file(self, path: Path) -> Any:
        with path.open("r", encoding="utf-8") as handle:
            return self._decode_envelope(json.load(handle))

    def _load_legacy_v2_files_locked(self) -> Optional[Dict[str, Any]]:
        mapping = {
            "tickets": "tickets.json",
            "metrics": "metrics.json",
            "intents": "intents.json",
        }
        present = {key: (self.dir / fname).exists() for key, fname in mapping.items()}
        if not any(present.values()):
            return None
        if not all(present.values()):
            raise ValueError("incomplete legacy v2 store layout")

        state = self._new_state()
        for key, fname in mapping.items():
            state[key] = self._read_encrypted_file(self.dir / fname)
        state["migrated_from"] = "public-v2-three-file-layout"
        return self._validate_state(state)

    def _load_state_locked(self) -> Dict[str, Any]:
        if self.state_path.exists():
            return self._validate_state(self._read_encrypted_file(self.state_path))
        legacy = self._load_legacy_v2_files_locked()
        return legacy if legacy is not None else self._new_state()

    def _persist_state_locked(self) -> None:
        self._state["schema"] = STATE_SCHEMA
        self._state["generation"] = int(self._state.get("generation", 0)) + 1
        self._state["updated_at"] = _format_utc(_utc_now())
        self._state["metrics"] = self._state.get("metrics", [])[-MAX_METRICS:]
        self._state["intents"] = self._state.get("intents", [])[-MAX_INTENTS:]
        envelope = {
            "schema": ENVELOPE_SCHEMA,
            "enc": _encrypt_blob(self.key, self._state),
            "sig": _hmac_sign(self.key, self._state),
        }
        _atomic_json_write(self.state_path, envelope)

    @contextmanager
    def transaction(self) -> Iterator["SealedStore"]:
        if self._transaction_depth > 0:
            self._transaction_depth += 1
            try:
                yield self
            finally:
                self._transaction_depth -= 1
            return

        with _StoreFileLock(self.lock_path):
            self._state = self._load_state_locked()
            before = copy.deepcopy(self._state)
            self._transaction_depth = 1
            try:
                yield self
                self._persist_state_locked()
            except Exception:
                self._state = before
                raise
            finally:
                self._transaction_depth = 0

    def _refresh_for_read(self) -> None:
        if self._transaction_depth > 0:
            return
        with _StoreFileLock(self.lock_path):
            self._state = self._load_state_locked()

    def _auto_mutation(self, callback) -> None:
        if self._transaction_depth > 0:
            callback()
        else:
            with self.transaction():
                callback()

    @property
    def generation(self) -> int:
        self._refresh_for_read()
        return int(self._state.get("generation", 0))

    def list_open_tickets(self) -> List[dict]:
        self._refresh_for_read()
        return [
            copy.deepcopy(ticket)
            for ticket in self._state["tickets"].values()
            if ticket.get("status") in ("OPEN", "ACKNOWLEDGED")
        ]

    def get_ticket(self, ticket_id: str) -> Optional[dict]:
        self._refresh_for_read()
        ticket = self._state["tickets"].get(ticket_id)
        return copy.deepcopy(ticket) if ticket is not None else None

    def put_ticket(self, ticket: dict) -> None:
        ticket_id = ticket.get("ticket_id")
        if not isinstance(ticket_id, str) or not ticket_id:
            raise ValueError("ticket_id required")

        def mutate():
            self._state["tickets"][ticket_id] = copy.deepcopy(ticket)
        self._auto_mutation(mutate)

    def append_metric(self, metric: dict) -> None:
        def mutate():
            self._state["metrics"].append(copy.deepcopy(metric))
        self._auto_mutation(mutate)

    def append_intent(self, intent: dict) -> None:
        def mutate():
            self._state["intents"].append(copy.deepcopy(intent))
        self._auto_mutation(mutate)

    def list_intents(self) -> List[dict]:
        self._refresh_for_read()
        return copy.deepcopy(self._state["intents"])

    def metrics_count(self) -> int:
        self._refresh_for_read()
        return len(self._state["metrics"])

    def close(self) -> None:
        try:
            self._state.clear()
        finally:
            for i in range(len(self.key)):
                self.key[i] = 0


class SealedCore:
    ROUTES = {
        "INCIDENT": {
            "match_keywords": [
                "down", "outage", "cannot login", "critical", "prod",
                "production", "urgent", "asap", "blocker",
            ],
            "owner_email": "oncall@local.system",
            "target_first_response_minutes": 5,
            "human_label": "Prod Emergency",
            "escalate_dm": "oncall@local.system",
        },
        "SUPPORT": {
            "match_keywords": [
                "help", "support", "bug", "issue", "question",
                "not working", "confused",
            ],
            "owner_email": "support@local.system",
            "target_first_response_minutes": 60,
            "human_label": "Support Request",
            "escalate_dm": None,
        },
        "BILLING": {
            "match_keywords": [
                "invoice", "refund", "charge", "charged", "billing",
                "payment failed", "receipt",
            ],
            "owner_email": "finance@local.system",
            "target_first_response_minutes": 120,
            "human_label": "Billing / Money",
            "escalate_dm": "finance@local.system",
        },
    }

    def __init__(
        self,
        owner_passphrase: Optional[str] = None,
        mode: str = "OWNER",
        storage_dir: str = DEFAULT_STORAGE_DIR,
    ):
        if owner_passphrase is None:
            owner_passphrase = os.environ.get("SEALED_OWNER_SECRET")
        if not owner_passphrase:
            raise RuntimeError(
                "owner passphrase required; pass owner_passphrase=... or set SEALED_OWNER_SECRET"
            )

        self.mode = str(mode).upper()
        if self.mode not in ("OWNER", "HELPER"):
            raise ValueError("mode must be OWNER or HELPER")

        machine_fp = _get_machine_fingerprint()
        self.master_key = _derive_master_key(owner_passphrase, machine_fp)
        self.store = SealedStore(self.master_key, storage_dir=storage_dir)
        self.routes = copy.deepcopy(self.ROUTES)
        self.default_route = "SUPPORT"
        self.sla_warning_minutes_before_deadline = 5

    def handle(self, raw_event: dict) -> dict:
        normalized = self._normalize(raw_event)
        route_name = self._classify(normalized)
        ticket = self._create_ticket_obj(normalized, route_name)

        with self.store.transaction():
            self.store.put_ticket(ticket)
            self.store.append_metric({
                "metric_type": "TICKET_CREATED",
                "ts": self._now_iso(),
                "ticket_id": ticket["ticket_id"],
                "route": ticket["route"],
                "urgency": ticket["urgency"],
            })
            self._queue_local_alert_intent(ticket)
            self._queue_autoreply_intent(ticket)

        return {
            "ticket_id": ticket["ticket_id"],
            "route": ticket["route"],
            "owner": ticket["owner_email"],
            "sla_deadline": ticket["sla_deadline_iso"],
            "status": ticket["status"],
        }

    def acknowledge_ticket(self, ticket_id: str) -> bool:
        ticket_id = self._validate_ticket_id(ticket_id)
        with self.store.transaction():
            ticket = self.store.get_ticket(ticket_id)
            if not ticket or ticket.get("status") == "CLOSED":
                return False
            ticket["status"] = "ACKNOWLEDGED"
            ticket["last_human_touch_iso"] = self._now_iso()
            self.store.put_ticket(ticket)
            self.store.append_metric({
                "metric_type": "TICKET_ACKNOWLEDGED",
                "ts": self._now_iso(),
                "ticket_id": ticket_id,
            })
        return True

    def close_ticket(self, ticket_id: str) -> bool:
        ticket_id = self._validate_ticket_id(ticket_id)
        with self.store.transaction():
            ticket = self.store.get_ticket(ticket_id)
            if not ticket:
                return False
            if ticket.get("status") == "CLOSED":
                return True
            ticket["status"] = "CLOSED"
            ticket["last_human_touch_iso"] = self._now_iso()
            self.store.put_ticket(ticket)
            self.store.append_metric({
                "metric_type": "TICKET_CLOSED",
                "ts": self._now_iso(),
                "ticket_id": ticket_id,
            })
        return True

    def get_ticket_detail(self, ticket_id: str) -> Optional[dict]:
        ticket_id = self._validate_ticket_id(ticket_id)
        ticket = self.store.get_ticket(ticket_id)
        return self._redact_ticket(ticket) if ticket else None

    def list_open_summary(self) -> List[dict]:
        return [self._redact_ticket(ticket) for ticket in self.store.list_open_tickets()]

    # Vault APIs are part of full SEALED Core v2.2 and are intentionally not
    # reconstructed in this v2.1 file.
    def seal_file(
        self,
        path: str,
        *,
        label: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        raise NotImplementedError("Vault APIs require the full SEALED Core v2.2 implementation")

    def seal_directory(
        self,
        path: str,
        *,
        label: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        raise NotImplementedError("Vault APIs require the full SEALED Core v2.2 implementation")

    def list_vault_summary(self) -> List[dict]:
        raise NotImplementedError("Vault APIs require the full SEALED Core v2.2 implementation")

    def unseal_file(
        self,
        object_id: str,
        *,
        output_path: Optional[str] = None,
        overwrite: bool = False,
    ) -> str:
        raise NotImplementedError("Vault APIs require the full SEALED Core v2.2 implementation")

    def restore_directory(self, object_id: str, output_dir: str, *, overwrite: bool = False) -> str:
        raise NotImplementedError("Vault APIs require the full SEALED Core v2.2 implementation")

    def seal_path(
        self,
        path: Path | str,
        *,
        label: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        raise NotImplementedError("Vault APIs require the full SEALED Core v2.2 implementation")

    def debug_snapshot(self) -> dict:
        return self.diagnostic_dump()

    def diagnostic_dump(self) -> dict:
        open_tickets = self.store.list_open_tickets()
        intents = self.store.list_intents()
        return {
            "timestamp": self._now_iso(),
            "schema": STATE_SCHEMA,
            "generation": self.store.generation,
            "mode": self.mode,
            "open_ticket_ids": [t["ticket_id"] for t in open_tickets],
            "open_ticket_count": len(open_tickets),
            "intent_queue_count": len(intents),
            "recent_intents_preview": [self._redact_intent(i) for i in intents[-5:]],
            "metrics_count": self.store.metrics_count(),
        }

    def watchdog_scan(self) -> int:
        warnings_created = 0
        now_dt = _utc_now()
        warn_delta = timedelta(minutes=self.sla_warning_minutes_before_deadline)

        with self.store.transaction():
            for summary in self.store.list_open_tickets():
                ticket = self.store.get_ticket(summary["ticket_id"])
                if not ticket:
                    continue

                sla_dt = _parse_timestamp(ticket["sla_deadline_iso"])
                desired_state: Optional[str] = None
                if now_dt >= sla_dt:
                    desired_state = "BREACHED"
                elif now_dt >= sla_dt - warn_delta:
                    desired_state = "NEAR"

                if not desired_state or ticket.get("sla_warning_state") == desired_state:
                    continue

                ticket["sla_warning_state"] = desired_state
                ticket["sla_warning_last_iso"] = self._now_iso()
                self.store.put_ticket(ticket)
                self.store.append_intent({
                    "intent_id": self._generate_intent_id(),
                    "intent_type": "SLA_WARNING_LOCAL",
                    "warning_state": desired_state,
                    "for_owner": ticket["owner_email"],
                    "ticket_id": ticket["ticket_id"],
                    "created_at": self._now_iso(),
                    "warning_preview": (
                        f"SLA {desired_state} {ticket['ticket_id']}\n"
                        f"Owner: {ticket['owner_email']}\n"
                        f"Subject: {ticket['subject']}\n"
                        f"SLA Deadline: {ticket['sla_deadline_iso']}\n"
                        f"Status: {ticket['status']}"
                    ),
                })
                warnings_created += 1

        return warnings_created

    def close(self) -> None:
        try:
            self.store.close()
        finally:
            self.master_key = bytearray()

    def __enter__(self) -> "SealedCore":
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    @staticmethod
    def _mask_email(email: str) -> str:
        if not isinstance(email, str) or "@" not in email:
            return "[REDACTED]"
        user, domain = email.split("@", 1)
        return f"{user[:2] if user else ''}***@{domain}"

    def _redact_ticket(self, ticket: dict) -> dict:
        if self.mode == "OWNER":
            return copy.deepcopy(ticket)

        allowed = {
            "ticket_id", "route", "owner_email", "status", "received_at_iso",
            "sla_deadline_iso", "target_first_response_minutes", "urgency",
            "last_human_touch_iso", "source", "sla_warning_state", "sla_warning_last_iso",
        }
        redacted = {key: copy.deepcopy(value) for key, value in ticket.items() if key in allowed}
        redacted["sender_email"] = self._mask_email(ticket.get("sender_email", ""))
        redacted["sender_name"] = "[REDACTED]"
        redacted["subject"] = "[REDACTED]"
        return redacted

    def _redact_intent(self, intent: dict) -> dict:
        if self.mode == "OWNER":
            return copy.deepcopy(intent)

        safe_keys = {"intent_id", "intent_type", "created_at", "ticket_id", "for_owner", "warning_state"}
        redacted = {key: copy.deepcopy(value) for key, value in intent.items() if key in safe_keys}
        if "to" in intent:
            redacted["to"] = self._mask_email(intent.get("to", ""))
        if any(key in intent for key in ("message_preview", "body_preview", "warning_preview")):
            redacted["content"] = "[REDACTED]"
        if "subject" in intent:
            redacted["subject"] = "[REDACTED]"
        return redacted

    @staticmethod
    def _bounded_text(value: Any, field: str, limit: int, *, default: str = "") -> str:
        if value is None:
            return default
        if not isinstance(value, str):
            raise ValueError(f"{field} must be a string")
        text = value.strip()
        if len(text) > limit:
            raise ValueError(f"{field} exceeds {limit} characters")
        if "\x00" in text:
            raise ValueError(f"{field} contains NUL")
        return text

    def _normalize(self, raw: dict) -> dict:
        if not isinstance(raw, dict):
            raise ValueError("event must be an object")

        subject = self._bounded_text(raw.get("subject"), "subject", MAX_SUBJECT_CHARS)
        body = self._bounded_text(raw.get("body"), "body", MAX_BODY_CHARS)
        sender = self._bounded_text(raw.get("from_email"), "from_email", MAX_EMAIL_CHARS).lower()
        source = self._bounded_text(raw.get("source"), "source", MAX_SOURCE_CHARS, default="unknown") or "unknown"

        timestamp = raw.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, str):
            raise ValueError("timestamp must be a string")
        received_at_iso = self._normalize_timestamp(timestamp)
        fulltext_lower = (subject + "\n" + body).lower()

        return {
            "subject": subject,
            "body": body,
            "sender_email": sender,
            "sender_name": self._infer_sender_name(sender),
            "received_at_iso": received_at_iso,
            "source": source,
            "urgency": self._infer_urgency(fulltext_lower),
            "fulltext_lower": fulltext_lower,
        }

    def _classify(self, norm: dict) -> str:
        text = norm["fulltext_lower"]
        for route_name, cfg in self.routes.items():
            for keyword in cfg["match_keywords"]:
                if keyword in text:
                    return route_name
        return self.default_route

    def _create_ticket_obj(self, norm: dict, route_name: str) -> dict:
        if route_name not in self.routes:
            raise ValueError("unknown route")
        cfg = self.routes[route_name]
        ticket_id = self._generate_ticket_id(route_name)
        received_at_iso = norm["received_at_iso"]
        sla_deadline_iso = self._compute_sla_deadline_iso(received_at_iso, cfg["target_first_response_minutes"])

        return {
            "ticket_id": ticket_id,
            "route": route_name,
            "owner_email": cfg["owner_email"],
            "status": "OPEN",
            "source": norm["source"],
            "received_at_iso": received_at_iso,
            "sla_deadline_iso": sla_deadline_iso,
            "target_first_response_minutes": cfg["target_first_response_minutes"],
            "subject": norm["subject"],
            "snippet": self._summarize(norm["body"], limit=200),
            "urgency": norm["urgency"],
            "sender_email": norm["sender_email"],
            "sender_name": norm["sender_name"],
            "last_human_touch_iso": None,
            "sla_warning_state": None,
            "sla_warning_last_iso": None,
        }

    def _queue_local_alert_intent(self, ticket: dict) -> None:
        alert_text = (
            f"[{ticket['ticket_id']}] {ticket['route']} {ticket['urgency']}\n"
            f"From: {ticket['sender_email']} ({ticket['sender_name']})\n"
            f"Subject: {ticket['subject']}\n"
            f"Snippet: {ticket['snippet']}\n"
            f"Owner: {ticket['owner_email']}\n"
            f"SLA: {ticket['target_first_response_minutes']}m (deadline {ticket['sla_deadline_iso']})"
        )
        self.store.append_intent({
            "intent_id": self._generate_intent_id(),
            "intent_type": "LOCAL_ALERT_DRAFT",
            "for_owner": ticket["owner_email"],
            "created_at": self._now_iso(),
            "ticket_id": ticket["ticket_id"],
            "message_preview": alert_text,
        })

    def _queue_local_alert_intents(self, ticket: dict) -> None:
        self._queue_local_alert_intent(ticket)

    def _queue_autoreply_intent(self, ticket: dict) -> None:
        reply_body = (
            f"Hi {ticket['sender_name'] or 'there'},\n\n"
            f"Your request has been logged as {ticket['ticket_id']} and assigned to {ticket['owner_email']}.\n"
            f"Our target first response is ~{ticket['target_first_response_minutes']} minutes.\n\n"
            "- automated local system\n"
        )
        self.store.append_intent({
            "intent_id": self._generate_intent_id(),
            "intent_type": "OUTBOUND_EMAIL_DRAFT",
            "to": ticket["sender_email"],
            "subject": f"[{ticket['ticket_id']}] Acknowledged",
            "body_preview": reply_body,
            "created_at": self._now_iso(),
            "ticket_id": ticket["ticket_id"],
        })

    @staticmethod
    def _summarize(text: str, limit: int = 160) -> str:
        return " ".join(text.split())[:limit]

    @staticmethod
    def _validate_ticket_id(ticket_id: Any) -> str:
        if not isinstance(ticket_id, str):
            raise ValueError("ticket_id must be a string")
        value = ticket_id.strip().upper()
        if not re.fullmatch(r"[A-Z]{3}-\d{8}-\d{6}-[A-F0-9]{6}", value):
            raise ValueError("invalid ticket_id format")
        return value

    def _generate_ticket_id(self, route_name: str) -> str:
        timestamp = _utc_now().strftime("%Y%m%d-%H%M%S")
        return f"{route_name[:3].upper()}-{timestamp}-{uuid.uuid4().hex[:6].upper()}"

    @staticmethod
    def _generate_intent_id() -> str:
        return "INT-" + uuid.uuid4().hex.upper()

    def _compute_sla_deadline_iso(self, start_iso: str, minutes: int) -> str:
        return _format_utc(_parse_timestamp(start_iso) + timedelta(minutes=int(minutes)))

    @staticmethod
    def _parse_iso(value: str) -> datetime:
        return _parse_timestamp(value)

    @staticmethod
    def _now_iso() -> str:
        return _format_utc(_utc_now())

    @staticmethod
    def _normalize_timestamp(value: Optional[str]) -> str:
        return _format_utc(_parse_timestamp(value)) if value else _format_utc(_utc_now())

    @staticmethod
    def _infer_sender_name(email_addr: str) -> str:
        local_part = email_addr.split("@", 1)[0] if "@" in email_addr else email_addr
        tokens = local_part.replace(".", " ").replace("_", " ").split()
        tokens = [token.capitalize() for token in tokens if token]
        return " ".join(tokens) if tokens else local_part

    @staticmethod
    def _infer_urgency(text_lower: str) -> str:
        markers = [
            "urgent", "asap", "cannot login", "down", "outage", "critical",
            "prod", "production", "blocker", "right now",
        ]
        return "critical" if any(marker in text_lower for marker in markers) else "normal"


def _run_self_tests() -> int:
    import tempfile as _tempfile

    secret = "self-test-owner-passphrase-32-chars"
    checks: List[tuple[str, bool, str]] = []

    def record(name: str, fn) -> None:
        try:
            fn()
        except Exception as exc:
            checks.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            checks.append((name, True, ""))

    with _tempfile.TemporaryDirectory(prefix="sealed-core-selftest-") as temp_root:
        storage = str(Path(temp_root) / "sealed_storage")
        ticket_holder: Dict[str, str] = {}

        def create_ticket_test():
            core = SealedCore(secret, storage_dir=storage)
            result = core.handle({
                "source": "self-test",
                "subject": "Production outage",
                "body": "Production is down and this is critical.",
                "from_email": "alice@example.com",
                "timestamp": "2026-08-11T10:00:00Z",
            })
            assert result["route"] == "INCIDENT"
            assert result["status"] == "OPEN"
            ticket_holder["id"] = result["ticket_id"]
            diag = core.diagnostic_dump()
            assert diag["open_ticket_count"] == 1
            assert diag["intent_queue_count"] == 2
            assert (Path(storage) / "state.json").is_file()
            core.close()

        record("atomic create + encrypted state", create_ticket_test)

        def persistence_test():
            core = SealedCore(secret, storage_dir=storage)
            detail = core.get_ticket_detail(ticket_holder["id"])
            assert detail is not None and detail["sender_email"] == "alice@example.com"
            assert core.acknowledge_ticket(ticket_holder["id"]) is True
            core.close()

            reopened = SealedCore(secret, storage_dir=storage)
            assert reopened.get_ticket_detail(ticket_holder["id"])["status"] == "ACKNOWLEDGED"
            reopened.close()

        record("lifecycle persists across reopen", persistence_test)

        def helper_redaction_test():
            helper = SealedCore(secret, mode="HELPER", storage_dir=storage)
            detail = helper.get_ticket_detail(ticket_holder["id"])
            assert detail is not None
            assert detail["subject"] == "[REDACTED]"
            assert detail["sender_name"] == "[REDACTED]"
            assert detail["sender_email"].endswith("@example.com")
            assert "snippet" not in detail
            for intent in helper.diagnostic_dump()["recent_intents_preview"]:
                assert "message_preview" not in intent
                assert "body_preview" not in intent
            helper.close()

        record("HELPER redaction", helper_redaction_test)

        def rollback_test():
            core = SealedCore(secret, storage_dir=storage)
            before = core.store.metrics_count()
            try:
                with core.store.transaction():
                    core.store.append_metric({"metric_type": "ROLLBACK_TEST"})
                    raise RuntimeError("intentional rollback")
            except RuntimeError:
                pass
            assert core.store.metrics_count() == before
            core.close()

        record("transaction rollback", rollback_test)

        def close_test():
            core = SealedCore(secret, storage_dir=storage)
            assert core.close_ticket(ticket_holder["id"]) is True
            assert core.get_ticket_detail(ticket_holder["id"])["status"] == "CLOSED"
            assert core.list_open_summary() == []
            core.close()

        record("close lifecycle", close_test)

        def tamper_test():
            tamper_storage = str(Path(temp_root) / "tamper_store")
            core = SealedCore(secret, storage_dir=tamper_storage)
            core.handle({"subject": "help", "body": "test", "from_email": "test@example.com"})
            core.close()

            state_path = Path(tamper_storage) / "state.json"
            raw = json.loads(state_path.read_text(encoding="utf-8"))
            cipher = raw["enc"]["cipher_hex"]
            raw["enc"]["cipher_hex"] = cipher[:-1] + ("0" if cipher[-1] != "0" else "1")
            state_path.write_text(json.dumps(raw), encoding="utf-8")

            failed_closed = False
            try:
                SealedCore(secret, storage_dir=tamper_storage)
            except (InvalidTag, ValueError):
                failed_closed = True
            assert failed_closed

        record("tamper detection fails closed", tamper_test)

    print("SEALED Core v2.1 self-test")
    print("=" * 30)
    passed = 0
    for name, ok, detail in checks:
        if ok:
            passed += 1
            print(f"PASS  {name}")
        else:
            print(f"FAIL  {name}: {detail}")
    print(f"\n{passed}/{len(checks)} passed")
    return 0 if passed == len(checks) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="SEALED Core v2.1 local-only core")
    parser.add_argument("--self-test", action="store_true", help="run isolated lifecycle/integrity tests")
    parser.add_argument("--diagnostic", action="store_true", help="print local diagnostic snapshot")
    parser.add_argument("--watchdog", action="store_true", help="run one local SLA watchdog scan")
    parser.add_argument("--storage-dir", default=DEFAULT_STORAGE_DIR)
    args = parser.parse_args()

    if args.self_test:
        return _run_self_tests()
    if not (args.diagnostic or args.watchdog):
        parser.print_help()
        return 0

    with SealedCore(storage_dir=args.storage_dir) as core:
        if args.watchdog:
            print(json.dumps({"warnings_created": core.watchdog_scan()}, indent=2))
        if args.diagnostic:
            print(json.dumps(core.diagnostic_dump(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
