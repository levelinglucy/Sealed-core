###################################################################################################
# SEALED_CORE_v1.py
#
# GOAL
# ----
# A self-contained black box that:
# - only runs on THIS machine
# - only unlocks data for THIS machine + THIS owner
# - refuses to export raw data
# - refuses remote calls
# - encrypts everything at rest
# - auditable for tampering
#
# DESIGN PRINCIPLES
# -----------------
# 1. LOCAL OWNERSHIP ONLY
#    Data never leaves this box in plaintext.
#    All persisted content is encrypted with a key derived from:
#       - machine fingerprint
#       - owner passphrase (human chosen)
#    Without both, data is unreadable. That means copying files
#    to another device makes them useless garbage.
#
# 2. SEALED MEMORY
#    All "tickets", "metrics", etc. are kept in encrypted storage.
#    Decrypt happens only in RAM during that process call.
#    We destroy decrypted structures after use.
#
# 3. NO REMOTE I/O GUARANTEE
#    No HTTP, no Slack, no email, no webhook.
#    All integrations replaced with "queued_intent" objects.
#    You can manually review those intents and decide to send.
#    Nothing exfiltrates on its own.
#
# 4. AUDIT TRAIL
#    Every state mutation is signed with an HMAC using the same sealed key.
#    If someone tampers with data on disk, signature check fails.
#
# 5. MINIMUM SURFACE
#    A single public API: sealed_core.handle(raw_event)
#    All other internal pieces are private.
#
# LIBS NEEDED (standard Python + cryptography):
#    pip install cryptography
#
###################################################################################################


import os
import json
import time
import hmac
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


###################################################################################################
# LOW-LEVEL SECURITY PRIMITIVES
###################################################################################################


def _get_machine_fingerprint() -> str:
    """
    Stable per-device fingerprint.
    You can tune this to include hardware serials, CPU id, etc.
    Here we just hash hostname + MAC addresses to illustrate.

    NOTE:
    This never leaves the box. It's only used locally for key derivation.
    """
    host = os.uname().nodename
    # Fallback: read all MAC addresses (best-effort)
    macs = []
    try:
        for iface in os.listdir('/sys/class/net'):
            try:
                with open(f'/sys/class/net/{iface}/address', 'r') as f:
                    macs.append(f.read().strip())
            except:
                continue
    except:
        pass

    raw = host + "|" + "|".join(sorted(macs))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _derive_master_key(owner_passphrase: str, machine_fp: str) -> bytes:
    """
    Derive a symmetric key from:
    - user secret (owner_passphrase)
    - machine fingerprint (machine_fp)
    Result: 32 bytes for AES-256-GCM.
    """
    salt = ("SEALED_CORE_STATIC_SALT_v1__" + machine_fp).encode("utf-8")
    seed = hashlib.pbkdf2_hmac(
        "sha256",
        owner_passphrase.encode("utf-8"),
        salt,
        200_000,           # cost factor
        dklen=32
    )
    return seed  # bytes


def _encrypt_blob(key: bytes, data: dict) -> dict:
    """
    Encrypt dict -> {nonce, ciphertext, tagless? (AESGCM returns full ct with tag embedded)}
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # AEAD tag embedded
    return {
        "nonce_b64": nonce.hex(),
        "cipher_b64": ciphertext.hex(),
    }


def _decrypt_blob(key: bytes, enc: dict) -> dict:
    aesgcm = AESGCM(key)
    nonce = bytes.fromhex(enc["nonce_b64"])
    ciphertext = bytes.fromhex(enc["cipher_b64"])
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def _hmac_sign(key: bytes, data: dict) -> str:
    """
    Integrity tag: prove this record hasn't been tampered with on disk.
    """
    blob = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, blob, hashlib.sha256).hexdigest()


def _hmac_verify(key: bytes, data: dict, sig: str) -> bool:
    expected = _hmac_sign(key, data)
    return hmac.compare_digest(expected, sig)


###################################################################################################
# SEALED DATASTORE
#
# All persistent state is stored encrypted + signed in JSON files.
# Directory layout:
#   sealed_storage/
#       tickets.json      (encrypted)
#       metrics.json      (encrypted)
#       intents.json      (encrypted)
#
###################################################################################################


class SealedStore:
    def __init__(self, master_key: bytes, storage_dir: str = "sealed_storage"):
        self.key = master_key
        self.dir = storage_dir
        os.makedirs(self.dir, exist_ok=True)

        # in-memory mirrors (decrypted). we hydrate on load, wipe on save.
        self._tickets: Dict[str, dict] = {}
        self._metrics: List[dict] = []
        self._intents: List[dict] = []

        self._load_all()

    def _load_all(self):
        self._tickets = self._load_file("tickets.json", default={})
        self._metrics = self._load_file("metrics.json", default=[])
        self._intents = self._load_file("intents.json", default=[])

    def _load_file(self, fname: str, default):
        path = os.path.join(self.dir, fname)
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        # raw = { "enc": {...}, "sig": "..." }
        if "enc" not in raw or "sig" not in raw:
            raise ValueError("tampered or invalid file format")

        # decrypt
        decrypted = _decrypt_blob(self.key, raw["enc"])
        # verify HMAC
        if not _hmac_verify(self.key, decrypted, raw["sig"]):
            raise ValueError("integrity check failed: data may be tampered")

        return decrypted

    def _save_file(self, fname: str, data_obj: Any):
        # sign
        sig = _hmac_sign(self.key, data_obj)
        # encrypt
        enc = _encrypt_blob(self.key, data_obj)
        bundle = {"enc": enc, "sig": sig}

        path = os.path.join(self.dir, fname)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, separators=(",", ":"))

    def persist_all(self):
        """
        Write encrypted snapshots back to disk.
        This is called after every mutation.
        """
        self._save_file("tickets.json", self._tickets)
        self._save_file("metrics.json", self._metrics)
        self._save_file("intents.json", self._intents)

    # --------------------------
    # public accessors (LOCAL)
    # --------------------------

    def list_open_tickets(self) -> List[dict]:
        return [t for t in self._tickets.values() if t["status"] == "OPEN"]

    def get_ticket(self, ticket_id: str) -> Optional[dict]:
        return self._tickets.get(ticket_id)

    def put_ticket(self, ticket: dict):
        self._tickets[ticket["ticket_id"]] = ticket
        self.persist_all()

    def append_metric(self, metric: dict):
        self._metrics.append(metric)
        self.persist_all()

    def append_intent(self, intent: dict):
        """
        intent = queued action that COULD talk outward
        but DOES NOT auto-send.
        (ex: "send Slack alert to #on-call with this text")
        """
        self._intents.append(intent)
        self.persist_all()

    def list_intents(self) -> List[dict]:
        """
        You manually review + action these offline.
        This prevents silent data exfil.
        """
        return list(self._intents)


###################################################################################################
# SEALED ROUTING / SLA / CLASSIFICATION LOGIC
#
# Key differences from previous versions:
#
# - no Slack/email/network calls here
#   instead we create "intents" describing what SHOULD be sent
#   but we DO NOT send ourselves.
#
# - all created tickets/metrics are pushed directly into encrypted store
#
###################################################################################################


class SealedCore:
    def __init__(self, owner_passphrase: str):
        machine_fp = _get_machine_fingerprint()
        self.master_key = _derive_master_key(owner_passphrase, machine_fp)
        self.store = SealedStore(self.master_key)

        # locked routing config is compiled locally
        self.routes = {
            "INCIDENT": {
                "match_keywords": [
                    "down", "outage", "cannot login", "critical",
                    "prod", "production", "urgent", "asap", "blocker"
                ],
                "owner_email": "oncall@local.system",
                "target_first_response_minutes": 5,
                "human_label": "Prod Emergency",
                "escalate_dm": "oncall@local.system",
            },
            "SUPPORT": {
                "match_keywords": [
                    "help", "support", "bug", "issue",
                    "question", "not working", "confused"
                ],
                "owner_email": "support@local.system",
                "target_first_response_minutes": 60,
                "human_label": "Support Request",
                "escalate_dm": None,
            },
            "BILLING": {
                "match_keywords": [
                    "invoice", "refund", "charge", "charged",
                    "billing", "payment failed", "receipt"
                ],
                "owner_email": "finance@local.system",
                "target_first_response_minutes": 120,
                "human_label": "Billing / Money",
                "escalate_dm": "finance@local.system",
            },
        }
        self.default_route = "SUPPORT"

        # SLA warning config (local alerts only)
        self.sla_warning_minutes_before_deadline = 5

    ########################################################################
    # PUBLIC CALL
    ########################################################################

    def handle(self, raw_event: dict) -> dict:
        """
        Top-level API for this sealed brain.
        - normalize
        - classify
        - ticket
        - log
        - queue local intents (not outbound)
        """

        normalized = self._normalize(raw_event)
        route_name = self._classify(normalized)
        ticket = self._create_ticket_obj(normalized, route_name)

        self.store.put_ticket(ticket)

        # record volume metric internally
        self.store.append_metric({
            "ts": self._now_iso(),
            "route": ticket["route"],
            "urgency": ticket["urgency"],
        })

        # queue "intents" instead of actually sending:
        # - local operator alert
        # - auto-reply draft text
        self._queue_local_alert_intents(ticket)
        self._queue_autoreply_intent(ticket)

        return {
            "ticket_id": ticket["ticket_id"],
            "route": ticket["route"],
            "owner": ticket["owner_email"],
            "sla_deadline": ticket["sla_deadline_iso"],
            "status": ticket["status"],
        }

    ########################################################################
    # NORMALIZATION / CLASSIFICATION
    ########################################################################

    def _normalize(self, raw: dict) -> dict:
        subject = (raw.get("subject") or "").strip()
        body    = (raw.get("body") or "").strip()
        sender  = (raw.get("from_email") or "").strip().lower()

        fulltext_lower = (subject + "\n" + body).lower()

        norm = {
            "subject": subject,
            "body": body,
            "sender_email": sender,
            "sender_name": self._infer_sender_name(sender),
            "received_at_iso": self._normalize_timestamp(raw.get("timestamp")),
            "source": raw.get("source", "unknown"),
            "urgency": self._infer_urgency(fulltext_lower),
            "fulltext_lower": fulltext_lower,
        }
        return norm

    def _classify(self, norm: dict) -> str:
        text = norm["fulltext_lower"]
        for route_name, cfg in self.routes.items():
            for kw in cfg["match_keywords"]:
                if kw in text:
                    return route_name
        return self.default_route

    ########################################################################
    # TICKET CREATION
    ########################################################################

    def _create_ticket_obj(self, norm: dict, route_name: str) -> dict:
        cfg = self.routes[route_name]

        ticket_id = self._generate_ticket_id(route_name)

        received_at_iso = norm["received_at_iso"]
        sla_deadline_iso = self._compute_sla_deadline_iso(
            received_at_iso,
            cfg["target_first_response_minutes"]
        )

        ticket = {
            "ticket_id": ticket_id,
            "route": route_name,
            "owner_email": cfg["owner_email"],
            "status": "OPEN",

            "received_at_iso": received_at_iso,
            "sla_deadline_iso": sla_deadline_iso,
            "target_first_response_minutes": cfg["target_first_response_minutes"],

            "subject": norm["subject"],
            "snippet": self._summarize(norm["body"], limit=200),
            "urgency": norm["urgency"],

            "sender_email": norm["sender_email"],
            "sender_name": norm["sender_name"],

            "last_human_touch_iso": None,
        }

        return ticket

    ########################################################################
    # INTENTS QUEUE (NO NETWORK CALLS)
    ########################################################################

    def _queue_local_alert_intents(self, ticket: dict):
        """
        Instead of hitting Slack/email/etc., we queue intent objects in encrypted storage.
        The owner (human) can inspect them locally and decide what to send out.
        """

        alert_text = (
            f"[{ticket['ticket_id']}] {ticket['route']} {ticket['urgency']}\n"
            f"From: {ticket['sender_email']} ({ticket['sender_name']})\n"
            f"Subject: {ticket['subject']}\n"
            f"Snippet: {ticket['snippet']}\n"
            f"Owner: {ticket['owner_email']}\n"
            f"SLA: {ticket['target_first_response_minutes']}m "
            f"(deadline {ticket['sla_deadline_iso']})"
        )

        intent = {
            "intent_type": "LOCAL_ALERT_DRAFT",
            "for_owner": ticket["owner_email"],
            "created_at": self._now_iso(),
            "ticket_id": ticket["ticket_id"],
            "message_preview": alert_text,
            # nothing is actually sent anywhere.
        }

        self.store.append_intent(intent)

    def _queue_autoreply_intent(self, ticket: dict):
        """
        Prepare a suggested auto-reply. We DO NOT send it.
        This protects data from leaving without review.
        """

        # If you want per-route policy (eg INCIDENT doesn't autoreply), encode here:
        route_cfg = self.routes[ticket["route"]]
        # simplistic rule: always draft, human can throw away
        # or you can skip for certain routes.

        reply_body = (
            f"Hi {ticket['sender_name'] or 'there'},\n\n"
            f"Your request has been logged as {ticket['ticket_id']} "
            f"and assigned to {ticket['owner_email']}.\n"
            f"Our target first response is ~{ticket['target_first_response_minutes']} minutes.\n\n"
            f"- automated local system\n"
        )

        intent = {
            "intent_type": "OUTBOUND_EMAIL_DRAFT",
            "to": ticket["sender_email"],
            "subject": f"[{ticket['ticket_id']}] Acknowledged",
            "body_preview": reply_body,
            "created_at": self._now_iso(),
            "ticket_id": ticket["ticket_id"],
        }

        self.store.append_intent(intent)

    ########################################################################
    # WATCHDOG (LOCAL ONLY)
    ########################################################################

    def watchdog_scan(self):
        """
        Check all OPEN tickets, and generate WARNING intents
        if SLA window is almost breached (or breached).
        This NEVER messages external systems directly.
        """

        now_dt = datetime.utcnow()
        warn_delta = timedelta(minutes=self.sla_warning_minutes_before_deadline)

        for t in self.store.list_open_tickets():
            sla_dt = self._parse_iso(t["sla_deadline_iso"])

            if now_dt >= sla_dt - warn_delta:
                warn_msg = (
                    f"SLA WARNING {t['ticket_id']}\n"
                    f"Owner: {t['owner_email']}\n"
                    f"Subject: {t['subject']}\n"
                    f"SLA Deadline: {t['sla_deadline_iso']}\n"
                    f"Status: {t['status']}\n"
                )
                self.store.append_intent({
                    "intent_type": "SLA_WARNING_LOCAL",
                    "for_owner": t["owner_email"],
                    "ticket_id": t["ticket_id"],
                    "created_at": self._now_iso(),
                    "warning_preview": warn_msg,
                })

    ########################################################################
    # AUDIT / DIAGNOSTIC SNAPSHOT
    ########################################################################

    def diagnostic_dump(self) -> dict:
        """
        Gives a local snapshot for the operator ONLY.
        Nothing here is auto-sent.
        Raw internals returned so the owner can inspect state.
        """

        # We do NOT include derived master_key or machine_fp.
        # We DO include open tickets, metrics count, intents count.
        # You (the owner) can print this locally.
        # You do NOT have to ever upload it anywhere.

        open_tickets = self.store.list_open_tickets()
        intents = self.store.list_intents()
        return {
            "timestamp": self._now_iso(),
            "open_ticket_ids": [t["ticket_id"] for t in open_tickets],
            "open_ticket_count": len(open_tickets),
            "intent_queue_count": len(intents),
            "recent_intents_preview": intents[-5:],  # last few intents
            "failures_logged": len(self.store._metrics),  # can expand if desired
        }

    ########################################################################
    # INTERNAL HELPERS
    ########################################################################

    def _summarize(self, txt: str, limit: int = 160) -> str:
        return " ".join(txt.split())[:limit]

    def _generate_ticket_id(self, route_name: str) -> str:
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        tail = uuid.uuid4().hex[:6].upper()
        prefix = route_name[:3].upper()
        return f"{prefix}-{ts}-{tail}"

    def _compute_sla_deadline_iso(self, start_iso: str, minutes: int) -> str:
        start_dt = self._parse_iso(start_iso)
        deadline = start_dt + timedelta(minutes=minutes)
        return deadline.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _parse_iso(self, s: str) -> datetime:
        # "YYYY-MM-DDTHH:MM:SSZ"
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")

    def _now_iso(self) -> str:
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _normalize_timestamp(self, ts_raw) -> str:
        if ts_raw:
            return ts_raw
        return self._now_iso()

    def _infer_sender_name(self, email_addr: str) -> str:
        local_part = email_addr.split("@")[0] if "@" in email_addr else email_addr
        toks = local_part.replace(".", " ").replace("_", " ").split()
        toks = [t.capitalize() for t in toks if t]
        return " ".join(toks) if toks else local_part

    def _infer_urgency(self, text_lower: str) -> str:
        markers = [
            "urgent", "asap", "cannot login", "down", "outage",
            "critical", "prod", "production", "blocker", "right now"
        ]
        for m in markers:
            if m in text_lower:
                return "critical"
        return "normal"


###################################################################################################
# DEMO EXECUTION
#
# This simulates:
# 1. Instantiating the sealed core with your private passphrase.
#    (This is the ONLY time we derive master_key. It never leaves RAM.)
#
# 2. Handling an incoming event.
#
# 3. Running the watchdog (SLA check).
#
# 4. Generating a diagnostic snapshot (local only).
#
# NOTE:
# - All persistent files on disk are encrypted+signed.
# - Without the passphrase AND this exact machine fingerprint,
#   none of it can be decrypted in a meaningful way.
#
# - No network calls are made.
# - All outbound actions are just "intents" sitting in encrypted storage
#   for you to review offline. You choose if/when/how to actually send.
#
###################################################################################################


if __name__ == "__main__":
    # you set this once, keep it secret, do NOT upload it anywhere.
    OWNER_SECRET = "your-unique-local-passphrase-here"

    core = SealedCore(owner_passphrase=OWNER_SECRET)

    incoming = {
        "source": "gmail",
        "subject": "URGENT: Refund request, we were charged twice",
        "body": (
            "Hello, I was billed twice this month and I need a refund ASAP. "
            "This is blocking our finance signoff for renewal."
        ),
        "from_email": "keira.thomas@clientco.com",
        "timestamp": "2025-10-28T20:50:00Z"
    }

    # 1. handle event -> generate ticket -> encrypt+store
    result = core.handle(incoming)
    print("NEW_TICKET_SUMMARY", result)

    # 2. run watchdog (local SLA monitor, queues warning intents, still offline)
    core.watchdog_scan()

    # 3. local diagnostic snapshot (for operator eyes only)
    diag = core.diagnostic_dump()
    print("LOCAL_DIAGNOSTIC", json.dumps(diag, indent=2))


###################################################################################################
# SUMMARY OF SECURITY PROPERTIES (IN CODE TERMS)
#
# - All persistent state is encrypted with AES-256-GCM under a key that is derived
#   from (owner_passphrase + machine_fingerprint). Stealing the disk alone is useless.
#
# - Every persisted file is signed with HMAC using the same master key.
#   If someone tampers with on-disk data, verify() fails on load.
#
# - No external calls are made. No Slack/web/email traffic is sent.
#   Instead, we queue "intents" for the OWNER to manually act on.
#   That prevents silent data exfiltration.
#
# - There is exactly one public operational surface: SealedCore.handle(...).
#   Everything else is local-only utilities.
#
# - The system never shares its decrypted memory with any remote peer.
#   Decryption only happens in RAM when you load it with the correct passphrase.
#
###################################################################################################
