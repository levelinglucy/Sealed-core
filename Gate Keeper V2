# gatekeeper.py - local-only policy enforcement layer
import os
from sealed_core import SealedCore   # <-- now correct import

# Secrets come from environment only (never commit!)
OWNER_SECRET = os.environ.get("SEALED_OWNER_SECRET")
if not OWNER_SECRET:
    raise RuntimeError("SEALED_OWNER_SECRET environment variable required")

GATEKEEPER_TOKEN = os.environ.get("SEALED_GATEKEEPER_TOKEN")
if not GATEKEEPER_TOKEN:
    raise RuntimeError("SEALED_GATEKEEPER_TOKEN environment variable required")

POLICY = { ... }  # exactly as you had

def gatekeeper_request(request: dict) -> dict:
    if request.get("auth_token") != GATEKEEPER_TOKEN:
        return {"ok": False, "error": "UNAUTHORIZED"}

    role = request.get("role", "")
    action = request.get("action", "")
    rule = POLICY.get(action)
    if not rule or role not in rule["allowed_roles"]:
        return {"ok": False, "error": "ROLE_NOT_ALLOWED"}

    core_mode = "OWNER" if role == "OWNER" else "HELPER"
    core = SealedCore(owner_passphrase=OWNER_SECRET, mode=core_mode)

    payload = request.get("payload", {})

    if action == "NEW_TICKET":
        incoming = {
            "source": payload.get("source", "external"),
            "subject": payload.get("subject", ""),
            "body": payload.get("body", ""),
            "from_email": payload.get("from_email", "unknown@example.com"),
            "timestamp": payload.get("timestamp", ""),
        }
        result = core.handle(incoming)
    elif action == "ACK_TICKET":
        core.acknowledge_ticket(payload.get("ticket_id", ""))
        result = core.get_ticket_detail(payload.get("ticket_id", ""))
    elif action == "CLOSE_TICKET":
        core.close_ticket(payload.get("ticket_id", ""))
        result = core.get_ticket_detail(payload.get("ticket_id", ""))
    elif action == "LIST_OPEN_SUMMARY":
        result = {
            "open": core.list_open_summary(),
            "time": core.debug_snapshot()["timestamp"]
        }
    else:
        return {"ok": False, "error": "NOT_IMPLEMENTED"}

    # Apply final policy redaction
    if rule["returns_detail"] == "none":
        safe_data = {}
    else:
        safe_data = result

    return {"ok": True, "data": safe_data}
