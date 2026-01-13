# gatekeeper.py

from sealed_ops_core import SealedCore

OWNER_SECRET = "YOUR-LOCAL-PASSPHRASE-HERE"
GATEKEEPER_TOKEN = "LONG_RANDOM_SHARED_TOKEN_ONLY_YOU_KNOW"  # like 64+ chars

# Access policy matrix:
POLICY = {
    # action_name: {
    #   "allowed_roles": ["OWNER","HELPER","EXTERNAL_CREATE","EXTERNAL_ACK",...],
    #   "returns_detail": "none" | "redacted" | "full",
    #   "write": True/False
    # }

    "NEW_TICKET": {
        "allowed_roles": ["OWNER", "EXTERNAL_CREATE"],
        "returns_detail": "redacted",
        "write": True,
    },
    "ACK_TICKET": {
        "allowed_roles": ["OWNER", "EXTERNAL_ACK"],
        "returns_detail": "redacted",
        "write": True,
    },
    "CLOSE_TICKET": {
        "allowed_roles": ["OWNER"],
        "returns_detail": "redacted",
        "write": True,
    },
    "LIST_OPEN_SUMMARY": {
        "allowed_roles": ["OWNER","HELPER","EXTERNAL_ACK"],
        "returns_detail": "redacted",
        "write": False,
    },
}

def gatekeeper_request(request: dict) -> dict:
    """
    request shape:
    {
        "auth_token": "...",
        "role": "OWNER" | "HELPER" | "EXTERNAL_CREATE" | "EXTERNAL_ACK",
        "action": "NEW_TICKET" | "ACK_TICKET" | "CLOSE_TICKET" | "LIST_OPEN_SUMMARY",
        "payload": {...}  # depends on action
    }

    returns:
    {
        "ok": True/False,
        "error": "...optional...",
        "data": {...optional...}
    }
    """

    # 1. auth check
    if request.get("auth_token") != GATEKEEPER_TOKEN:
        return {"ok": False, "error": "UNAUTHORIZED"}

    role = request.get("role", "")
    action = request.get("action", "")

    # 2. action/role policy check
    rule = POLICY.get(action)
    if not rule:
        return {"ok": False, "error": "UNKNOWN_ACTION"}

    if role not in rule["allowed_roles"]:
        return {"ok": False, "error": "ROLE_NOT_ALLOWED"}

    # 3. open sealed core in that role
    #    If role is OWNER -> full view, else HELPER-style redaction.
    #    For roles like EXTERNAL_CREATE we treat them as HELPER-equivalent view.
    core_mode = "OWNER" if role == "OWNER" else "HELPER"
    core = SealedCore(owner_passphrase=OWNER_SECRET, mode=core_mode)

    # unlock session if you're using the session lock feature
    # core.unlock_session(OWNER_SECRET)

    # 4. execute
    payload = request.get("payload", {})

    if action == "NEW_TICKET":
        # allowed to write
        incoming_event = {
            "source": payload.get("source","external"),
            "subject": payload.get("subject",""),
            "body": payload.get("body",""),
            "from_email": payload.get("from_email","unknown@example.com"),
            "timestamp": payload.get("timestamp",""),
        }
        result = core.handle(incoming_event)

    elif action == "ACK_TICKET":
        ticket_id = payload.get("ticket_id","")
        core.acknowledge_ticket(ticket_id)
        # we can return updated summary
        result = core.get_ticket_detail(ticket_id)

    elif action == "CLOSE_TICKET":
        ticket_id = payload.get("ticket_id","")
        core.close_ticket(ticket_id)
        result = core.get_ticket_detail(ticket_id)

    elif action == "LIST_OPEN_SUMMARY":
        result = {
            "open": core.list_open_summary(),
            "time": core.debug_snapshot()["time"]
        }

    else:
        return {"ok": False, "error": "NOT_IMPLEMENTED"}

    # 5. scrub output if needed
    detail_level = rule["returns_detail"]
    if detail_level == "none":
        safe_data = {}
    elif detail_level == "redacted":
        # core in HELPER mode already redacts sender email for us,
        # so if role != OWNER we’re safe by default.
        safe_data = result
    else:  # "full"
        safe_data = result

    return {"ok": True, "data": safe_data}
