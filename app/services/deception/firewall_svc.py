"""No host firewall authority in the control process."""
from app.services.deception import blocklist_svc


def block(ip: str, reason: str = "") -> dict:
    raise RuntimeError("Host firewall mutations disabled; use scoped isolation helper")


def unblock(ip: str) -> dict:
    raise RuntimeError("Host firewall mutations disabled; use scoped isolation helper")


def status() -> dict:
    return {"enabled": False, "applied": False, "blocked": blocklist_svc.list_blocked(),
            "reason": "control plane has no firewall authority"}
