"""Bounded administrative request audit; never logs credentials or query strings."""
import asyncio
import logging
import threading
from functools import partial

logger = logging.getLogger(__name__)
_slots = threading.BoundedSemaphore(128)
_stats = {"rejected": 0, "storage_errors": 0}


class AuditMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") == "/api/health":
            return await self.app(scope, receive, send)
        code = 500
        async def wrapped(message):
            nonlocal code
            if message["type"] == "http.response.start":
                code = message["status"]
            await send(message)
        try:
            await self.app(scope, receive, wrapped)
        finally:
            # Template instead of raw path, never query/body/Authorization.
            route = getattr(scope.get("route"), "path", "<unmatched>")
            method = scope.get("method", "unknown")[:16]
            _log_async(action="api_" + method.lower(), username=_get_username(scope),
                       details=f"{method} {route}", ip_address=_get_client_ip(scope),
                       success=200 <= code < 400, path=route, method=method,
                       response_status=code)


def health():
    return {**_stats, "queue_capacity": 128}


def _log_async(**kwargs):
    if not _slots.acquire(blocking=False):
        _stats["rejected"] += 1
        logger.error("control_audit_queue_full rejected=%d", _stats["rejected"])
        return
    try:
        future = asyncio.get_running_loop().run_in_executor(None, partial(_safe_log, **kwargs))
        future.add_done_callback(lambda _: _slots.release())
    except Exception:
        _slots.release()
        _stats["rejected"] += 1
        logger.error("control_audit_schedule_failed")


def _safe_log(**kwargs):
    try:
        from app.services.audit_svc import log_event
        result = log_event(**kwargs)
        if not result.get("id"):
            raise RuntimeError("audit persistence did not return an ID")
    except Exception:
        _stats["storage_errors"] += 1
        logger.error("control_audit_storage_unavailable count=%d", _stats["storage_errors"])


def _get_username(scope):
    user = (scope.get("state") or {}).get("user")
    return str(user.get("sub", "anonymous"))[:64] if isinstance(user, dict) else "anonymous"


def _get_client_ip(scope):
    client = scope.get("client")
    return client[0] if client else "unknown"  # No untrusted proxy-header override.
