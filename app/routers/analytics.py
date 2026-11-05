"""Read-only analytics BFF for the Dystopia web interface.

The browser talks to these endpoints with its Dystopia JWT. Elasticsearch
credentials and the raw index are never exposed to the client.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.middleware.auth import JWTBearer
from app.middleware.rbac import get_current_user, requires_role
from app.services import analytics_svc

router = APIRouter(
    prefix="/api/analytics",
    tags=["Analytics"],
    dependencies=[Depends(JWTBearer()), Depends(requires_role("viewer"))],
)
log = logging.getLogger(__name__)


def _human_session(request: Request) -> dict:
    principal = get_current_user(request)
    if principal.get("api_key_id") is not None or str(principal.get("sub", "")).startswith("apikey:"):
        raise HTTPException(403, "User session required for analytics access")
    return principal


def _safe(operation: Any) -> Any:
    try:
        return operation()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except analytics_svc.AnalyticsDisabled:
        raise HTTPException(503, "Analytics plane is not configured") from None
    except analytics_svc.AnalyticsUnavailable as exc:
        log.warning("analytics backend failure: %s", type(exc).__name__)
        raise HTTPException(503, "Analytics backend unavailable") from None


@router.get("/overview")
def overview(
    request: Request,
    from_time: str | None = Query(default=None, alias="from", max_length=64),
    to_time: str | None = Query(default=None, alias="to", max_length=64),
):
    _human_session(request)
    return _safe(lambda: analytics_svc.service().overview(from_time, to_time))


@router.get("/timeline")
def timeline(
    request: Request,
    from_time: str | None = Query(default=None, alias="from", max_length=64),
    to_time: str | None = Query(default=None, alias="to", max_length=64),
    interval: str = Query(default="1h", max_length=8),
):
    _human_session(request)
    return _safe(lambda: analytics_svc.service().timeline(from_time, to_time, interval))


@router.get("/origins")
def origins(
    request: Request,
    from_time: str | None = Query(default=None, alias="from", max_length=64),
    to_time: str | None = Query(default=None, alias="to", max_length=64),
    limit: int = Query(default=50, ge=1, le=100),
):
    _human_session(request)
    return _safe(lambda: analytics_svc.service().origins(from_time, to_time, limit))


@router.get("/events")
def events(
    request: Request,
    from_time: str | None = Query(default=None, alias="from", max_length=64),
    to_time: str | None = Query(default=None, alias="to", max_length=64),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10_000),
    q: str = Query(default="", max_length=200),
    severity: str = Query(default="", max_length=16),
    sensor: str = Query(default="", max_length=64),
    protocol: str = Query(default="", max_length=32),
):
    _human_session(request)
    return _safe(
        lambda: analytics_svc.service().events(
            from_time,
            to_time,
            limit=limit,
            offset=offset,
            query_text=q,
            severity=severity,
            sensor=sensor,
            protocol=protocol,
        )
    )


@router.get("/health")
def health(request: Request):
    _human_session(request)
    return _safe(lambda: analytics_svc.service().health())
