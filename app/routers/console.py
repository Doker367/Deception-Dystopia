"""Administrative console contracts. Declarative only; never invokes isolation/VM APIs."""
from datetime import datetime
from contextlib import closing
from ipaddress import ip_address
import csv
import io
import os
import sqlite3
import stat
import re
import secrets
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.middleware.auth import JWTBearer
from app.middleware.rbac import get_current_user, requires_role
from app.services import console_svc, query_client
from app.core.settings import STATE_DIR

router = APIRouter(prefix="/api/console", tags=["Console"], dependencies=[Depends(JWTBearer())])
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
# All telemetry is obtained from a process-credentialled Unix socket, never SQLite.


class Draft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    purpose: str = Field(min_length=1, max_length=240)
    profile: str | None = None
    segment: str | None = None
    address: str | None = None
    sensor_id: str | None = None
    device_id: str | None = None
    cpu: int = Field(default=1, ge=1, le=16)
    memory_mb: int = Field(default=512, ge=256, le=16384)
    allowed_ports: list[int] = Field(default_factory=list, max_length=16)

    @field_validator("name", "purpose")
    @classmethod
    def nonblank(cls, value):
        value = value.strip()
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("nonblank printable text required")
        return value

    @field_validator("profile")
    @classmethod
    def profile_valid(cls, v):
        if v is not None and v not in {"server", "pc", "camera", "switch", "firewall", "router"}:
            raise ValueError("unsupported profile")
        return v

    @field_validator("segment", "sensor_id", "device_id")
    @classmethod
    def id_valid(cls, v):
        if v is not None and not ID.fullmatch(v):
            raise ValueError("invalid identifier")
        return v

    @field_validator("address")
    @classmethod
    def ip_valid(cls, v):
        if v is not None and str(ip_address(v)) != v:
            raise ValueError("canonical IP required")
        return v

    @field_validator("allowed_ports")
    @classmethod
    def ports_valid(cls, ports):
        if len(set(ports)) != len(ports) or any(not 1 <= p <= 65535 for p in ports):
            raise ValueError("ports must be distinct and between 1 and 65535")
        return ports


class Revision(BaseModel):
    revision: int = Field(ge=1)


def _storage_error(exc):
    raise HTTPException(503, "Private cell store unavailable; check provisioning and permissions") from exc


@router.get("/capabilities", dependencies=[Depends(requires_role("viewer"))])
def capabilities(request: Request):
    user = get_current_user(request)
    role = user["role"]
    configured_env = os.getenv("NETPULSE_ENV") or os.getenv("DYSTOPIA_ENVIRONMENT", "unconfigured")
    environment = configured_env if configured_env in {"laboratory", "production"} else "unconfigured"
    return {"environment": environment,
            "role": role, "can_edit_drafts": role == "admin", "can_validate_drafts": role in {"admin", "operator"},
            "can_manage_users": role == "admin", "can_activate_cells": False,
            "can_provision_sensors": False, "can_manage_vms": False,
            "events_configured": query_client.SOCKET_PATH is not None,
            "incidents": "not_implemented", "sensor_status": "not_available",
            "verification": "not_implemented", "mfa": "not_implemented", "sessions": "not_implemented"}


@router.get("/cells", dependencies=[Depends(requires_role("viewer"))])
def cells():
    try:
        return console_svc.list_cells()
    except (OSError, sqlite3.Error, RuntimeError, PermissionError) as exc:
        _storage_error(exc)


@router.get("/cells/{cell_id}", dependencies=[Depends(requires_role("viewer"))])
def cell(cell_id: str):
    if not ID.fullmatch(cell_id):
        raise HTTPException(422, "invalid cell identifier")
    try:
        result = console_svc.get_cell(cell_id)
    except (OSError, sqlite3.Error, RuntimeError, PermissionError) as exc:
        _storage_error(exc)
    if result is None:
        raise HTTPException(404, "cell not found")
    return result


@router.post("/cells/{cell_id}", status_code=201, dependencies=[Depends(requires_role("admin"))])
def create_cell(cell_id: str, draft: Draft, request: Request):
    if not ID.fullmatch(cell_id):
        raise HTTPException(422, "invalid cell identifier")
    try:
        return console_svc.save(cell_id, draft.model_dump(), get_current_user(request)["sub"])
    except console_svc.Conflict as exc:
        raise HTTPException(409, str(exc)) from None
    except (OSError, sqlite3.Error, RuntimeError, PermissionError) as exc:
        _storage_error(exc)


@router.put("/cells/{cell_id}", dependencies=[Depends(requires_role("admin"))])
def edit_cell(cell_id: str, draft: Draft, request: Request, revision: int = Query(ge=1)):
    if not ID.fullmatch(cell_id):
        raise HTTPException(422, "invalid cell identifier")
    try:
        return console_svc.save(cell_id, draft.model_dump(), get_current_user(request)["sub"], revision)
    except console_svc.Conflict as exc:
        raise HTTPException(409, str(exc)) from None
    except (OSError, sqlite3.Error, RuntimeError, PermissionError) as exc:
        _storage_error(exc)


@router.post("/cells/{cell_id}/validate", dependencies=[Depends(requires_role("operator"))])
def validate_cell(cell_id: str, body: Revision, request: Request):
    if not ID.fullmatch(cell_id):
        raise HTTPException(422, "invalid cell identifier")
    try:
        if console_svc.get_cell(cell_id) is None:
            raise HTTPException(404, "cell not found")
        return console_svc.validate(cell_id, body.revision, get_current_user(request)["sub"])
    except console_svc.Conflict as exc:
        raise HTTPException(409, str(exc)) from None
    except (OSError, sqlite3.Error, RuntimeError, PermissionError) as exc:
        _storage_error(exc)


@router.post("/cells/{cell_id}/prepare", dependencies=[Depends(requires_role("admin"))])
@router.post("/cells/{cell_id}/activate", dependencies=[Depends(requires_role("admin"))])
def blocked_lifecycle(cell_id: str):
    raise HTTPException(409, "ActivationBlocked: independent Linux containment verifier and libvirt lifecycle unavailable")


@router.get("/cells/{cell_id}/history", dependencies=[Depends(requires_role("viewer"))])
def history(cell_id: str):
    if not ID.fullmatch(cell_id):
        raise HTTPException(422, "invalid cell identifier")
    try:
        return console_svc.history(cell_id)
    except (OSError, sqlite3.Error, RuntimeError, PermissionError) as exc:
        _storage_error(exc)


def _human_session(request: Request):
    """Events require a stored user-backed JWT, never a generic API key."""
    principal = get_current_user(request)
    if principal.get("api_key_id") is not None or str(principal.get("sub", "")).startswith("apikey:"):
        raise HTTPException(403, "User session required for event access")
    return principal


def _bridge(operation, **params):
    try:
        return query_client.query(operation, **params)
    except query_client.BridgeError as exc:
        message = {422: "Invalid or limited event query", 404: "Event not found"}.get(
            exc.status, "Event query service unavailable")
        error_id = exc.error_id or secrets.token_hex(8)
        logging.getLogger(__name__).warning("event_query_failure id=%s status=%d", error_id, exc.status)
        headers = {"Cache-Control": "no-store", "X-Query-Error-ID": error_id}
        raise HTTPException(exc.status, message, headers=headers) from None


def _query_filters(sensor, device, source, kind, proto, from_time, to_time):
    if any(t is not None and t.tzinfo is None for t in (from_time, to_time)):
        raise HTTPException(422, "timezone required")
    return {name: value for name, value in (
        ("sensor", sensor), ("device", device), ("source", source),
        ("kind", kind), ("proto", proto),
        ("from_time", from_time.isoformat() if from_time else None),
        ("to_time", to_time.isoformat() if to_time else None)) if value is not None}


@router.get("/events", dependencies=[Depends(requires_role("viewer")), Depends(_human_session)])
def events(sensor: str | None = Query(default=None, max_length=64),
           device: str | None = Query(default=None, max_length=64),
           source: str | None = Query(default=None, max_length=64),
           kind: str | None = Query(default=None, max_length=32),
           proto: str | None = Query(default=None, max_length=16),
           from_time: datetime | None = None, to_time: datetime | None = None,
           limit: int = Query(default=25, ge=1, le=100),
           cursor: str | None = Query(default=None, max_length=1024)):
    filters = _query_filters(sensor, device, source, kind, proto, from_time, to_time)
    return _bridge("list", filters=filters, limit=limit, **({"cursor": cursor} if cursor else {}))


@router.get("/events/{sensor}/{event_id}", dependencies=[Depends(requires_role("viewer")), Depends(_human_session)])
def event_detail(sensor: str, event_id: str):
    return _bridge("detail", sensor=sensor, event_id=event_id)


@router.get("/activity", dependencies=[Depends(requires_role("viewer")), Depends(_human_session)])
def activity(minutes: int = Query(default=30, ge=5, le=1440)):
    return _bridge("activity", minutes=minutes)


@router.get("/audit", dependencies=[Depends(requires_role("admin"))])
def audit_events(limit: int = Query(default=25, ge=1, le=100),
                 offset: int = Query(default=0, ge=0, le=10000)):
    """Minimal administrative log metadata; no details or client IP exposed."""
    path = STATE_DIR / "audit" / "audit.db"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise PermissionError("private audit database required")
        with closing(sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
            db.execute('PRAGMA query_only=ON')
            total = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
            rows = db.execute('SELECT id,ts,action,username,method,path,response_status FROM audit '
                              'ORDER BY id DESC LIMIT ? OFFSET ?', (limit, offset)).fetchall()
        return {"total": total, "items": [dict(zip(
            ('id','timestamp','action','actor','method','path','status'), r)) for r in rows]}
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(503, "Private audit database unavailable") from exc


def _csv_safe(value):
    value = str(value or "")
    return "'" + value if value.lstrip(" \t\r\n\ufeff\u200b").startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value


@router.get("/events.csv", dependencies=[Depends(requires_role("viewer")), Depends(_human_session)])
def export_events(sensor: str | None = Query(default=None, max_length=64),
                  device: str | None = Query(default=None, max_length=64),
                  source: str | None = Query(default=None, max_length=64),
                  kind: str | None = Query(default=None, max_length=32),
                  proto: str | None = Query(default=None, max_length=16),
                  from_time: datetime | None = None, to_time: datetime | None = None):
    filters = _query_filters(sensor, device, source, kind, proto, from_time, to_time)
    result = _bridge("export", filters=filters, limit=500)
    out = io.StringIO()
    writer = csv.writer(out)
    keys = ("sensor", "event_id", "device", "received_at", "observed_at", "kind", "source", "proto")
    writer.writerow(keys)
    for row in result["items"]:
        writer.writerow([_csv_safe(row[key]) for key in keys])
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="dystopia-events.csv"',
                             "Cache-Control": "no-store", "X-Export-Truncated": str(result["truncated"]).lower(),
                             "X-Export-Rows": str(len(result["items"])),
                             "X-Query-At": result["queried_at"]})
