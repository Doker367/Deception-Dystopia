"""Authenticated investigation and honeypot draft APIs; no container lifecycle."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from io import StringIO
from ipaddress import ip_address
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.middleware.auth import JWTBearer
from app.middleware.rbac import get_current_user, requires_role
from app.services import analytics_svc, investigation_svc

router = APIRouter(prefix="/api/investigations", tags=["Investigations"],
                   dependencies=[Depends(JWTBearer()), Depends(requires_role("viewer"))])


def human(request: Request):
    user = get_current_user(request)
    if user.get("api_key_id") is not None or str(user.get("sub", "")).startswith("apikey:"):
        raise HTTPException(403, "User session required")
    return user


def canonical_ip(source: str) -> str:
    try:
        address = ip_address(source)
    except ValueError:
        raise HTTPException(422, "Invalid source IP") from None
    if str(address) != source:
        raise HTTPException(422, "Canonical source IP required")
    return source


def sensor_id(sensor: str) -> str:
    if sensor not in investigation_svc.SENSORS:
        raise HTTPException(404, "Unknown honeypot")
    return sensor


def storage_error(exc: Exception):
    raise HTTPException(503, "Private investigation store unavailable") from exc


class ProfileEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=0)
    alias: str = Field(default="", max_length=80)
    classification: str = Field(default="unclassified", pattern="^(unclassified|scanner|brute_force|targeted|benign|other)$")
    tags: list[str] = Field(default_factory=list, max_length=12)
    notes: str = Field(default="", max_length=4000)

    @field_validator("alias", "notes")
    @classmethod
    def clean_text(cls, value: str):
        if any(ord(char) < 32 and char not in "\n\t" for char in value):
            raise ValueError("control characters are not allowed")
        return value.strip()

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, values: list[str]):
        tags = [value.strip() for value in values]
        if any(not tag or len(tag) > 32 or any(ord(char) < 32 for char in tag) for tag in tags):
            raise ValueError("tags must be 1–32 printable characters")
        if len(set(tags)) != len(tags):
            raise ValueError("duplicate tags")
        return tags


class SensorEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=0)
    display_name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=500)
    memory_mib: int = Field(ge=128, le=4096)
    cpus: float = Field(ge=0.1, le=4)
    pids_limit: int = Field(ge=32, le=1024)

    @field_validator("display_name", "description")
    @classmethod
    def clean_text(cls, value: str):
        value = value.strip()
        if any(ord(char) < 32 for char in value):
            raise ValueError("control characters are not allowed")
        return value


@router.get("/attackers", dependencies=[Depends(human)])
def search_attackers(query: str = Query(min_length=2, max_length=45, pattern=r"^[0-9.:]+$"),
                     limit: int = Query(default=20, ge=1, le=100)):
    try:
        return analytics_svc.service().search_attackers(query, limit)
    except (analytics_svc.AnalyticsUnavailable, OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)


@router.get("/attackers/{source}/timeline", dependencies=[Depends(human)])
def attacker_timeline(source: str, interval: Literal["1h", "1d"] = "1h"):
    source = canonical_ip(source)
    try:
        return analytics_svc.service().attacker_timeline(source, interval)
    except (analytics_svc.AnalyticsUnavailable, OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)


@router.get("/attackers/{source}", dependencies=[Depends(human)])
def attacker(source: str, offset: int = Query(default=0, ge=0, le=10000),
             limit: int = Query(default=50, ge=1, le=100), summary: bool = True):
    source = canonical_ip(source)
    try:
        evidence = analytics_svc.service().attacker(source, offset, limit, include_summary=summary)
        annotation = investigation_svc.profile(source)
    except (analytics_svc.AnalyticsUnavailable, OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)
    return {**evidence, "annotation": annotation or {"revision": 0, "alias": "", "classification": "unclassified",
                                                     "tags": [], "notes": ""}}


EXPORT_COLUMNS = ("timestamp", "sensor", "device", "kind", "action", "proto",
                  "port", "severity", "message", "event_id")


def _csv_cell(value: object) -> object:
    """Keep spreadsheet programs from interpreting captured text as a formula."""
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


@router.get("/attackers/{source}/export", dependencies=[Depends(human)])
def export_attacker(source: str, format: Literal["csv", "json"] = "csv",
                    limit: int = Query(default=5000, ge=1, le=10000)):
    source = canonical_ip(source)
    try:
        payload = analytics_svc.service().export_attacker(source, limit)
    except (analytics_svc.AnalyticsUnavailable, OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # Only the canonical, validated IP and a server-generated UTC stamp enter the filename.
    filename = f"dystopia-{source.replace(':', '-')}-{stamp}.{format}"
    headers = {"Cache-Control": "no-store",
               "Content-Disposition": f'attachment; filename="{filename}"',
               "X-Export-Rows": str(payload["exported"]),
               "X-Export-Truncated": str(payload["truncated"]).lower()}
    if format == "json":
        return JSONResponse(payload, headers=headers)
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(EXPORT_COLUMNS)
    for item in payload["items"]:
        writer.writerow([_csv_cell(item["id"] if column == "event_id" else item[column])
                         for column in EXPORT_COLUMNS])
    return Response(output.getvalue(), media_type="text/csv; charset=utf-8", headers=headers)


@router.put("/attackers/{source}/annotation", dependencies=[Depends(requires_role("operator")), Depends(human)])
def save_attacker(source: str, body: ProfileEdit, request: Request):
    source = canonical_ip(source)
    try:
        return investigation_svc.save_profile(source, body.model_dump(exclude={"revision"}),
                                               get_current_user(request)["sub"], body.revision)
    except investigation_svc.Conflict as exc:
        raise HTTPException(409, str(exc)) from None
    except (OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)


@router.get("/attackers/{source}/history", dependencies=[Depends(human)])
def attacker_history(source: str, limit: int = Query(default=20, ge=1, le=100)):
    source = canonical_ip(source)
    try:
        return {"source": source, "items": investigation_svc.history("profile", source, limit)}
    except (OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)


@router.get("/honeypots/{sensor}", dependencies=[Depends(human)])
def honeypot(sensor: str):
    sensor = sensor_id(sensor)
    try:
        draft = investigation_svc.sensor_draft(sensor)
        described = investigation_svc.plan(sensor)
    except (OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)
    return {"sensor": sensor, "draft": draft, "plan": described, "application": "blocked",
            "reason": "Independent containment verification and sensor lifecycle are not implemented"}


@router.put("/honeypots/{sensor}", dependencies=[Depends(requires_role("admin")), Depends(human)])
def save_honeypot(sensor: str, body: SensorEdit, request: Request):
    sensor = sensor_id(sensor)
    try:
        draft = investigation_svc.save_sensor(sensor, body.model_dump(exclude={"revision"}),
                                              get_current_user(request)["sub"], body.revision)
        described = investigation_svc.plan(sensor)
    except investigation_svc.Conflict as exc:
        raise HTTPException(409, str(exc)) from None
    except (OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)
    return {"sensor": sensor, "draft": draft, "plan": described, "application": "blocked",
            "reason": "Independent containment verification and sensor lifecycle are not implemented"}


@router.get("/honeypots/{sensor}/plan", dependencies=[Depends(human)])
def honeypot_plan(sensor: str):
    sensor = sensor_id(sensor)
    try:
        return investigation_svc.plan(sensor)
    except (OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)


@router.get("/honeypots/{sensor}/history", dependencies=[Depends(human)])
def honeypot_history(sensor: str, limit: int = Query(default=20, ge=1, le=100)):
    sensor = sensor_id(sensor)
    try:
        return {"sensor": sensor, "items": investigation_svc.history("sensor_draft", sensor, limit)}
    except (OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)


@router.post("/honeypots/{sensor}/apply", dependencies=[Depends(requires_role("admin")), Depends(human)])
def apply_honeypot(sensor: str):
    sensor_id(sensor)
    try:
        described = investigation_svc.plan(sensor)
    except (OSError, sqlite3.Error, PermissionError, RuntimeError) as exc:
        storage_error(exc)
    raise HTTPException(
        409,
        f"ActivationBlocked: independent Linux containment verifier and sensor lifecycle unavailable "
        f"(plan {described['plan_sha256'][:12]})",
    )
