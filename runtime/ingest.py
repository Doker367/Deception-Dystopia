"""Separate FastAPI ingress. Launch only via runtime.cli ingest with TLS.

No admin routes, JWT, global settings, listeners, hypervisor or AI imports.
Never trust forwarding headers to establish transport security.
"""
import asyncio
import sqlite3
import time
from collections import OrderedDict

from fastapi import FastAPI, HTTPException, Request
from starlette.responses import JSONResponse

from runtime.contracts import MAX_BATCH_BYTES, decode_batch
from runtime.storage import CapacityError


def create_app(registry, store):
    app = FastAPI(title="Dystopia telemetry v1", docs_url=None, redoc_url=None, openapi_url=None)
    slots = asyncio.Semaphore(8)
    budgets = OrderedDict()

    @app.middleware("http")
    async def boundary(request, call_next):
        if request.scope.get("scheme") != "https":
            return JSONResponse({"detail": "direct TLS required"}, status_code=426)
        if request.headers.get("content-encoding", "identity") != "identity":
            return JSONResponse({"detail": "compression not accepted"}, status_code=415)
        if slots.locked():
            return JSONResponse({"detail": "ingestion busy"}, status_code=503, headers={"Retry-After": "5"})
        async with slots:
            return await call_next(request)

    @app.post("/v1/events")
    async def ingest(request: Request):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(401, "sensor credential required")
        try:
            sensor, devices = registry.authenticate(auth[7:])
        except PermissionError:
            raise HTTPException(401, "invalid sensor credential") from None
        except (sqlite3.Error, OSError, CapacityError):
            raise HTTPException(503, "credential registry unavailable") from None
        # Fixed cardinality and bounded per-identity request rate; no attacker IP map.
        now = time.monotonic()
        start, count = budgets.get(sensor, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        budgets[sensor] = (start, count + 1)
        budgets.move_to_end(sensor)
        if len(budgets) > 1024:
            budgets.popitem(last=False)
        if count >= 120:
            raise HTTPException(429, "sensor request budget exhausted", headers={"Retry-After": "60"})
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            raise HTTPException(415, "JSON required")

        async def body():
            data = bytearray()
            async for chunk in request.stream():
                if len(data) + len(chunk) > MAX_BATCH_BYTES:
                    raise HTTPException(413, "batch too large")
                data.extend(chunk)
            return bytes(data)

        try:
            raw = await asyncio.wait_for(body(), timeout=5)
            events = decode_batch(raw)
        except asyncio.TimeoutError:
            raise HTTPException(408, "body deadline exceeded") from None
        except ValueError:
            raise HTTPException(422, "invalid v1 event batch") from None
        if any(e["device_id"] not in devices for e in events):
            raise HTTPException(403, "device not assigned to this credential")
        try:
            # Recheck immediately before persistence, no identity from request fields.
            with registry.authorized(auth[7:]) as (current_sensor, current_devices):
                if current_sensor != sensor or any(e["device_id"] not in current_devices for e in events):
                    raise HTTPException(403, "assignment changed")
                result = store.ingest(sensor, events)
        except PermissionError:
            raise HTTPException(401, "credential revoked") from None
        except ValueError:
            raise HTTPException(409, "event ID conflict") from None
        except (CapacityError, sqlite3.Error, OSError):
            raise HTTPException(503, "persistence unavailable", headers={"Retry-After": "30"}) from None
        return {"version": 1, **result}

    return app
