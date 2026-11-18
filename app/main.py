"""Dystopia control plane. Never owns sensor or hypervisor lifecycles."""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, cast

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.limiter import limiter
from app.core.settings import API_TITLE, API_VERSION
from app.middleware.audit import AuditMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.routers import (
    auth, admin_users, deception, fabric, vms, console, analytics, investigations, ai_rag,
)

logger = logging.getLogger("fabric.console")

# Cada cuántos segundos revisa el segador las sesiones inactivas.
REAP_INTERVAL_S = 30


@asynccontextmanager
async def lifespan(app: FastAPI):
    # No flags, import side effects or shutdown hooks may start/stop sensors.
    # Segador de sesiones de consola del fabric (idle/max-age, Fase 11):
    # ``console_svc.reap_idle()`` era código muerto; sin el loop el idle
    # timeout y la edad máxima declarados no se aplicaban nunca.
    reaper_task: asyncio.Task | None = None
    if os.getenv("DYSTOPIA_FABRIC_CONSOLE_ENABLED", "false").strip().lower() == "true":
        from app.services.fabric.console_svc import console_service

        async def reap_loop() -> None:
            while True:
                await asyncio.sleep(REAP_INTERVAL_S)
                try:
                    reap_idle_result = console_service.reap_idle()
                except Exception:  # noqa: BLE001 - el segador nunca tumba la API
                    logger.exception("[fabric] reap_idle falló")
                    continue
                if reap_idle_result:
                    logger.info("[fabric] reap_idle cerró %d sesión(es)", reap_idle_result)

        reaper_task = asyncio.create_task(reap_loop())
    yield
    if reaper_task is not None:
        reaper_task.cancel()


app = FastAPI(title=API_TITLE, version=API_VERSION, lifespan=lifespan)
app.state.limiter = limiter
# slowapi declares the handler as taking RateLimitExceeded; Starlette's
# ExceptionHandler protocol widens the exc parameter to Exception, so the
# callable is not structurally assignable even though it is the documented API.
app.add_exception_handler(
    RateLimitExceeded, cast(Any, _rate_limit_exceeded_handler)
)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditMiddleware)
app.include_router(auth.router)
app.include_router(admin_users.router)
app.include_router(deception.router)
app.include_router(fabric.router)
app.include_router(vms.router)
app.include_router(console.router)
app.include_router(analytics.router)
app.include_router(investigations.router)
app.include_router(ai_rag.router)


@app.get("/api/health")
def health():
    from app.middleware.audit import health as audit_health
    return {"status": "healthy", "plane": "control", "sensors_started": False,
            "audit": audit_health()}


WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"


@app.get("/")
def dashboard():
    index = WEB_DIST / "index.html"
    if index.is_file():
        return FileResponse(index)
    return FileResponse("app/static/dashboard.html")


@app.get("/console")
def legacy_console():
    return RedirectResponse("/static/dashboard.html", status_code=307)


@app.get("/app")
@app.get("/app/{path:path}")
def web_app(path: str = ""):
    index = WEB_DIST / "index.html"
    if index.is_file():
        return FileResponse(index)
    return RedirectResponse("/", status_code=307)


@app.get("/favicon.svg")
def favicon():
    return FileResponse("app/static/favicon.svg", media_type="image/svg+xml")


if WEB_DIST.is_dir():
    app.mount("/static/web", StaticFiles(directory=WEB_DIST, html=True), name="web")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
