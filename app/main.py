"""Dystopia control plane. Never owns sensor or hypervisor lifecycles."""
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
from app.routers import auth, admin_users, deception, vms, console, analytics


@asynccontextmanager
async def lifespan(app: FastAPI):
    # No flags, import side effects or shutdown hooks may start/stop sensors.
    yield


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
app.include_router(vms.router)
app.include_router(console.router)
app.include_router(analytics.router)


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
