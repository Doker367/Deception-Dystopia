"""Dystopia control plane. Never owns sensor or hypervisor lifecycles."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.limiter import limiter
from app.core.settings import API_TITLE, API_VERSION
from app.middleware.audit import AuditMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.routers import auth, admin_users, deception, vms, console


@asynccontextmanager
async def lifespan(app: FastAPI):
    # No flags, import side effects or shutdown hooks may start/stop sensors.
    yield


app = FastAPI(title=API_TITLE, version=API_VERSION, lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditMiddleware)
app.include_router(auth.router)
app.include_router(admin_users.router)
app.include_router(deception.router)
app.include_router(vms.router)
app.include_router(console.router)


@app.get("/api/health")
def health():
    from app.middleware.audit import health as audit_health
    return {"status": "healthy", "plane": "control", "sensors_started": False,
            "audit": audit_health()}


@app.get("/")
def dashboard():
    return FileResponse("app/static/dashboard.html")


@app.get("/favicon.svg")
def favicon():
    return FileResponse("app/static/favicon.svg", media_type="image/svg+xml")


app.mount("/static", StaticFiles(directory="app/static"), name="static")
