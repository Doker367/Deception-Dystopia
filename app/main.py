"""Dystopia — independent deception platform."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.limiter import limiter
from app.core.settings import API_TITLE, API_VERSION
from app.middleware.audit import AuditMiddleware
from app.middleware.metrics import MetricsMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.models.schemas import HealthResponse
from app.routers import audit, auth, metrics as metrics_router, notifications, admin_users, prometheus_proxy, alerts, security_ext, integrations, deception, monitoring, ai, vms

# ── Rate Limiter (definido en app/core/limiter.py) ──────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown."""
    # Deception: reflejar topología señuelo en métricas (motor en Fase B)
    from app.core.settings import DECEPTION_ENABLED
    try:
        from app.services import metrics_svc
        from app.services.deception import topology_svc
        summary = topology_svc.summary()
        metrics_svc.netpulse_deception_devices_configured.set(summary["devices"])
        metrics_svc.netpulse_deception_devices_enabled.set(summary["devices_enabled"])
        state = "habilitada" if DECEPTION_ENABLED else "deshabilitada"
        print(f"🎭 Red señuelo {state} ({summary['devices']} dispositivos, {summary['segments']} segmentos)")
    except Exception as e:
        print(f"⚠️ Deception no inicializó métricas: {e}")

    # Arrancar el motor nativo de deception (solo si está habilitado)
    if DECEPTION_ENABLED:
        try:
            from app.services.deception import engine_svc
            report = await engine_svc.start()
            print(f"🎭 Motor deception: {report.get('status')} "
                  f"({report.get('started', 0)} listeners, {report.get('failed', 0)} fallos)")
        except Exception as e:
            print(f"⚠️ Motor deception no arrancó: {e}")
        try:
            from app.services.deception.integrations import tailer_svc
            tailer_svc.start()
            print("🎭 Tailer de honeypots reales iniciado")
        except Exception as e:
            print(f"⚠️ Tailer de deception no arrancó: {e}")

    yield

    # Shutdown: detener tailer y motor de deception
    try:
        from app.services.deception.integrations import tailer_svc
        tailer_svc.stop()
    except Exception:
        pass

    try:
        from app.services.deception import engine_svc
        await engine_svc.stop()
    except Exception:
        pass

    # Shutdown: detener collectors
    try:
        from app.services.collectors import syslog_svc
        syslog_svc.stop_syslog_collector()
    except Exception:
        pass

    try:
        from app.services.collectors import metrics_poller
        metrics_poller.stop()
    except Exception:
        pass

    try:
        from app.services import metrics_history_svc
        metrics_history_svc.flush()
    except Exception:
        pass


app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware ───────────────────────────────────────────────
# En Starlette el ÚLTIMO middleware añadido queda como el MÁS EXTERNO.
# Por eso MetricsMiddleware se añade al final (captura todos los requests).

# CORS (más interno)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Audit (captura todos los requests)
app.add_middleware(AuditMiddleware)

# Metrics (OUTERMOST — captura TODO, incluso lo que no llega a un endpoint)
app.add_middleware(MetricsMiddleware)

# ── Health ──────────────────────────────────────────────────


@app.get("/api/health", response_model=HealthResponse, tags=["Health"])
@limiter.limit("10/minute")  # Stricter limit for health checks
async def health(request: Request):
    return HealthResponse(
        status="healthy",
        devices_configured=topology_svc.summary().get("devices", 0),
    )


# ── Routers ─────────────────────────────────────────────────

app.include_router(audit.router)
app.include_router(auth.router)
app.include_router(metrics_router.router)
app.include_router(notifications.router)
app.include_router(admin_users.router)
app.include_router(prometheus_proxy.router)
app.include_router(alerts.router)
app.include_router(security_ext.router)
app.include_router(integrations.router)
app.include_router(deception.router)
app.include_router(monitoring.router)
app.include_router(ai.router)
app.include_router(vms.router)

# ── Static files (Dashboard UI) ──────────────────────────────

@app.get("/", response_class=FileResponse)
async def dashboard():
    return FileResponse("app/static/dashboard.html")

@app.get("/favicon.svg", response_class=FileResponse)
async def favicon():
    return FileResponse("app/static/favicon.svg")

# Mount static files directory AFTER route handlers
app.mount("/static", StaticFiles(directory="app/static"), name="static")

