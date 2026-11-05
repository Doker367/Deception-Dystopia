"""NetPulse — Security Middleware.

Adds security headers and removes Server header from responses.
"""

import logging
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects security headers into every response and strips Server."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        headers = response.headers

        # Prevent MIME-type sniffing
        headers.setdefault("X-Content-Type-Options", "nosniff")

        # Prevent clickjacking
        headers.setdefault("X-Frame-Options", "DENY")

        # XSS filter
        headers.setdefault("X-XSS-Protection", "1; mode=block")

        # HSTS (1 year, include subdomains)
        headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

        # Referrer policy
        headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        # Permissions policy
        headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")

        # Legacy console has same-origin JS/CSS only; no inline execution.
        if (request.url.path.startswith("/static/console.")
                or request.url.path == "/static/dashboard.html"
                or request.url.path == "/console"):
            headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            )
        # Dystopia Web is a React SPA. React and the chart/globe libraries set
        # inline style attributes, and the bundled fonts may be data URLs.
        # Scripts remain restricted to same-origin bundles.
        elif request.url.path == "/" or request.url.path.startswith("/app") or request.url.path.startswith("/static/web"):
            headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; "
                "worker-src 'self' blob:; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'",
            )
        elif request.url.path.startswith("/api/"):
            headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; connect-src 'self'",
            )
        else:
            headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; connect-src 'self'; frame-src 'self' http://localhost:3000 http://127.0.0.1:3000",
            )

        # Even FastAPI's own 422/401 validation failures get a safe diagnostic ID.
        # Never log a request path/query: sensor identifiers are untrusted.
        path = request.url.path
        if (path in {"/api/console/events", "/api/console/events.csv", "/api/console/activity"}
                or path.startswith("/api/console/events/")) and response.status_code >= 400:
            if "X-Query-Error-ID" not in headers:
                error_id = secrets.token_hex(8)
                headers["X-Query-Error-ID"] = error_id
                logging.getLogger(__name__).warning("console_query_rejected id=%s status=%d",
                                                    error_id, response.status_code)

        # Remove Server header (uvicorn adds it)
        if "server" in headers:
            del headers["server"]

        # No cachear el HTML/JS del dashboard (evita servir JS viejo tras
        # una actualización y que el usuario tenga que forzar recarga).
        if request.url.path in ("/", "/app", "/favicon.svg"):
            headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            headers["Pragma"] = "no-cache"
            headers["Expires"] = "0"

        return response
