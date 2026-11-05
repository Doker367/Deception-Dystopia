"""Behavioral/UI contract checks for the control plane.

These tests use ASGI TestClient: no TCP listener, honeypot, VM, or host mutation.
They verify the current surface as shipped, not real browser pixel fidelity.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("NETPULSE_JWT_SECRET", "synthetic-ui-test-secret-0123456789abcdefgh")
    from app.middleware import audit
    monkeypatch.setattr(audit, "_log_async", lambda **kwargs: None)
    from app.main import app
    with TestClient(app) as test_client:
        yield test_client


def test_dashboard_renders_safe_operator_entry_points(client):
    # The legacy console remains reachable at an explicit path while the
    # Dystopia Web SPA owns "/".
    response = client.get("/static/dashboard.html")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert '<html lang="es">' in html
    assert "Dystopia" in html
    assert '/static/console.css' in html
    assert '/static/console.js' in html
    assert 'id="navigation"' in html
    assert 'data-page="cells"' in html
    assert 'data-page="events"' in html
    # The panel may expose authentication, but not executable VM controls.
    assert "login-form" in html
    assert "javascript:" not in html.lower()
    assert "vnc://" not in html.lower()
    assert 'id="login-form"' in html
    assert 'data-page="infrastructure"' in html
    assert 'id="confirmation"' in html
    assert 'id="environment"' in html


def test_static_assets_and_api_docs_are_reachable(client):
    favicon = client.get("/favicon.svg")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"].startswith("image/svg")
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "swagger" in docs.text.lower()
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    paths = openapi.json()["paths"]
    assert "/api/health" in paths
    assert "/api/auth/login" in paths
    assert not any(path.startswith("/api/deception/ingest") for path in paths)


def test_health_is_explicit_about_control_only(client):
    payload = client.get("/api/health").json()
    assert payload["status"] == "healthy"
    assert payload["plane"] == "control"
    assert payload["sensors_started"] is False
    assert isinstance(payload["audit"]["storage_errors"], int)
    assert payload["audit"]["storage_errors"] >= 0  # cumulative across requests in this process


def test_unauthenticated_and_legacy_actions_are_predictable(client):
    assert client.get("/api/deception/status").status_code == 401
    assert client.get("/api/vms").status_code == 401
    assert client.post("/api/deception/ingest", json={}).status_code == 410
    assert client.post("/api/vms/demo/start").status_code == 409
    assert client.post("/api/deception/firewall/block", json={}).status_code == 409


def test_console_assets_are_cohesive_and_do_not_fake_telemetry(client):
    dashboard = (ROOT / 'app/static/dashboard.html').read_text(encoding='utf-8')
    js = (ROOT / 'app/static/console.js').read_text(encoding='utf-8')
    css = (ROOT / 'app/static/console.css').read_text(encoding='utf-8')
    assert '/static/console.js' in dashboard and '/static/console.css' in dashboard
    assert client.get('/static/console.js').status_code == 200
    assert client.get('/static/console.css').status_code == 200
    assert "script-src 'self'" in client.get('/static/dashboard.html').headers['content-security-policy']
    assert 'unsafe-inline' not in client.get('/static/dashboard.html').headers['content-security-policy']
    assert 'overflow-y:auto' in css
    assert '/api/console/activity' in js and '/api/console/events' in js
    assert 'alert(' not in js and 'window.confirm(' not in js
    assert "dialog.returnValue=''" in js  # Escape cannot reuse a previous confirmation
    assert 'No disponible' in js


def test_legacy_console_route_redirects(client):
    response = client.get("/console", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/static/dashboard.html"


def test_dystopia_web_is_served_when_built(client):
    if not (ROOT / "web" / "dist" / "index.html").is_file():
        pytest.skip("Dystopia Web build is not present")
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Dystopia · Security Operations" in response.text
    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
