"""Contrato de retirada del router de monitoring en el plano de control.

La observabilidad vive en ``docker-compose.monitoring.yml`` (Prometheus,
Loki, Grafana y Alertmanager). El control mínimo ya no expone
``/api/monitoring/*``; estas pruebas fijan esa ausencia para que un cambio
accidental no reintroduzca la superficie retirada.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from app.core.security import create_access_token
from app.main import app

VIEWER = {"Authorization": "Bearer " + create_access_token({"sub": "viewer", "role": "viewer"})}


def test_monitoring_overview_retirado():
    client = TestClient(app)
    r = client.get("/api/monitoring/overview", headers=VIEWER)
    assert r.status_code == 404, r.text


def test_monitoring_series_retirado():
    client = TestClient(app)
    r = client.get("/api/monitoring/series?query=up&minutes=5", headers=VIEWER)
    assert r.status_code == 404, r.text


def test_monitoring_sin_rutas_montadas():
    rutas = {getattr(r, "path", "") for r in app.routes}
    assert not any(p.startswith("/api/monitoring") for p in rutas)
