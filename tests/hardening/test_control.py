"""No host sockets or processes. Fixtures use only synthetic credentials."""
import asyncio
import importlib
import socket
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def control(tmp_path, monkeypatch):
    monkeypatch.setenv("NETPULSE_JWT_SECRET", "synthetic-test-only-" + "x"*48)
    monkeypatch.setenv("DYSTOPIA_CONTROL_STATE", str(tmp_path))
    monkeypatch.setenv("DYSTOPIA_CONTROL_CONFIG", str(tmp_path / "config"))
    monkeypatch.setenv("NETPULSE_DECEPTION_ENABLED", "true")
    monkeypatch.setenv("NETPULSE_VMS_ENABLED", "true")
    monkeypatch.setenv("NETPULSE_FIREWALL_ENABLED", "true")
    from app.middleware import audit
    monkeypatch.setattr(audit, "_log_async", lambda **kw: None)
    from app.main import app
    def forbidden(*args, **kwargs):
        raise AssertionError("control tried to open a listener or spawn a host process")
    monkeypatch.setattr(asyncio, "start_server", forbidden)
    monkeypatch.setattr(socket.socket, "bind", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with TestClient(app) as client:
        yield client


def test_control_never_starts_honeypots_even_with_legacy_flags(control):
    assert control.get("/api/health").json()["sensors_started"] is False
    for route in ("/engine/start", "/integrations/start", "/firewall/block", "/simulate"):
        assert control.post("/api/deception" + route, json={}).status_code == 409
    assert control.post("/api/vms/example/start").status_code == 409
    assert control.post("/api/deception/ingest", json={}).status_code == 410


def test_legacy_qemu_cannot_use_default_network(tmp_path, monkeypatch):
    monkeypatch.setenv("NETPULSE_JWT_SECRET", "synthetic-test-only-" + "x"*48)
    from app.services.deception import vm_svc
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("QEMU must not execute"))
    assert vm_svc.start_vm("any")["success"] is False
    source = Path(vm_svc.__file__).read_text()
    assert "subprocess" not in source
    assert "os.kill" not in source


def test_missing_jwt_secret_fails_closed(monkeypatch):
    monkeypatch.setenv("NETPULSE_JWT_SECRET", "synthetic-test-only-" + "x"*48)
    import app.core.security as security
    monkeypatch.delenv("NETPULSE_JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        importlib.reload(security)
    monkeypatch.setenv("NETPULSE_JWT_SECRET", "synthetic-test-only-" + "x"*48)
    importlib.reload(security)


def test_no_simulated_private_or_ai_suppression(monkeypatch):
    monkeypatch.setenv("NETPULSE_JWT_SECRET", "synthetic-test-only-" + "x"*48)
    from app.services.deception import alert_svc
    monkeypatch.setattr(alert_svc, "DECEPTION_ALERTS_ENABLED", True)
    monkeypatch.setattr(alert_svc, "_cooldown_ok", lambda _: True)
    monkeypatch.setattr(alert_svc, "_dispatch", lambda _: None)
    monkeypatch.setattr(alert_svc, "_ai_triage", lambda *args: {"suppress": True})
    record = {"type": "login_success", "device_id": "fixture", "src_ip": "10.0.0.1",
              "detail": {"simulated": True, "password": "SYNTHETIC-ONLY"}}
    assert len(alert_svc.evaluate(record)) == 1
    assert alert_svc.evaluate(record)[0]["detail"] == {}
