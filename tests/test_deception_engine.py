"""Tests del motor nativo de deception y sus listeners (Fase B).

Levantan listeners reales en 127.0.0.1 con puertos efímeros y verifican
que las interacciones del "atacante" queden registradas en el store.
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.deception import engine_svc, store_svc
from app.services.deception.listeners import (
    BannerListener,
    HttpListener,
    SshListener,
    TelnetListener,
    UdpListener,
)


@pytest.fixture()
def db_path(tmp_path, monkeypatch):
    db = tmp_path / "deception.db"
    monkeypatch.setattr(store_svc, "DB_PATH", db)
    return db


async def _read_until(reader, marker: bytes, timeout: float = 3.0) -> bytes:
    data = b""
    while marker not in data:
        chunk = await asyncio.wait_for(reader.read(512), timeout=timeout)
        if not chunk:
            break
        data += chunk
    return data


def test_telnet_captura_login_y_comandos(db_path):
    async def scenario():
        listener = TelnetListener("srv-01", "server", "127.0.0.1", 0)
        await listener.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
            await _read_until(reader, b"login:")
            writer.write(b"root\r\n")
            await writer.drain()
            await _read_until(reader, b"Password:")
            writer.write(b"root\r\n")
            await writer.drain()
            await _read_until(reader, b"# ")
            writer.write(b"whoami\r\n")
            await writer.drain()
            await _read_until(reader, b"# ")
            writer.write(b"id\r\n")
            await writer.drain()
            await _read_until(reader, b"# ")
            writer.close()
        finally:
            await listener.stop()

    asyncio.run(scenario())

    events = store_svc.get_events()
    types = [e["type"] for e in events]
    assert "connect" in types
    assert "login_attempt" in types
    assert "login_success" in types
    commands = [e["detail"].get("command") for e in events if e["type"] == "command"]
    assert "whoami" in commands
    assert "id" in commands


def test_http_panel_y_credenciales(db_path):
    async def scenario():
        listener = HttpListener("cam-01", "camera", "127.0.0.1", 0)
        await listener.start()
        try:
            # GET → panel de login con el vendor
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
            writer.write(b"GET /admin HTTP/1.0\r\nHost: x\r\n\r\n")
            await writer.drain()
            body = await asyncio.wait_for(reader.read(4096), timeout=3)
            assert b"Hikvision" in body
            writer.close()

            # POST → captura de credenciales
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
            payload = b"username=admin&password=1234"
            req = (
                b"POST /login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
            )
            writer.write(req)
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), timeout=3)
            writer.close()
        finally:
            await listener.stop()

    asyncio.run(scenario())

    events = store_svc.get_events()
    assert any(e["type"] == "http_request" for e in events)
    logins = [e for e in events if e["type"] == "login_attempt"]
    assert logins and logins[0]["username"] == "admin"
    assert logins[0]["detail"].get("password") == "1234"


def test_banner_rtsp_responde(db_path):
    async def scenario():
        listener = BannerListener("cam-01", "camera", "127.0.0.1", 0, proto="rtsp")
        await listener.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
            writer.write(b"OPTIONS rtsp://127.0.0.1 RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(512), timeout=3)
            assert b"RTSP/1.0 200" in resp
            writer.close()
        finally:
            await listener.stop()

    asyncio.run(scenario())
    assert any(e["type"] == "rtsp_request" for e in store_svc.get_events())


def test_udp_snmp_registra(db_path):
    async def scenario():
        listener = UdpListener("sw-01", "switch", "127.0.0.1", 0)
        await listener.start()
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol, remote_addr=("127.0.0.1", listener.port)
            )
            transport.sendto(b"\x30\x26\x02\x01\x00\x04\x06public")
            await asyncio.sleep(0.2)
            transport.close()
        finally:
            await listener.stop()

    asyncio.run(scenario())
    events = store_svc.get_events()
    assert any(e["type"] == "snmp_query" for e in events)


def _ssh_client_session(port: int) -> None:
    """Cliente SSH de prueba: acepta host key y ejecuta un comando."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1", port=port, username="root", password="toor",
        allow_agent=False, look_for_keys=False, timeout=5,
    )
    try:
        chan = client.invoke_shell()
        chan.send("whoami\n")
        chan.settimeout(2)
        try:
            chan.recv(4096)
        except Exception:  # noqa: BLE001
            pass
        chan.close()
    finally:
        client.close()


def test_ssh_captura_login_y_comando(db_path):
    async def scenario():
        listener = SshListener("srv-01", "server", "127.0.0.1", 0)
        await listener.start()
        try:
            await asyncio.to_thread(_ssh_client_session, listener.port)
        finally:
            await listener.stop()

    asyncio.run(scenario())

    events = store_svc.get_events()
    assert any(e["type"] == "login_success" and e["username"] == "root" for e in events)
    assert any(
        e["type"] == "command" and e["detail"].get("command") == "whoami"
        for e in events
    )


def test_engine_start_stop_bloqueado(db_path):
    """El motor heredado no arranca listeners en el plano de control.

    Los listeners deben vivir en una celda sensor validada; el contrato aquí
    es la negativa explícita y la ausencia de estado en ejecución.
    """

    async def scenario():
        report = await engine_svc.start()
        assert report["status"] == "blocked", report
        assert report["started"] == 0
        assert "sensor" in report["reason"]
        assert engine_svc.is_running() is False

        st = engine_svc.status()
        assert st["running"] is False
        assert st["count"] == 0
        assert st["state"] == "blocked"

        stop = await engine_svc.stop()
        assert stop["stopped"] == 0
        assert engine_svc.status()["running"] is False

    asyncio.run(scenario())
