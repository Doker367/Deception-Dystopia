"""Pruebas del binding de motores reales (Cowrie/OpenCanary, Fase 11).

Cubren la resolución de configuración, la generación de ficheros, el tail
de logs nativos, la normalización al sink del agente, el fallback al
listener nativo y la supervisión con reinicio y backoff.

No arrancan procesos reales: ``popen`` y ``which`` se inyectan.
"""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from fabric.engines import (  # noqa: E402
    EngineSupervisor,
    EngineUnavailable,
    _Tail,
    build_supervisor,
    engine_supported,
    find_binary,
    plan_engine,
    render_cowrie_config,
    render_opencanary_config,
    write_engine_config,
)

FIXTURES = REPO / "deploy" / "honeypots" / "fixtures"


# ── Detección ───────────────────────────────────────────────


@pytest.mark.parametrize("engine", ["cowrie", "OpenCanary", " opencanary "])
def test_engine_supported(engine):
    assert engine_supported(engine) is True


@pytest.mark.parametrize("engine", ["native", "dionaea", "heralding", "", "x"])
def test_engine_no_soportado(engine):
    assert engine_supported(engine) is False


def test_find_binary_inyectado():
    assert find_binary("cowrie", which=lambda name: f"/usr/bin/{name}") == "/usr/bin/cowrie"
    assert find_binary("cowrie", which=lambda name: None) is None
    assert find_binary("native", which=lambda name: "/x") is None


# ── Plan ────────────────────────────────────────────────────


def test_plan_cowrie_ssh(tmp_path):
    plan = plan_engine(
        "cowrie", "pc-01", 22, "ssh", tmp_path, binary="/usr/bin/cowrie",
    )
    assert plan.engine == "cowrie"
    assert plan.port == 22
    assert plan.config_path == tmp_path / "cowrie" / "etc" / "cowrie.cfg"
    assert plan.log_path == tmp_path / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"
    assert plan.command == ("/usr/bin/cowrie", "start")
    assert plan.key == "cowrie:pc-01:22"


def test_plan_cowrie_proto_invalido(tmp_path):
    with pytest.raises(EngineUnavailable):
        plan_engine("cowrie", "pc-01", 80, "http", tmp_path, binary="/usr/bin/cowrie")


def test_plan_opencanary_http(tmp_path):
    plan = plan_engine(
        "opencanary", "cam-01", 80, "http", tmp_path, binary="/usr/bin/opencanaryd",
    )
    assert plan.engine == "opencanary"
    assert plan.config_path == tmp_path / "opencanary" / "opencanary.conf"
    assert plan.command == (
        "/usr/bin/opencanaryd", "--dev", "--config",
        str(tmp_path / "opencanary" / "opencanary.conf"),
    )


def test_plan_sin_binario(tmp_path):
    with pytest.raises(EngineUnavailable) as excinfo:
        plan_engine("cowrie", "pc-01", 22, "ssh", tmp_path, binary=None)
    assert "no está instalado" in str(excinfo.value)


def test_plan_engine_desconocido(tmp_path):
    with pytest.raises(EngineUnavailable):
        plan_engine("dionaea", "pc-01", 445, "smb", tmp_path, binary="/x")


# ── Configuración generada ──────────────────────────────────


def test_render_cowrie_config(tmp_path):
    config = render_cowrie_config(
        "pc-01", 2222, "ssh", tmp_path / "cowrie.json",
        persona_hostname="RECEPCION-PC", ssh_banner="SSH-2.0-OpenSSH_8.9",
    )
    assert "listen_endpoints = tcp:2222:interface=0.0.0.0" in config
    assert "auth_class = AuthRandom" in config
    assert "[output_jsonlog]" in config
    assert "enabled = true" in config
    assert "logfile = var/log/cowrie/cowrie.json" in config
    assert "hostname = \"RECEPCION-PC\"" in config
    assert "SSH-2.0-OpenSSH_8.9" in config
    # Nunca credenciales del manifiesto en la config del motor.
    assert "password" not in config.lower()
    assert "credentials" not in config.lower()


def test_render_cowrie_telnet(tmp_path):
    config = render_cowrie_config("pc-01", 23, "telnet", tmp_path / "c.json")
    assert "[telnet]" in config
    assert "enabled = true" in config.split("[telnet]")[1].split("[")[0]


def test_render_opencanary_config(tmp_path):
    config = render_opencanary_config(
        "cam-01", 80, "http", tmp_path / "opencanary.log",
    )
    assert "80" in config
    assert "http" in config
    assert "password" not in config.lower()


def test_write_engine_config(tmp_path):
    plan = plan_engine(
        "cowrie", "pc-01", 22, "ssh", tmp_path, binary="/usr/bin/cowrie",
    )
    path = write_engine_config(plan, persona_hostname="PC")
    assert path.exists()
    assert "listen_endpoints = tcp:22" in path.read_text()


# ── Tail ────────────────────────────────────────────────────


def test_tail_lee_solo_lineas_completas(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text('{"a": 1}\n{"b": 2}\n{"partial":')
    tail = _Tail()
    records = tail.read(log)
    assert records == [{"a": 1}, {"b": 2}]
    # La línea parcial no se consume hasta que se completa.
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(" 3}\n")
    assert tail.read(log) == [{"partial": 3}]


def test_tail_detecta_rotacion(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text('{"a": 1}\n')
    tail = _Tail()
    assert tail.read(log) == [{"a": 1}]
    # Rotación: mismo tamaño o menor, contenido distinto.
    log.write_text('{"b": 2}\n')
    assert tail.read(log) == [{"b": 2}]


def test_tail_ignora_json_invalido(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text('no-json\n{"ok": 1}\n')
    assert _Tail().read(log) == [{"ok": 1}]


# ── Supervisor y normalización ──────────────────────────────


class _FakeProc:
    def __init__(self, pid=4242, exit_code=None):
        self.pid = pid
        self._exit_code = exit_code
        self.terminated = False
        self.killed = False

    def poll(self):
        return self._exit_code

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return self._exit_code or 0


def _supervisor(tmp_path, emit, procs=None, **kwargs):
    procs = procs if procs is not None else [_FakeProc()]

    def popen(*args, **kw):
        return procs.pop(0) if procs else _FakeProc()

    return EngineSupervisor(
        "pc-01", tmp_path, emit=emit, popen=popen,
        which=lambda name: f"/usr/bin/{name}", **kwargs,
    )


def test_supervisor_emite_eventos_normalizados(tmp_path):
    emitted = []
    supervisor = _supervisor(tmp_path, lambda **kw: emitted.append(kw))
    supervisor.add("cowrie", 22, "ssh")

    # Registro real de Cowrie (fixture del repo).
    record = json.loads((FIXTURES / "cowrie.jsonl").read_text().splitlines()[0])
    log = tmp_path / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(json.dumps(record) + "\n")

    assert supervisor.drain() == 1
    event = emitted[0]
    assert event["device_id"] == "pc-01"
    assert event["src_ip"] == "203.0.113.9"
    assert event["proto"] == "ssh"
    assert event["detail"]["engine"] == "cowrie"
    assert event["event_type"]


def test_supervisor_cuenta_registros_invalidos(tmp_path):
    emitted = []
    supervisor = _supervisor(tmp_path, lambda **kw: emitted.append(kw))
    supervisor.add("cowrie", 22, "ssh")
    log = tmp_path / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text('{"eventid": "desconocido"}\n')

    assert supervisor.drain() == 0
    state = supervisor.states[0]
    assert state["errors"] == 1


def test_supervisor_reinicia_con_backoff(tmp_path):
    emitted = []
    procs = [_FakeProc(pid=1, exit_code=1), _FakeProc(pid=2, exit_code=None)]
    supervisor = _supervisor(
        tmp_path, lambda **kw: emitted.append(kw), procs=procs,
        max_restarts=3, restart_backoff=1.0, clock=lambda: 100.0,
    )
    supervisor.add("cowrie", 22, "ssh")
    key = supervisor.states[0]["key"]

    assert supervisor._start_engine(key) is True
    # El proceso muere: el chequeo programa un reintento con backoff.
    supervisor._check(key)
    state = supervisor.states[0]
    assert state["status"] == "restarting"
    assert state["restarts"] == 1

    # Tras el backoff, el siguiente chequeo lo relanza.
    supervisor._next_retry[key] = 0.0
    supervisor._check(key)
    state = supervisor.states[0]
    assert state["status"] == "running"
    assert state["pid"] == 2


def test_supervisor_agota_reintentos(tmp_path):
    emitted = []
    procs = [_FakeProc(pid=1, exit_code=1) for _ in range(5)]
    supervisor = _supervisor(
        tmp_path, lambda **kw: emitted.append(kw), procs=procs,
        max_restarts=1, restart_backoff=0.0, clock=lambda: 0.0,
    )
    supervisor.add("cowrie", 22, "ssh")
    key = supervisor.states[0]["key"]
    supervisor._start_engine(key)
    supervisor._check(key)  # primer fallo → reintento 1
    supervisor._next_retry[key] = 0.0
    supervisor._check(key)  # relanza (pid 1, muere)
    supervisor._check(key)  # segundo fallo → failed
    assert supervisor.states[0]["status"] == "failed"


def test_supervisor_stop_mata_procesos(tmp_path):
    proc = _FakeProc(pid=7)
    supervisor = _supervisor(tmp_path, lambda **kw: None, procs=[proc])
    supervisor.add("cowrie", 22, "ssh")
    supervisor._start_engine(supervisor.states[0]["key"])
    supervisor.stop()
    assert proc.terminated is True


# ── build_supervisor / fallback ─────────────────────────────


class _Config:
    def __init__(self, services, device_id="pc-01", hostname="PC"):
        self.device_id = device_id
        self.services = services
        self.persona = type("P", (), {"hostname": hostname})()


class _Service:
    def __init__(self, port, proto, engine, banner=None):
        self.port = port
        self.proto = proto
        self.engine = engine
        self.banner = banner


def test_build_supervisor_native_no_crea_supervisor(tmp_path):
    supervisor, warnings, fallbacks = build_supervisor(
        _Config([_Service(22, "ssh", "native")]), tmp_path,
        which=lambda name: "/usr/bin/x",
    )
    assert supervisor is None
    assert warnings == [] and fallbacks == []


def test_build_supervisor_engine_sin_binding_cae_a_nativo(tmp_path):
    supervisor, warnings, fallbacks = build_supervisor(
        _Config([_Service(445, "smb", "dionaea")]), tmp_path,
        which=lambda name: "/usr/bin/x",
    )
    assert supervisor is None
    assert fallbacks == [("smb", 445, "dionaea")]
    assert "sin binding real" in warnings[0]


def test_build_supervisor_sin_binario_cae_a_nativo(tmp_path):
    supervisor, warnings, fallbacks = build_supervisor(
        _Config([_Service(22, "ssh", "cowrie")]), tmp_path,
        which=lambda name: None,
    )
    assert supervisor is None
    assert fallbacks == [("ssh", 22, "cowrie")]
    assert "no disponible" in warnings[0]


def test_build_supervisor_registra_motor_real(tmp_path):
    supervisor, warnings, fallbacks = build_supervisor(
        _Config([_Service(22, "ssh", "cowrie", banner="SSH-2.0-OpenSSH_8.9")]),
        tmp_path, which=lambda name: "/usr/bin/cowrie",
    )
    assert supervisor is not None
    assert warnings == [] and fallbacks == []
    assert supervisor.states[0]["engine"] == "cowrie"
    assert supervisor.states[0]["port"] == 22
