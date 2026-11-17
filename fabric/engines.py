"""NetPulse — Fabric: binding de motores reales (Cowrie/OpenCanary) (Fase 11).

Corre **dentro** del contenedor del dispositivo, junto al agente
(``fabric/agent.py``). Cuando un servicio declara ``engine: cowrie`` o
``engine: opencanary`` y el motor está instalado en la imagen, este
módulo:

1. Genera la configuración del motor en ``/var/log/fabric/engines/<engine>/``
   (writable por uid 2000, junto al volumen de logs del agente).
2. Arranca el proceso del honeypot escuchando en el puerto declarado.
3. Taila su log nativo (JSON por línea) y convierte cada registro con
   ``runtime.normalize.normalize_raw(engine, device_id, record)`` al sink
   JSONL del agente (``/var/log/fabric/events.jsonl``). El forwarder y el
   control no cambian: ven el mismo formato que los listeners nativos.

Fallback
--------
Si el motor no está disponible (binario/paquete ausente) o no arranca, se
emite un warning y el agente usa el **listener nativo** de ese protocolo
(comportamiento de la Fase 5a). Nunca se cae el agente por un motor roto.

Supervisión
-----------
Un hilo por motor comprueba ``proc.poll()`` cada ``poll_interval``; si el
proceso muere se reinicia con backoff exponencial acotado
(``restart_backoff * 2**n``, máx. ``max_restarts`` = 3). Agotados los
reintentos el motor queda ``failed`` y no se vuelve a intentar (el
listener nativo, si existe, sigue sirviendo).

Seguridad
---------
- Sin ``docker``/``mininet``: solo ``subprocess`` y la stdlib.
- La configuración generada **no** contiene credenciales del manifiesto
  (Cowrie usa ``auth_class = AuthRandom``; OpenCanary no recibe usuarios).
- Los eventos normalizados pasan por ``normalize_raw``, que redacta las
  contraseñas capturadas del ``detail`` (el sink del agente añade además
  su propio filtro de claves sensibles).
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ``runtime.normalize`` vive en la raíz del repo (``/opt/dystopia`` en la
# imagen). El agente se ejecuta como script, así que la raíz no está en
# ``sys.path`` por defecto.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Engines con binding real en esta fase. El resto (dionaea, heralding,
# redishoneypot, endlessh) siguen en el listener nativo: sus imágenes
# requieren paquetes de sistema que no se pueden instalar por pip sobre la
# base pequeña del dispositivo (ver docs/FABRIC.md).
SUPPORTED_ENGINES = ("cowrie", "opencanary")

ENGINES_DIR_ENV = "FABRIC_ENGINES_DIR"
DEFAULT_ENGINES_DIR = "/var/log/fabric/engines"

# Nombre del ejecutable que debe existir para considerar el motor instalado.
BINARIES = {
    "cowrie": "cowrie",
    "opencanary": "opencanaryd",
}

# Ficheros de log nativos (JSON por línea) dentro del directorio del motor.
NATIVE_LOGS = {
    "cowrie": "var/log/cowrie/cowrie.json",
    "opencanary": "opencanary.log",
}

# Subdirectorios que Cowrie exige en su "state directory" (los crea
# ``cowrie init``; aquí se crean sin invocar el binario).
COWRIE_STATE_DIRS = (
    "var/log/cowrie",
    "var/lib/cowrie",
    "var/lib/cowrie/downloads",
    "var/lib/cowrie/tty",
    "var/run",
)

DEFAULT_MAX_RESTARTS = 3
DEFAULT_RESTART_BACKOFF = 1.0
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_TAIL_INTERVAL = 0.5
MAX_LINE_BYTES = 64 * 1024


def _head_fingerprint(path: Path) -> str:
    """SHA-256 de la primera línea (detecta rotación aunque el tamaño coincida)."""
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return ""
    if not chunk:
        return ""
    line, separator, _rest = chunk.partition(b"\n")
    return hashlib.sha256(line + separator).hexdigest()
MAX_FILE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class EnginePlan:
    """Configuración resuelta de un motor para un servicio del manifiesto."""

    engine: str
    device_id: str
    port: int
    proto: str
    workdir: Path
    config_path: Path
    log_path: Path
    command: tuple[str, ...]

    @property
    def key(self) -> str:
        """Clave única del motor (un proceso por dispositivo/puerto)."""
        return f"{self.engine}:{self.device_id}:{self.port}"


class EngineUnavailable(RuntimeError):
    """El motor no está instalado o no se puede configurar (fallback)."""


# ── Detección ───────────────────────────────────────────────


def engine_supported(engine: str) -> bool:
    """True si el engine tiene binding real en esta fase."""
    return (engine or "").strip().lower() in SUPPORTED_ENGINES


def find_binary(engine: str, which: Callable[[str], Optional[str]] = shutil.which) -> Optional[str]:
    """Ruta del ejecutable del motor, o ``None`` si no está instalado."""
    name = BINARIES.get((engine or "").strip().lower())
    if name is None:
        return None
    return which(name)


# ── Generación de configuración ─────────────────────────────


def _yaml_scalar(value: Any) -> str:
    """Escalar YAML mínimo (strings entre comillas dobles, números/bools tal cual)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def render_cowrie_config(
    device_id: str,
    port: int,
    proto: str,
    log_path: Path,
    *,
    persona_hostname: str = "device",
    ssh_banner: Optional[str] = None,
) -> str:
    """Genera ``cowrie.cfg`` para un único listener SSH o Telnet.

    Se usa ``listen_endpoints = tcp:<port>:interface=0.0.0.0`` (formato de
    Cowrie 3.x) y ``backend = shell`` con ``auth_class = AuthRandom``: el
    backend shell es el que emite ``cowrie.command.input`` y el login
    aleatorio evita que las credenciales del manifiesto viajen al motor.
    """
    proto = (proto or "ssh").strip().lower()
    banner = ssh_banner or "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
    ssh_enabled = proto == "ssh"
    telnet_enabled = proto == "telnet"
    lines = [
        "# Generado por fabric/engines.py (Fase 11) — no editar a mano.",
        f"# device={device_id} proto={proto} port={port}",
        "# Se coloca en <workdir>/etc/cowrie.cfg: Cowrie lo busca en el",
        "# state directory (cwd) y lo superpone a su cowrie.cfg.dist.",
        "",
        "[honeypot]",
        f"hostname = {_yaml_scalar(persona_hostname)}",
        f"sensor_name = {_yaml_scalar(f'cowrie-{device_id}')}",
        # Rutas relativas al cwd (el workdir del motor).
        "log_path = var/log/cowrie",
        "logtype = plain",
        "state_path = var/lib/cowrie",
        "download_path = var/lib/cowrie/downloads",
        "ttylog = false",
        "interactive_timeout = 180",
        "authentication_timeout = 120",
        "backend = shell",
        "auth_class = AuthRandom",
        "auth_class_parameters = 2, 5, 10",
        "timezone = UTC",
        "",
        "[shell]",
        "arch = linux-x64-lsb",
        "kernel_version = 6.1.0-21-amd64",
        "kernel_build_string = #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1",
        "hardware_platform = x86_64",
        "operating_system = GNU/Linux",
        f"ssh_version = {_yaml_scalar(banner.removeprefix('SSH-2.0-'))}",
        "",
        "[ssh]",
        f"enabled = {_yaml_scalar(ssh_enabled)}",
        f"version = {_yaml_scalar(banner)}",
        f"listen_endpoints = tcp:{port}:interface=0.0.0.0",
        "sftp_enabled = false",
        "forwarding = false",
        "forward_redirect = false",
        "forward_tunnel = false",
        "auth_none_enabled = false",
        "auth_keyboard_interactive_enabled = true",
        "auth_publickey_allow_any = true",
        "",
        "[telnet]",
        f"enabled = {_yaml_scalar(telnet_enabled)}",
        f"listen_endpoints = tcp:{port}:interface=0.0.0.0",
        "reported_port = 23",
        "",
        "# JSON por línea: el formato que consume runtime.normalize.",
        "# ``logfile`` es relativo al cwd (Cowrie no expande rutas absolutas",
        "# en este apartado); debe coincidir con NATIVE_LOGS['cowrie'].",
        "[output_jsonlog]",
        "enabled = true",
        "logfile = var/log/cowrie/cowrie.json",
        "epoch_timestamp = false",
        "",
        "[output_textlog]",
        "enabled = false",
        "logfile = var/log/cowrie/cowrie-textlog.log",
        "",
    ]
    return "\n".join(lines)


# Protocolo del manifiesto → módulo de OpenCanary.
_OPENCANARY_MODULES = {
    "ftp": "ftp",
    "ssh": "ssh",
    "telnet": "telnet",
    "http": "http",
    "https": "http",
    "mysql": "mysql",
    "smb": "smb",
}


def render_opencanary_config(
    device_id: str,
    port: int,
    proto: str,
    log_path: Path,
) -> str:
    """Genera ``opencanary.conf`` (JSON) con un único módulo activo.

    OpenCanary no permite dos módulos en el mismo puerto, así que se
    activa solo el módulo del protocolo declarado y se desactiva el resto.
    El logger es ``PyLogger`` con un ``FileHandler`` JSON por línea en
    ``log_path`` (el formato que consume ``runtime.normalize``).
    """
    module = _OPENCANARY_MODULES.get((proto or "").strip().lower())
    if module is None:
        raise EngineUnavailable(
            f"OpenCanary no soporta el protocolo '{proto}' "
            f"(soportados: {', '.join(sorted(_OPENCANARY_MODULES))})"
        )
    config: dict[str, Any] = {
        "device.node_id": device_id,
        "ip.ignorelist": [],
        "logtype.ignorelist": [],
        "git.enabled": False,
    }
    for name in sorted(set(_OPENCANARY_MODULES.values())):
        config[f"{name}.enabled"] = name == module
        if name == module:
            config[f"{name}.port"] = port
    if module == "ssh":
        config["ssh.version"] = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    if module == "http":
        config["http.banner"] = "Apache/2.4.41 (Ubuntu)"
        config["http.skin"] = "nasLogin"
    if module == "ftp":
        config["ftp.banner"] = "FTP server ready"
        config["ftp.log_auth_attempt_initiated"] = True
    if module == "telnet":
        config["telnet.banner"] = "Ubuntu 20.04 LTS"
    if module == "mysql":
        config["mysql.banner"] = "5.5.43-0ubuntu0.14.04.1"
    config["logger"] = {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {"plain": {"format": "%(message)s"}},
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": str(log_path),
                }
            },
        },
    }
    return json.dumps(config, indent=4, sort_keys=True) + "\n"


def plan_engine(
    engine: str,
    device_id: str,
    port: int,
    proto: str,
    engines_dir: Path | str = DEFAULT_ENGINES_DIR,
    *,
    persona_hostname: str = "device",
    ssh_banner: Optional[str] = None,
    binary: Optional[str] = None,
) -> EnginePlan:
    """Resuelve configuración, rutas y comando de un motor.

    Lanza ``EngineUnavailable`` si el engine no tiene binding real, si el
    binario no está instalado o si el protocolo no está soportado por el
    motor. El llamante hace fallback al listener nativo.
    """
    engine = (engine or "").strip().lower()
    if not engine_supported(engine):
        raise EngineUnavailable(f"engine '{engine}' sin binding real (Fase 11)")
    path = binary or find_binary(engine)
    if path is None:
        raise EngineUnavailable(
            f"el motor '{engine}' no está instalado "
            f"(falta '{BINARIES[engine]}'); usa la imagen con motores"
        )
    proto = (proto or "").strip().lower()
    workdir = Path(engines_dir) / engine
    log_path = workdir / NATIVE_LOGS[engine]
    if engine == "cowrie":
        if proto not in ("ssh", "telnet"):
            raise EngineUnavailable(
                f"Cowrie solo sirve ssh/telnet (recibido '{proto}')"
            )
        # Cowrie 3.x lee ``etc/cowrie.cfg`` desde el state directory (cwd);
        # no acepta ``--config``. ``COWRIE_STDOUT=yes`` (lo pone el
        # supervisor) lo ejecuta en primer plano sin pidfile.
        config_path = workdir / "etc" / "cowrie.cfg"
        command = (path, "start")
    else:
        config_path = workdir / "opencanary.conf"
        # El wrapper oficial arranca en primer plano con --dev.
        command = (path, "--dev", "--config", str(config_path))
    return EnginePlan(
        engine=engine,
        device_id=device_id,
        port=port,
        proto=proto,
        workdir=workdir,
        config_path=config_path,
        log_path=log_path,
        command=command,
    )


def write_engine_config(
    plan: EnginePlan,
    *,
    persona_hostname: str = "device",
    ssh_banner: Optional[str] = None,
) -> Path:
    """Escribe la configuración del motor (0600) y prepara su directorio."""
    plan.workdir.mkdir(parents=True, exist_ok=True)
    os.chmod(plan.workdir, 0o700)
    if plan.engine == "cowrie":
        for relative in COWRIE_STATE_DIRS:
            (plan.workdir / relative).mkdir(parents=True, exist_ok=True)
        plan.config_path.parent.mkdir(parents=True, exist_ok=True)
        content = render_cowrie_config(
            plan.device_id, plan.port, plan.proto, plan.log_path,
            persona_hostname=persona_hostname, ssh_banner=ssh_banner,
        )
    else:
        content = render_opencanary_config(
            plan.device_id, plan.port, plan.proto, plan.log_path,
        )
    tmp = plan.config_path.with_suffix(plan.config_path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, plan.config_path)
    return plan.config_path


# ── Lectura del log nativo ──────────────────────────────────


@dataclass
class _Tail:
    """Cursor de un fichero nativo (inodo + offset + huella), tolerante a rotación."""

    dev: int = -1
    ino: int = -1
    offset: int = 0
    head: str = ""

    def read(self, path: Path) -> list[Any]:
        """Devuelve los registros completos nuevos (JSON) o ``[]``."""
        try:
            info = path.stat()
        except OSError:
            return []
        if not info.st_size or info.st_size > MAX_FILE_BYTES:
            return []
        head = _head_fingerprint(path)
        if (
            info.st_dev != self.dev
            or info.st_ino != self.ino
            or info.st_size < self.offset
            or (self.offset > 0 and head != self.head)
        ):
            self.dev, self.ino, self.offset = info.st_dev, info.st_ino, 0
        if self.offset >= info.st_size:
            self.head = head
            return []
        try:
            with open(path, "rb") as handle:
                handle.seek(self.offset)
                data = handle.read(info.st_size - self.offset)
        except OSError:
            return []
        complete, _, _partial = data.rpartition(b"\n")
        if not complete:
            return []
        self.offset += len(complete) + 1
        self.head = head
        records: list[Any] = []
        for line in complete.split(b"\n"):
            line = line.rstrip(b"\r")
            if not line.strip() or len(line) > MAX_LINE_BYTES:
                continue
            try:
                record = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                continue
            if isinstance(record, dict):
                records.append(record)
        return records


# ── Supervisor ──────────────────────────────────────────────


@dataclass
class EngineState:
    """Estado observable de un motor (para ``/status`` y tests)."""

    key: str
    engine: str
    device_id: str
    port: int
    proto: str
    status: str = "pending"  # pending|running|restarting|failed|stopped
    pid: int = 0
    restarts: int = 0
    events: int = 0
    errors: int = 0
    last_error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "engine": self.engine,
            "device_id": self.device_id,
            "port": self.port,
            "proto": self.proto,
            "status": self.status,
            "pid": self.pid,
            "restarts": self.restarts,
            "events": self.events,
            "errors": self.errors,
            "last_error": self.last_error,
        }


class EngineSupervisor:
    """Arranca, taila y supervisa los motores reales de un dispositivo.

    Un único hilo de supervisión comprueba todos los motores y taila sus
    logs, así que el coste es constante con el número de servicios. Cada
    motor es independiente: si uno falla, los demás siguen.
    """

    def __init__(
        self,
        device_id: str,
        engines_dir: Path | str = DEFAULT_ENGINES_DIR,
        *,
        emit: Optional[Callable[..., Any]] = None,
        popen: Callable[..., Any] = subprocess.Popen,
        which: Callable[[str], Optional[str]] = shutil.which,
        max_restarts: int = DEFAULT_MAX_RESTARTS,
        restart_backoff: float = DEFAULT_RESTART_BACKOFF,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        tail_interval: float = DEFAULT_TAIL_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.device_id = device_id
        self.engines_dir = Path(engines_dir)
        self._emit = emit
        self._popen = popen
        self._which = which
        self._max_restarts = max_restarts
        self._backoff = restart_backoff
        self._poll_interval = poll_interval
        self._tail_interval = tail_interval
        self._clock = clock
        self._sleep = sleep
        self._plans: dict[str, EnginePlan] = {}
        self._procs: dict[str, Any] = {}
        self._states: dict[str, EngineState] = {}
        self._tails: dict[str, _Tail] = {}
        self._next_retry: dict[str, float] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # ── Ciclo de vida ───────────────────────────────────────

    def add(
        self,
        engine: str,
        port: int,
        proto: str,
        *,
        persona_hostname: str = "device",
        ssh_banner: Optional[str] = None,
    ) -> EngineState:
        """Registra un motor; ``EngineUnavailable`` si no se puede usar."""
        plan = plan_engine(
            engine, self.device_id, port, proto, self.engines_dir,
            persona_hostname=persona_hostname, ssh_banner=ssh_banner,
            binary=self._which(BINARIES.get(engine, "")),
        )
        write_engine_config(
            plan, persona_hostname=persona_hostname, ssh_banner=ssh_banner,
        )
        state = EngineState(
            key=plan.key, engine=plan.engine, device_id=self.device_id,
            port=port, proto=plan.proto,
        )
        with self._lock:
            self._plans[plan.key] = plan
            self._states[plan.key] = state
            self._tails[plan.key] = _Tail()
        return state

    def start(self) -> None:
        """Arranca los motores registrados y el hilo de supervisión."""
        for key in list(self._plans):
            self._start_engine(key)
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name=f"fabric-engines-{self.device_id}", daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Detiene el hilo, mata los procesos y espera a que salgan."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(5.0, self._poll_interval * 2))
            self._thread = None
        with self._lock:
            procs = list(self._procs.items())
            self._procs.clear()
            for key, proc in procs:
                state = self._states.get(key)
                if state is not None:
                    state.status = "stopped"
        for _key, proc in procs:
            self._terminate(proc)

    @property
    def states(self) -> list[dict]:
        """Estado de cada motor (sin rutas ni configuración)."""
        with self._lock:
            return [state.as_dict() for state in self._states.values()]

    def running(self) -> int:
        """Número de motores con proceso vivo."""
        with self._lock:
            return sum(1 for state in self._states.values() if state.status == "running")

    # ── Procesos ────────────────────────────────────────────

    def _start_engine(self, key: str) -> bool:
        """Arranca el proceso del motor; False si falla (se reintenta después)."""
        plan = self._plans[key]
        state = self._states[key]
        env = dict(os.environ)
        if plan.engine == "cowrie":
            # Primer plano sin pidfile: el supervisor controla el ciclo de
            # vida y mata el proceso directamente (``cowrie start`` hace
            # exec de twistd, así que el pid es el del honeypot).
            env["COWRIE_STDOUT"] = "yes"
        try:
            proc = self._popen(
                list(plan.command),
                cwd=str(plan.workdir),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            self._record_failure(key, f"no se pudo arrancar '{plan.engine}': {exc}")
            return False
        with self._lock:
            self._procs[key] = proc
            state.pid = int(getattr(proc, "pid", 0) or 0)
            state.status = "running"
            state.last_error = None
        logger.info(
            "[fabric-engines] %s %s:%s arrancado (pid=%s)",
            plan.engine, plan.device_id, plan.port, state.pid,
        )
        return True

    def _record_failure(self, key: str, error: str) -> None:
        """Cuenta el fallo y programa el siguiente reintento (backoff acotado)."""
        state = self._states[key]
        with self._lock:
            state.errors += 1
            state.last_error = error
            state.pid = 0
            if state.restarts >= self._max_restarts:
                state.status = "failed"
                logger.error(
                    "[fabric-engines] %s agotó los reintentos: %s",
                    state.engine, error,
                )
                return
            delay = self._backoff * (2 ** state.restarts)
            state.restarts += 1
            state.status = "restarting"
            self._next_retry[key] = self._clock() + delay
        logger.warning(
            "[fabric-engines] %s (%s:%s) falló: %s; reintento %d/%d en %.1fs",
            state.engine, state.device_id, state.port, error,
            state.restarts, self._max_restarts, delay,
        )

    def _check(self, key: str) -> None:
        """Comprueba el proceso y lo reinicia si murió (con backoff)."""
        with self._lock:
            state = self._states[key]
            proc = self._procs.get(key)
        if state.status == "failed":
            return
        if proc is not None:
            code = proc.poll()
            if code is None:
                return
            with self._lock:
                self._procs.pop(key, None)
            self._record_failure(key, f"el proceso terminó (rc={code})")
            return
        retry_at = self._next_retry.get(key)
        if retry_at is not None and self._clock() >= retry_at:
            self._next_retry.pop(key, None)
            self._start_engine(key)

    def _terminate(self, proc: Any) -> None:
        """SIGTERM y, si no sale en 3 s, SIGKILL (sin excepciones)."""
        try:
            if proc.poll() is not None:
                return
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:  # noqa: BLE001 - best effort
                proc.kill()
        except Exception:  # noqa: BLE001 - el proceso puede haber desaparecido
            logger.debug("[fabric-engines] error al terminar el proceso", exc_info=True)

    # ── Tail + normalización ────────────────────────────────

    def drain(self) -> int:
        """Lee los registros nuevos de todos los motores y los emite.

        Devuelve el número de eventos emitidos. Un registro inválido se
        cuenta como error y no detiene el resto.
        """
        emitted = 0
        for key, plan in list(self._plans.items()):
            with self._lock:
                tail = self._tails[key]
                state = self._states[key]
            for record in tail.read(plan.log_path):
                event = self._normalize(plan, record)
                if event is None:
                    with self._lock:
                        state.errors += 1
                    continue
                if self._emit is None:
                    continue
                try:
                    self._emit(**event)
                except Exception as exc:  # noqa: BLE001 - el sink no tumba el motor
                    with self._lock:
                        state.errors += 1
                        state.last_error = f"emit falló: {exc}"
                    logger.exception("[fabric-engines] emit falló para %s", plan.engine)
                    continue
                with self._lock:
                    state.events += 1
                emitted += 1
        return emitted

    def _normalize(self, plan: EnginePlan, record: dict) -> Optional[dict]:
        """Registro nativo → argumentos del sink (o ``None`` si se descarta)."""
        try:
            from runtime.normalize import NormalizeError, normalize_raw

            event = normalize_raw(plan.engine, self.device_id, record)
        except NormalizeError as exc:
            logger.debug("[fabric-engines] %s: registro descartado: %s", plan.engine, exc)
            return None
        except Exception:  # noqa: BLE001 - import/validación inesperada
            logger.exception("[fabric-engines] %s: no se pudo normalizar", plan.engine)
            return None
        if event is None:
            return None
        detail = dict(event.get("detail") or {})
        detail.setdefault("engine", plan.engine)
        return {
            "device_id": self.device_id,
            "src_ip": event["src_ip"],
            "proto": event["proto"],
            "event_type": event["type"],
            "detail": detail,
            "username": detail.get("username"),
            "success": event["type"] == "login_success",
            "src_port": event.get("src_port"),
            "ts": event.get("observed_at"),
        }

    # ── Hilo ────────────────────────────────────────────────

    def _loop(self) -> None:
        """Supervisión + tail en un único hilo daemon."""
        last_tail = 0.0
        while not self._stop.is_set():
            now = self._clock()
            for key in list(self._plans):
                try:
                    self._check(key)
                except Exception:  # noqa: BLE001 - un motor no tumba el hilo
                    logger.exception("[fabric-engines] fallo supervisando %s", key)
            if now - last_tail >= self._tail_interval:
                try:
                    self.drain()
                except Exception:  # noqa: BLE001
                    logger.exception("[fabric-engines] fallo en el tail")
                last_tail = now
            self._stop.wait(self._poll_interval)


def build_supervisor(
    config: Any,
    engines_dir: Path | str = DEFAULT_ENGINES_DIR,
    *,
    emit: Optional[Callable[..., Any]] = None,
    **kwargs: Any,
) -> tuple[Optional[EngineSupervisor], list[str], list[tuple[str, int, str]]]:
    """Registra los motores reales de un ``DeviceConfig``.

    Devuelve ``(supervisor, warnings, fallbacks)``:

    - ``supervisor`` es ``None`` si no hay ningún motor real utilizable.
    - ``warnings`` explica cada motor que cae al listener nativo.
    - ``fallbacks`` lista ``(proto, port, engine)`` que el agente debe
      servir con el listener nativo.
    """
    warnings: list[str] = []
    fallbacks: list[tuple[str, int, str]] = []
    supervisor: Optional[EngineSupervisor] = None
    for service in config.services:
        engine = (service.engine or "native").strip().lower()
        if engine == "native":
            continue
        if not engine_supported(engine):
            warnings.append(
                f"engine '{engine}' sin binding real (Fase 11); "
                f"se usa el listener nativo para '{service.proto}'"
            )
            fallbacks.append((service.proto, service.port, engine))
            continue
        try:
            if supervisor is None:
                supervisor = EngineSupervisor(
                    config.device_id, engines_dir, emit=emit, **kwargs,
                )
            supervisor.add(
                engine, service.port, service.proto,
                persona_hostname=config.persona.hostname,
                ssh_banner=service.banner,
            )
        except EngineUnavailable as exc:
            warnings.append(
                f"engine '{engine}' no disponible ({exc}); "
                f"se usa el listener nativo para '{service.proto}'"
            )
            fallbacks.append((service.proto, service.port, engine))
    # Si ningún motor llegó a registrarse, no hay supervisor que arrancar.
    if supervisor is not None and not supervisor.states:
        supervisor = None
    return supervisor, warnings, fallbacks


__all__ = [
    "BINARIES",
    "DEFAULT_ENGINES_DIR",
    "EnginePlan",
    "EngineState",
    "EngineSupervisor",
    "EngineUnavailable",
    "NATIVE_LOGS",
    "SUPPORTED_ENGINES",
    "build_supervisor",
    "engine_supported",
    "find_binary",
    "plan_engine",
    "render_cowrie_config",
    "render_opencanary_config",
    "write_engine_config",
]
