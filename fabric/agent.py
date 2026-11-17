"""NetPulse — Fabric: agente de dispositivo (Fase 5a).

Corre **dentro** del contenedor señuelo del fabric. Sustituye el antiguo
bucle de espera: lee el manifiesto del dispositivo, instala un sink de
eventos JSONL y arranca un listener nativo por servicio declarado.

``/etc/fabric/device.json`` (montado read-only por el Device Runtime)::

    {
      "device_id": "pc-recepcion-01",
      "role": "pc",
      "persona": {"vendor": "dell", "os": "windows", "hostname": "RECEPCION-PC"},
      "services": [
        {"port": 22, "proto": "ssh", "engine": "native", "banner": "OpenSSH_8.9"},
        {"port": 80, "proto": "http", "engine": "native", "banner": null}
      ],
      "credentials": [
        {"username": "admin", "password": "admin123", "service": "ssh",
         "purpose": "Credencial señuelo"}
      ]
    }

Eventos: una línea JSON por evento en ``/var/log/fabric/events.jsonl``
(``flush`` tras cada escritura)::

    {"detail": {"password": "…capturada…"}, "device_id": "...",
     "proto": "ssh", "src_ip": "...", "src_port": 4242, "success": false,
     "ts": "2026-...Z", "type": "login_attempt", "username": "admin"}

Las credenciales **capturadas del atacante** (``password``/``username``
que prueba) SÍ se registran: son el objetivo del honeypot. Lo que nunca
se escribe es la **configuración del manifiesto**: ``device.json`` no se
pasa al sink y las claves de configuración (``credentials``, ``secret``,
``token``, ``authorization``, ``api_key``) se eliminan del ``detail``. El
control agrupa las capturadas en ``detail.credentials`` al ingerirlas.

La host key SSH se persiste en ``/var/log/fabric/keys/ssh_host_rsa_key``
(volumen persistente); ``NETPULSE_DECEPTION_SSH_HOST_KEY`` se fija **antes**
de importar los listeners para que ``app.core.settings`` la lea.

``engine: native`` usa el listener nativo por protocolo. Los motores
reales **Cowrie** y **OpenCanary** (Fase 11) se arrancan con
``fabric/engines.py`` si están instalados en la imagen: el agente genera
su configuración, taila su log nativo y normaliza cada registro al mismo
sink JSONL. Si el motor no está disponible, se avisa y se usa el listener
nativo (fallback). El resto de engines (dionaea, heralding, redishoneypot,
endlessh) siguen en el listener nativo. Un protocolo no soportado se omite
con warning; si ningún listener ni motor arranca, el agente sale con error
accionable (exit 1).
"""

import asyncio
import json
import logging
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)

CONFIG_ENV = "FABRIC_DEVICE_CONFIG"
LOG_DIR_ENV = "FABRIC_LOG_DIR"
HOST_KEY_ENV = "NETPULSE_DECEPTION_SSH_HOST_KEY"
DEFAULT_CONFIG = "/etc/fabric/device.json"
DEFAULT_LOG_DIR = "/var/log/fabric"
LISTEN_HOST = "0.0.0.0"

# Claves que se eliminan del detail: son **configuración** del dispositivo
# (manifiesto), no datos del atacante. Las credenciales *capturadas*
# (``password``/``username`` que el atacante prueba) SÍ se registran: son
# el objetivo del honeypot y el control las normaliza a
# ``detail.credentials``. ``device.json`` nunca se pasa al sink, así que
# el contenido del manifiesto no puede acabar en el JSONL.
_SENSITIVE_KEYS = frozenset({
    "credentials", "secret", "token",
    "authorization", "api_key",
})


class AgentConfigError(RuntimeError):
    """Configuración del agente inválida o sin listeners utilizables."""


class AgentPersona(BaseModel):
    """Identidad falsa del dispositivo (vendor/OS/hostname)."""

    model_config = ConfigDict(extra="ignore")

    vendor: str = "generic"
    os: str = "linux"
    hostname: str = "device"


class AgentService(BaseModel):
    """Servicio señuelo declarado en el manifiesto."""

    model_config = ConfigDict(extra="ignore")

    port: int = Field(..., ge=1, le=65535)
    proto: str = Field(..., min_length=1)
    engine: str = "native"
    banner: Optional[str] = None


class AgentCredential(BaseModel):
    """Credencial señuelo (solo se usa en la configuración del contenedor)."""

    model_config = ConfigDict(extra="ignore")

    username: str
    password: str
    service: str = ""
    purpose: str = ""


class DeviceConfig(BaseModel):
    """Contenido de ``/etc/fabric/device.json``."""

    model_config = ConfigDict(extra="ignore")

    device_id: str = Field(..., min_length=1)
    role: str = Field(default="pc", min_length=1)
    persona: AgentPersona = Field(default_factory=AgentPersona)
    services: list[AgentService] = Field(default_factory=list)
    credentials: list[AgentCredential] = Field(default_factory=list)


def load_device_config(path: Path | str) -> DeviceConfig:
    """Carga y valida ``device.json``; errores accionables."""
    config_path = Path(path)
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AgentConfigError(
            f"No se puede leer la configuración '{config_path}': {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise AgentConfigError(
            f"JSON inválido en '{config_path}': {exc}"
        ) from exc
    try:
        return DeviceConfig.model_validate(raw)
    except ValidationError as exc:
        errors = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors()
        )
        raise AgentConfigError(f"device.json inválido: {errors}") from exc


def _sanitize(value: Any) -> Any:
    """Copia recursiva sin claves sensibles (credenciales capturadas)."""
    if isinstance(value, dict):
        return {
            key: _sanitize(item)
            for key, item in value.items()
            if str(key).lower() not in _SENSITIVE_KEYS
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


class JsonlSink:
    """Sink de eventos: una línea JSON por evento con ``flush`` inmediato."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def __call__(
        self,
        device_id: str,
        src_ip: str,
        proto: str,
        event_type,
        *,
        detail: Optional[dict] = None,
        username: Optional[str] = None,
        success: bool = False,
        src_port: Optional[int] = None,
        ts: Optional[str] = None,
        **kwargs: Any,
    ) -> dict:
        record = {
            "ts": ts or datetime.now(timezone.utc).isoformat(),
            "device_id": device_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "proto": proto,
            "type": getattr(event_type, "value", event_type),
            "detail": _sanitize(detail or {}),
            "username": username,
            "success": bool(success),
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
        return record


def create_listeners(
    config: DeviceConfig,
    engine_ports: Optional[set[int]] = None,
) -> tuple[list[Any], list[str]]:
    """Instancia un listener nativo por servicio (sin arrancarlo).

    Devuelve ``(listeners, warnings)``. ``engine: native`` y engines
    desconocidos usan el listener nativo por protocolo; los protocolos no
    soportados se omiten con warning.

    ``engine_ports`` son los puertos ya servidos por un motor real
    (Cowrie/OpenCanary): no se abre un listener nativo en el mismo puerto.
    """
    from app.services.deception.listeners import build_listener

    claimed = set(engine_ports or ())
    listeners: list[Any] = []
    warnings: list[str] = []
    for service in config.services:
        proto = (service.proto or "").strip().lower()
        if service.port in claimed:
            continue
        if service.engine and service.engine.strip().lower() != "native":
            warnings.append(
                f"engine '{service.engine}' no enlazado; "
                f"se usa el listener nativo para '{proto}'"
            )
        listener = build_listener(
            config.device_id, config.role, LISTEN_HOST,
            service.port, proto, service.banner,
        )
        if listener is None:
            warnings.append(
                f"protocolo '{proto}' no soportado; se omite el servicio "
                f"{service.port}"
            )
            continue
        listeners.append(listener)
    return listeners, warnings


def _build_engines(config: DeviceConfig, sink: JsonlSink):
    """Registra los motores reales del dispositivo (Fase 11).

    Import perezoso: ``fabric.engines`` arrastra ``runtime.normalize``, que
    no hace falta cuando todos los servicios son nativos.
    """
    try:
        from fabric.engines import DEFAULT_ENGINES_DIR, ENGINES_DIR_ENV, build_supervisor
    except Exception:  # noqa: BLE001 - sin motores se sirve todo nativo
        logger.exception("[fabric-agent] no se pudo cargar el binding de motores")
        return None, [], []
    engines_dir = os.getenv(ENGINES_DIR_ENV, DEFAULT_ENGINES_DIR)
    return build_supervisor(config, engines_dir, emit=sink)


def _engine_ports(supervisor) -> set[int]:
    """Puertos servidos por motores reales (para no abrir listeners nativos)."""
    if supervisor is None:
        return set()
    return {state["port"] for state in supervisor.states}


async def run_agent(
    config_path: Optional[Path | str] = None,
    log_dir: Optional[Path | str] = None,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    """Carga la configuración, arranca listeners y espera TERM/INT."""
    config_file = Path(config_path or os.getenv(CONFIG_ENV, DEFAULT_CONFIG))
    log_root = Path(log_dir or os.getenv(LOG_DIR_ENV, DEFAULT_LOG_DIR))

    config = load_device_config(config_file)
    if not config.services:
        raise AgentConfigError(
            "device.json no declara servicios; el agente no tiene nada que servir"
        )

    # Debe fijarse antes de importar los listeners: settings lee la ruta
    # de la host key al cargarse.
    os.environ[HOST_KEY_ENV] = str(log_root / "keys" / "ssh_host_rsa_key")

    from app.services.deception.listeners.base import set_event_sink

    try:
        sink = JsonlSink(log_root / "events.jsonl")
    except OSError as exc:
        raise AgentConfigError(
            f"No se puede escribir el log de eventos en '{log_root}': {exc}"
        ) from exc
    set_event_sink(sink)

    # Fase 11: motores reales (Cowrie/OpenCanary) si están instalados.
    # Se registran antes de los listeners para reservar sus puertos.
    supervisor, engine_warnings, _fallbacks = _build_engines(config, sink)
    for warning in engine_warnings:
        logger.warning("[fabric-agent] %s", warning)

    listeners, warnings = create_listeners(
        config, engine_ports=_engine_ports(supervisor),
    )
    for warning in warnings:
        logger.warning("[fabric-agent] %s", warning)

    started: list[Any] = []
    for listener in listeners:
        try:
            await listener.start()
            started.append(listener)
        except Exception as exc:  # noqa: BLE001 - un servicio no debe tumbar el resto
            logger.error(
                "[fabric-agent] %s:%s (%s) no arrancó: %s",
                listener.host, listener.port, listener.proto, exc,
            )

    if supervisor is not None:
        supervisor.start()

    if not started and supervisor is None:
        set_event_sink(None)
        raise AgentConfigError(
            "ningún listener pudo arrancar; revisa services/proto/engine en device.json"
        )

    logger.info(
        "[fabric-agent] %s sirviendo %d listeners y %d motores reales (log=%s)",
        config.device_id, len(started),
        supervisor.running() if supervisor is not None else 0, sink.path,
    )

    stop = stop_event or asyncio.Event()
    if stop_event is None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):  # pragma: no cover
                pass

    try:
        await stop.wait()
    finally:
        if supervisor is not None:
            try:
                supervisor.stop()
            except Exception:  # noqa: BLE001
                logger.exception("[fabric-agent] error al parar los motores")
        for listener in started:
            try:
                await listener.stop()
            except Exception:  # noqa: BLE001
                logger.exception("[fabric-agent] error al parar %s", listener.proto)
        set_event_sink(None)
        logger.info("[fabric-agent] detenido")


def main() -> int:
    """Entrypoint del contenedor: logs a stdout, exit 1 si no arranca."""
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stdout,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        asyncio.run(run_agent())
    except AgentConfigError as exc:
        logger.error("[fabric-agent] %s", exc)
        return 1
    except KeyboardInterrupt:  # pragma: no cover - señal en primer plano
        return 0
    except Exception:  # noqa: BLE001
        logger.exception("[fabric-agent] fallo inesperado")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - arranque del contenedor
    sys.exit(main())
