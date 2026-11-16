"""Listener nativo base (asyncio).

Gestiona el ciclo de vida de un servidor TCP y delega el manejo de cada
conexión a la subclase. Centraliza el registro de eventos vía
``telemetry_svc`` para que ningún listener se olvide de reportar.
"""

import asyncio
import inspect
import logging
from typing import Callable, Optional

from app.services.deception import telemetry_svc

logger = logging.getLogger(__name__)

READ_TIMEOUT = 30.0  # segundos de inactividad antes de cerrar

# Sink de eventos inyectable (p. ej. el agente del fabric escribe JSONL).
# Firma: sink(device_id, src_ip, proto, event_type, **kwargs) → dict | None.
EventSink = Callable[..., object]
_event_sink: Optional[EventSink] = None


def set_event_sink(sink: Optional[EventSink]) -> None:
    """Instala (o retira con ``None``) el sink global de eventos."""
    global _event_sink
    _event_sink = sink


def get_event_sink() -> Optional[EventSink]:
    """Sink activo, o ``None`` si los eventos van a ``telemetry_svc``."""
    return _event_sink


def _call_sink(sink: EventSink, device_id: str, src_ip: str, proto: str,
               event_type, **kwargs):
    return sink(device_id, src_ip, proto, event_type, **kwargs)


async def _emit_with_sink(sink: EventSink, device_id: str, src_ip: str,
                          proto: str, event_type, **kwargs):
    """Invoca el sink admitiendo implementaciones síncronas o asíncronas."""
    result = _call_sink(sink, device_id, src_ip, proto, event_type, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


async def emit_event(device_id: str, src_ip: str, proto: str, event_type, **kwargs):
    """Emite un evento asíncrono: sink si existe, si no ``telemetry_svc``."""
    sink = get_event_sink()
    if sink is not None:
        return await _emit_with_sink(
            sink, device_id, src_ip, proto, event_type, **kwargs
        )
    return await telemetry_svc.emit(device_id, src_ip, proto, event_type, **kwargs)


def emit_sync(device_id: str, src_ip: str, proto: str, event_type, **kwargs):
    """Emite desde un hilo (SSH): sink si existe, si no ``telemetry_svc``.

    Un sink asíncrono se ejecuta con ``asyncio.run`` (el listener SSH corre
    en un thread sin loop propio).
    """
    sink = get_event_sink()
    if sink is None:
        return telemetry_svc.emit_sync(device_id, src_ip, proto, event_type, **kwargs)
    result = _call_sink(sink, device_id, src_ip, proto, event_type, **kwargs)
    if inspect.isawaitable(result):
        return asyncio.run(result)
    return result


async def read_line(reader: asyncio.StreamReader,
                    timeout: float = READ_TIMEOUT) -> Optional[str]:
    """Lee una línea (hasta \\n) con timeout; None si se cierra o expira."""
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except asyncio.TimeoutError:
        return None
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace").strip("\r\n")


class BaseListener:
    """Servidor TCP señuelo para un dispositivo y servicio concretos."""

    proto: str = "tcp"

    def __init__(self, device_id: str, role: str, host: str, port: int,
                 banner: Optional[str] = None, proto: Optional[str] = None):
        self.device_id = device_id
        self.role = role
        self.host = host
        self.port = port
        self.banner = banner
        self.vendor = None
        if proto:
            self.proto = proto
        self._server: Optional[asyncio.AbstractServer] = None

    # ── Ciclo de vida ────────────────────────────────────────

    async def start(self) -> None:
        """Enlaza el socket; actualiza ``self.port`` si era efímero (0)."""
        self._server = await asyncio.start_server(self._client, self.host, self.port)
        sockets = self._server.sockets or []
        if sockets:
            self.port = sockets[0].getsockname()[1]
        logger.info("[deception] %s %s:%s escuchando (%s)",
                    self.proto, self.host, self.port, self.device_id)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._server = None

    # ── Conexión ─────────────────────────────────────────────

    async def _client(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip, src_port = peer[0], peer[1]
        await self.emit(src_ip, "connect", src_port=src_port)
        try:
            await self.handle(reader, writer, src_ip, src_port)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("[deception] %s error con %s: %s", self.proto, src_ip, exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                     src_ip: str, src_port: int) -> None:
        raise NotImplementedError

    # ── Utilidades ───────────────────────────────────────────

    async def emit(self, src_ip: str, event_type, **kwargs) -> dict:
        """Reporta un evento; usa el sink global si está instalado."""
        return await emit_event(
            self.device_id, src_ip, self.proto, event_type, **kwargs
        )

    async def write(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        writer.write(data)
        try:
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
