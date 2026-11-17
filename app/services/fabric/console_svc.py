"""Consola interactiva (PTY) hacia los contenedores señuelo del fabric.

Fase 11 del spec: "entrar en la máquina". Cada sesión es un
``docker exec -i -t`` hacia el contenedor del ``device_id`` solicitado,
con límites duros:

- Fail-closed: exige ``DYSTOPIA_FABRIC_CONSOLE_ENABLED=true``.
- Máximo de sesiones concurrentes (``DYSTOPIA_FABRIC_CONSOLE_MAX``).
- Timeout de inactividad (``DYSTOPIA_FABRIC_CONSOLE_IDLE``, segundos).
- Duración máxima de sesión (``DYSTOPIA_FABRIC_CONSOLE_MAX_AGE``).
- El contenedor SIEMPRE sale del manifiesto validado (nunca un id libre).

Las sesiones viven en memoria del control: al reiniciar el proceso el
fabric vuelve a ``ready`` y las sesiones desaparecen (el runtime real lo
recrea el host service).

El puente WebSocket vive en el router (``app/routers/fabric.py``); este
módulo solo gestiona el proceso ``docker exec`` y su cola de salida.
"""

from __future__ import annotations

import asyncio
import fcntl
import inspect
import logging
import os
import pty
import secrets
import struct
import termios
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

logger = logging.getLogger("fabric.console")

# ── Límites (env con defaults conservadores) ─────────────────

CONSOLE_ENABLED_ENV = "DYSTOPIA_FABRIC_CONSOLE_ENABLED"
CONSOLE_MAX_SESSIONS = int(os.getenv("DYSTOPIA_FABRIC_CONSOLE_MAX", "4"))
CONSOLE_IDLE_TIMEOUT = int(os.getenv("DYSTOPIA_FABRIC_CONSOLE_IDLE", "600"))
CONSOLE_MAX_AGE = int(os.getenv("DYSTOPIA_FABRIC_CONSOLE_MAX_AGE", "3600"))

# Con el engine "remote" los contenedores viven en el host y el control no
# tiene socket de Docker: la consola se abre contra el servicio del host.
REMOTE_ENGINE_ENV = "DYSTOPIA_FABRIC_ENGINE"
REMOTE_URL_ENV = "DYSTOPIA_FABRIC_REMOTE_URL"
REMOTE_TOKEN_ENV = "DYSTOPIA_FABRIC_REMOTE_TOKEN"
REMOTE_CA_ENV = "DYSTOPIA_FABRIC_REMOTE_CA"

# Frame de control que el puente envía antes de cerrar por un gate fallido.
# El frontend lo muestra como error en vez de escribirlo en el terminal.
ERROR_PREFIX = "\x00ERR:"


def console_enabled() -> bool:
    """Gate de entorno de la consola (independiente del gate de deploy)."""
    return os.getenv(CONSOLE_ENABLED_ENV, "false").strip().lower() == "true"


def remote_console_target() -> tuple[str, str, str] | None:
    """Destino WS del servicio del host para la consola, o ``None``.

    Devuelve ``(base_ws, token, ca)`` cuando el motor es ``remote`` y hay
    URL+token configurados; en cualquier otro caso la consola usa
    ``docker exec`` local (control en el host con acceso a Docker).
    """
    if os.getenv(REMOTE_ENGINE_ENV, "stub").strip().lower() != "remote":
        return None
    base = os.getenv(REMOTE_URL_ENV, "").strip().rstrip("/")
    token = os.getenv(REMOTE_TOKEN_ENV, "").strip()
    if not base or not token:
        return None
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    else:
        return None
    return base, token, os.getenv(REMOTE_CA_ENV, "").strip()


@dataclass
class ConsoleSession:
    """Sesión de terminal viva hacia un contenedor del fabric."""

    session_id: str
    device_id: str
    container_name: str
    username: str
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    proc: asyncio.subprocess.Process | None = None
    # Maestro del PTY del `docker exec -t` (modo local); None en remoto.
    pty_fd: int | None = None
    # Conexión WS al servicio del host (engine remoto); None en modo local.
    ws: Any | None = None
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    closed: bool = False


class ConsoleService:
    """Gestor de sesiones de terminal del fabric.

    Mantiene el registro en memoria de las sesiones abiertas, aplica la
    cuota de concurrencia y expone lectura/escritura acotadas para el
    puente WebSocket del router. Sin shell en el host: el comando del
    subprocess está fijado (``docker exec -i -t <contenedor> /bin/sh``).
    """

    def __init__(self) -> None:
        self._sessions: dict[str, ConsoleSession] = {}
        self._lock = asyncio.Lock()

    # ── Consultas ────────────────────────────────────────────

    def get(self, session_id: str) -> ConsoleSession | None:
        return self._sessions.get(session_id)

    def list_for_device(self, device_id: str) -> list[ConsoleSession]:
        return [
            session for session in self._sessions.values()
            if session.device_id == device_id and not session.closed
        ]

    @property
    def active_count(self) -> int:
        return sum(1 for session in self._sessions.values() if not session.closed)

    # ── Ciclo de vida ────────────────────────────────────────

    async def open_session(
        self,
        device_id: str,
        container_name: str,
        username: str,
        cols: int = 80,
        rows: int = 24,
    ) -> ConsoleSession:
        """Abre una consola hacia el contenedor del device.

        Con el motor ``remote`` abre un WS contra el servicio del host (que
        es quien tiene acceso a Docker); si no, lanza ``docker exec -i -t``
        en local. El ``device_id`` viene del manifiesto validado (lo
        comprueba el router antes de llamar); aquí solo se aplica la cuota.
        """
        async with self._lock:
            if self.active_count >= CONSOLE_MAX_SESSIONS:
                raise RuntimeError(
                    f"Máximo de {CONSOLE_MAX_SESSIONS} consolas concurrentes alcanzado"
                )
            session_id = f"tty-{secrets.token_hex(8)}"
            target = remote_console_target()
            if target is not None:
                session = ConsoleSession(
                    session_id=session_id,
                    device_id=device_id,
                    container_name=container_name,
                    username=username,
                )
                try:
                    session.ws = await self._connect_remote(
                        target, device_id, cols, rows
                    )
                except Exception as exc:  # noqa: BLE001 - se traduce a error de API
                    raise RuntimeError(
                        "No se pudo abrir la consola en el servicio del host: "
                        f"{exc}"
                    ) from exc
                self._sessions[session_id] = session
                asyncio.create_task(self._pump_remote(session))
            else:
                # `docker exec -t` exige que el stdin del cliente sea un TTY.
                # Se le da un PTY real: el maestro lo lee este proceso y el
                # esclavo va como stdin/stdout/stderr del `docker exec`.
                master_fd, slave_fd = pty.openpty()
                try:
                    # Tamaño real del xterm del navegador (si no, 80x24).
                    fcntl.ioctl(
                        master_fd,
                        termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0),
                    )
                    proc = await asyncio.create_subprocess_exec(
                        "docker", "exec",
                        "-i", "-t",
                        "-e", f"COLUMNS={max(40, min(cols, 500))}",
                        "-e", f"LINES={max(12, min(rows, 200))}",
                        "-e", "TERM=xterm-256color",
                        container_name, "/bin/sh", "-i",
                        stdin=slave_fd,
                        stdout=slave_fd,
                        stderr=slave_fd,
                        close_fds=True,
                    )
                except Exception as exc:  # noqa: BLE001 - se traduce a error de API
                    os.close(master_fd)
                    os.close(slave_fd)
                    raise RuntimeError(
                        f"No se pudo ejecutar docker exec: {exc}"
                    ) from exc
                os.close(slave_fd)
                session = ConsoleSession(
                    session_id=session_id,
                    device_id=device_id,
                    container_name=container_name,
                    username=username,
                    proc=proc,
                    pty_fd=master_fd,
                )
                self._sessions[session_id] = session
                asyncio.create_task(self._pump_pty(session))
        logger.info(
            "[fabric] consola abierta: %s → %s (usuario %s, transporte %s)",
            session_id, container_name, username,
            "remote" if session.ws is not None else "docker",
        )
        return session

    @staticmethod
    async def _connect_remote(
        target: tuple[str, str, str],
        device_id: str,
        cols: int,
        rows: int,
    ) -> Any:
        """Conecta el WS al servicio del host (bearer + CA opcional)."""
        import ssl as ssl_mod

        import websockets

        base, token, ca = target
        url = (
            f"{base}/console/ws?device_id={quote(device_id)}"
            f"&cols={max(40, min(cols, 500))}&rows={max(12, min(rows, 200))}"
        )
        kwargs: dict[str, Any] = {
            "max_size": None,
            "open_timeout": 10,
            "ping_interval": 20,
            "ping_timeout": 20,
        }
        headers = {"Authorization": f"Bearer {token}"}
        try:
            params = inspect.signature(websockets.connect).parameters
            key = "additional_headers" if "additional_headers" in params else "extra_headers"
            kwargs[key] = headers
        except (TypeError, ValueError):  # pragma: no cover - versión exótica
            kwargs["extra_headers"] = headers
        if base.startswith("wss://"):
            kwargs["ssl"] = ssl_mod.create_default_context(cafile=ca or None)
        return await websockets.connect(url, **kwargs)

    @staticmethod
    async def _pump_remote(session: ConsoleSession) -> None:
        """Lee del WS remoto y encola la salida hasta el cierre."""
        ws = session.ws
        if ws is None:
            await session.queue.put(None)
            return
        try:
            async for message in ws:
                if isinstance(message, str):
                    message = message.encode("utf-8")
                await session.queue.put(message)
        except Exception:  # noqa: BLE001 - cierre remoto o red caída
            pass
        finally:
            await session.queue.put(None)  # EOF para el lector

    @staticmethod
    async def _pump_pty(session: ConsoleSession) -> None:
        """Lee del maestro del PTY (sin hilos) y encola la salida."""
        loop = asyncio.get_running_loop()
        fd = session.pty_fd
        if fd is None:
            await session.queue.put(None)
            return
        done = asyncio.Event()

        def _readable() -> None:
            try:
                data = os.read(fd, 4096)
            except OSError:  # EIO al cerrarse el esclavo
                data = b""
            if data:
                session.queue.put_nowait(data)
                return
            loop.remove_reader(fd)
            done.set()

        loop.add_reader(fd, _readable)
        try:
            await done.wait()
        finally:
            try:
                loop.remove_reader(fd)
            except Exception:  # noqa: BLE001 - ya retirado
                pass
            await session.queue.put(None)  # EOF para el lector

    async def write_session(self, session_id: str, data: bytes) -> bool:
        """Escribe entrada del usuario en la sesión; ``False`` si murió."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.last_activity = time.time()
        if session.ws is not None:
            try:
                await session.ws.send(data)
            except Exception:  # noqa: BLE001 - WS remoto cerrado
                await self.close_session(session_id)
                return False
            return True
        if session.pty_fd is not None:
            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, os.write, session.pty_fd, data
                )
            except OSError:
                await self.close_session(session_id)
                return False
            return True
        if session.proc is None or session.proc.stdin is None:
            return False
        try:
            session.proc.stdin.write(data)
            await session.proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            await self.close_session(session_id)
            return False
        return True

    async def read_chunk(self, session_id: str, timeout: float = 0.5) -> bytes | None:
        """Lee un bloque de salida de la sesión (``None`` = EOF/cerrada).

        Con timeout para que el puente WebSocket pueda hacer keepalive y
        detectar sesiones inactivas sin bloquear el event loop.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return None
        try:
            return await asyncio.wait_for(session.queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return b""

    async def close_session(self, session_id: str) -> None:
        """Cierra la sesión y mata el proceso/WS subyacente (tolerante)."""
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        session.closed = True
        if session.ws is not None:
            try:
                await session.ws.close()
            except Exception:  # noqa: BLE001 - ya cerrado
                pass
        if session.pty_fd is not None:
            try:
                os.close(session.pty_fd)
            except OSError:
                pass
            session.pty_fd = None
        proc = session.proc
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except (ProcessLookupError, asyncio.TimeoutError):
                pass
        logger.info("[fabric] consola cerrada: %s", session_id)

    def reap_idle(self) -> int:
        """Cierra sesiones que superan el idle timeout o la edad máxima.

        Tolerante fuera de un event loop (tests): intenta programar el
        cierre en el loop activo y, si no lo hay, cierra en línea.
        """
        now = time.time()
        stale = [
            session_id for session_id, session in self._sessions.items()
            if now - session.last_activity > CONSOLE_IDLE_TIMEOUT
            or now - session.started_at > CONSOLE_MAX_AGE
        ]
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        for session_id in stale:
            if loop is not None:
                loop.create_task(self.close_session(session_id))
            else:
                self._sessions.pop(session_id, None)
        return len(stale)


# Singleton del módulo (patrón de los demás servicios del fabric).
console_service = ConsoleService()
