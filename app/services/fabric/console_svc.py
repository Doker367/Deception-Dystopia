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
import logging
import os
import secrets
import time
from dataclasses import dataclass, field

logger = logging.getLogger("fabric.console")

# ── Límites (env con defaults conservadores) ─────────────────

CONSOLE_ENABLED_ENV = "DYSTOPIA_FABRIC_CONSOLE_ENABLED"
CONSOLE_MAX_SESSIONS = int(os.getenv("DYSTOPIA_FABRIC_CONSOLE_MAX", "4"))
CONSOLE_IDLE_TIMEOUT = int(os.getenv("DYSTOPIA_FABRIC_CONSOLE_IDLE", "600"))
CONSOLE_MAX_AGE = int(os.getenv("DYSTOPIA_FABRIC_CONSOLE_MAX_AGE", "3600"))


def console_enabled() -> bool:
    """Gate de entorno de la consola (independiente del gate de deploy)."""
    return os.getenv(CONSOLE_ENABLED_ENV, "false").strip().lower() == "true"


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
        """Abre un ``docker exec -i -t`` hacia el contenedor del device.

        El ``device_id`` viene del manifiesto validado (lo comprueba el
        router antes de llamar); aquí solo se aplica la cuota.
        """
        async with self._lock:
            if self.active_count >= CONSOLE_MAX_SESSIONS:
                raise RuntimeError(
                    f"Máximo de {CONSOLE_MAX_SESSIONS} consolas concurrentes alcanzado"
                )
            session_id = f"tty-{secrets.token_hex(8)}"
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec",
                "-i", "-t",
                "-e", f"COLUMNS={max(40, min(cols, 500))}",
                "-e", f"LINES={max(12, min(rows, 200))}",
                "-e", "TERM=xterm-256color",
                container_name, "/bin/sh", "-i",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            session = ConsoleSession(
                session_id=session_id,
                device_id=device_id,
                container_name=container_name,
                username=username,
                proc=proc,
            )
            self._sessions[session_id] = session
        logger.info(
            "[fabric] consola abierta: %s → %s (usuario %s)",
            session_id, container_name, username,
        )
        asyncio.create_task(self._pump_output(session))
        return session

    @staticmethod
    async def _pump_output(session: ConsoleSession) -> None:
        """Lee la salida del proceso y la encola hasta EOF."""
        proc = session.proc
        if proc is None or proc.stdout is None:
            return
        try:
            while True:
                chunk = await proc.stdout.read(4096)
                if not chunk:
                    break
                await session.queue.put(chunk)
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            await session.queue.put(None)  # EOF para el lector

    async def write_session(self, session_id: str, data: bytes) -> bool:
        """Escribe entrada del usuario en la sesión; ``False`` si murió."""
        session = self._sessions.get(session_id)
        if session is None or session.proc is None or session.proc.stdin is None:
            return False
        session.last_activity = time.time()
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
        """Cierra la sesión y mata el proceso subyacente (tolerante)."""
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        session.closed = True
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
