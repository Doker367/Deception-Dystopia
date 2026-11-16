"""NetPulse — Fabric: forwarder de eventos JSONL → control (Fase 5b).

El agente de cada dispositivo escribe ``events.jsonl`` en su volumen
(``<devices_dir>/<device_id>/events.jsonl``); este forwarder, que corre
como hilo daemon del **servicio del host**, los reenvía al control
(``POST /api/fabric/events`` con ``X-Fabric-Token``).

Garantías:

- **Offsets persistentes** en ``forwarder-state.json`` (byte offset por
  archivo): no duplica ni pierde eventos tras reiniciar el servicio.
- **Archivo truncado** (tamaño < offset): el offset se reinicia a 0 y se
  relee (el agente rotó/reinició el log).
- **Línea parcial** al final (sin ``\n``): no se consume hasta completarse.
- **Lotes de hasta 100 eventos**; un fallo de envío mantiene el offset y
  reintenta en el siguiente ciclo (no se pierden).
- **Reintentos acotados (máx. 3) con backoff** solo para errores
  transitorios (red, timeout, 409/429/5xx); los 4xx permanentes
  (401/403/413/422) descartan el lote (nunca tendrían éxito).
- Líneas JSON malformadas se descartan y cuentan como ``failed``.

Variables de entorno: ``DYSTOPIA_FABRIC_EVENTS_URL`` (default
``http://127.0.0.1:8082/api/fabric/events``), ``DYSTOPIA_FABRIC_EVENTS_INTERVAL``
(default 5s) y ``DYSTOPIA_FABRIC_EVENTS_ENABLED`` (default true).
"""

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

EVENTS_URL_ENV = "DYSTOPIA_FABRIC_EVENTS_URL"
EVENTS_INTERVAL_ENV = "DYSTOPIA_FABRIC_EVENTS_INTERVAL"
EVENTS_ENABLED_ENV = "DYSTOPIA_FABRIC_EVENTS_ENABLED"
EVENTS_TOKEN_ENV = "DYSTOPIA_FABRIC_EVENTS_TOKEN"
DEVICES_DIR_ENV = "DYSTOPIA_FABRIC_DEVICES_DIR"

DEFAULT_DEVICES_DIR = "/var/lib/dystopia/fabric/logs"
DEFAULT_EVENTS_URL = "http://127.0.0.1:8082/api/fabric/events"
DEFAULT_INTERVAL = 5.0
DEFAULT_BATCH_SIZE = 100
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF = 0.5
HTTP_TIMEOUT = 5.0
# 4xx que nunca tendrán éxito reintentando (el lote se descarta).
_PERMANENT_STATUS = frozenset({400, 401, 403, 404, 413, 422})


class EventForwarder:
    """Reenvía los JSONL del agente al control con offsets persistentes."""

    def __init__(
        self,
        devices_dir: Path | str = DEFAULT_DEVICES_DIR,
        state_path: Optional[Path | str] = None,
        url: str = DEFAULT_EVENTS_URL,
        token: str = "",
        interval: float = DEFAULT_INTERVAL,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        client: Optional[httpx.Client] = None,
        enabled: bool = True,
        stop_event: Optional[threading.Event] = None,
    ):
        self._devices_dir = Path(devices_dir)
        self._state_path = Path(state_path) if state_path is not None else (
            self._devices_dir.parent / "forwarder-state.json"
        )
        self._url = url
        self._token = token
        self._interval = interval
        self._batch_size = max(1, batch_size)
        self._max_retries = max(1, max_retries)
        self._backoff = backoff
        self._client = client or httpx.Client(timeout=HTTP_TIMEOUT)
        self._enabled = enabled
        self._stop = stop_event or threading.Event()
        self._lock = threading.Lock()
        self._offsets: dict[str, int] = {}
        self._sent = 0
        self._failed = 0
        self._pending = 0
        self._last_error: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._load_state()

    # ── Estado persistente ──────────────────────────────────

    def _load_state(self) -> None:
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        offsets = data.get("offsets") if isinstance(data, dict) else None
        if isinstance(offsets, dict):
            self._offsets = {
                str(key): int(value) for key, value in offsets.items()
                if isinstance(value, int) and value >= 0
            }

    def _save_state(self) -> None:
        """Escritura atómica del estado de offsets (tmp + os.replace)."""
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps({"offsets": self._offsets}, sort_keys=True),
                encoding="utf-8",
            )
            os.replace(tmp, self._state_path)
        except OSError:
            logger.exception("[fabric-forwarder] no se pudo guardar el estado")

    # ── Lectura de JSONL ────────────────────────────────────

    def _files(self) -> list[Path]:
        if not self._devices_dir.exists():
            return []
        return sorted(self._devices_dir.glob("*/events.jsonl"))

    def collect(self) -> list[tuple[dict, str, int]]:
        """Lee las líneas nuevas de cada JSONL.

        Devuelve ``(evento, archivo, offset_final)``; los offsets solo se
        confirman cuando el lote correspondiente se envía con éxito.
        Las líneas malformadas se descartan (contadas como ``failed``) y
        avanzan el offset candidato para no atascar el forwarder.
        """
        candidate = dict(self._offsets)
        items: list[tuple[dict, str, int]] = []
        for path in self._files():
            key = str(path)
            offset = candidate.get(key, 0)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size < offset:
                logger.warning(
                    "[fabric-forwarder] %s truncado (%d < %d); se relee desde 0",
                    path, size, offset,
                )
                offset = 0
            try:
                with open(path, "rb") as handle:
                    handle.seek(offset)
                    data = handle.read()
            except OSError:
                logger.exception("[fabric-forwarder] no se pudo leer %s", path)
                continue
            if not data:
                continue
            complete, _, _remainder = data.rpartition(b"\n")
            if not complete:
                continue  # solo una línea parcial: nada consolidado
            candidate[key] = offset + len(complete) + 1
            for line in complete.split(b"\n"):
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                try:
                    event = json.loads(text)
                except ValueError:
                    with self._lock:
                        self._failed += 1
                        self._last_error = f"línea JSONL inválida en {path.name}"
                    logger.warning("[fabric-forwarder] línea inválida en %s", path)
                    continue
                if isinstance(event, dict):
                    items.append((event, key, candidate[key]))
        self._candidate_offsets = candidate
        return items

    # ── Envío ───────────────────────────────────────────────

    def _send_with_retry(self, batch: list[dict]) -> tuple[bool, Optional[str]]:
        """POST al control; reintentos con backoff solo para transitorios."""
        last_error: Optional[str] = None
        for attempt in range(self._max_retries):
            try:
                response = self._client.post(
                    self._url,
                    json={"events": batch},
                    headers={"X-Fabric-Token": self._token},
                )
            except httpx.HTTPError as exc:
                last_error = f"error de red: {type(exc).__name__}"
                logger.warning("[fabric-forwarder] %s", last_error)
            else:
                if response.status_code == 200:
                    return True, None
                detail = response.text[:200]
                if response.status_code in _PERMANENT_STATUS:
                    return False, (
                        f"HTTP {response.status_code}: {detail} "
                        "(error permanente; lote descartado)"
                    )
                last_error = f"HTTP {response.status_code}: {detail}"
                logger.warning("[fabric-forwarder] %s", last_error)
            if attempt < self._max_retries - 1 and self._backoff > 0:
                time.sleep(self._backoff * (2 ** attempt))
        return False, last_error

    # ── Ciclo ───────────────────────────────────────────────

    def run_once(self) -> dict:
        """Un ciclo: leer → enviar lotes → confirmar offsets."""
        if not self._enabled:
            return {"sent": 0, "failed": 0, "pending": 0, "error": None}
        items = self.collect()
        if items:
            logger.info(
                "[fabric-forwarder] %d evento(s) nuevos en %d archivo(s)",
                len(items), len({key for _event, key, _end in items}),
            )
        error: Optional[str] = None
        sent = 0
        failed = 0
        committed: dict[str, int] = {}

        if not items:
            # Solo líneas malformadas/parciales: consolida lo avanzado.
            if self._offsets != self._candidate:
                self._offsets = dict(self._candidate)
                self._save_state()
        else:
            for start in range(0, len(items), self._batch_size):
                batch = items[start:start + self._batch_size]
                ok, batch_error = self._send_with_retry(
                    [event for event, _key, _end in batch]
                )
                if ok:
                    sent += len(batch)
                    for _event, key, end in batch:
                        committed[key] = max(committed.get(key, 0), end)
                else:
                    failed += len(batch)
                    error = batch_error
                    break  # mantener el orden: lo demás reintenta después

            if committed:
                self._offsets.update(committed)
                self._save_state()

        with self._lock:
            self._sent += sent
            self._failed += failed
            self._last_error = error
            # Lo no enviado (fallido incluido) sigue pendiente: el offset
            # no se confirmó, así que el siguiente ciclo reintenta.
            self._pending = max(0, len(items) - sent)
        if error:
            logger.error("[fabric-forwarder] ciclo con errores: %s", error)
        return {
            "sent": sent, "failed": failed,
            "pending": self._pending, "error": error,
        }

    @property
    def _candidate(self) -> dict[str, int]:
        """Últimos offsets candidatos calculados por ``collect``."""
        return getattr(self, "_candidate_offsets", self._offsets)

    def run_forever(self) -> None:
        """Bucle del hilo daemon: ciclo + espera del intervalo."""
        logger.info(
            "[fabric-forwarder] iniciado (dir=%s url=%s interval=%ss)",
            self._devices_dir, self._url, self._interval,
        )
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - el bucle nunca muere
                logger.exception("[fabric-forwarder] ciclo falló")
            self._stop.wait(self._interval)
        logger.info("[fabric-forwarder] detenido")

    def start(self) -> None:
        """Arranca el hilo daemon (idempotente)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self.run_forever, name="fabric-event-forwarder", daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ── Estado para /status ─────────────────────────────────

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "pending": self._pending,
                "sent": self._sent,
                "failed": self._failed,
                "last_error": self._last_error,
                "offsets": dict(self._offsets),
                "dir": str(self._devices_dir),
                "dir_exists": self._devices_dir.exists(),
                "dir_entries": (
                    sorted(p.name for p in self._devices_dir.iterdir())
                    if self._devices_dir.exists() else []
                ),
                "files": [str(path) for path in self._files()],
            }


def forwarder_from_env(
    settings_token: str,
    devices_dir: Optional[Path | str] = None,
    state_path: Optional[Path | str] = None,
) -> Optional[EventForwarder]:
    """Construye el forwarder según el entorno; ``None`` si está deshabilitado."""
    enabled = os.getenv(EVENTS_ENABLED_ENV, "true").strip().lower() != "false"
    if not enabled:
        return None
    token = os.getenv(EVENTS_TOKEN_ENV, "").strip()
    if len(token) < 32:
        logger.warning(
            "[fabric-forwarder] %s no configurado; usando el token de operación "
            "(deprecado: separa los tokens)", EVENTS_TOKEN_ENV,
        )
        token = settings_token
    devices = Path(devices_dir or os.getenv(DEVICES_DIR_ENV, DEFAULT_DEVICES_DIR))
    url = os.getenv(EVENTS_URL_ENV, DEFAULT_EVENTS_URL).strip() or DEFAULT_EVENTS_URL
    raw_interval = os.getenv(EVENTS_INTERVAL_ENV, str(DEFAULT_INTERVAL)).strip()
    try:
        interval = max(0.5, float(raw_interval))
    except ValueError:
        interval = DEFAULT_INTERVAL
    return EventForwarder(
        devices_dir=devices,
        state_path=state_path,
        url=url,
        token=token,
        interval=interval,
    )
