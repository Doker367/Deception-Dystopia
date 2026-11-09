"""Colector continuo de honeypots: logs declarados -> telemetría SQLite.

Une las tres piezas que el repositorio ya trae en un bucle pequeño y
polleable:

    runtime.logreader.LogReader  -> cola de registros (offsets + rotación)
    runtime.normalize.normalize_raw -> evento v1 validado
    app.services.deception.store_svc.log_event -> SQLite del control plane

A diferencia de ``runtime.dataplane`` (spool + transporte HTTPS autenticado
hacia el receptor), este colector escribe directamente en ``deception.db``
mediante ``store_svc``: es la forma de ingesta para una celda donde el plano
de control y el sensor comparten el almacén SQLite.

Decisiones de diseño (supuestos documentados):

* **Offsets.** El offset por byte de cada fichero declarado vive en los
  cursores de ``LogReader``, que ya resuelven las dos formas de rotación
  (cambio de inodo = rename+recreate; truncado = copytruncate). Por defecto los
  cursores se persisten en la tabla ``collector_offsets`` de la MISMA base de
  datos y se confirman en la misma transacción que los eventos (ver
  ``store_svc.log_events_batch``): si la escritura falla, el offset no avanza
  y el siguiente poll relee el tramo. ``OffsetLedger`` (JSON) queda solo como
  modo de depuración.
* **Dedupe.** El índice único SQLite ``(engine, source_event_id)`` es la
  fuente de verdad; ``INSERT OR IGNORE`` convierte un reproceso en un no-op
  idempotente. El anillo en memoria es solo una caché para no repetir trabajo
  dentro del mismo poll.
* **Tipos desconocidos.** El ``type`` normalizado se mapea a
  ``DeceptionEventType``; lo que el control plane no tiene en el enum (p. ej.
  ``disconnect``) degrada a ``OTHER``, nunca se descarta.
* **Entrada malformada.** Un registro que falla al normalizar se cuenta, deja
  una muestra acotada en ``collector_dead_letters`` y se salta: el colector
  nunca se detiene por una línea hostil. Un fallo de *lectura* (JSONL roto)
  aborta el chunk actual de esa única fuente (misma semántica que
  ``LogReader.collect``).
* **Heartbeat.** Cada poll escribe ``collector_heartbeat`` en la misma
  transacción; ``GET /api/analytics/health`` lo lee y marca el colector como
  activo/stale/missing.
* **device_id.** Se toma del inventario revisado
  (``deploy/honeypots/inventory.yaml``): ``srv-files-01`` (Cowrie/Dionaea),
  ``sw-access-01`` (OpenCanary), ``srv-db-01`` (Heralding/RedisHoneyPot) y
  ``fw-edge-01`` (Endlessh). No se declaran device_ids aquí.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
import time

from runtime.logreader import LogReader, Sources
from runtime.normalize import NormalizeError, fingerprint, normalize_raw

logger = logging.getLogger(__name__)

class OffsetLedger:
    """Snapshot atómico de los cursores de ``LogReader`` en un fichero JSON."""

    VERSION = 1

    def __init__(self, path):
        self.path = Path(path).expanduser()
        self.saved_at = None

    def load(self) -> dict | None:
        """Carga el estado persistido; un ledger roto no debe bloquear el arranque."""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("version") != self.VERSION:
            return None
        if not isinstance(data.get("cursors"), dict):
            return None
        return data

    def save(self, cursors: dict, source_paths: dict) -> None:
        """Escribe estado/*.tmp y renombra: el ledger nunca queda a medias."""
        state = {
            "version": self.VERSION,
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cursors": {
                engine: {
                    "dev": cursor.dev,
                    "ino": cursor.ino,
                    "offset": max(0, int(cursor.offset)),
                    "pending": base64.b64encode(cursor.pending).decode("ascii"),
                    "path": source_paths.get(engine, ""),
                }
                for engine, cursor in cursors.items()
            },
        }
        self.saved_at = state["saved_at"]
        tmp = self.path.with_name(self.path.name + ".tmp")
        with open(tmp, "wb") as stream:
            stream.write(json.dumps(state, sort_keys=True).encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, self.path)


def _event_type(value) -> "DeceptionEventType":  # noqa: F821
    from app.models.deception import DeceptionEventType

    try:
        return DeceptionEventType(value)
    except ValueError:
        # Tipo v1 desconocido para el control plane (p. ej. ``disconnect``)
        # degrada a OTHER, nunca se descarta el evento.
        return DeceptionEventType.OTHER


class SqliteOffsetStore:
    """Cursores de ``LogReader`` persistidos en la propia BD de eventos.

    A diferencia del ledger JSON (solo depuración), esta variante permite que
    ``store_svc.log_events_batch`` confirme eventos y offsets en la MISMA
    transacción: nunca se avanza el cursor si el lote no se escribió.
    """

    atomic = True

    def __init__(self, store):
        self.store = store

    @property
    def db_path(self) -> Path:
        return Path(str(self.store.DB_PATH))

    def load(self) -> dict | None:
        try:
            with sqlite3.connect(str(self.db_path), timeout=10) as conn:
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS collector_offsets (
                           engine TEXT PRIMARY KEY, path TEXT NOT NULL,
                           dev INTEGER NOT NULL DEFAULT -1,
                           ino INTEGER NOT NULL DEFAULT -1,
                           offset INTEGER NOT NULL DEFAULT 0,
                           pending BLOB NOT NULL DEFAULT X'',
                           updated_at TEXT NOT NULL)"""
                )
                rows = conn.execute(
                    """SELECT engine, path, dev, ino, offset, pending
                       FROM collector_offsets"""
                ).fetchall()
        except sqlite3.Error:
            return None
        if not rows:
            return None
        return {
            "version": 1,
            "cursors": {
                engine: {"path": path, "dev": dev, "ino": ino,
                         "offset": offset,
                         "pending": base64.b64encode(bytes(pending)).decode("ascii")}
                for engine, path, dev, ino, offset, pending in rows
            },
        }

    def rows(self, cursors: dict, source_paths: dict) -> list[dict]:
        now = datetime.now(timezone.utc).isoformat()
        return [
            {"engine": engine, "path": source_paths.get(engine, ""),
             "dev": cursor.dev, "ino": cursor.ino,
             "offset": max(0, int(cursor.offset)),
             "pending": bytes(cursor.pending), "updated_at": now}
            for engine, cursor in cursors.items()
        ]

    def save(self, cursors: dict, source_paths: dict) -> None:
        """Fallback para llamadas manuales; el colector usa ``rows``."""
        self.store.log_events_batch([], self.rows(cursors, source_paths))


class Collector:
    """Ingesta polleable: logs declarados -> evento v1 -> ``store_svc`` SQLite."""

    def __init__(self, reader, ledger_path=None, *, store=None,
                 dedupe_window: int = 10_000, poll_interval: float = 30.0,
                 offset_store=None, dead_letter_limit: int = 25):
        if not isinstance(reader, LogReader):
            raise ValueError("Collector requires a runtime LogReader")
        if dedupe_window < 1:
            raise ValueError("dedupe_window must be positive")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if dead_letter_limit < 0:
            raise ValueError("dead_letter_limit must be >= 0")
        self.dead_letter_limit = dead_letter_limit
        self.reader = reader
        if store is None:
            from app.services.deception import store_svc as store
        self.store = store
        # Offset store: SQLite (atómico, por defecto) o ledger JSON (legacy).
        if offset_store is not None:
            self.offset_store = offset_store
        elif ledger_path is not None:
            self.offset_store = OffsetLedger(ledger_path)
        else:
            self.offset_store = SqliteOffsetStore(self.store)
        self.ledger = self.offset_store  # alias de compatibilidad
        self.dedupe_window = dedupe_window
        self.poll_interval = poll_interval
        self.stop_event = threading.Event()
        self.started_at = datetime.now(timezone.utc).isoformat()

        # Contadores de ingesta (vida del proceso).
        self.polls = 0
        self.ingested = 0
        self.duplicated = 0
        self.skipped = 0
        self.failed = 0
        self.dead_letters = 0
        self.read_errors = 0
        self.last_errors: list = []

        # Anillo de dedupe en memoria: las últimas (engine, source_event_id).
        # Es solo una caché: la verdad la impone el índice único de SQLite.
        self._seen: dict = {}
        self._restore()

    # ── Ciclo ────────────────────────────────────────────────

    def poll_once(self) -> dict:
        """Un poll: leer, normalizar, deduplicar y escribir lo nuevo en lote.

        Todas las escrituras del poll (eventos, offsets y heartbeat) van en una
        única transacción SQLite. Si esa transacción falla, el offset no avanza
        y el siguiente poll reintenta el mismo tramo.
        """
        self.polls += 1
        cursor_snapshot = self._snapshot_cursors()
        records, errors = self.reader.collect()
        self.last_errors = errors
        self.read_errors += len(errors)

        got = {"ingested": 0, "duplicated": 0, "skipped": 0, "failed": 0}
        payloads = []
        dead_letters = []
        batch_seen: set = set()

        for engine, _device_id, _format, raw in records:
            key = (engine, fingerprint(raw))
            if key in self._seen or key in batch_seen:
                self._remember(key)
                self.duplicated += 1
                got["duplicated"] += 1
                continue
            try:
                event = normalize_raw(engine, self._device_id[engine], raw)
            except (NormalizeError, ValueError) as exc:
                # Línea hostil/malformada: muestra acotada + contador, sin
                # detener el bucle ni bloquear el fichero.
                self.failed += 1
                got["failed"] += 1
                if len(dead_letters) < self.dead_letter_limit:
                    dead_letters.append({
                        "engine": engine,
                        "path": self._paths.get(engine, ""),
                        "byte_offset": int(getattr(
                            self.reader.cursors.get(engine), "offset", 0) or 0),
                        "raw": raw,
                        "error": f"{type(exc).__name__}: {exc}",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    })
                continue
            if event is None:
                # Línea vacía o sin evento (p. ej. TOTALS de Endlessh).
                self.skipped += 1
                got["skipped"] += 1
                continue
            payloads.append((key, self._payload(engine, event, key[1])))
            batch_seen.add(key)

        heartbeat = {
            "started_at": self.started_at,
            "last_poll_at": datetime.now(timezone.utc).isoformat(),
            "polls": self.polls,
            "ingested": self.ingested,
            "interval": self.poll_interval,
            "status": "ok",
        }
        offset_rows = None
        if getattr(self.offset_store, "atomic", False):
            offset_rows = self.offset_store.rows(self.reader.cursors, self._paths)

        try:
            results = self.store.log_events_batch(
                [payload for _, payload in payloads], offset_rows,
                heartbeat, dead_letters)
        except Exception:  # noqa: BLE001 - el bucle no se detiene nunca
            logger.exception("[collector] fallo al escribir el lote; "
                             "offsets sin avanzar")
            self._rollback_cursors(cursor_snapshot)
            self.failed += len(payloads)
            got["failed"] += len(payloads)
            self.last_errors = [f"batch write failed: {len(payloads)} events"]
            return {"collected": 0, **got, "read_errors": len(errors),
                    "errors": list(errors), "totals": self.stats()}

        for (key, _payload), result in zip(payloads, results):
            self._remember(key)
            if result["inserted"]:
                self.ingested += 1
                got["ingested"] += 1
            else:
                # Lo rechazó el índice único: duplicado idempotente.
                self.duplicated += 1
                got["duplicated"] += 1

        self.dead_letters += len(dead_letters)

        if not getattr(self.offset_store, "atomic", False):
            try:
                self.offset_store.save(self.reader.cursors, self._paths)
            except OSError:
                # Sin offsets duraderos el poll actual igualmente se procesó;
                # el siguiente podría repetir, y ahí entra el índice único.
                logger.exception("[collector] no se pudo guardar el ledger %s",
                                 getattr(self.offset_store, "path", "?"))
        return {"collected": got["ingested"], **got, "read_errors": len(errors),
                "errors": list(errors), "totals": self.stats()}

    def run_forever(self, interval: float | None = None) -> dict:
        """Bucle continuo cada ``poll_interval`` segundos; termina con ``stop()``."""
        interval = float(interval or self.poll_interval)
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                self.poll_once()
            except Exception:  # noqa: BLE001 - el bucle no se detiene nunca
                logger.exception("[collector] poll fallido; se reintenta")
            self.stop_event.wait(max(0.0, interval - (time.monotonic() - started)))
        return self.stats()

    def stop(self) -> None:
        """Señal de parada cooperativa (segura para un handler de señal)."""
        self.stop_event.set()

    # ── Diagnóstico ─────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "polls": self.polls,
            "ingested": self.ingested,
            "duplicated": self.duplicated,
            "skipped": self.skipped,
            "failed": self.failed,
            "dead_letters": self.dead_letters,
            "read_errors": self.read_errors,
            "errors": list(self.last_errors),
        }

    def health(self) -> dict:
        """Diagnóstico read-only para el ciclo de operación."""
        saved_at = getattr(self.ledger, "saved_at", None)
        info = {**self.stats(), "interval": self.poll_interval,
                "dedupe_entries": len(self._seen),
                "stopping": self.stop_event.is_set(),
                "started_at": self.started_at,
                "offset_store": type(self.ledger).__name__,
                "offset_atomic": bool(getattr(self.ledger, "atomic", False)),
                "reader": self.reader.health()}
        if self.ledger:
            info["ledger"] = {
                "path": str(getattr(self.ledger, "path", "")),
                "saved_at": saved_at,
                "atomic": bool(getattr(self.ledger, "atomic", False)),
            }
        else:
            info["ledger"] = None
        if hasattr(self.store, "get_collector_health"):
            info["db_heartbeat"] = self.store.get_collector_health()
        return info

    # ── Internos ────────────────────────────────────────────

    @property
    def _device_id(self) -> dict:
        return {s.engine: s.device_id for s in self.reader.sources.sources}

    @property
    def _paths(self) -> dict:
        return {s.engine: s.path for s in self.reader.sources.sources}

    def _remember(self, key) -> None:
        self._seen[key] = None
        while len(self._seen) > self.dedupe_window:
            self._seen.pop(next(iter(self._seen)))

    def _snapshot_cursors(self) -> dict:
        """Copia el estado en memoria de los cursores antes de leer."""
        return {engine: (cursor.dev, cursor.ino, int(cursor.offset),
                         bytes(cursor.pending))
                for engine, cursor in self.reader.cursors.items()}

    def _rollback_cursors(self, snapshot: dict) -> None:
        """Si el lote no se escribió, el próximo poll debe releer el tramo."""
        for engine, (dev, ino, offset, pending) in snapshot.items():
            cursor = self.reader.cursors.get(engine)
            if cursor is None:
                continue
            cursor.dev, cursor.ino = dev, ino
            cursor.offset, cursor.pending = offset, pending

    def _payload(self, engine: str, event: dict, source_id: str):
        """Convierte el evento v1 en ``DeceptionEventIn`` para ``store_svc``."""
        from app.models.deception import DeceptionEventIn

        detail = dict(event.get("detail") or {})
        detail["engine"] = engine
        detail["source_event_id"] = source_id
        etype = event.get("type", "other")
        return DeceptionEventIn(
            device_id=event["device_id"],
            src_ip=event["src_ip"],
            src_port=event.get("src_port"),
            proto=event.get("proto", "tcp"),
            type=_event_type(etype),
            detail=detail,
            username=detail.get("username"),
            success=etype == "login_success",
            ts=event["observed_at"],
        )

    def _restore(self) -> None:
        """Restaura los cursores persistidos; cualquier duda => leer desde 0."""
        if not self.ledger:
            return
        state = self.ledger.load()
        if not state:
            return
        for engine, rec in state["cursors"].items():
            cursor = self.reader.cursors.get(engine)
            if cursor is None:
                continue
            source = next(s for s in self.reader.sources.sources if s.engine == engine)
            if rec.get("path") != source.path:
                # La ruta declarada cambió: no se puede confiar en el offset.
                continue
            try:
                cursor.dev = int(rec.get("dev", -1))
                cursor.ino = int(rec.get("ino", -1))
                cursor.offset = max(0, int(rec.get("offset", 0)))
                pending = base64.b64decode(str(rec.get("pending", "")), validate=True)
                if isinstance(pending, bytes):
                    cursor.pending = pending
            except (TypeError, ValueError):
                cursor.dev, cursor.ino, cursor.offset, cursor.pending = -1, -1, 0, b""


def build(inventory_path, ledger_path=None, *, data_root=None, cell=None, **kwargs):
    """Construye un ``Collector`` desde el inventario revisado de honeypots."""
    return Collector(
        LogReader(Sources.from_inventory(inventory_path, data_root=data_root, cell=cell)),
        ledger_path, **kwargs)


def main(argv=None):
    """Arranque del colector: ``python -m runtime.collector --inventory ...``.

    Sin daemonización ni sockets: bucle de poll con parada cooperativa
    mediante SIGINT/SIGTERM (o Ctrl-C).
    """
    import argparse
    import signal

    parser = argparse.ArgumentParser(description="Colector continuo de honeypots a SQLite")
    parser.add_argument("--inventory", required=True,
                        help="ruta a deploy/honeypots/inventory.yaml")
    parser.add_argument("--data-root",
                        help="raíz host de los logs reales (<host_root>/cells/<N>)")
    parser.add_argument("--cell", type=int,
                        help="número de celda cuando --data-root es el host_root")
    parser.add_argument("--fixtures", action="store_true",
                        help="modo demo: usar las fixtures del inventario en vez "
                             "de logs reales (requiere --data-root ausente)")
    parser.add_argument("--ledger",
                        help="ledger JSON de offsets (depuración). Por defecto "
                             "los offsets viven en SQLite, en la misma tabla "
                             "collector_offsets, y se confirman en la misma "
                             "transacción que los eventos")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="segundos entre polls (30 por defecto)")
    parser.add_argument("--dedupe-window", type=int, default=10_000,
                        help="tamaño del anillo de dedupe en memoria")
    parser.add_argument("--dead-letter-limit", type=int, default=25,
                        help="muestras de líneas irrecuperables por poll")
    parser.add_argument("--once", action="store_true", help="un único poll y salir")
    args = parser.parse_args(argv)
    if args.cell is not None and args.data_root is None:
        parser.error("--cell requiere --data-root")
    if args.data_root is None and not args.fixtures:
        parser.error("--data-root es obligatorio para leer logs reales "
                     "(usa --fixtures solo para demo)")

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    collector = build(args.inventory, args.ledger, data_root=args.data_root,
                      cell=args.cell, poll_interval=args.interval,
                      dedupe_window=args.dedupe_window,
                      dead_letter_limit=args.dead_letter_limit)
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, lambda *_: collector.stop())
            except (ValueError, OSError):
                pass  # fuera del hilo principal (tests): la parada manual sirve
    if args.once:
        summary = collector.poll_once()
        print(json.dumps(summary, sort_keys=True), flush=True)
        return 0
    collector.run_forever()
    logger.info("[collector] parado: %s", json.dumps(collector.stats(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["Collector", "OffsetLedger", "build", "main"]
