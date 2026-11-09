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
  (cambio de inodo = rename+recreate; truncado = copytruncate). El
  ``OffsetLedger`` persiste esos cursores a disco tras cada poll y los
  restaura al arrancar, de forma que el colector reanuda exactamente donde
  quedó. La escritura es atómica (``.tmp`` + ``os.replace``).
* **Dedupe.** Dos capas: (1) un anillo en memoria con las últimas
  ``dedupe_window`` claves ``source_event_id``; (2) una búsqueda por lotes
  contra los eventos ya escritos en SQLite usando ``detail["source_event_id"]``
  — el id es la huella SHA-256 estable del registro crudo, así que una
  relecture del mismo log (offsets perdidos, fichero releído desde 0) se
  reconoce aunque el evento se guardara hace días.
* **Tipos desconocidos.** El ``type`` normalizado se mapea a
  ``DeceptionEventType``; lo que el control plane no tiene en el enum (p. ej.
  ``disconnect``) degrada a ``OTHER``, nunca se descarta.
* **Entrada malformada.** Un registro que falla al normalizar o al guardar se
  cuenta y se salta: el colector nunca se detiene por una línea hostil. Un
  fallo de *lectura* (JSONL roto) aborta el chunk actual de esa única fuente:
  los offsets ya avanzaron, la línea no se reintenta al infinito y el resto de
  motores sigue fluyendo (misma semántica que ``LogReader.collect``).
* **device_id.** Se toma del inventario revisado
  (``deploy/honeypots/inventory.yaml``): ``srv-files-01`` (Cowrie/Dionaea),
  ``sw-access-01`` (OpenCanary), ``srv-db-01`` (Heralding/RedisHoneyPot) y
  ``fw-edge-01`` (Endlessh). No se declaran device_ids aquí.
"""

from __future__ import annotations

import base64
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

# Claves por lote en la búsqueda de dedupe contra la base de datos.
_DEDUPE_DB_CHUNK = 100


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


def _like_pattern(source_id: str) -> str:
    """Patrón LIKE escapado para una huella (hex), seguro con comodines."""
    safe = source_id.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
    return f'%"source_event_id": "{safe}"%'


class Collector:
    """Ingesta polleable: logs declarados -> evento v1 -> ``store_svc`` SQLite."""

    def __init__(self, reader, ledger_path=None, *, store=None,
                 dedupe_window: int = 10_000, poll_interval: float = 30.0):
        if not isinstance(reader, LogReader):
            raise ValueError("Collector requires a runtime LogReader")
        if dedupe_window < 1:
            raise ValueError("dedupe_window must be positive")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self.reader = reader
        self.ledger = OffsetLedger(ledger_path) if ledger_path else None
        if store is None:
            from app.services.deception import store_svc as store
        self.store = store
        self.dedupe_window = dedupe_window
        self.poll_interval = poll_interval
        self.stop_event = threading.Event()

        # Contadores de ingesta (vida del proceso).
        self.polls = 0
        self.ingested = 0
        self.duplicated = 0
        self.skipped = 0
        self.failed = 0
        self.read_errors = 0
        self.last_errors: list = []

        # Anillo de dedupe en memoria: las últimas (engine, source_event_id).
        self._seen: dict = {}
        self._restore()

    # ── Ciclo ────────────────────────────────────────────────

    def poll_once(self) -> dict:
        """Un poll: leer, normalizar, deduplicar y escribir lo nuevo.

        Devuelve los contadores *de este poll*; los acumulados de vida del
        proceso están en ``stats()``/``health()`` y los atributos públicos.
        Estrictamente ``collected == ingested`` (alias por compatibilidad).
        """
        self.polls += 1
        records, errors = self.reader.collect()
        self.last_errors = errors
        self.read_errors += len(errors)

        candidate_keys = []
        candidate_records = []
        for engine, _device_id, _format, raw in records:
            candidate_keys.append((engine, fingerprint(raw)))
            candidate_records.append((engine, raw))

        stored = self._stored_keys(set(candidate_keys))

        got = {"ingested": 0, "duplicated": 0, "skipped": 0, "failed": 0}
        for (key_engine, source_id), (engine, raw) in zip(candidate_keys,
                                                          candidate_records):
            key = (key_engine, source_id)
            try:
                event = normalize_raw(engine, self._device_id[engine], raw)
            except (NormalizeError, ValueError):
                # Línea hostil/malformada: contar y seguir sin romper el bucle.
                self.failed += 1
                got["failed"] += 1
                continue
            if event is None:
                # Línea vacía o sin evento (p. ej. TOTALS de Endlessh).
                self.skipped += 1
                got["skipped"] += 1
                continue
            if key in self._seen or key in stored:
                self._remember(key)
                self.duplicated += 1
                got["duplicated"] += 1
                continue

            payload = self._payload(engine, event, source_id)
            try:
                record = self.store.log_event(payload)
            except Exception:  # noqa: BLE001 - el bucle no se detiene nunca
                logger.exception("[collector] fallo al escribir %s", engine)
                self.failed += 1
                got["failed"] += 1
                continue
            if not record or record.get("id", 0) == 0:
                self.failed += 1
                got["failed"] += 1
                continue
            self._remember(key)
            self.ingested += 1
            got["ingested"] += 1

        if self.ledger:
            try:
                self.ledger.save(self.reader.cursors, self._paths)
            except OSError:
                # Sin offsets duraderos el poll actual igualmente se procesó;
                # el siguiente podría repetir, y ahí entra la dedupe.
                logger.exception("[collector] no se pudo guardar el ledger %s",
                                 self.ledger.path)
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
            "read_errors": self.read_errors,
            "errors": list(self.last_errors),
        }

    def health(self) -> dict:
        """Diagnóstico read-only para el ciclo de operación."""
        info = {**self.stats(), "interval": self.poll_interval,
                "dedupe_entries": len(self._seen),
                "stopping": self.stop_event.is_set(),
                "reader": self.reader.health()}
        if self.ledger:
            info["ledger"] = {"path": str(self.ledger.path),
                              "saved_at": self.ledger.saved_at}
        else:
            info["ledger"] = None
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

    def _stored_keys(self, candidates: set) -> set:
        """Búsqueda por lotes de claves (engine, source_event_id) ya en SQLite.

        Una consulta por bloque con ``LIKE`` filtrando por ``detail``: los ids
        son huellas hex, sin comodines; el juego de filas devuelta es proporcional
        a los duplicados reales, no al tamaño de la tabla.
        """
        if not candidates:
            return set()
        db_path = Path(str(getattr(self.store, "DB_PATH", "")))
        if not db_path or db_path.name == "" or not db_path.exists():
            return set()
        keys = list(candidates)
        found: set = set()
        conn = sqlite3.connect(str(db_path), timeout=10)
        try:
            for start in range(0, len(keys), _DEDUPE_DB_CHUNK):
                chunk = keys[start:start + _DEDUPE_DB_CHUNK]
                pattern = " OR ".join(["detail LIKE ?"] * len(chunk))
                sql = (f"SELECT detail FROM deception_events WHERE ({pattern})")
                params = [_like_pattern(key[1]) for key in chunk]
                for (detail_text,) in conn.execute(sql, params):
                    try:
                        detail = json.loads(detail_text or "{}")
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if not isinstance(detail, dict):
                        continue
                    key = (detail.get("engine"), detail.get("source_event_id"))
                    if key in candidates:
                        found.add(key)
        finally:
            conn.close()
        return found

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

    from app.services.deception import store_svc

    parser = argparse.ArgumentParser(description="Colector continuo de honeypots a SQLite")
    parser.add_argument("--inventory", required=True,
                        help="ruta a deploy/honeypots/inventory.yaml")
    parser.add_argument("--data-root",
                        help="raíz host de los logs renderizados (lab: omitir)")
    parser.add_argument("--cell", type=int,
                        help="número de celda cuando --data-root es el host_root")
    parser.add_argument("--ledger",
                        help="fichero de offsets (por defecto junto a deception.db)")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="segundos entre polls (30 por defecto)")
    parser.add_argument("--dedupe-window", type=int, default=10_000,
                        help="tamaño del anillo de dedupe en memoria")
    parser.add_argument("--once", action="store_true", help="un único poll y salir")
    args = parser.parse_args(argv)
    if args.cell is not None and args.data_root is None:
        parser.error("--cell requiere --data-root")

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ledger_path = args.ledger or str(Path(store_svc.DB_PATH).parent / "collector-offsets.json")
    collector = build(args.inventory, ledger_path, data_root=args.data_root,
                      cell=args.cell, poll_interval=args.interval,
                      dedupe_window=args.dedupe_window)
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
