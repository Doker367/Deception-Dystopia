"""Collector: tail the declared honeypot logs and emit raw records.

This is the read-only half of the sensor cell. It knows nothing about the v1
event contract or transport; it only turns the log files declared by
``deploy/honeypots/inventory.yaml`` into raw records (JSON objects for the five
jsonl engines, text lines for Endlessh) for ``runtime.normalize`` to consume.

Safety rules (from ``deploy/honeypots/adapters.md``):

* **Read, never execute.** Only text is read, line-bounded; binaries, URLs and
  HTML are never opened or interpreted.
* **Rotation-aware.** Each source remembers ``(device, inode, offset)``. On
  truncation (copytruncate) or inode change (rename+recreate) the reader resets
  to the start of the new file instead of silently re-emitting or skipping.
* **Bounded.** A single line is capped (``max_line_bytes``) and a file larger
  than the declared cap is rejected up front; the reader never slurps a log.
* **Explicit sources only.** Log paths are *declared*: either built from the
  reviewed inventory (``Sources.from_inventory``) or passed literally. Nothing
  is discovered from the filesystem.

In the offline lab the reader defaults to the shipped synthetic fixtures
(``deploy/honeypots/fixtures/*``), which are the test material declared by the
inventory. On a real Linux cell the operator points ``data_root`` at the
rendered per-cell root (``<host_root>/cells/<N>``) and the same reader tails the
live files. The container log path is translated through the ``volumes`` entry
declared for that engine, never by guessing a shared prefix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat as stat_module
from typing import Iterator

FORMATS = ("jsonl", "text")

# A single line is hostile data; keep it bounded even if the file has none.
DEFAULT_MAX_LINE_BYTES = 64 * 1024
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024


class LogReaderError(ValueError):
    """Invalid source declaration or unreadable log file."""


@dataclass(frozen=True)
class Source:
    """One declared log file to tail."""

    engine: str
    path: str
    format: str
    device_id: str

    def __post_init__(self):
        if not isinstance(self.engine, str) or not self.engine.strip():
            raise LogReaderError("engine required")
        if self.format not in FORMATS:
            raise LogReaderError(f"unsupported log format {self.format!r}")
        if not self.path or not isinstance(self.path, str):
            raise LogReaderError("log path required")
        if not isinstance(self.device_id, str) or not self.device_id.strip():
            raise LogReaderError("device_id required")

    @property
    def resolved(self) -> Path:
        return Path(self.path).expanduser()


class Sources:
    """Build the declared source list from the reviewed inventory (lazy yaml)."""

    def __init__(self, sources):
        for source in sources:
            if not isinstance(source, Source):
                raise LogReaderError("sources must be Source entries")
        if not sources:
            raise LogReaderError("at least one source is required")
        seen = {s.engine for s in sources}
        if len(seen) != len(sources):
            raise LogReaderError("duplicate engine in sources")
        self._sources = tuple(sources)

    @property
    def sources(self):
        return self._sources

    @classmethod
    def from_inventory(cls, inventory_path, data_root=None, cell=None):
        """Resolve the six declared engines to concrete log files.

        ``inventory_path`` is ``deploy/honeypots/inventory.yaml``. In the lab
        (no ``data_root``) the reader uses the declared fixture file; with a
        ``data_root`` it maps each engine's container-internal ``log_path`` onto
        the host bind declared by the same inventory entry.

        ``data_root`` is the host directory that contains the per-engine volume
        subdirectories (normally ``<host_root>/cells/<N>``). Pass the cell number
        as ``cell`` when ``data_root`` is the inventory ``storage.host_root``;
        the reader then appends ``cells/<N>`` itself.
        """
        from runtime.honeypots import load_inventory

        inventory = load_inventory(inventory_path)
        use_host_paths = data_root is not None
        if use_host_paths:
            root = Path(data_root).expanduser()
            if cell is not None:
                if type(cell) is not int or cell < 1:
                    raise LogReaderError("cell must be a positive integer")
                root = root / "cells" / str(cell)
        sources = []
        for engine in inventory.engines.values():
            if use_host_paths:
                host_path = _map_log_path(root, engine.log_path, engine.volumes)
            else:
                host_path = str((inventory.base / engine.fixture).resolve())
            sources.append(Source(
                engine=engine.name,
                path=host_path,
                format=engine.log_format,
                device_id=engine.device_id,
            ))
        return cls(sources)


def _map_log_path(data_root, log_path: str, volumes=None) -> str:
    """Map a container-internal log path onto the host bind for that engine.

    The inventory declares volumes as ``source:target`` (for example
    ``cowrie/var:/cowrie/cowrie-git/var``). The rendered per-cell bind is
    ``<cell-root>/cowrie/var``, so a container log
    ``/cowrie/cowrie-git/var/log/cowrie/cowrie.json`` becomes
    ``<cell-root>/cowrie/var/log/cowrie/cowrie.json``.

    ``volumes`` is required for that translation. Without it the function falls
    back to the old container-tail mapping, kept only for callers that already
    know the target layout; inventory-driven code always passes volumes.
    """
    path = Path(log_path)
    if not path.is_absolute() or ".." in path.parts:
        raise LogReaderError(f"log path must be an absolute container path: {log_path}")
    root = Path(data_root).expanduser()
    if volumes is None:
        return str(root / Path(*path.parts[1:]))

    matches = []
    for source, target in volumes:
        source_path = Path(source)
        target_path = Path(target)
        if source_path.is_absolute() or ".." in source_path.parts:
            raise LogReaderError(f"volume source must be a safe relative path: {source}")
        if ".." in target_path.parts or not target_path.is_absolute():
            raise LogReaderError(f"volume target must be an absolute path: {target}")
        if path == target_path or path.is_relative_to(target_path):
            matches.append((len(target_path.parts), source_path,
                            path.relative_to(target_path)))
    if not matches:
        raise LogReaderError(f"log path is outside every declared volume: {log_path}")
    _, source_path, remainder = max(matches, key=lambda item: item[0])
    return str(root / source_path / remainder)


@dataclass
class _Cursor:
    dev: int = -1
    ino: int = -1
    offset: int = 0
    pending: bytes = b""
    errors: int = 0


@dataclass
class LogReader:
    """Pollable multi-source tailer. One ``step`` reads new lines from all files."""

    sources: Sources
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    cursors: dict = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.sources, Sources):
            raise LogReaderError("Sources required")
        if self.max_line_bytes < 1 or self.max_file_bytes < 1:
            raise LogReaderError("bounds must be positive")
        self.cursors = {s.engine: _Cursor() for s in self.sources.sources}

    def _read_source(self, source: Source) -> Iterator:
        path = source.resolved
        if path.is_symlink() or not path.is_file():
            raise LogReaderError(f"missing regular log file: {path}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise LogReaderError(f"cannot open {path}: {exc.strerror or exc}") from None
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat_module.S_ISREG(info.st_mode):
                raise LogReaderError(f"not a regular log file: {path}")
            if info.st_size > self.max_file_bytes:
                raise LogReaderError(f"log file exceeds {self.max_file_bytes} bytes: {path}")
            cursor = self.cursors[source.engine]
            if cursor.dev != info.st_dev or cursor.ino != info.st_ino \
                    or info.st_size < cursor.offset:
                # New file (rotation) or truncated (copytruncate): start over
                # and drop any held tail bytes from the old inode.
                cursor.dev, cursor.ino = info.st_dev, info.st_ino
                cursor.offset, cursor.pending = 0, b""
            if cursor.offset >= info.st_size and not cursor.pending:
                return
            read_start = cursor.offset
            stream.seek(read_start)
            data = stream.read(info.st_size - read_start)

        chunk = cursor.pending + data
        cursor.pending = b""
        # Only complete lines are emitted. A trailing partial line is held back
        # so a poll in the middle of a write never emits half a record.
        if chunk and not chunk.endswith(b"\n"):
            last_nl = chunk.rfind(b"\n")
            if last_nl == -1:
                if len(chunk) > self.max_line_bytes:
                    cursor.pending = b""
                    cursor.offset = info.st_size
                    raise LogReaderError(
                        f"unterminated line exceeds {self.max_line_bytes} bytes in {path}")
                cursor.pending = chunk
                # Re-reading ``data`` re-reads the old pending bytes too.
                # ``offset`` must stay at the first byte of the held line, not
                # move back by the whole combined buffer.
                cursor.offset = read_start
                return
            cursor.pending = chunk[last_nl + 1:]
            chunk = chunk[: last_nl + 1]
        # Consumed bytes end where the held partial line starts.
        cursor.offset = info.st_size - len(cursor.pending)

        if chunk and not chunk.endswith(b"\n"):
            raise AssertionError("complete chunk must end with a newline")
        for raw_line in chunk.split(b"\n")[:-1]:
            raw_line = raw_line.rstrip(b"\r")
            if len(raw_line) > self.max_line_bytes:
                raise LogReaderError(f"line exceeds {self.max_line_bytes} bytes in {path}")
            line = raw_line.decode("utf-8", "replace")
            if not line.strip():
                continue
            if source.format == "jsonl":
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LogReaderError(f"invalid JSONL in {path}: {exc.msg}") from None
                if not isinstance(record, dict):
                    raise LogReaderError(f"JSONL record must be an object in {path}")
                yield record
            else:
                yield line

    def collect(self) -> tuple:
        """Read every source and return ``(records, errors)``.

        A failure in one source does not discard records already read from the
        others: the error is reported per engine and the caller can count it.
        ``records`` use the safe tuple ``(engine, device_id, format, raw)``.
        """
        emitted = []
        errors = []
        for source in self.sources.sources:
            try:
                for record in self._read_source(source):
                    emitted.append((source.engine, source.device_id, source.format, record))
            except LogReaderError as exc:
                self.cursors[source.engine].errors += 1
                errors.append({"engine": source.engine, "error": str(exc)})
            except OSError as exc:
                self.cursors[source.engine].errors += 1
                errors.append({"engine": source.engine,
                               "error": f"cannot read {source.path}: {exc}"})
        return emitted, errors

    def step(self) -> list:
        """Read all newly available records; raise on the first source error.

        The strict API is kept for callers that must stop on a malformed log.
        The collector loop uses :meth:`collect`, which keeps the records read
        from healthy sources and reports errors without losing them.
        """
        emitted, errors = self.collect()
        if errors:
            raise LogReaderError(errors[0]["error"])
        return emitted

    def health(self) -> dict:
        """Read-only diagnostics; no payloads or paths beyond the declared sources."""
        return {
            "sources": [
                {
                    "engine": s.engine,
                    "device_id": s.device_id,
                    "format": s.format,
                    "path": s.path,
                    "offset": self.cursors[s.engine].offset,
                    "errors": self.cursors[s.engine].errors,
                }
                for s in self.sources.sources
            ],
        }


def resolve_sources(inventory_path, data_root=None, cell=None):
    """Convenience wrapper returning a ready ``LogReader`` for the inventory."""
    return LogReader(Sources.from_inventory(inventory_path, data_root=data_root, cell=cell))


__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_LINE_BYTES",
    "LogReader",
    "LogReaderError",
    "Source",
    "Sources",
    "resolve_sources",
]
