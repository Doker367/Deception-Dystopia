"""Offline lab data-plane runner: log files -> v1 events -> ingest.

This module is the *only* place that wires the three halves together, and it is
never imported by ``runtime.ingest`` (the receiver) or by the control plane.
It is the executable shape of the sensor cell's collector loop, kept offline
and deterministic so the whole path can be exercised against fixtures.

Flow per ``step``:

    LogReader.collect()       -> raw records (engine, device_id, format, record)
    normalize.normalize_raw() -> validated v1 events (fail-closed, bounded)
    Spool.submit()            -> durable bounded queue, idempotent on event_id
    Spool.flush_once()        -> authenticated HTTPS batch to the ingest endpoint

There is deliberately no daemonization, no listeners and no network socket here:
``Transport`` is the only thing that ever talks to the receiver and it is
constructed explicitly by the caller (or injected in tests).
"""

from __future__ import annotations

import json

from runtime.logreader import LogReader, Sources
from runtime.normalize import NormalizeError, normalize_raw
from runtime.storage import CapacityError


class DataPlane:
    """Pollable collector that normalizes and spools, then flushes one batch."""

    def __init__(self, reader: LogReader, spool, transport=None):
        self.reader = reader
        self.spool = spool
        self.transport = transport
        self.normalized = 0
        self.skipped = 0
        self.failed = 0
        self.read_failed = 0
        self.paused = False
        self.last_errors = []

    def step(self):
        """Read, normalize and spool newly available records; then try to flush."""
        collected = 0
        self.paused = False
        # ``collect`` keeps the records read from healthy sources when one
        # malformed log fails; the per-source error is counted, not raised.
        records, errors = self.reader.collect()
        self.last_errors = errors
        self.read_failed += len(errors)
        for engine, device_id, _format, record in records:
            try:
                event = normalize_raw(engine, device_id, record)
            except (NormalizeError, ValueError):
                # Fail closed: count and continue; never guess, never block the
                # rest of the cell on one hostile/malformed line.
                self.failed += 1
                continue
            if event is None:
                self.skipped += 1
                continue
            try:
                self.spool.submit(event)
            except CapacityError:
                # Reject-new is authoritative. Pause the collector instead of
                # spinning; the spool already persisted its discard counter.
                self.failed += 1
                self.paused = True
                break
            except ValueError:
                # Same event_id with different content: a bug or a hostile
                # replay. Never overwrite; count it and keep the rest moving.
                self.failed += 1
                continue
            self.normalized += 1
            collected += 1
        flushed = bool(self.transport and not self.paused
                       and self.spool.flush_once(self.transport))
        return {"collected": collected, "flushed": flushed, **self.stats()}

    def stats(self):
        return {
            "normalized": self.normalized,
            "skipped": self.skipped,
            "failed": self.failed,
            "read_failed": self.read_failed,
            "paused": self.paused,
            "errors": self.last_errors,
            "spool": self.spool.health(),
        }

    def run(self, max_steps=None):
        """Drain the current files for as many polls as new data appears."""
        steps = 0
        while max_steps is None or steps < max_steps:
            result = self.step()
            steps += 1
            if result["collected"] == 0 or result["paused"]:
                break
        return steps


def build(inventory_path, spool, transport=None, data_root=None, cell=None):
    """Construct a DataPlane from the reviewed inventory and a live spool."""
    return DataPlane(
        LogReader(Sources.from_inventory(inventory_path, data_root=data_root, cell=cell)),
        spool, transport)


def main(argv=None):
    """One-shot offline lab run: emit a JSON summary, never a daemon or socket."""
    import argparse
    from runtime.sensor import Spool
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--spool", required=True)
    parser.add_argument("--data-root")
    parser.add_argument("--cell", type=int,
                        help="cell number when --data-root is the host storage root")
    parser.add_argument("--max-steps", type=int)
    args = parser.parse_args(argv)
    if args.cell is not None and args.data_root is None:
        parser.error("--cell requires --data-root")
    spool = Spool(args.spool)
    plane = build(args.inventory, spool, data_root=args.data_root, cell=args.cell)
    plane.run(max_steps=args.max_steps)
    print(json.dumps(plane.stats(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["DataPlane", "build", "main"]
