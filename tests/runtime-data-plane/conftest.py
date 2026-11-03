"""Shared fixtures for the offline runtime data-plane tests.

Everything here is deterministic and offline: no nftables, no Docker, no
containers, no sockets. The only inputs are the reviewed inventory + synthetic
fixtures, the borrowed stdlib-only runtime modules, and scratch tmp_path DBs.
"""
from pathlib import Path

import pytest

from runtime.identity import Registry
from runtime.storage import EventStore

REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = REPO_ROOT / "deploy" / "honeypots" / "inventory.yaml"

# The device_ids declared by the six engines in the inventory. One sensor cell
# is assigned exactly these decoys so the ingest receiver accepts their events.
INVENTORY_DEVICES = ["srv-files-01", "sw-access-01", "srv-db-01", "fw-edge-01"]


@pytest.fixture(scope="session")
def inventory_path():
    return INVENTORY_PATH


@pytest.fixture
def sensor_token(tmp_path):
    registry = Registry(tmp_path / "identity.db")
    token = registry.rotate("sensor-lab", INVENTORY_DEVICES)
    return registry, token


@pytest.fixture
def event_store(tmp_path):
    return EventStore(tmp_path / "events.db", max_bytes=8 * 1024 * 1024)
