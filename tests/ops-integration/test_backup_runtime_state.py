"""Integrated runtime-state report of the backup contract.

Deterministic and offline: the report reuses the fixed artifact table and
the runtime health snapshots of synthetic stores. No service, container,
network or privileged operation is involved.
"""
import json
import os
from pathlib import Path

import pytest

from runtime import backup


def _report(state, **kwargs):
    specs = backup.default_artifact_specs(state["state_root"], state["control_env_dir"],
                                          state["elastic_env"])
    return backup.runtime_state(specs, state_root=state["state_root"],
                                 control_env_dir=state["control_env_dir"],
                                 elastic_env=state["elastic_env"], **kwargs)


def test_runtime_state_reuses_the_fixed_artifact_table(state):
    report = _report(state)

    paths = [item["path"] for item in report["artifacts"]]
    assert paths == sorted(paths)
    assert len(paths) == len(backup.default_artifact_specs(
        state["state_root"], state["control_env_dir"], state["elastic_env"]))
    assert report["schema"] == backup.RUNTIME_STATE_SCHEMA
    assert report["dry_run"] is True
    assert report["host_operations"] == []
    assert report["ready_for_backup"] is True
    assert report["missing_required"] == []


def test_runtime_state_reuses_the_runtime_health_snapshots(state):
    report = _report(state)

    ingest = report["runtime"]["ingest"]
    assert ingest["status"] == "available"
    assert ingest["events"] == 1
    assert ingest["outbox_pending"] == 1
    spool = report["runtime"]["sensor_spool"]
    assert spool["status"] == "available"
    assert spool["queued"] == 1
    assert spool["quarantined"] == 0


def test_runtime_state_reports_the_declared_gaps(state):
    report = _report(state)

    relpaths = {item["relpath"] for item in report["uncovered"]}
    assert relpaths == {item.relpath for item in backup.UNCOVERED_RUNTIME_STATE}
    spool = next(item for item in report["uncovered"] if item["relpath"] == "sensor/spool.db")
    assert spool["status"] == "present"
    assert spool["runtime"]["queued"] == 1
    assert spool["reason"]
    token = next(item for item in report["uncovered"] if item["relpath"] == "sensor/token")
    assert token["status"] == "missing"
    assert "secret" in token["reason"]


def test_runtime_state_marks_missing_required_artifacts(state):
    state["users"].unlink()

    report = _report(state)

    assert report["ready_for_backup"] is False
    assert report["missing_required"] == [str(state["users"])]


def test_runtime_state_never_exposes_environment_values(state):
    report = _report(state)

    dumped = json.dumps(report)
    for secret in ("NETPULSE_JWT_SECRET", "b" * 64, "CHANGEME_UNIQUE_ADMIN_PASSWORD_PER_INSTANCE"):
        assert secret not in dumped
    environment = next(item for item in report["artifacts"]
                       if item["path"] == "artifacts/manager/control.env.json")
    assert environment["settings_exported"] == [
        "DYSTOPIA_CONTROL_CONFIG", "DYSTOPIA_CONTROL_STATE", "NETPULSE_ENV"]
    assert "production" not in json.dumps(environment)


def test_runtime_state_reports_an_unreadable_environment(state, monkeypatch):
    def denied(spec):
        raise PermissionError(f"denied: {spec.source}")

    monkeypatch.setattr(backup, "exported_setting_names", denied)

    report = _report(state)

    environment = next(item for item in report["artifacts"]
                       if item["path"] == "artifacts/manager/control.env.json")
    assert environment["status"] == "unreadable"
    assert environment["settings_exported"] == []
    assert "PermissionError" in environment["detail"]
    # The rest of the report still describes the host instead of crashing.
    assert report["ready_for_backup"] is True


def test_runtime_state_is_read_only(state):
    before = {path: path.read_bytes() for path in
              (state["users"], state["events"], state["spool"])}

    _report(state)

    for path, payload in before.items():
        assert path.read_bytes() == payload
    # No artifact, database or side file was created by the report.
    assert sorted(item.name for item in state["state_root"].iterdir()) == [
        "control", "ingest", "sensor"]
    assert sorted(item.name for item in state["control_env_dir"].iterdir()) == [
        "control.env", "install.json"]


def test_runtime_state_does_not_create_a_missing_database(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()

    report = backup.runtime_state(state_root=empty, control_env_dir=empty,
                                  elastic_env=empty)

    assert report["runtime"]["ingest"] == {"status": "missing"}
    assert report["runtime"]["sensor_spool"] == {"status": "missing"}
    assert list(empty.iterdir()) == []
    assert not Path(empty / "ingest/events.db").exists()


def test_uncovered_artifact_rejects_an_unknown_base():
    with pytest.raises(backup.BackupError):
        backup.UncoveredArtifact("sensor", "sensor/spool.db", "nowhere", "file",
                                 "reason")
    with pytest.raises(backup.BackupError):
        backup.UncoveredArtifact("sensor", "sensor/spool.db", "state", "socket",
                                 "reason")


def test_runtime_state_permissions_of_the_source_are_not_changed(state):
    before = os.stat(state["users"]).st_mode

    _report(state)

    assert os.stat(state["users"]).st_mode == before
