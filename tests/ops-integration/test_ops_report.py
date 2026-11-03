"""Offline integration of the operations plane with the runtime layer.

The report is read-only and deterministic: it states what the control,
backup, honeypot and runtime planes expose, and which deployed unit paths
the operations plane does not account for. No service, container, network,
nftables, KVM or systemd operation is performed.
"""
import json
from pathlib import Path

import pytest

from runtime import ops
from runtime.cli import main

REPO_ROOT = Path(__file__).resolve().parents[2]


def _context(state, **kwargs):
    defaults = {
        "state_root": state["state_root"],
        "control_env_dir": state["control_env_dir"],
        "elastic_env": state["elastic_env"],
        "inventory": REPO_ROOT / "deploy/honeypots/inventory.yaml",
        "profile": REPO_ROOT / "deploy/honeypots/profiles/cell-mvp.example.yaml",
        "units_dir": REPO_ROOT / "deploy/systemd",
    }
    defaults.update(kwargs)
    return ops.OpsContext(**defaults)


def _stable(report):
    """Drop the live counters: the rest of the report is byte-deterministic."""
    copy = json.loads(json.dumps(report))
    copy.pop("runtime", None)
    copy.get("backup", {}).pop("runtime", None)
    for item in copy.get("backup", {}).get("uncovered", []):
        item.pop("runtime", None)
    return copy


def _cli(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _cli_args(state, *extra):
    return ["ops", "status",
            "--state-root", str(state["state_root"]),
            "--control-env-dir", str(state["control_env_dir"]),
            "--elastic-env", str(state["elastic_env"]), *extra]


# --------------------------------------------------------------------------
# Report content
# --------------------------------------------------------------------------


def test_status_report_covers_every_plane(state):
    report = ops.status(_context(state))

    assert report["schema"] == ops.SCHEMA
    assert report["dry_run"] is True
    assert report["host_operations"] == []
    assert report["control"]["present"] is True
    assert report["backup"]["ready_for_backup"] is True
    assert report["runtime"]["ingest"]["status"] == "available"
    assert report["honeypots"]["status"] == "valid"
    assert report["honeypots"]["activation_allowed"] is False
    assert report["gate"]["activation_performed"] is False
    assert report["alignment"]["unaccounted"] == []
    assert report["ok"] is True
    assert report["limits"]


def test_status_report_is_deterministic(state):
    first = _stable(ops.status(_context(state)))
    second = _stable(ops.status(_context(state)))

    assert first == second


def test_status_report_never_materializes_a_secret(state):
    report = ops.status(_context(state))

    dumped = json.dumps(report)
    assert "NETPULSE_JWT_SECRET" not in dumped
    assert "b" * 64 not in dumped
    assert "CHANGEME_UNIQUE_ADMIN_PASSWORD_PER_INSTANCE" not in dumped
    assert "production" not in dumped


def test_status_report_states_the_declared_gaps(state):
    report = ops.status(_context(state))

    relpaths = {item["relpath"] for item in report["backup"]["uncovered"]}
    assert "sensor/spool.db" in relpaths
    assert "sensor/token" in relpaths
    assert report["backup"]["runtime"]["sensor_spool"]["queued"] == 1


def test_status_report_matches_the_deployed_units(state):
    report = ops.status(_context(state))

    classifications = {item["classification"] for item in report["alignment"]["paths"]}
    assert "backup-covered" in classifications
    assert "declared-outside-backup" in classifications
    assert "unaccounted" not in classifications
    covered = {item["path"] for item in report["alignment"]["paths"]
               if item["classification"] == "backup-covered"}
    assert "/var/lib/dystopia/ingest/events.db" in covered
    assert "/var/lib/dystopia/control/config/users.yaml" in covered


def test_status_report_fails_when_a_unit_path_is_unaccounted(tmp_path, state):
    units = tmp_path / "units"
    units.mkdir()
    (units / "rogue.service").write_text(
        "[Service]\nExecStart=/usr/bin/true --events /var/lib/dystopia/ingest/rogue.db\n")

    report = ops.status(_context(state, units_dir=units))

    assert report["alignment"]["unaccounted"] == ["/var/lib/dystopia/ingest/rogue.db"]
    check = next(item for item in report["checks"]
                 if item["id"] == "unit_paths_accounted_for")
    assert check["status"] == "fail"
    assert report["ok"] is False


def test_status_report_fails_when_required_state_is_missing(state):
    state["users"].unlink()

    report = ops.status(_context(state))

    assert report["ok"] is False
    failed = {item["id"] for item in report["checks"] if item["status"] == "fail"}
    assert "control_state_present" in failed
    assert "backup_contract_ready" in failed


def test_status_report_evaluates_the_gate_without_activating(tmp_path, state):
    policy = tmp_path / "cell.json"
    policy.write_text(json.dumps({
        "version": 1, "cell": 7, "bridge": "dybr7",
        "gateway_mac": "02:10:20:30:40:50",
        "services": [{"address": "198.51.100.20", "protocol": "tcp", "port": 22}],
        "telemetry": None, "memory_mib": 512, "vcpus": 1}))

    report = ops.status(_context(state, policies=((7, policy),)))

    assert report["gate"]["cells"][0]["cell"] == 7
    assert report["gate"]["activation_allowed"] is False
    assert report["gate"]["activation_performed"] is False
    check = next(item for item in report["checks"]
                 if item["id"] == "activation_gate_fail_closed")
    assert check["status"] == "pass"


def test_status_report_records_an_invalid_policy(state):
    report = ops.status(_context(state, policies=((7, Path("/nonexistent.json")),)))

    assert report["gate"]["status"] == "invalid"
    assert report["gate"]["policy_errors"]["7"]
    assert report["gate"]["cells"] == []
    check = next(item for item in report["checks"]
                 if item["id"] == "cell_policies_valid")
    assert check["status"] == "fail"
    assert report["ok"] is False


def test_status_report_reads_optional_unit_path_prefixes(tmp_path, state):
    units = tmp_path / "units"
    units.mkdir()
    (units / "optional.service").write_text(
        "[Unit]\n"
        "ConditionPathExists=-/etc/dystopia/control.env\n"
        "[Service]\n"
        "EnvironmentFile=-/etc/dystopia/ingest.env\n"
        "ExecStart=/opt/dystopia/venv/bin/python -m runtime.processor "
        "--events=/var/lib/dystopia/ingest/events.db\n")

    report = ops.status(_context(state, units_dir=units))

    assert report["alignment"]["unaccounted"] == []
    classifications = {(item["path"], item["classification"])
                       for item in report["alignment"]["paths"]}
    assert ("/etc/dystopia/control.env", "backup-covered") in classifications
    assert ("/etc/dystopia/ingest.env", "declared-outside-backup") in classifications
    assert ("/var/lib/dystopia/ingest/events.db", "backup-covered") in classifications


# --------------------------------------------------------------------------
# CLI contract
# --------------------------------------------------------------------------


def test_cli_status_is_deterministic_json(state, capsys):
    code, first, err = _cli(_cli_args(state), capsys)
    assert code == 0 and err == ""
    code, second, _ = _cli(_cli_args(state), capsys)
    assert code == 0

    assert _stable(json.loads(first)) == _stable(json.loads(second))


def test_cli_verify_returns_zero_when_every_check_passes(state, capsys):
    code, out, _ = _cli(["ops", "verify",
                         "--state-root", str(state["state_root"]),
                         "--control-env-dir", str(state["control_env_dir"]),
                         "--elastic-env", str(state["elastic_env"])], capsys)

    assert code == 0
    report = json.loads(out)
    assert report["action"] == "ops-verify"
    assert report["ok"] is True


def test_cli_verify_returns_two_when_a_check_fails(state, capsys):
    state["users"].unlink()

    code, out, _ = _cli(["ops", "verify",
                         "--state-root", str(state["state_root"]),
                         "--control-env-dir", str(state["control_env_dir"]),
                         "--elastic-env", str(state["elastic_env"])], capsys)

    assert code == 2
    assert json.loads(out)["ok"] is False


def test_cli_rejects_a_malformed_policy_argument(state, capsys):
    with pytest.raises(SystemExit):
        main(_cli_args(state, "--policy", "not-a-cell"))


def test_cli_ops_does_not_change_the_process_umask(state, capsys, monkeypatch):
    from unittest.mock import patch

    with patch("runtime.cli.os.umask") as umask:
        code, _, _ = _cli(_cli_args(state), capsys)

    umask.assert_not_called()
    assert code == 0


def test_cli_ops_writes_nothing_to_the_state_root(state, capsys):
    before = sorted(str(path) for path in state["state_root"].rglob("*"))

    _cli(_cli_args(state), capsys)

    after = sorted(str(path) for path in state["state_root"].rglob("*"))
    assert before == after
