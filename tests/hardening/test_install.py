"""Installer validation tests use synthetic config and scratch files only."""
import json
import subprocess
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import pytest

from runtime import install
from runtime.cli import bootstrap
from runtime.health import snapshot
from runtime.localfiles import create_private, read_private


def config():
    return {"version": 1, "management_interface": "mgmt0", "management_network": "198.51.100.0/24",
            "deception_interface": "decoy0", "deception_network": "192.0.2.0/24",
            "protected_networks": ["198.51.100.0/24", "203.0.113.0/24", "fd42:d570:100::/64"],
            "control_bind": "127.0.0.1", "recovery": "Synthetic disposable console recovery fixture"}


def test_dry_run_has_no_writes_or_host_commands(tmp_path, capsys):
    file = tmp_path / "install.json"
    file.write_text(json.dumps(config()))
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    def forbidden(*args, **kwargs):
        raise AssertionError("dry-run attempted a host mutation or command")
    with patch.object(install, "_command", forbidden), patch.object(install, "create_private", forbidden), \
            patch.object(install.os, "mkdir", forbidden), patch.object(install.os, "chown", forbidden):
        assert install.main(["--config", str(file), "--dry-run"]) == 0
    after = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert before == after
    output = json.loads(capsys.readouterr().out)
    assert output["network_changes"] == []
    assert output["activation"] == "blocked"
    assert output["enable_and_start_after_local_bootstrap"] == ["dystopia-control.service"]


@pytest.mark.parametrize("change", [
    {"deception_interface": "mgmt0"}, {"deception_network": "198.51.100.0/25"},
    {"protected_networks": []}, {"control_bind": "0.0.0.0"},
    {"management_interface": "eth0;false"}, {"recovery": ""},
    {"deception_network": "fd42:d570:100::/64"},
])
def test_unsafe_install_config_is_blocked(change):
    with pytest.raises(ValueError):
        install.plan({**config(), **change})


def test_apply_requires_explicit_authorization_before_any_preflight():
    with patch.object(install, "preflight", side_effect=AssertionError("must not reach preflight")):
        with pytest.raises(PermissionError):
            install.apply(config(), Path("unused"), confirmation=None)


def test_reprovision_preserves_secrets_config_and_users(tmp_path):
    secret, cfg, users = (tmp_path / name for name in ("control.env", "install.json", "users.yaml"))
    assert create_private(secret, b"SYNTHETIC-SECRET-ONLY")
    assert create_private(cfg, json.dumps(config()).encode())
    bootstrap(users, "fixture-admin", "synthetic-test-password-not-real")
    before = [p.read_bytes() for p in (secret, cfg, users)]
    assert not create_private(secret, b"do-not-replace")
    assert not create_private(cfg, b"do-not-replace")
    with pytest.raises(FileExistsError):
        bootstrap(users, "another-admin", "another-synthetic-password")
    assert before == [p.read_bytes() for p in (secret, cfg, users)]
    assert all(p.stat().st_mode & 0o077 == 0 for p in (secret, cfg, users))


def test_failed_secret_write_does_not_publish_partial_file(tmp_path):
    dest = tmp_path / "secret"
    with patch("runtime.localfiles.os.fsync", side_effect=OSError("synthetic disk failure")):
        with pytest.raises(OSError):
            create_private(dest, b"synthetic")
    assert not dest.exists()
    assert list(tmp_path.iterdir()) == []


def test_private_files_reject_symlinks_and_world_permissions(tmp_path):
    dest, link = tmp_path / "secret", tmp_path / "link"
    create_private(dest, b"fixture")
    link.symlink_to(dest)
    with pytest.raises(OSError):
        read_private(link)
    dest.chmod(0o644)
    with pytest.raises(PermissionError):
        read_private(dest)


def test_status_does_not_create_missing_database(tmp_path):
    with pytest.raises(FileNotFoundError):
        snapshot(tmp_path / "missing.db", "sensor")
    assert list(tmp_path.iterdir()) == []


def test_diagnostic_reports_inactive_service_without_raising():
    failure = subprocess.CalledProcessError(3, ["systemctl"], output="inactive\n")
    with patch.object(install, "_command", side_effect=failure):
        assert install.diagnose()["management"] == "inactive"


def test_release_ancestor_writable_by_other_user_is_rejected():
    with patch.object(install.os, "open", return_value=999), \
            patch.object(install.os, "close"), \
            patch.object(install.os, "fstat", return_value=SimpleNamespace(st_uid=1234, st_mode=0o755)):
        with pytest.raises(PermissionError):
            install._root_directory("/opt/dystopia/current", mode=0o755)


def test_bundle_rejects_unhashed_unpinned_or_wrong_digest(tmp_path):
    (tmp_path / "hashes.json").write_text(json.dumps({"requirements.lock": "0"*64}))
    (tmp_path / "requirements.lock").write_text("fastapi\n")
    with pytest.raises(ValueError):
        install.verify_bundle(tmp_path)


def test_units_separate_users_and_never_enable_sensors_implicitly():
    root = Path(__file__).resolve().parents[2]
    for role in ("control", "ingest", "sensor", "processor", "query"):
        text = (root / "deploy/systemd" / ("dystopia-"+role+".service")).read_text()
        assert "NoNewPrivileges=yes" in text
        assert "ProtectSystem=strict" in text
        assert "CapabilityBoundingSet=\n" in text
        assert "IPAddressDeny=any" in text
        assert "ExecStart=" in text and "sudo" not in text
        assert "ExecStop=" not in text  # must not remove containment rules
    socket_unit=(root / 'deploy/systemd/dystopia-query.socket').read_text()
    assert 'SocketMode=0600' in socket_unit
    assert 'SocketUser=dystopia-control' in socket_unit
    control=(root / 'deploy/systemd/dystopia-control.service').read_text()
    assert 'InaccessiblePaths=-/var/lib/dystopia/ingest' in control
    assert 'DYSTOPIA_QUERY_SOCKET=/run/dystopia-query/query.sock' in control
    query=(root / 'deploy/systemd/dystopia-query.service').read_text()
    assert 'User=dystopia-query' in query and 'ReadOnlyPaths=/var/lib/dystopia/ingest/events.db' in query
    assert 'RestrictAddressFamilies=AF_UNIX' in query
    sensor = (root / "deploy/systemd/dystopia-sensor.service").read_text()
    assert "EnvironmentFile=/etc/dystopia/sensor.env" in sensor
    assert "EnvironmentFile=/etc/dystopia/control.env" not in sensor
