"""Backup/restore contract tests for the Dystopia offline control plane.

Deterministic, offline and secret-free: every test builds a synthetic state
root with bounded fixtures (small sqlite state, synthetic TLS material,
allowlisted environment settings) and asserts the pure contract in
runtime/backup.py plus the JSON contract of runtime.cli and the shell syntax
of the operator scripts. No Docker, no sudo, no systemd, no network.
"""
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys

import pytest

from runtime import backup
from runtime.cli import main

REPO_ROOT = Path(__file__).resolve().parents[2]
CREATED = "2026-11-02T10:00:00Z"
# Synthetic, never-real secret material used only to prove it stays excluded.
PLANTED_SECRETS = (
    "CHANGEME_UNIQUE_ADMIN_PASSWORD_PER_INSTANCE",
    "CHANGEME_KIBANA_SERVICE_TOKEN",
    "CHANGEME_openssl_rand_hex_32",
    "synthetic-api-key-never-in-backup",
)
TLS_KEY_MARKER = "-----BEGIN SYNTHETIC SERVER.KEY-----"
REGISTRY_MARKER = "synthetic-auth-registry-digest"
ANALYTICS_ENV = (
    "# generated fixture for the allowlist test\n"
    "ELASTIC_VERSION=9.3.5\n"
    "ELASTIC_MEMORY_LIMIT=3g\n"
    "KIBANA_MEMORY_LIMIT=1536m\n"
    "ILM_DECEPTION_EVENTS_DAYS=30\n"
    "DYSTOPIA_ELASTIC_URL=https://127.0.0.1:9200\n"
    "DYSTOPIA_ELASTIC_INDEX=deception-events\n"
    f"DYSTOPIA_ELASTIC_API_KEY={PLANTED_SECRETS[3]}\n"
    f"ELASTIC_PASSWORD={PLANTED_SECRETS[0]}\n"
    f"KIBANA_SYSTEM_PASSWORD={PLANTED_SECRETS[1]}\n"
    f"KIBANA_SAVED_OBJECTS_ENCRYPTION_KEY={PLANTED_SECRETS[2]}\n"
)
CONTROL_ENV = ("DYSTOPIA_CONTROL_STATE=/var/lib/dystopia/control\n"
               "DYSTOPIA_CONTROL_CONFIG=/var/lib/dystopia/control/config\n"
               "NETPULSE_ENV=production\n"
               f"NETPULSE_JWT_SECRET={'a' * 64}\n"
               f"ELASTIC_PASSWORD={PLANTED_SECRETS[0]}\n")


def _make_db(path, note="synthetic ingest state"):
    db = sqlite3.connect(path)
    db.executescript("CREATE TABLE events (id INTEGER PRIMARY KEY, note TEXT);"
                     f"INSERT INTO events VALUES (1,'{note}')")
    db.commit()
    db.close()


@pytest.fixture()
def state(tmp_path):
    state = tmp_path / "state"
    etc = tmp_path / "etc"
    (state / "control/config").mkdir(parents=True)
    (state / "ingest").mkdir()
    etc.mkdir()
    users = state / "control/config/users.yaml"
    users.write_text("users:\n- username: done\n  password_hash: "
                     "synthetic-hash-never-a-real-bcrypt-value\n")
    for name in ("server.crt", "server.key"):
        marker = state / "ingest" / name
        marker.write_text(f"-----BEGIN SYNTHETIC {name.upper()}-----\n" + "ab" * 16 + "\n")
    _make_db(state / "ingest/events.db")
    _make_db(state / "ingest/sensors.db", REGISTRY_MARKER)
    (etc / "install.json").write_text(json.dumps({"version": 1}))
    (etc / "control.env").write_text(CONTROL_ENV)
    elastic = tmp_path / "deploy" / "elastic" / ".env"
    elastic.parent.mkdir(parents=True)
    elastic.write_text(ANALYTICS_ENV)
    paths = (users, state / "ingest/events.db", state / "ingest/sensors.db",
             state / "ingest/server.crt", state / "ingest/server.key",
             etc / "install.json", etc / "control.env", elastic)
    for path in paths:
        os.chmod(path, 0o600)
    return {"state": state, "etc": etc, "elastic": elastic}


def export_backup(state, out):
    specs = backup.default_artifact_specs(state["state"], state["etc"],
                                          state["elastic"])
    return backup.create_backup(specs, out, created_at=CREATED, repo_root=None)


def reseal(out, manifest=None):
    """Rewrite a tampered manifest so its sealed digest is internally valid."""
    manifest = manifest if manifest is not None \
        else json.loads((out / "manifest.json").read_text())
    sealed = hashlib.sha256()
    for item in manifest["artifacts"]:
        if item["sha256"] is not None:
            sealed.update(item["sha256"].encode())
    manifest["artifacts_sha256"] = sealed.hexdigest()
    (out / "manifest.json").write_text(json.dumps(manifest))
    return manifest


def spec_count():
    return len(backup.default_artifact_specs(Path("/x"), Path("/y"), Path("/z")))


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_manifest_is_byte_deterministic(tmp_path, state):
    _, first = export_backup(state, tmp_path / "backup-1")
    _, second = export_backup(state, tmp_path / "backup-2")
    assert first == second
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()


def test_backup_id_and_manifest_bytes_are_stable(tmp_path, state):
    manifest, data = export_backup(state, tmp_path / "backup-id")
    assert backup.backup_id(data) == hashlib.sha256(data).hexdigest()[:16]
    assert data == backup.manifest_bytes(manifest)
    assert data.endswith(b"\n")


def test_manifest_shape_is_oracle_free(tmp_path, state):
    manifest, _ = export_backup(state, tmp_path / "backup-shape")
    assert manifest["schema"] == "dystopia.backup/v1"
    assert manifest["created_at"] == CREATED
    assert manifest["artifact_count"] == spec_count()
    paths = [item["path"] for item in manifest["artifacts"]]
    assert paths == sorted(paths)
    assert all(set(item) == {"role", "path", "kind", "required", "secret",
                             "bytes", "sha256", "status"}
               for item in manifest["artifacts"])


# --------------------------------------------------------------------------
# Secrets never materialize
# --------------------------------------------------------------------------


def test_environment_secrets_never_land_in_any_backup_file(tmp_path, state):
    out = tmp_path / "backup-secrets"
    manifest, _ = export_backup(state, out)
    # Scan every produced file, not only the two env snapshots. The backup
    # intentionally carries the TLS key and registry, so the assertion here is
    # about secrets that the env allowlist promised to exclude.
    blob = b"".join(path.read_bytes() for path in sorted(out.rglob("*"))
                    if path.is_file())
    for secret in PLANTED_SECRETS:
        assert secret.encode() not in blob
    for secret in PLANTED_SECRETS:
        assert secret not in json.dumps(manifest["artifacts"])
    settings = json.loads(
        (out / "artifacts/analytics/elastic.env.json").read_text())["settings"]
    assert set(settings) == {
        "ELASTIC_VERSION", "ELASTIC_MEMORY_LIMIT", "KIBANA_MEMORY_LIMIT",
        "DYSTOPIA_ELASTIC_URL", "DYSTOPIA_ELASTIC_INDEX",
        "ILM_DECEPTION_EVENTS_DAYS"}
    control_settings = json.loads(
        (out / "artifacts/manager/control.env.json").read_text())["settings"]
    # '/etc/dystopia/control.env' uses its own non-secret allowlist: paths and
    # environment mode only; NETPULSE_JWT_SECRET must never be exported.
    assert control_settings == {
        "DYSTOPIA_CONTROL_STATE": "/var/lib/dystopia/control",
        "DYSTOPIA_CONTROL_CONFIG": "/var/lib/dystopia/control/config",
        "NETPULSE_ENV": "production"}


def test_backup_is_declared_secret_bearing(tmp_path, state):
    out = tmp_path / "backup-classification"
    manifest, _ = export_backup(state, out)
    policy = manifest["policy"]
    assert policy["classification"] == "secret-bearing"
    assert policy["secrets"] == "secret-bearing"
    assert policy["secret_artifacts"] == sorted(backup.SECRET_BEARING_ARTIFACTS)
    assert "encrypted" in policy["custody"]
    secret_entries = {item["path"] for item in manifest["artifacts"]
                      if item["secret"] is True}
    assert secret_entries == set(backup.SECRET_BEARING_ARTIFACTS)
    # These artifacts are intentionally present and must be named as secret.
    assert TLS_KEY_MARKER.encode() in (out / "artifacts/ingest/server.key").read_bytes()
    assert REGISTRY_MARKER.encode() in (out / "artifacts/ingest/sensors.db").read_bytes()


def test_plan_and_runtime_state_never_claim_a_secret_free_backup(tmp_path, state):
    specs = backup.default_artifact_specs(state["state"], state["etc"], state["elastic"])
    planned = backup.plan(specs)
    assert planned["classification"] == "secret-bearing"
    assert planned["secret_artifacts"] == sorted(backup.SECRET_BEARING_ARTIFACTS)
    assert all("secret" in item for item in planned["artifacts"])
    report = backup.runtime_state(specs, state_root=state["state"],
                                  control_env_dir=state["etc"],
                                  elastic_env=state["elastic"])
    assert report["classification"] == "secret-bearing"
    assert report["secret_artifacts"] == sorted(backup.SECRET_BEARING_ARTIFACTS)
    assert "excluded" not in json.dumps(report)


def test_manifest_declares_the_restore_policy(tmp_path, state):
    manifest, _ = export_backup(state, tmp_path / "backup-policy")
    assert manifest["policy"]["restore_overwrite"] == "refused"
    assert manifest["policy"]["env_export"] == "non-secret allowlist only"


# --------------------------------------------------------------------------
# Fail-closed planning and restore
# --------------------------------------------------------------------------


def test_plan_fails_when_required_artifacts_missing(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(backup.BackupError) as err:
        backup.plan(state_root=tmp_path / "empty", control_env_dir=tmp_path / "empty",
                    elastic_env=tmp_path / "empty")
    assert "users.yaml" in str(err.value) and "events.db" in str(err.value)


def test_restore_fails_if_a_backed_up_file_is_missing(tmp_path, state):
    out = tmp_path / "backup-missing"
    export_backup(state, out)
    (out / "artifacts/ingest/events.db").unlink()
    with pytest.raises(backup.BackupError) as err:
        backup.restore(out, state_root=tmp_path / "into", control_env_dir=tmp_path / "etc")
    assert "events.db" in str(err.value)


def test_restore_fails_if_a_backed_up_digest_is_tampered(tmp_path, state):
    out = tmp_path / "backup-tampered"
    export_backup(state, out)
    payload = out / "artifacts/control/config/users.yaml"
    payload.write_text(payload.read_text() + "- intruder\n")
    with pytest.raises(backup.BackupError):
        backup.restore(out, state_root=tmp_path / "into",
                       control_env_dir=tmp_path / "etc")


def test_restore_never_overwrites_existing_state(tmp_path, state):
    out = tmp_path / "backup-overwrite"
    export_backup(state, out)
    root = tmp_path / "into"
    (root / "ingest").mkdir(parents=True)
    existing = root / "ingest/events.db"
    existing.write_text("live state")
    with pytest.raises(FileExistsError):
        backup.restore(out, state_root=root, control_env_dir=tmp_path / "etc2")
    assert existing.read_text() == "live state"


def test_restore_rejects_a_writable_or_symlinked_state_root(tmp_path, state):
    out = tmp_path / "backup-parent-trust"
    export_backup(state, out)

    shared = tmp_path / "shared-root"
    shared.mkdir()
    shared.chmod(0o777)
    try:
        with pytest.raises(PermissionError):
            backup.restore(out, state_root=shared, control_env_dir=tmp_path / "etc-lax")
        assert not (shared / "ingest").exists()
    finally:
        shared.chmod(0o700)

    real = tmp_path / "real-root"
    real.mkdir(mode=0o700)
    link = tmp_path / "linked-root"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(backup.BackupError):
        backup.restore(out, state_root=link, control_env_dir=tmp_path / "etc-link")
    assert not (real / "ingest").exists()


def test_restore_rejects_manifest_paths_outside_the_fixed_table(tmp_path, state):
    out = tmp_path / "backup-rogue"
    export_backup(state, out)
    manifest = json.loads((out / "manifest.json").read_text())
    manifest["artifacts"].append({
        "role": "control", "path": "artifacts/../escape", "kind": "file",
        "required": False, "bytes": 0, "sha256": None, "status": "present"})
    (out / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(backup.BackupError):
        backup.restore(out, state_root=tmp_path / "into", control_env_dir=tmp_path / "etc3")


def test_restore_round_trip_and_env_artifacts_stay_derived(tmp_path, state):
    out = tmp_path / "backup-roundtrip"
    manifest, _ = export_backup(state, out)
    report = backup.restore(out, state_root=tmp_path / "into",
                            control_env_dir=tmp_path / "etc-restore")
    restored = sorted(Path(target).name for target in report["restored"])
    assert restored == ["events.db", "install.json", "sensors.db",
                        "server.crt", "server.key", "users.yaml"]
    assert report["overwrites"] == 0
    assert report["not_restored_env_derived"] == [
        "artifacts/analytics/elastic.env.json", "artifacts/manager/control.env.json"]
    assert report["skipped_missing"] == [
        "artifacts/control/elastic-queue.db", "artifacts/control/export-cursor.db"]
    # Restored content is byte-identical to the verified backup payloads.
    for name in ("events.db", "sensors.db", "server.crt", "server.key"):
        assert (tmp_path / "into/ingest" / name).read_bytes() == \
            (out / "artifacts/ingest" / name).read_bytes()
    assert manifest["artifact_count"] == spec_count()


def test_restore_rejects_a_manifest_without_a_sealed_digest(tmp_path, state):
    out = tmp_path / "backup-noseal"
    export_backup(state, out)
    manifest = json.loads((out / "manifest.json").read_text())
    del manifest["artifacts_sha256"]
    (out / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(backup.BackupError):
        backup.restore(out, state_root=tmp_path / "into", control_env_dir=tmp_path / "etc4")


def test_restore_rejects_a_required_artifact_marked_missing(tmp_path, state):
    out = tmp_path / "backup-required-missing"
    export_backup(state, out)
    manifest = json.loads((out / "manifest.json").read_text())
    entry = next(item for item in manifest["artifacts"]
                 if item["path"] == "artifacts/ingest/sensors.db")
    entry.update(status="missing", sha256=None, bytes=None)
    reseal(out, manifest)
    with pytest.raises(backup.BackupError, match="required artifact is missing"):
        backup.restore(out, state_root=tmp_path / "into",
                       control_env_dir=tmp_path / "etc-required")
    assert not (tmp_path / "into").exists()
    assert not (tmp_path / "etc-required").exists()


def test_restore_rejects_an_incomplete_artifact_set(tmp_path, state):
    out = tmp_path / "backup-incomplete-set"
    export_backup(state, out)
    manifest = json.loads((out / "manifest.json").read_text())
    manifest["artifacts"] = [
        item for item in manifest["artifacts"]
        if item["path"] != "artifacts/ingest/sensors.db"]
    manifest["artifact_count"] = len(manifest["artifacts"])
    reseal(out, manifest)
    with pytest.raises(backup.BackupError):
        backup.restore(out, state_root=tmp_path / "into",
                       control_env_dir=tmp_path / "etc-incomplete")
    assert not (tmp_path / "into").exists()


def test_restore_rejects_a_wrong_artifact_count(tmp_path, state):
    out = tmp_path / "backup-count"
    export_backup(state, out)
    manifest = json.loads((out / "manifest.json").read_text())
    manifest["artifact_count"] += 1
    reseal(out, manifest)
    with pytest.raises(backup.BackupError, match="artifact_count"):
        backup.restore(out, state_root=tmp_path / "into",
                       control_env_dir=tmp_path / "etc-count")


def test_restore_rejects_an_unknown_artifact_status(tmp_path, state):
    out = tmp_path / "backup-status"
    export_backup(state, out)
    manifest = json.loads((out / "manifest.json").read_text())
    entry = next(item for item in manifest["artifacts"]
                 if item["path"] == "artifacts/control/export-cursor.db")
    entry["status"] = "skipped"
    reseal(out, manifest)
    with pytest.raises(backup.BackupError, match="unsupported artifact status"):
        backup.restore(out, state_root=tmp_path / "into",
                       control_env_dir=tmp_path / "etc-status")


def test_late_destination_collision_writes_nothing(tmp_path, state):
    out = tmp_path / "backup-late-collision"
    export_backup(state, out)
    root = tmp_path / "into"
    etc = tmp_path / "etc-late"
    etc.mkdir()
    existing = etc / "install.json"
    existing.write_text("live state")
    with pytest.raises(FileExistsError):
        backup.restore(out, state_root=root, control_env_dir=etc)
    assert existing.read_text() == "live state"
    assert not root.exists()


def test_publish_failure_rolls_back_every_written_target(tmp_path, state, monkeypatch):
    out = tmp_path / "backup-rollback"
    export_backup(state, out)
    original = backup._publish_staged
    calls = []

    def fail_second(staged, target):
        calls.append(target)
        if len(calls) == 2:
            raise RuntimeError("injected publish failure")
        return original(staged, target)

    monkeypatch.setattr(backup, "_publish_staged", fail_second)
    root = tmp_path / "into"
    etc = tmp_path / "etc-rollback"
    with pytest.raises(RuntimeError):
        backup.restore(out, state_root=root, control_env_dir=etc)
    assert calls
    assert not root.exists()
    assert not etc.exists()


# --------------------------------------------------------------------------
# Permissions from birth (umask independent)
# --------------------------------------------------------------------------


def test_backup_files_are_private_from_birth_under_umask_022(tmp_path, state,
                                                             monkeypatch):
    out = tmp_path / "umask-backup"
    out.mkdir()
    os.chmod(out, 0o755)
    observed = []
    original = backup.file_digest

    def checking_digest(path):
        observed.append((Path(path), stat.S_IMODE(Path(path).stat().st_mode)))
        return original(path)

    monkeypatch.setattr(backup, "file_digest", checking_digest)
    previous = os.umask(0o022)
    try:
        export_backup(state, out)
    finally:
        os.umask(previous)
    assert observed
    assert all(mode & 0o077 == 0 for _, mode in observed)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for path in out.rglob("*"):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode & 0o077 == 0, (path, oct(mode))


def test_output_directory_is_hardened_before_the_first_artifact(tmp_path, state,
                                                               monkeypatch):
    out = tmp_path / "prehardened"
    out.mkdir()
    os.chmod(out, 0o755)
    observed = []
    original = backup._copy_regular

    def checking_copy(source, destination):
        observed.append(stat.S_IMODE(out.stat().st_mode))
        return original(source, destination)

    monkeypatch.setattr(backup, "_copy_regular", checking_copy)
    export_backup(state, out)
    assert observed
    assert set(observed) == {0o700}


# --------------------------------------------------------------------------
# CLI contract
# --------------------------------------------------------------------------


def run_cli(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_plan_export_and_restore_on_clean_targets(tmp_path, state, capsys):
    out = tmp_path / "cli-backup"
    code, plan_text, _ = run_cli([
        "backup-plan", "--state-root", str(state["state"]),
        "--control-env-dir", str(state["etc"])], capsys)
    assert code == 0
    plan = json.loads(plan_text)
    assert plan["dry_run"] is True
    assert plan["classification"] == "secret-bearing"
    code, export_text, _ = run_cli([
        "backup-export", "--output", str(out), "--state-root", str(state["state"]),
        "--control-env-dir", str(state["etc"]), "--created-at", CREATED], capsys)
    assert code == 0
    payload = json.loads(export_text)
    assert payload["backup_id"] == backup.backup_id(
        json.loads((out / "manifest.json").read_bytes()))
    assert payload["classification"] == "secret-bearing"
    code, restore_text, err = run_cli([
        "backup-restore", "--backup", str(out), "--state-root",
        str(tmp_path / "cli-restored"), "--control-env-dir",
        str(tmp_path / "cli-etc")], capsys)
    assert code == 0
    restored = json.loads(restore_text)
    assert restored["overwrites"] == 0


def test_cli_plan_fails_with_exit_2_on_missing_state(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    code, _, err = run_cli(["backup-plan", "--state-root", str(empty),
                            "--control-env-dir", str(empty)], capsys)
    assert code == 2
    payload = json.loads(err)
    assert payload["error"] == "BackupError"


def test_cli_export_fails_without_required_state(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    code, _, err = run_cli([
        "backup-export", "--output", str(tmp_path / "cli-out"), "--state-root",
        str(empty), "--control-env-dir", str(empty)], capsys)
    assert code == 2
    assert "BackupError" in err


# --------------------------------------------------------------------------
# Operator scripts: syntax and conservative contract
# --------------------------------------------------------------------------


SCRIPTS = ("backup-control.sh", "restore-control.sh")


@pytest.mark.parametrize("name", SCRIPTS)
def test_operator_scripts_have_valid_bash_syntax(name):
    try:
        proc = subprocess.run(["bash", "-n", str(REPO_ROOT / "scripts" / name)],
                              capture_output=True, text=True, timeout=30)
    except FileNotFoundError as exc:
        pytest.skip(f"bash unavailable: {exc}")
    assert proc.returncode == 0, proc.stderr


def test_restore_script_requires_the_confirmation_guard():
    text = (REPO_ROOT / "scripts" / "restore-control.sh").read_text()
    assert "DYSTOPIA_RESTORE_CONFIRM" in text


def test_backup_scripts_refuse_repository_output():
    proc = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "backup-control.sh"),
         str(REPO_ROOT / "backups")],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=60,
        env=dict(os.environ, PYTHON=sys.executable))
    assert proc.returncode == 1
    assert "outside the repository" in proc.stderr


def test_backup_control_script_end_to_end(tmp_path, state):
    env = dict(os.environ, PYTHON=sys.executable,
               DYSTOPIA_STATE_ROOT=str(state["state"]),
               DYSTOPIA_CONTROL_ENV_DIR=str(state["etc"]))
    out = tmp_path / "script-backup"
    for direction in (out, tmp_path / "script-backup-2"):
        proc = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "backup-control.sh"), str(direction),
             "--created-at", CREATED],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=120)
        assert proc.returncode == 0, proc.stderr
        assert "backup_complete" in proc.stdout
        assert "classification: secret-bearing" in proc.stdout
    # Same state and same --created-at → byte-identical manifests.
    first = (out / "manifest.json").read_bytes()
    second = (tmp_path / "script-backup-2" / "manifest.json").read_bytes()
    assert first == second


def test_restore_control_script_guard_and_roundtrip(tmp_path, state):
    src = tmp_path / "script-src-backup"
    export_backup(state, src)
    target = tmp_path / "script-restore-target"
    etc_target = tmp_path / "script-etc-target"
    env = dict(os.environ, PYTHON=sys.executable)
    # Refuses without the confirmation guard.
    proc = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "restore-control.sh"),
         "--backup", str(src), "--state-root", str(target),
         "--control-env-dir", str(etc_target)],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=120)
    assert proc.returncode == 2
    assert not target.exists()
    # Round-trips with the guard, never touching the source state.
    env["DYSTOPIA_RESTORE_CONFIRM"] = "restore"
    proc = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "restore-control.sh"),
         "--backup", str(src), "--state-root", str(target),
         "--control-env-dir", str(etc_target)],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=120)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["overwrites"] == 0
    assert (target / "control/config/users.yaml").read_bytes() == \
        (src / "artifacts/control/config/users.yaml").read_bytes()


# --------------------------------------------------------------------------
# Real state is never versioned
# --------------------------------------------------------------------------


def test_gitignore_blocks_backups_and_real_env():
    gitignore = (REPO_ROOT / ".gitignore").read_text()
    lines = [line.strip() for line in gitignore.splitlines()]
    assert "backups/" in lines or "backups/*" in lines
    assert any(line in (".env", ".env.*") for line in lines)
    assert "!.env.example" in lines


def test_no_backup_artifacts_are_tracked():
    try:
        tracked = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT,
                                 capture_output=True, text=True,
                                 timeout=30).stdout.splitlines()
    except FileNotFoundError:
        pytest.skip("git unavailable")
    assert not [path for path in tracked if "backups/" in path]
    assert not [path for path in tracked if Path(path).name == "manifest.json"]
    assert "deploy/elastic/.env" not in tracked
    assert "deploy/elastic/.env.example" in tracked
