"""Offline backup/restore contract for the Dystopia control plane.

Pure Python only: no subprocess, no shell, no Docker, no network, no daemon
and never a privileged or dangerous command. The contract is a strict read of
declared state artifacts plus bounded copies into a caller-supplied offline
directory, always closed by a deterministic manifest (``dystopia.backup/v1``).

Design rules
------------
* Artifacts are declared per role with an absolute source path, a POSIX
  relative backup path and a kind (``file``, ``sqlite`` or ``env``). The
  table is fixed: a backup can only contain declared artifacts, so a
  manifest can never be used to write arbitrary paths on restore.
* SQLite state (``events.db``, ``sensors.db``) is exported through the
  sqlite3 online-backup API from a read-only connection, so an active
  ingestion service yields a consistent copy and the source is never
  written.
* Environment-file secrets are never expanded into backups: ``control.env``
  and the analytics ``deploy/elastic/.env`` are filtered through a reviewed
  allowlist of non-secret setting names (deny by default), so passwords,
  tokens and encryption keys stay out of the exported ``env`` artifacts.
* The complete backup is nevertheless **secret-bearing**: the required TLS
  private key (``server.key``) and the sensor registry (``sensors.db``) are
  copied for recovery, so the manifest declares the real classification and
  the operator must treat every backup as secret material. No runbook, CLI
  output or manifest may call such a copy "secrets excluded".
* Restore fails closed: the whole backup is verified (exact artifact set,
  presence of every required artifact, size, SHA-256) before anything is
  staged, existing target files are never overwritten, destinations are
  re-derived from the fixed artifact table and all destinations are
  preflighted before the first write. A failed publish rolls back the files
  written during that restore, so a late collision cannot leave a partial
  state mix.

The module also exposes an integrated, read-only view of the runtime state
that sits behind the same table (:func:`runtime_state`). It reuses the fixed
artifact table and the runtime health snapshots: it never writes, never
starts a service and never materializes a secret value.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tempfile
import time
from dataclasses import dataclass

from runtime.localfiles import open_trusted_directory, verify_ancestor_chain

SCHEMA = "dystopia.backup/v1"
RUNTIME_STATE_SCHEMA = "dystopia.backup.runtime-state/v1"
STATE_ROOT = Path("/var/lib/dystopia")
CONTROL_ENV_DIR = Path("/etc/dystopia")
INSTALLED_RELEASE = Path("/opt/dystopia/current")
REPO_ROOT = Path(__file__).resolve().parent.parent

# Hard bounds: control-plane state is small here; a bound protects against
# accidentally backing up runaway data.
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_DB_BYTES = 8 * 1024 * 1024 * 1024
_CHUNK = 1024 * 1024

# The backup carries recovery material that is itself secret. This is a
# declared contract, not an implementation detail: no output may claim the
# copy is secret-free while these artifacts are part of the fixed table.
BACKUP_CLASSIFICATION = "secret-bearing"
SECRET_BEARING_ARTIFACTS = (
    "artifacts/ingest/sensors.db",
    "artifacts/ingest/server.key",
)
_ENTRY_KEYS = frozenset({
    "role", "path", "kind", "required", "secret", "bytes", "sha256", "status",
})
_MANIFEST_KEYS = frozenset({
    "schema", "label", "created_at", "artifact_count", "artifacts",
    "artifacts_sha256", "policy",
})


class BackupError(ValueError):
    """Invalid backup request, state layout, manifest or backup directory."""


@dataclass(frozen=True)
class ArtifactSpec:
    """One immutable declaration of a state file and its backup identity."""

    role: str
    relpath: str          # POSIX relative path inside the backup directory
    source: Path          # absolute source path on the host (declared, fixed)
    kind: str             # "file" | "sqlite" | "env"
    required: bool
    max_bytes: int
    secret: bool = False  # carries secret material into the backup

    def __post_init__(self):
        if self.role not in ROLES:
            raise BackupError(f"unknown backup role: {self.role}")
        if self.kind not in KINDS:
            raise BackupError(f"unknown artifact kind: {self.kind}")
        if type(self.secret) is not bool:
            raise BackupError("secret must be a boolean")
        if self.secret != (self.relpath in SECRET_BEARING_ARTIFACTS):
            raise BackupError(f"secret classification drifted for {self.relpath}")
        if not self.source.is_absolute():
            raise BackupError(f"artifact source must be declared absolute: {self.source}")
        if ".." in Path(self.relpath).parts or "\\" in self.relpath \
                or Path(self.relpath).is_absolute():
            raise BackupError(f"relpath must be a safe POSIX relative path: "
                              f"{self.relpath}")
        if self.max_bytes <= 0:
            raise BackupError("max_bytes must be positive")


ROLES = ("control", "manager", "ingest", "analytics")
KINDS = ("file", "sqlite", "env")


@dataclass(frozen=True)
class UncoveredArtifact:
    """Runtime state a provisioned host owns but the backup table omits.

    ``base`` selects the root the relative path hangs from: ``"state"`` for
    the Dystopia state root and ``"control_env"`` for the control
    environment directory. ``runtime_key`` names the runtime snapshot the
    integrated report exposes for it, if any.
    """

    role: str
    relpath: str
    base: str
    kind: str
    reason: str
    runtime_key: str | None = None
    health_role: str | None = None

    def __post_init__(self):
        if self.base not in ("state", "control_env"):
            raise BackupError(f"unknown uncovered artifact base: {self.base}")
        if self.kind not in KINDS and self.kind != "directory":
            raise BackupError(f"unknown uncovered artifact kind: {self.kind}")


# Declared, reviewed gaps: runtime state that exists on a provisioned host
# and is deliberately NOT part of the control-plane backup table. They are
# reported (read-only) so an operator sees the gap instead of assuming that
# a backup covers the whole host.
UNCOVERED_RUNTIME_STATE = (
    UncoveredArtifact(
        "sensor", "sensor/spool.db", "state", "sqlite",
        "queued sensor telemetry is drained, never restored; identities are "
        "re-emitted with rotate-sensor",
        runtime_key="sensor_spool", health_role="sensor"),
    UncoveredArtifact(
        "sensor", "sensor/token", "state", "file",
        "sensor bearer token is a secret and is never exported"),
    UncoveredArtifact(
        "sensor", "sensor/ca.crt", "state", "file",
        "sensor trust anchor belongs to the host TLS material"),
    UncoveredArtifact(
        "sensor", "sensor.env", "control_env", "file",
        "sensor environment file carries the ingestion endpoint, not "
        "control-plane state"),
    UncoveredArtifact(
        "ingest", "ingest.env", "control_env", "file",
        "ingest environment file carries the bind address; the TLS material "
        "it points to is covered, the file itself is not"),
    UncoveredArtifact(
        "cell", "cells", "state", "directory",
        "cell data roots are operator-provisioned workloads, not control-plane state"),
    UncoveredArtifact(
        "honeypot", "honeypots", "state", "directory",
        "honeypot cell logs are workload data, not control-plane state"),
)

# Reviewed allowlist of non-secret settings exported from environment files.
# Deny by default: keys not listed here (plus ILM_* retention days) must not
# appear in a backup. Additions require review of the value's secrecy.
ANALYTICS_EXPORT_KEYS = frozenset({
    "ELASTIC_VERSION", "ELASTIC_JAVA_OPTS", "ELASTIC_MEMORY_LIMIT",
    "KIBANA_MEMORY_LIMIT", "DYSTOPIA_ELASTIC_URL", "DYSTOPIA_ELASTIC_INDEX",
    "DYSTOPIA_ELASTIC_CA_FILE", "DYSTOPIA_ELASTIC_TIMEOUT",
    "DYSTOPIA_ELASTIC_RETRIES", "DYSTOPIA_ELASTIC_BACKOFF",
    "DYSTOPIA_ELASTIC_MAX_BACKOFF", "DYSTOPIA_ELASTIC_BATCH",
    "DYSTOPIA_ELASTIC_QUEUE_MAX", "DYSTOPIA_ELASTIC_QUEUE_BYTES",
})
ANALYTIC_EXPORT_PREFIXES = ("ILM_",)
# Non-secret keys known to live in /etc/dystopia/control.env
# (runtime.install._environment_valid). NETPULSE_JWT_SECRET must never appear.
CONTROL_EXPORT_KEYS = frozenset({
    "DYSTOPIA_CONTROL_STATE", "DYSTOPIA_CONTROL_CONFIG", "NETPULSE_ENV",
})
_EXPORTABLE_VALUE = re.compile(r"[A-Za-z0-9_./:+@~, -]{0,200}\Z")
_SETTING_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _setting_is_exportable(name, allowlist, prefixes):
    if name in allowlist:
        return True
    return prefixes is not None and name.startswith(prefixes)


def default_elastic_env(repo_root=REPO_ROOT):
    """Prefer the installed release ``.env`` copy, else the source checkout."""
    for base in (INSTALLED_RELEASE, Path(repo_root)):
        path = Path(base) / "deploy/elastic/.env"
        if path.is_file() and not path.is_symlink():
            return path
    return Path(repo_root) / "deploy/elastic/.env"


def default_artifact_specs(state_root=STATE_ROOT, control_env_dir=CONTROL_ENV_DIR,
                           elastic_env=None):
    """Return the fixed artifact table for planning, export and restore.

    ``elastic_env`` defaults to :func:`default_elastic_env` so analytics
    plugin configuration is captured when the environment file exists;
    secrets are always filtered out on export.
    """
    state_root = Path(state_root)
    control_env_dir = Path(control_env_dir)
    if elastic_env is None:
        elastic_env = default_elastic_env()
    return (
        ArtifactSpec("control", "artifacts/control/config/users.yaml",
                     state_root / "control/config/users.yaml", "file", True,
                     MAX_FILE_BYTES),
        ArtifactSpec("manager", "artifacts/manager/install.json",
                     control_env_dir / "install.json", "file", True, MAX_FILE_BYTES),
        ArtifactSpec("manager", "artifacts/manager/control.env.json",
                     control_env_dir / "control.env", "env", False, MAX_FILE_BYTES),
        ArtifactSpec("ingest", "artifacts/ingest/events.db",
                     state_root / "ingest/events.db", "sqlite", True, MAX_DB_BYTES),
        ArtifactSpec("ingest", "artifacts/ingest/sensors.db",
                     state_root / "ingest/sensors.db", "sqlite", True,
                     MAX_DB_BYTES, secret=True),
        ArtifactSpec("ingest", "artifacts/ingest/server.crt",
                     state_root / "ingest/server.crt", "file", True, MAX_FILE_BYTES),
        ArtifactSpec("ingest", "artifacts/ingest/server.key",
                     state_root / "ingest/server.key", "file", True,
                     MAX_FILE_BYTES, secret=True),
        ArtifactSpec("control", "artifacts/control/elastic-queue.db",
                     state_root / "control/elastic-queue.db", "sqlite", False,
                     MAX_DB_BYTES),
        ArtifactSpec("control", "artifacts/control/export-cursor.db",
                     state_root / "control/export-cursor.db", "sqlite", False,
                     MAX_DB_BYTES),
        ArtifactSpec("analytics", "artifacts/analytics/elastic.env.json",
                     Path(elastic_env), "env", False, MAX_FILE_BYTES),
    )


def parse_exportable_settings(path, *, allowlist=ANALYTICS_EXPORT_KEYS,
                              prefixes=ANALYTIC_EXPORT_PREFIXES):
    """Return the non-secret KEY=VALUE subset of an environment file.

    Unknown or secret-looking keys are dropped, never renamed and never
    reported as present, so a secret value cannot leak through this function.
    ``/etc/dystopia/control.env`` expects ``allowlist=CONTROL_EXPORT_KEYS``
    and ``prefixes=()``.
    """
    settings = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if not _SETTING_NAME.fullmatch(name) \
                or not _setting_is_exportable(name, allowlist, prefixes):
            continue
        if _EXPORTABLE_VALUE.fullmatch(value) is None:
            continue
        settings[name] = value
    return dict(sorted(settings.items()))


def _env_policy_for(spec):
    """Per-artifact allowlist: control.env and analytics .env differ."""
    if spec.relpath == "artifacts/manager/control.env.json":
        return CONTROL_EXPORT_KEYS, ()
    return ANALYTICS_EXPORT_KEYS, ANALYTIC_EXPORT_PREFIXES


def _check_regular_private(path):
    """Fail closed unless the artifact is a private regular non-symlink file."""
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise BackupError(f"artifact must be a regular non-symlink file: {path}")
    if st.st_mode & 0o077:
        raise BackupError(f"artifact must not be group/world readable: {path}")
    return st


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


def plan(specs=None, *, state_root=STATE_ROOT, control_env_dir=CONTROL_ENV_DIR,
         elastic_env=None):
    """Read-only report of what a backup contains and what is missing.

    Raises :class:`BackupError` when any required artifact is missing, so an
    operator cannot plan against a host with incomplete Dystopia state.
    """
    if specs is None:
        specs = default_artifact_specs(state_root, control_env_dir, elastic_env)
    entries = []
    for spec in specs:
        present = spec.source.is_file() and not spec.source.is_symlink()
        entry = {
            "role": spec.role,
            "source_path": str(spec.source),
            "path": spec.relpath,
            "kind": spec.kind,
            "required": spec.required,
            "secret": spec.secret,
            "status": "present" if present else "missing",
        }
        if present:
            size = spec.source.stat().st_size
            if size > spec.max_bytes:
                raise BackupError(f"{spec.source} exceeds the backup bound "
                                  f"({size} bytes > {spec.max_bytes})")
            entry["bytes"] = size
            if spec.kind in ("file", "sqlite"):
                _check_regular_private(spec.source)
            if spec.kind == "env":
                allowlist, prefixes = _env_policy_for(spec)
                entry["settings_exported"] = len(
                    parse_exportable_settings(spec.source, allowlist=allowlist,
                                              prefixes=prefixes))
        entries.append(entry)
    missing = sorted(entry["source_path"] for entry in entries
                     if entry["status"] == "missing" and entry["required"])
    if missing:
        raise BackupError("required state artifacts are missing: " + ", ".join(missing))
    entries.sort(key=lambda item: (item["path"], item["source_path"]))
    return {
        "schema": SCHEMA,
        "action": "plan",
        "artifacts": entries,
        "required_count": sum(1 for item in entries if item["required"]),
        "optional_count": sum(1 for item in entries if not item["required"]),
        "classification": BACKUP_CLASSIFICATION,
        "secret_artifacts": sorted(SECRET_BEARING_ARTIFACTS),
        "dry_run": True,
        "host_operations": [],
        "requires": [
            "operator-reviewed offline storage, root-only permissions",
            "restore drill against a disposable copy, never the live host first",
        ],
    }


# --------------------------------------------------------------------------
# Integrated runtime state (read-only)
# --------------------------------------------------------------------------


def exported_setting_names(spec):
    """Names (never values) of the allowlisted non-secret settings of an env artifact.

    The values are deliberately dropped: the integrated report states *which*
    reviewed settings are configured, never what they contain.
    """
    allowlist, prefixes = _env_policy_for(spec)
    settings = parse_exportable_settings(spec.source, allowlist=allowlist,
                                         prefixes=prefixes)
    return sorted(settings)


def _runtime_snapshot(path, role) -> dict[str, object]:
    """Read-only runtime snapshot; never writes and never creates a database."""
    from runtime.health import snapshot
    try:
        return {"status": "available", **snapshot(path, role)}
    except (FileNotFoundError, OSError, ValueError, sqlite3.Error) as exc:
        return {"status": "unavailable", "detail": f"{type(exc).__name__}: {exc}"}


def uncovered_sources(state_root=STATE_ROOT, control_env_dir=CONTROL_ENV_DIR):
    """Resolve the declared runtime state that the backup table does not cover."""
    roots = {"state": Path(state_root), "control_env": Path(control_env_dir)}
    resolved: list[dict[str, object]] = []
    for item in UNCOVERED_RUNTIME_STATE:
        source = roots[item.base] / item.relpath
        entry: dict[str, object] = {
            "role": item.role,
            "relpath": item.relpath,
            "base": item.base,
            "path": str(source),
            "kind": item.kind,
            "reason": item.reason,
        }
        if item.kind == "directory":
            present = source.is_dir() and not source.is_symlink()
        else:
            present = source.is_file() and not source.is_symlink()
        entry["status"] = "present" if present else "missing"
        if present and item.kind != "directory":
            try:
                entry["bytes"] = source.stat().st_size
            except OSError as exc:
                entry["status"] = "unreadable"
                entry["detail"] = f"{type(exc).__name__}: {exc}"
        if present and entry["status"] == "present" and item.health_role:
            entry["runtime"] = _runtime_snapshot(source, item.health_role)
        resolved.append(entry)
    return resolved


def runtime_state(specs=None, *, state_root=STATE_ROOT, control_env_dir=CONTROL_ENV_DIR,
                  elastic_env=None):
    """Integrated, read-only report of the runtime state behind the backup table.

    The report reuses the fixed artifact table and the runtime health
    snapshots (``runtime.health``). It never writes, never starts a service,
    never opens a socket and never materializes a secret value: environment
    artifacts are described by the names of their allowlisted settings only.

    The result is a report, not an action: it states what is present, what is
    readable and what the backup contract deliberately does not carry.
    """
    if specs is None:
        specs = default_artifact_specs(state_root, control_env_dir, elastic_env)
    artifacts: list[dict[str, object]] = []
    missing_required: list[str] = []
    for spec in specs:
        present = spec.source.is_file() and not spec.source.is_symlink()
        entry: dict[str, object] = {
            "role": spec.role,
            "path": spec.relpath,
            "source_path": str(spec.source),
            "kind": spec.kind,
            "required": spec.required,
            "secret": spec.secret,
            "status": "present" if present else "missing",
        }
        if present:
            try:
                entry["bytes"] = spec.source.stat().st_size
                if spec.kind == "env":
                    entry["settings_exported"] = exported_setting_names(spec)
            except (OSError, UnicodeDecodeError) as exc:
                # A report must not crash, nor read a secret, just because an
                # artifact is unreadable for the reporting user.
                entry["status"] = "unreadable"
                entry["detail"] = f"{type(exc).__name__}: {exc}"
                if spec.kind == "env":
                    entry["settings_exported"] = []
        elif spec.required:
            missing_required.append(str(spec.source))
        artifacts.append(entry)
    artifacts.sort(key=lambda item: (item["path"], item["source_path"]))

    runtime: dict[str, object] = {}
    by_path = {spec.relpath: spec for spec in specs}
    ingest = by_path.get("artifacts/ingest/events.db")
    if ingest is None:
        runtime["ingest"] = {"status": "undeclared"}
    elif ingest.source.is_file() and not ingest.source.is_symlink():
        runtime["ingest"] = _runtime_snapshot(ingest.source, "ingest")
    else:
        runtime["ingest"] = {"status": "missing"}

    uncovered = uncovered_sources(state_root, control_env_dir)
    for declared, item in zip(UNCOVERED_RUNTIME_STATE, uncovered):
        if declared.runtime_key:
            runtime[declared.runtime_key] = item.get("runtime", {"status": "missing"})

    return {
        "schema": RUNTIME_STATE_SCHEMA,
        "action": "runtime-state",
        "dry_run": True,
        "host_operations": [],
        "state_root": str(Path(state_root)),
        "control_env_dir": str(Path(control_env_dir)),
        "artifacts": artifacts,
        "runtime": runtime,
        "uncovered": uncovered,
        "missing_required": sorted(missing_required),
        "ready_for_backup": not missing_required,
        "classification": BACKUP_CLASSIFICATION,
        "secret_artifacts": sorted(SECRET_BEARING_ARTIFACTS),
    }


# --------------------------------------------------------------------------
# Deterministic serialization, digests and identifiers
# --------------------------------------------------------------------------


def manifest_bytes(manifest):
    """Canonical bytes: sorted keys, fixed separators, one trailing newline."""
    text = json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True,
                      separators=(",", ": "))
    return (text + "\n").encode()


def file_digest(path):
    """SHA-256 of a file read in bounded blocks (memory-safe)."""
    sha = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            block = stream.read(_CHUNK)
            if not block:
                break
            sha.update(block)
    return sha.hexdigest()


def backup_id(manifest_data):
    """Deterministic short identifier derived from the manifest bytes."""
    data = manifest_data if isinstance(manifest_data, bytes) \
        else manifest_bytes(manifest_data)
    return hashlib.sha256(data).hexdigest()[:16]


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------


def _open_private(path, flags):
    """Create a new private file; fail closed on an existing leaf or symlink."""
    return os.open(path, flags | os.O_CREAT | os.O_EXCL
                   | getattr(os, "O_NOFOLLOW", 0), 0o600)


def _ensure_private_dir(path):
    """Create a directory tree and harden every level this backup owns."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _copy_regular(source, destination):
    status = _check_regular_private(source)
    if status.st_size > MAX_FILE_BYTES:
        raise BackupError(f"{source} exceeds the artifact bound "
                          f"({status.st_size} bytes > {MAX_FILE_BYTES})")
    written = 0
    descriptor = _open_private(destination, os.O_WRONLY)
    try:
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            descriptor = -1
            while True:
                block = reader.read(_CHUNK)
                if not block:
                    break
                writer.write(block)
                written += len(block)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return written


def _copy_sqlite(source, destination):
    """Consistent snapshot through the sqlite3 backup API; read-only source."""
    source = Path(source)
    if stat.S_ISLNK(source.lstat().st_mode):
        raise BackupError(f"database must not be a symlink: {source}")
    if source.stat().st_size > MAX_DB_BYTES:
        raise BackupError(f"{source} exceeds the database bound of {MAX_DB_BYTES} bytes")
    # Create the destination ourselves with 0600 before SQLite can use its
    # default umask-derived mode. The enclosing umask 077 also covers SQLite
    # journal/WAL side files.
    descriptor = _open_private(destination, os.O_WRONLY)
    os.close(descriptor)
    db = sqlite3.connect(source.absolute().as_uri() + "?mode=ro", uri=True, timeout=2)
    target = sqlite3.connect(str(destination))
    try:
        db.execute("PRAGMA query_only=ON")
        db.backup(target)
        written = target.execute("PRAGMA page_size").fetchone()[0] \
            * target.execute("PRAGMA page_count").fetchone()[0]
        if written > MAX_DB_BYTES:
            raise BackupError(f"snapshot of {source} exceeds {MAX_DB_BYTES} bytes")
    finally:
        target.close()
        db.close()
    destination.chmod(0o600)
    return written


def _write_env_snapshot(source, destination, allowlist, prefixes):
    """Write the non-secret allowlist subset of an environment file."""
    settings = parse_exportable_settings(source, allowlist=allowlist,
                                         prefixes=prefixes)
    payload = {
        "schema": "dystopia.analytics.settings/v1",
        "source_path": str(source),
        "settings": settings,
        "secret_policy": "deny-by-default, non-secret allowlist only",
    }
    data = (json.dumps(payload, sort_keys=True, indent=2,
                       ensure_ascii=True) + "\n").encode("utf-8")
    descriptor = _open_private(destination, os.O_WRONLY)
    try:
        with os.fdopen(descriptor, "wb") as writer:
            descriptor = -1
            writer.write(data)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return len(data)


def _write_manifest(destination, data):
    descriptor = _open_private(destination, os.O_WRONLY)
    try:
        with os.fdopen(descriptor, "wb") as writer:
            descriptor = -1
            writer.write(data)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def create_backup(specs, output_dir, *, created_at=None, repo_root=REPO_ROOT,
                  label="backup"):
    """Export declared artifacts into ``output_dir`` and write the manifest.

    The manifest is byte-deterministic for the same artifact contents and the
    same ``created_at`` string. ``output_dir`` must be new or empty and must
    not live inside the source repository, so real state can never be
    tracked by accident. Every file is created ``0600`` and every directory
    ``0700`` from birth, independent of the caller's umask. Returns
    ``(manifest, manifest_bytes)``.
    """
    previous_umask = os.umask(0o077)
    try:
        return _create_backup(specs, output_dir, created_at=created_at,
                              repo_root=repo_root, label=label)
    finally:
        os.umask(previous_umask)


def _create_backup(specs, output_dir, *, created_at, repo_root, label):
    output_dir = Path(output_dir)
    if repo_root is not None:
        resolved = output_dir.expanduser().resolve()
        root = Path(repo_root).resolve()
        if resolved == root or resolved.is_relative_to(root):
            raise BackupError("backup output must stay outside the repository so "
                              f"real state is never versioned: {resolved}")
    if output_dir.exists():
        if not output_dir.is_dir() or output_dir.is_symlink():
            raise BackupError(f"backup output must be a real directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise BackupError(f"backup output directory must be empty: {output_dir}")
    else:
        output_dir.mkdir(mode=0o700, parents=True)
    # Harden the output root before the first artifact is created: a
    # pre-existing 0755 directory must not expose the export window.
    output_dir.chmod(0o700)
    created_at = created_at if created_at is not None \
        else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    artifacts = []
    for spec in specs:
        entry = {"role": spec.role, "path": spec.relpath, "kind": spec.kind,
                 "required": spec.required, "secret": spec.secret}
        destination = output_dir / spec.relpath
        _ensure_private_dir(destination.parent)
        if not spec.source.is_file() or spec.source.is_symlink():
            if spec.required:
                raise BackupError(f"required artifact vanished mid-export: {spec.source}")
            entry.update(bytes=None, sha256=None, status="missing")
        else:
            if spec.kind == "file":
                entry["bytes"] = _copy_regular(spec.source, destination)
            elif spec.kind == "sqlite":
                entry["bytes"] = _copy_sqlite(spec.source, destination)
            else:
                allowlist, prefixes = _env_policy_for(spec)
                entry["bytes"] = _write_env_snapshot(spec.source, destination,
                                                     allowlist, prefixes)
            destination.chmod(0o600)
            entry.update(sha256=file_digest(destination), status="present")
        artifacts.append(entry)
    artifacts.sort(key=lambda item: item["path"])
    # Sealed digest over the sorted, present artifacts' own digests.
    sealed = hashlib.sha256()
    for item in artifacts:
        if item["sha256"] is not None:
            sealed.update(item["sha256"].encode())
    manifest = {
        "schema": SCHEMA,
        "label": label,
        "created_at": created_at,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "artifacts_sha256": sealed.hexdigest(),
        "policy": {
            "classification": BACKUP_CLASSIFICATION,
            "env_export": "non-secret allowlist only",
            "secret_artifacts": sorted(SECRET_BEARING_ARTIFACTS),
            "secrets": "secret-bearing",
            "custody": "root-only offline storage, encrypted at rest with an "
                       "independent recovery identity",
            "restore_overwrite": "refused",
        },
    }
    data = manifest_bytes(manifest)
    _write_manifest(output_dir / "manifest.json", data)
    # Belt and braces: the explicit creation modes above already guarantee
    # this, but a final pass keeps the invariant obvious and auditable.
    for path in sorted(output_dir.rglob("*")):
        path.chmod(0o700 if path.is_dir() else 0o600)
    output_dir.chmod(0o700)
    return manifest, data


# --------------------------------------------------------------------------
# Restore (fail-closed, overwrite never allowed)
# --------------------------------------------------------------------------


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BackupError(f"duplicate manifest key: {key!r}")
        result[key] = value
    return result


def _preflight_target(target):
    """Return the parent directories that must be created, without writing."""
    target = Path(target)
    if target.is_symlink() or target.exists():
        raise FileExistsError(
            f"restore never overwrites existing state: {target}; move it aside "
            "or point --state-root at a clean directory")
    missing = set()
    for parent in target.parents:
        if parent.is_symlink():
            raise BackupError(f"restore target parent must not be a symlink: {parent}")
        if parent.exists():
            if not parent.is_dir():
                raise BackupError(f"restore target parent must be a real directory: "
                                  f"{parent}")
        else:
            missing.add(parent)
    # The immediate existing ancestor is the trust boundary for the new leaf:
    # it must be owned by root/the service and never writable by group/other.
    # The rest of the chain is checked too, admitting sticky shared roots such
    # as /tmp while still rejecting symlinked or foreign-owned ancestors.
    nearest = target.parent
    while not nearest.exists() and not nearest.is_symlink():
        nearest = nearest.parent
    descriptor = open_trusted_directory(nearest)
    os.close(descriptor)
    verify_ancestor_chain(target.parent)
    return missing


def _preflight_restore(items, specs_by_path):
    """Check every destination before the first write; return targets and dirs."""
    targets = []
    directories = set()
    for item in items:
        spec = specs_by_path[item["path"]]
        target = spec.source
        if target in targets:
            raise BackupError(f"manifest maps two artifacts to one destination: {target}")
        targets.append(target)
        directories.update(_preflight_target(target))
    conflicts = set(targets) & directories
    if conflicts:
        raise BackupError("restore destination collides with a required directory: "
                          + ", ".join(str(item) for item in sorted(conflicts)))
    return targets, sorted(directories, key=lambda item: len(item.parts))


def _nearest_existing_directory(path):
    path = Path(path)
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise BackupError(f"restore staging parent must not be a symlink: {candidate}")
        if candidate.exists():
            if not candidate.is_dir():
                raise BackupError(f"restore staging parent must be a directory: {candidate}")
            return candidate
    raise BackupError(f"no existing directory for restore staging: {path}")


def _stage_verified_payload(payload, staged, item):
    """Copy one payload into private staging and re-verify its digest/size."""
    source_fd = os.open(payload, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    destination_fd = -1
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode):
            raise BackupError(f"backup payload must be a regular file: {payload}")
        destination_fd = _open_private(staged, os.O_WRONLY)
        digest = hashlib.sha256()
        written = 0
        with os.fdopen(source_fd, "rb") as reader, \
                os.fdopen(destination_fd, "wb") as writer:
            source_fd = -1
            destination_fd = -1
            while True:
                block = reader.read(_CHUNK)
                if not block:
                    break
                digest.update(block)
                writer.write(block)
                written += len(block)
    finally:
        for descriptor in (source_fd, destination_fd):
            if descriptor >= 0:
                os.close(descriptor)
    if written != item["bytes"] or digest.hexdigest() != item["sha256"]:
        raise BackupError(f"artifact changed while staging, refusing restore: "
                          f"{item['path']}")
    staged.chmod(0o600)


def _publish_staged(staged, target):
    """Publish without overwrite: a hard link fails closed on an existing target."""
    try:
        os.link(staged, target)
    except FileExistsError:
        raise FileExistsError(
            f"restore never overwrites existing state: {target}; move it aside "
            "or point --state-root at a clean directory") from None
    try:
        staged.unlink()
    except OSError:
        # The staging directory is removed by the caller; the published target
        # is already correct and must not be rolled back for this cleanup issue.
        pass


def _load_verified_manifest(backup_dir, specs):
    """Parse, resolve and veritably verify a backup before anything is staged."""
    backup_dir = Path(backup_dir)
    manifest_path = backup_dir / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise BackupError(f"missing backup manifest: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"),
                              object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, ValueError) as exc:
        raise BackupError(f"invalid manifest JSON: {manifest_path}") from exc
    if type(manifest) is not dict or set(manifest) != _MANIFEST_KEYS:
        raise BackupError(f"manifest must use the exact v1 field set: {manifest_path}")
    if manifest.get("schema") != SCHEMA:
        raise BackupError(f"unsupported manifest schema: {manifest.get('schema')!r}")
    entries = manifest.get("artifacts")
    if type(entries) is not list or not entries:
        raise BackupError(f"manifest lists no artifacts: {manifest_path}")
    if manifest.get("artifact_count") != len(entries) \
            or manifest.get("artifact_count") != len(specs):
        raise BackupError("manifest artifact_count does not match the fixed table")
    sealed = hashlib.sha256()
    seen = set()
    for item in entries:
        if type(item) is not dict or set(item) != _ENTRY_KEYS:
            raise BackupError(f"manifest entry is not a declared artifact: {item!r}")
        spec = specs.get(item["path"])
        if spec is None:
            raise BackupError(f"manifest declares an unknown artifact: {item['path']}")
        if item["path"] in seen:
            raise BackupError(f"manifest declares a duplicate artifact: {item['path']}")
        seen.add(item["path"])
        if item["role"] != spec.role or item["kind"] != spec.kind \
                or item["required"] is not spec.required \
                or item["secret"] is not spec.secret:
            raise BackupError(f"manifest metadata drifted from the declared table: "
                              f"{item['path']}")
        status = item["status"]
        if status not in ("present", "missing"):
            raise BackupError(f"manifest has an unsupported artifact status: {status!r}")
        if status == "missing":
            if item["sha256"] is not None or item["bytes"] is not None:
                raise BackupError(f"missing artifact carries a digest or size: "
                                  f"{item['path']}")
            if spec.required:
                raise BackupError(f"required artifact is missing from the backup: "
                                  f"{item['path']}")
            continue
        if type(item["bytes"]) is not int or type(item["bytes"]) is bool \
                or item["bytes"] < 0:
            raise BackupError(f"artifact has an invalid size: {item['path']}")
        if type(item["sha256"]) is not str or _SHA256.fullmatch(item["sha256"]) is None:
            raise BackupError(f"artifact has an invalid digest: {item['path']}")
        payload = backup_dir / item["path"]
        if payload.is_symlink() or not payload.is_file():
            raise BackupError(f"backed-up artifact is missing: {item['path']}")
        if item["sha256"] != file_digest(payload) \
                or item["bytes"] != payload.stat().st_size:
            raise BackupError(f"artifact digest or size mismatch, refusing "
                              f"restore: {item['path']}")
        sealed.update(item["sha256"].encode())
    if seen != set(specs):
        raise BackupError("manifest artifact set is not exactly the fixed table")
    if manifest.get("artifacts_sha256") != sealed.hexdigest():
        raise BackupError("manifest artifacts digest mismatch, refusing restore")
    return manifest


def restore(backup_dir, *, state_root=STATE_ROOT, control_env_dir=CONTROL_ENV_DIR,
            elastic_env=None):
    """Verify a backup completely, preflight it, then publish atomically per file.

    Destinations are re-derived from the fixed artifact table using the
    caller's ``state_root``, not taken from manifest paths. Every required
    artifact must be present and the manifest must list exactly the fixed
    table. Existing target state files are never overwritten; all parents and
    destinations are checked before staging. Payloads are copied into a
    private staging directory, re-verified, then published with a no-overwrite
    hard link; a failure during publish rolls back the files already published
    and the directories created by this restore.
    """
    backup_dir = Path(backup_dir)
    specs_by_path = {spec.relpath: spec for spec in
                     default_artifact_specs(state_root, control_env_dir, elastic_env)}
    manifest = _load_verified_manifest(backup_dir, specs_by_path)

    present = [item for item in manifest["artifacts"] if item["status"] == "present"]
    skipped = [item["path"] for item in manifest["artifacts"]
               if item["status"] == "missing"]
    not_restored = sorted(item["path"] for item in present
                          if specs_by_path[item["path"]].kind == "env")
    writable = [(item, specs_by_path[item["path"]]) for item in present
                if specs_by_path[item["path"]].kind != "env"]
    _targets, directories = _preflight_restore(
        [item for item, _ in writable], specs_by_path)

    staging_dirs = {}
    created_dirs = []
    published = []

    def cleanup_staging():
        for staging in staging_dirs.values():
            shutil.rmtree(staging, ignore_errors=True)

    try:
        staged = []
        for item, spec in writable:
            base = _nearest_existing_directory(spec.source.parent)
            staging = staging_dirs.get(str(base))
            if staging is None:
                staging = Path(tempfile.mkdtemp(prefix=".dystopia-restore-", dir=base))
                staging.chmod(0o700)
                staging_dirs[str(base)] = staging
            staged_path = staging / f"{len(staged):02d}-{spec.source.name}"
            _stage_verified_payload(backup_dir / item["path"], staged_path, item)
            staged.append((staged_path, spec.source))
        for directory in directories:
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            created_dirs.append(directory)
        for staged_path, target in staged:
            _publish_staged(staged_path, target)
            published.append(target)
    except BaseException:
        for target in reversed(published):
            try:
                target.unlink()
            except OSError:
                pass
        cleanup_staging()
        for directory in reversed(created_dirs):
            try:
                directory.rmdir()
            except OSError:
                pass
        raise
    finally:
        cleanup_staging()

    return {
        "schema": SCHEMA,
        "action": "restore",
        "backup_dir": str(backup_dir),
        "created_at": manifest["created_at"],
        "classification": BACKUP_CLASSIFICATION,
        "restored": [str(target) for target in published],
        "skipped_missing": skipped,
        "not_restored_env_derived": not_restored,
        "overwrites": 0,
        "partial_write": False,
        "verification": "exact required set and sha256-and-size verified before "
                        "staging; publish is per-file no-overwrite with rollback",
    }



__all__ = [
    "ANALYTICS_EXPORT_KEYS", "ArtifactSpec", "BACKUP_CLASSIFICATION",
    "BackupError", "CONTROL_ENV_DIR",
    "CONTROL_EXPORT_KEYS",
    "INSTALLED_RELEASE", "KINDS", "MAX_DB_BYTES", "MAX_FILE_BYTES", "REPO_ROOT",
    "ROLES", "RUNTIME_STATE_SCHEMA", "SCHEMA", "SECRET_BEARING_ARTIFACTS",
    "STATE_ROOT",
    "UNCOVERED_RUNTIME_STATE", "UncoveredArtifact", "backup_id", "create_backup",
    "default_artifact_specs", "default_elastic_env", "exported_setting_names",
    "file_digest", "manifest_bytes", "parse_exportable_settings", "plan",
    "restore", "runtime_state", "uncovered_sources",
]
