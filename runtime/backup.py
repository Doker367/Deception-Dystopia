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
* Secrets are never expanded into backups: ``control.env`` and the analytics
  ``deploy/elastic/.env`` are filtered through a reviewed allowlist of
  non-secret setting names (deny by default), so passwords, tokens and
  encryption keys stay out of every backup file.
* Restore fails closed: the whole backup is verified (presence, size,
  SHA-256) before anything is written, existing target files are never
  overwritten, and destinations are re-derived from the fixed artifact
  table instead of trusting manifest paths.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import time
from dataclasses import dataclass

SCHEMA = "dystopia.backup/v1"
STATE_ROOT = Path("/var/lib/dystopia")
CONTROL_ENV_DIR = Path("/etc/dystopia")
INSTALLED_RELEASE = Path("/opt/dystopia/current")
REPO_ROOT = Path(__file__).resolve().parent.parent

# Hard bounds: control-plane state is small here; a bound protects against
# accidentally backing up runaway data.
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_DB_BYTES = 8 * 1024 * 1024 * 1024
_CHUNK = 1024 * 1024


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

    def __post_init__(self):
        if self.role not in ROLES:
            raise BackupError(f"unknown backup role: {self.role}")
        if self.kind not in KINDS:
            raise BackupError(f"unknown artifact kind: {self.kind}")
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
                     state_root / "ingest/sensors.db", "sqlite", True, MAX_DB_BYTES),
        ArtifactSpec("ingest", "artifacts/ingest/server.crt",
                     state_root / "ingest/server.crt", "file", True, MAX_FILE_BYTES),
        ArtifactSpec("ingest", "artifacts/ingest/server.key",
                     state_root / "ingest/server.key", "file", True, MAX_FILE_BYTES),
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
        "dry_run": True,
        "host_operations": [],
        "requires": [
            "operator-reviewed offline storage, root-only permissions",
            "restore drill against a disposable copy, never the live host first",
        ],
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


def _copy_regular(source, destination):
    status = _check_regular_private(source)
    if status.st_size > MAX_FILE_BYTES:
        raise BackupError(f"{source} exceeds the artifact bound "
                          f"({status.st_size} bytes > {MAX_FILE_BYTES})")
    written = 0
    with source.open("rb") as reader, destination.open("xb") as writer:
        while True:
            block = reader.read(_CHUNK)
            if not block:
                break
            writer.write(block)
            written += len(block)
    return written


def _copy_sqlite(source, destination):
    """Consistent snapshot through the sqlite3 backup API; read-only source."""
    source = Path(source)
    if stat.S_ISLNK(source.lstat().st_mode):
        raise BackupError(f"database must not be a symlink: {source}")
    if source.stat().st_size > MAX_DB_BYTES:
        raise BackupError(f"{source} exceeds the database bound of {MAX_DB_BYTES} bytes")
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
    destination.write_text(json.dumps(payload, sort_keys=True, indent=2,
                                      ensure_ascii=True) + "\n", encoding="utf-8")
    return destination.stat().st_size


def create_backup(specs, output_dir, *, created_at=None, repo_root=REPO_ROOT,
                  label="backup"):
    """Export declared artifacts into ``output_dir`` and write the manifest.

    The manifest is byte-deterministic for the same artifact contents and the
    same ``created_at`` string. ``output_dir`` must be new or empty and must
    not live inside the source repository, so real state can never be
    tracked by accident. Returns ``(manifest, manifest_bytes)``.
    """
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
    created_at = created_at if created_at is not None \
        else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    artifacts = []
    for spec in specs:
        entry = {"role": spec.role, "path": spec.relpath, "kind": spec.kind,
                 "required": spec.required}
        destination = output_dir / spec.relpath
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
            "env_export": "non-secret allowlist only",
            "secrets": "excluded",
            "restore_overwrite": "refused",
        },
    }
    data = manifest_bytes(manifest)
    (output_dir / "manifest.json").write_bytes(data)
    (output_dir / "manifest.json").chmod(0o600)
    # Independent of the caller's umask: no backup element is ever
    # group/world readable.
    for path in sorted(output_dir.rglob("*")):
        path.chmod(0o700 if path.is_dir() else 0o600)
    output_dir.chmod(0o700)
    return manifest, data


# --------------------------------------------------------------------------
# Restore (fail-closed, overwrite never allowed)
# --------------------------------------------------------------------------


def _load_verified_manifest(backup_dir, specs):
    """Parse, resolve and veritably verify a backup before anything is written."""
    backup_dir = Path(backup_dir)
    manifest_path = backup_dir / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise BackupError(f"missing backup manifest: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BackupError(f"invalid manifest JSON: {manifest_path}") from exc
    if manifest.get("schema") != SCHEMA:
        raise BackupError(f"unsupported manifest schema: {manifest.get('schema')!r}")
    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or not entries:
        raise BackupError(f"manifest lists no artifacts: {manifest_path}")
    sealed = hashlib.sha256()
    seen = set()
    for item in entries:
        if not isinstance(item, dict) or not {"role", "path", "kind", "required",
                                              "bytes", "sha256", "status"} <= set(item):
            raise BackupError(f"manifest entry is not a declared artifact: {item!r}")
        spec = specs.get(item["path"])
        if spec is None:
            raise BackupError(f"manifest declares an unknown artifact: {item['path']}")
        if item["path"] in seen:
            raise BackupError(f"manifest declares a duplicate artifact: {item['path']}")
        seen.add(item["path"])
        if item["role"] != spec.role or item["kind"] != spec.kind \
                or item["required"] != spec.required:
            raise BackupError(f"manifest metadata drifted from the declared table: "
                              f"{item['path']}")
        if item["status"] == "present":
            payload = backup_dir / item["path"]
            if payload.is_symlink() or not payload.is_file():
                raise BackupError(f"backed-up artifact is missing: {item['path']}")
            if item["sha256"] != file_digest(payload) \
                    or item["bytes"] != payload.stat().st_size:
                raise BackupError(f"artifact digest or size mismatch, refusing "
                                  f"restore: {item['path']}")
            sealed.update(item["sha256"].encode())
    if manifest.get("artifacts_sha256") != sealed.hexdigest():
        raise BackupError("manifest artifacts digest mismatch, refusing restore")
    return manifest, specs


def restore(backup_dir, *, state_root=STATE_ROOT, control_env_dir=CONTROL_ENV_DIR,
            elastic_env=None):
    """Verify a backup completely, then restore its present file artifacts.

    Destinations are re-derived from the fixed artifact table using the
    caller's ``state_root``, not taken from manifest paths. Existing target
    state files are never overwritten (raise :class:`FileExistsError`);
    ``env``-kind artifacts carry derived, non-secret settings and are not
    written back over live input, only reported.
    """
    backup_dir = Path(backup_dir)
    specs_by_path = {spec.relpath: spec for spec in
                     default_artifact_specs(state_root, control_env_dir, elastic_env)}
    manifest, _ = _load_verified_manifest(backup_dir, specs_by_path)
    written, skipped, not_restored = [], [], []
    for item in manifest["artifacts"]:
        if item["status"] != "present":
            skipped.append(item["path"])
            continue
        spec = specs_by_path[item["path"]]
        if spec.kind == "env":
            not_restored.append(item["path"])
            continue
        target = spec.source
        if target.parent.exists():
            if target.parent.is_symlink() or not target.parent.is_dir():
                raise BackupError(f"restore target parent must be a real directory: "
                                  f"{target.parent}")
        else:
            target.parent.mkdir(parents=True, mode=0o700)
        if target.exists() or target.is_symlink():
            raise FileExistsError(
                f"restore never overwrites existing state: {target}; move it aside "
                "or point --state-root at a clean directory")
        shutil.copy2(backup_dir / item["path"], target)
        target.chmod(0o600)
        written.append(str(target))
    return {
        "schema": SCHEMA,
        "action": "restore",
        "backup_dir": str(backup_dir),
        "created_at": manifest["created_at"],
        "restored": written,
        "skipped_missing": skipped,
        "not_restored_env_derived": sorted(not_restored),
        "overwrites": 0,
        "verification": "sha256-and-size verified before any write",
    }


__all__ = [
    "ANALYTICS_EXPORT_KEYS", "ArtifactSpec", "BackupError", "CONTROL_ENV_DIR",
    "CONTROL_EXPORT_KEYS",
    "INSTALLED_RELEASE", "KINDS", "MAX_DB_BYTES", "MAX_FILE_BYTES", "REPO_ROOT",
    "ROLES", "SCHEMA", "STATE_ROOT", "backup_id", "create_backup",
    "default_artifact_specs", "default_elastic_env", "file_digest",
    "manifest_bytes", "parse_exportable_settings", "plan", "restore",
]
