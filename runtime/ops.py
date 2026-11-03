"""Offline integration of the Dystopia operations plane with the runtime layer.

This module is the read-only seam between contracts that already exist:

* ``runtime.backup``     - the fixed control-plane artifact table and its
  declared gaps (:func:`runtime.backup.runtime_state`).
* ``runtime.health``     - the runtime snapshots of the ingest and sensor
  stores, reused through the backup report.
* ``runtime.honeypots``  - the declarative per-cell Compose planning.
* ``runtime.cell_gate``  - the fail-closed activation gate and its report.

Nothing here starts a service, opens a socket, touches Docker, nftables,
KVM, systemd or a database in write mode, and no secret value is ever
materialized: environment files are described by the names of their
reviewed allowlisted settings only.

The result is a *report*, never an action. It states, per plane, what is
present, what is readable, what the backup contract deliberately does not
carry and which paths the deployed units reference but the operations plane
does not account for.
"""
from dataclasses import dataclass
from pathlib import Path
import re

from runtime import backup
from runtime import cell_gate
from runtime import honeypots

SCHEMA = "dystopia.ops/v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
UNITS_DIR = REPO_ROOT / "deploy/systemd"

# Declared limits of this report. They are part of the output on purpose: an
# operations report that hides what it does not verify is worse than none.
LIMITATIONS = (
    "read-only: no service is started, stopped, reloaded or reconfigured",
    "no container, network, nftables, KVM, libvirt or systemd operation is performed",
    "the activation gate stays fail-closed: a v1 bundle never authorizes a cell",
    "a report describes state that exists on disk; it is not containment evidence",
    "secrets are never materialized: environment files are listed by setting name only",
    "the sensor spool and the cell data roots stay outside the control-plane backup table",
    "the deployed units are read as text; systemd is never asked to evaluate them",
)

_UNIT_LIMIT = 256 * 1024
_EXEC_OPTION = re.compile(r"--[a-z][a-z-]*(?:=|\s+)(/[^\s;]+)")


@dataclass(frozen=True)
class OpsContext:
    """Everything the report may read. Nothing here is written."""

    state_root: Path = backup.STATE_ROOT
    control_env_dir: Path = backup.CONTROL_ENV_DIR
    elastic_env: Path | None = None
    inventory: Path | None = None
    profile: Path | None = None
    policies: tuple = ()
    artifacts_path: Path | None = None
    units_dir: Path | None = UNITS_DIR


# --------------------------------------------------------------------------
# Unit alignment
# --------------------------------------------------------------------------


def _unit_paths(text):
    """Absolute state paths referenced by a systemd unit, read as text."""
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("ConditionPathExists=") or line.startswith("EnvironmentFile="):
            # systemd allows an optional leading "-" on these directives.
            paths.append(line.split("=", 1)[1].strip().lstrip("-"))
        elif line.startswith("ExecStart"):
            paths.extend(_EXEC_OPTION.findall(line))
    return [path for path in paths
            if path.startswith("/") and "%" not in path and "${" not in path]


def _classify(path, covered, declared):
    if path in covered:
        return "backup-covered"
    if path in declared:
        return "declared-outside-backup"
    if path.startswith(str(backup.STATE_ROOT) + "/") \
            or path.startswith(str(backup.CONTROL_ENV_DIR) + "/"):
        return "unaccounted"
    return "outside-control-state"


def unit_alignment(units_dir: Path | None = UNITS_DIR, *, state_root=None,
                   control_env_dir=None):
    """Match the deployed unit paths against the operations contracts.

    The classification always uses the canonical deployment roots: the unit
    files name the canonical state and control-environment paths, so a report
    produced for a different root is compared against them and the difference
    is stated instead of hidden.
    """
    units_dir = Path(units_dir) if units_dir is not None else None
    covered = {str(spec.source) for spec in backup.default_artifact_specs()}
    declared = {item["path"]
                for item in backup.uncovered_sources(backup.STATE_ROOT,
                                                     backup.CONTROL_ENV_DIR)}
    entries = []
    units = []
    if units_dir is not None and units_dir.is_dir():
        units = sorted(units_dir.glob("*.service")) + sorted(units_dir.glob("*.socket"))
    for unit in units:
        try:
            raw = unit.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(raw) > _UNIT_LIMIT:
            continue
        for path in sorted(set(_unit_paths(raw))):
            entries.append({
                "unit": unit.name,
                "path": path,
                "classification": _classify(path, covered, declared),
            })
    entries.sort(key=lambda item: (item["path"], item["unit"]))
    roots = {
        "canonical_state_root": str(backup.STATE_ROOT),
        "canonical_control_env_dir": str(backup.CONTROL_ENV_DIR),
    }
    if state_root is not None and Path(state_root) != backup.STATE_ROOT:
        roots["reported_state_root"] = str(Path(state_root))
    if control_env_dir is not None and Path(control_env_dir) != backup.CONTROL_ENV_DIR:
        roots["reported_control_env_dir"] = str(Path(control_env_dir))
    return {
        "units_dir": str(units_dir) if units_dir is not None else None,
        "units": [unit.name for unit in units],
        "paths": entries,
        "unaccounted": [item["path"] for item in entries
                        if item["classification"] == "unaccounted"],
        "roots": roots,
    }


# --------------------------------------------------------------------------
# Plane sections
# --------------------------------------------------------------------------


def _artifact(state, relpath) -> dict[str, object]:
    for item in state["artifacts"]:
        if item["path"] == relpath:
            return dict(item)
    return {"path": relpath, "status": "undeclared"}


def control_section(state):
    """Control-plane view: identity store, install plan and environment names.

    The environment artifact already carries the names (never the values) of
    its allowlisted settings, so this section reuses the backup report instead
    of re-reading the file.
    """
    identity = _artifact(state, "artifacts/control/config/users.yaml")
    install = _artifact(state, "artifacts/manager/install.json")
    environment = _artifact(state, "artifacts/manager/control.env.json")
    return {
        "identity_store": identity,
        "install_plan": install,
        "environment": environment,
        "present": identity["status"] == "present" and install["status"] == "present",
    }


def honeypot_section(inventory, profile):
    """Declarative per-cell planning; never renders, never starts anything."""
    if inventory is None or profile is None:
        return {"status": "not-requested", "activation_allowed": False,
                "containment_verified": False}
    try:
        document = honeypots.load_inventory(inventory)
        cell = honeypots.load_cell(profile, document)
        report = honeypots.validate(inventory, profile)
    except honeypots.HoneypotError as exc:
        return {"status": "invalid", "detail": str(exc), "activation_allowed": False,
                "containment_verified": False}
    except OSError as exc:
        return {"status": "unavailable", "detail": f"{type(exc).__name__}: {exc}",
                "activation_allowed": False, "containment_verified": False}
    report["status"] = "valid"
    report["data_root"] = cell.data_root
    return report


def gate_section(policies, artifacts_path):
    """Fail-closed activation gate per cell; never activates anything."""
    loaded = {}
    errors = {}
    for cell, path in policies:
        try:
            loaded[cell] = cell_gate.load_policy(path)
        except (OSError, ValueError, TypeError) as exc:
            errors[str(cell)] = f"{type(exc).__name__}: {exc}"
    report = cell_gate.gate_report(loaded, artifacts_path=artifacts_path)
    report["policy_errors"] = errors
    if not policies:
        report["status"] = "not-requested"
    elif errors and not loaded:
        report["status"] = "invalid"
    else:
        report["status"] = "evaluated"
    return report


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def _check(identifier, ok, detail, *, skipped=False):
    """A check is neutral when skipped: only a failed check makes a report fail."""
    return {
        "id": identifier,
        "status": "skipped" if skipped else ("pass" if ok else "fail"),
        "ok": True if skipped else bool(ok),
        "detail": detail,
    }


def _checks(state, control, honeypots_report, gate, alignment):
    checks = []
    checks.append(_check(
        "control_state_present", control["present"],
        "control identity store and install plan are present"
        if control["present"] else "control identity store or install plan is missing"))
    checks.append(_check(
        "backup_contract_ready", state["ready_for_backup"],
        "every required artifact of the backup table is present"
        if state["ready_for_backup"]
        else "required artifacts are missing: " + ", ".join(state["missing_required"])))
    ingest = state["runtime"].get("ingest", {})
    ingest_present = _artifact(state, "artifacts/ingest/events.db")["status"] == "present"
    checks.append(_check(
        "runtime_state_readable", ingest.get("status") == "available",
        "ingest event store is readable"
        if ingest.get("status") == "available"
        else ("event store is absent on this host" if not ingest_present
              else f"ingest event store is not readable: {ingest.get('detail', 'unknown')}"),
        skipped=not ingest_present))
    checks.append(_check(
        "honeypot_profile_valid", honeypots_report["status"] == "valid",
        f"honeypot profile is {honeypots_report['status']}"
        if honeypots_report["status"] != "valid"
        else "honeypot profile renders inside its safety invariants",
        skipped=honeypots_report["status"] == "not-requested"))
    data_root = str(honeypots_report.get("data_root") or "")
    aligned = bool(data_root) and data_root.startswith(str(backup.STATE_ROOT) + "/")
    checks.append(_check(
        "honeypot_data_root_aligned", aligned,
        f"cell data root {data_root} lives under the Dystopia state root"
        if aligned else
        (f"cell data root {data_root} is outside the Dystopia state root"
         if data_root else "no honeypot cell data root to compare"),
        skipped=honeypots_report["status"] != "valid"))
    checks.append(_check(
        "unit_paths_accounted_for", not alignment["unaccounted"],
        "every deployed unit path is either backup-covered or a declared gap"
        if not alignment["unaccounted"] else
        "unit paths are not accounted for: " + ", ".join(alignment["unaccounted"])))
    checks.append(_check(
        "cell_policies_valid", not gate["policy_errors"],
        "every requested cell policy is valid"
        if not gate["policy_errors"] else
        "cell policies could not be read or validated: "
        + ", ".join(f"cell {cell}" for cell in sorted(gate["policy_errors"])),
        skipped=gate["status"] == "not-requested"))
    blocked = all(not item["activation_allowed"] for item in gate["cells"])
    checks.append(_check(
        "activation_gate_fail_closed",
        gate["activation_performed"] is False and blocked,
        "the gate refused to authorize any cell and performed no activation"
        if blocked else "the gate reported an authorized cell",
        skipped=not gate["cells"]))
    return checks


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def status(context):
    """Assemble the integrated, read-only operations report."""
    context = context if isinstance(context, OpsContext) else OpsContext(**dict(context))
    specs = backup.default_artifact_specs(context.state_root, context.control_env_dir,
                                          context.elastic_env)
    state = backup.runtime_state(specs, state_root=context.state_root,
                                 control_env_dir=context.control_env_dir,
                                 elastic_env=context.elastic_env)
    control = control_section(state)
    honeypots_report = honeypot_section(context.inventory, context.profile)
    gate = gate_section(context.policies, context.artifacts_path)
    alignment = unit_alignment(context.units_dir,
                                state_root=context.state_root,
                                control_env_dir=context.control_env_dir)
    checks = _checks(state, control, honeypots_report, gate, alignment)
    return {
        "schema": SCHEMA,
        "action": "ops-status",
        "dry_run": True,
        "host_operations": [],
        "state_root": str(Path(context.state_root)),
        "control_env_dir": str(Path(context.control_env_dir)),
        "control": control,
        "backup": state,
        "runtime": state["runtime"],
        "honeypots": honeypots_report,
        "gate": gate,
        "alignment": alignment,
        "checks": checks,
        "ok": all(check["ok"] for check in checks),
        "limits": list(LIMITATIONS),
    }


def verify(context):
    """Same report, framed as a verification: ``ok`` drives the exit code."""
    report = status(context)
    report["action"] = "ops-verify"
    return report


__all__ = [
    "LIMITATIONS", "OpsContext", "REPO_ROOT", "SCHEMA", "UNITS_DIR",
    "control_section", "gate_section", "honeypot_section", "status",
    "unit_alignment", "verify",
]
