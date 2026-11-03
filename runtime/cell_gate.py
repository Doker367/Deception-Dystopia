"""Offline, fail-closed activation gate for versioned cell verification evidence.

This module only validates policy and reads a signed evidence bundle. It never
applies firewall rules, inspects a live host, starts a workload, or activates a
cell. A bundle is trusted only when its verifier key has been pinned here after
independent review; the trust store intentionally starts empty.
"""
from dataclasses import dataclass, fields, is_dataclass
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from runtime.isolation.containers import ContainerCellPolicy
from runtime.isolation.policy import CellPolicy


SCHEMA = "dystopia.cell-verification/v1"
GATE_REPORT_SCHEMA = "dystopia.cell-verification.report/v1"
MANIFEST_LIMIT = 64 * 1024
ARTIFACT_LIMIT = 16 * 1024 * 1024
POLICY_LIMIT = 16 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_BOOT_ID = re.compile(r"[0-9a-fA-F-]{36}\Z")
_HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
MAX_BUNDLE_LIFETIME_SECONDS = 3600
DEFAULT_CLOCK_SKEW_SECONDS = 300

# Public Ed25519 keys, keyed by verifier_key_id. Add a key only after the
# independent Linux verifier and its key custody have been reviewed. Never
# accept a key supplied by the evidence bundle itself.
TRUSTED_VERIFIER_KEYS: dict[str, str] = {}

REQUIRED_ARTIFACTS = (
    "host_identity",
    "network_topology",
    "nft_policy",
    "connectivity_matrix",
    "resource_limits",
    "storage_quota",
    "workload_boundary",
    "activation_barrier",
)


@dataclass(frozen=True)
class CellGateContext:
    """Expected cell identity and the observation window of this evaluation.

    ``host_id`` and ``boot_id`` are the identities provisioned for the host
    that would consume the cell. ``now``/``clock_skew_seconds`` define the
    freshness check; ``challenge`` optionally binds a verifier nonce. The
    context is supplied by the operator/activator, never by the bundle.
    """

    cell: int
    apply_succeeded: bool = False
    host_id: str | None = None
    boot_id: str | None = None
    now: datetime | str | None = None
    challenge: str | None = None
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS


@dataclass(frozen=True)
class CellGateResult:
    activation_allowed: bool
    containment_verified: bool
    blocking_reasons: list[str]
    required_artifacts: list[str]
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "activation_allowed": self.activation_allowed,
            "blocking_reasons": list(self.blocking_reasons),
            "containment_verified": self.containment_verified,
            "detail": self.detail,
            "required_artifacts": list(self.required_artifacts),
        }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _utc_timestamp(value):
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise ValueError("timestamp must use YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)


def _context_now(context):
    if context.now is None:
        return datetime.now(timezone.utc)
    if type(context.now) is datetime:
        if context.now.tzinfo is None:
            raise ValueError("CellGateContext.now must be timezone-aware")
        return context.now.astimezone(timezone.utc)
    return _utc_timestamp(context.now)


def load_policy(path):
    """Read and validate a cell policy file without applying anything.

    The policy is parsed from a bounded regular file and validated by the
    strict isolation contracts. A container policy is recognised by its
    ``workload`` field; anything else is read as a KVM cell policy. This
    helper only reads: it never renders, applies or starts anything.
    """
    raw = Path(path).read_bytes()
    if len(raw) > POLICY_LIMIT:
        raise ValueError("policy exceeds 16 KiB")
    document = json.loads(raw, object_pairs_hook=_unique_object)
    if type(document) is not dict:
        raise ValueError("policy object required")
    if document.get("workload") == "container":
        return ContainerCellPolicy.from_mapping(document)
    return CellPolicy.from_mapping(document)


def _canonical(value):
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _canonical(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(value)
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in value.items()}
    return value


def policy_sha256(policy: CellPolicy | ContainerCellPolicy) -> str:
    """Return the stable digest of a validated policy's canonical JSON form."""
    if type(policy) not in (CellPolicy, ContainerCellPolicy):
        raise TypeError("validated CellPolicy or ContainerCellPolicy required")
    payload = json.dumps(_canonical(policy), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("expected a bounded regular, non-symlink artifact file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(descriptor)
        if (len(raw) != before.st_size or len(raw) > limit
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise ValueError("artifact size changed or exceeds its limit")
        return raw
    finally:
        os.close(descriptor)


def _decode_manifest(path: Path) -> dict:
    raw = _read_regular(path, MANIFEST_LIMIT)
    document = json.loads(raw, object_pairs_hook=_unique_object)
    if type(document) is not dict:
        raise ValueError("attestation manifest must be a JSON object")
    return document


def _verify_signature(document: dict, key_id: str) -> bool:
    encoded_key = TRUSTED_VERIFIER_KEYS.get(key_id)
    if encoded_key is None:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        signature = base64.b64decode(document["signature"], validate=True)
        public_key = base64.b64decode(encoded_key, validate=True)
        signed_document = {key: value for key, value in document.items() if key != "signature"}
        message = json.dumps(signed_document, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (ImportError, KeyError, TypeError, ValueError):
        return False
    except Exception as exc:
        # Invalid signatures are expected input, not a reason to leak backend
        # exceptions or alter the gate's deterministic result.
        if type(exc).__name__ == "InvalidSignature":
            return False
        return False


def _manifest_blockers(document: dict, policy, context: CellGateContext,
                       directory: Path, now: datetime) -> list[str]:
    reasons = []
    if document.get("verification") in ("mock", "self-check"):
        reasons.append("verification mode is not independent Linux evidence")
    if "internal" in document:
        reasons.append("internal claims are not containment evidence")

    expected_keys = {
        "schema", "cell", "workload", "policy_sha256", "verification", "platform",
        "verifier_key_id", "artifacts", "signature", "issued_at", "expires_at",
        "host_id", "challenge",
    }
    if set(document) != expected_keys:
        reasons.append("attestation manifest has missing or unknown fields")
        return reasons

    workload = "container" if type(policy) is ContainerCellPolicy else "kvm"
    if document["schema"] != SCHEMA:
        reasons.append("unsupported verification schema")
    if type(document["cell"]) is not int or document["cell"] != context.cell:
        reasons.append("attestation cell does not match the requested cell")
    if document["workload"] != workload:
        reasons.append("attestation workload does not match the validated policy")
    if document["policy_sha256"] != policy_sha256(policy):
        reasons.append("attestation is not bound to this exact policy")
    if document["verification"] != "linux-live-independent":
        if "verification mode is not independent Linux evidence" not in reasons:
            reasons.append("verification mode must be linux-live-independent")

    platform_info = document["platform"]
    platform_valid = False
    if type(platform_info) is not dict or set(platform_info) != {
            "distribution", "version_id", "kernel_release", "boot_id"}:
        reasons.append("Linux host identity is incomplete")
    elif (platform_info["distribution"] != "ubuntu"
          or platform_info["version_id"] != "24.04"
          or type(platform_info["kernel_release"]) is not str
          or not platform_info["kernel_release"]
          or type(platform_info["boot_id"]) is not str
          or _BOOT_ID.fullmatch(platform_info["boot_id"]) is None):
        reasons.append("evidence must identify Ubuntu 24.04 and the observed kernel boot")
    else:
        platform_valid = True

    if type(document["host_id"]) is not str \
            or _HOST_ID.fullmatch(document["host_id"]) is None:
        reasons.append("attestation host identity is invalid")
    elif context.host_id is None:
        reasons.append("expected host identity is missing from the gate context "
                       "(fail-closed)")
    elif document["host_id"] != context.host_id:
        reasons.append("attestation host does not match the expected host")

    if context.boot_id is None:
        reasons.append("expected boot id is missing from the gate context "
                       "(fail-closed)")
    elif platform_valid and platform_info["boot_id"] != context.boot_id:
        reasons.append("attestation boot id does not match the expected boot")

    challenge = document["challenge"]
    if challenge is not None and (type(challenge) is not str
                                  or _CHALLENGE.fullmatch(challenge) is None):
        reasons.append("attestation challenge is invalid")
    elif context.challenge is not None and challenge != context.challenge:
        reasons.append("attestation challenge does not match the expected challenge")

    try:
        issued_at = _utc_timestamp(document["issued_at"])
        expires_at = _utc_timestamp(document["expires_at"])
    except ValueError:
        reasons.append("attestation issue/expiry timestamps are invalid")
    else:
        lifetime = (expires_at - issued_at).total_seconds()
        if lifetime <= 0:
            reasons.append("attestation expires_at must be after issued_at")
        elif lifetime > MAX_BUNDLE_LIFETIME_SECONDS:
            reasons.append("attestation validity window exceeds the accepted "
                           "maximum lifetime")
        skew = timedelta(seconds=context.clock_skew_seconds)
        if now + skew < issued_at:
            reasons.append("attestation is not valid yet")
        if now - skew >= expires_at:
            reasons.append("attestation has expired")

    key_id = document["verifier_key_id"]
    if type(key_id) is not str or _KEY_ID.fullmatch(key_id) is None:
        reasons.append("invalid verifier key identifier")
    elif key_id not in TRUSTED_VERIFIER_KEYS:
        reasons.append("verifier signing key is not pinned by this gate")

    artifacts = document["artifacts"]
    if type(artifacts) is not dict or set(artifacts) != set(REQUIRED_ARTIFACTS):
        reasons.append("artifact set does not exactly match the v1 contract")
    else:
        seen_files = set()
        for name in REQUIRED_ARTIFACTS:
            item = artifacts[name]
            if type(item) is not dict or set(item) != {"file", "sha256", "result"}:
                reasons.append(f"artifact {name} has an invalid record")
                continue
            filename, digest, result = item["file"], item["sha256"], item["result"]
            if (type(filename) is not str or not filename or filename in (".", "..")
                    or Path(filename).name != filename or "/" in filename or "\\" in filename):
                reasons.append(f"artifact {name} has an unsafe filename")
                continue
            if filename in seen_files:
                reasons.append("artifact files must be unique")
                continue
            seen_files.add(filename)
            if type(digest) is not str or _SHA256.fullmatch(digest) is None:
                reasons.append(f"artifact {name} has an invalid SHA-256 digest")
                continue
            if result != "pass":
                reasons.append(f"artifact {name} did not pass")
                continue
            try:
                contents = _read_regular(directory / filename, ARTIFACT_LIMIT)
            except (OSError, ValueError):
                reasons.append(f"artifact {name} is missing or is not a bounded regular file")
                continue
            if hashlib.sha256(contents).hexdigest() != digest:
                reasons.append(f"artifact {name} digest does not match its contents")

    if type(key_id) is str and _KEY_ID.fullmatch(key_id) and key_id in TRUSTED_VERIFIER_KEYS:
        if not _verify_signature(document, key_id):
            reasons.append("attestation signature is invalid")
    return reasons


def evaluate_cell_gate(policy: CellPolicy | ContainerCellPolicy,
                       context: CellGateContext | int,
                       artifacts_path: str | Path | None = None) -> CellGateResult:
    """Evaluate evidence without performing any host or workload operation.

    ``artifacts_path`` is a directory containing ``cell-N.attestation.json``
    and the evidence files named by that signed manifest. The integer context
    form is shorthand for ``CellGateContext(cell=N)``.
    """
    if type(policy) not in (CellPolicy, ContainerCellPolicy):
        raise TypeError("validated CellPolicy or ContainerCellPolicy required")
    if type(context) is int:
        context = CellGateContext(cell=context)
    if type(context) is not CellGateContext or type(context.cell) is not int \
            or not 1 <= context.cell <= 254 or type(context.apply_succeeded) is not bool:
        raise ValueError("valid CellGateContext required")
    if context.host_id is not None and (
            type(context.host_id) is not str
            or _HOST_ID.fullmatch(context.host_id) is None):
        raise ValueError("CellGateContext.host_id is invalid")
    if context.boot_id is not None and (
            type(context.boot_id) is not str
            or _BOOT_ID.fullmatch(context.boot_id) is None):
        raise ValueError("CellGateContext.boot_id is invalid")
    if context.challenge is not None and (
            type(context.challenge) is not str
            or _CHALLENGE.fullmatch(context.challenge) is None):
        raise ValueError("CellGateContext.challenge is invalid")
    if type(context.clock_skew_seconds) is not int \
            or not 0 <= context.clock_skew_seconds <= 3600:
        raise ValueError("CellGateContext.clock_skew_seconds must be 0..3600")
    now = _context_now(context)

    reasons = []
    if policy.cell != context.cell:
        reasons.append("validated policy cell does not match the requested cell")
    if type(policy) is ContainerCellPolicy:
        reasons.extend(policy.deployment_errors())

    if artifacts_path is None:
        reasons.append("no Linux verification artifacts were supplied")
    else:
        directory = Path(artifacts_path)
        manifest_path = directory / f"cell-{context.cell}.attestation.json"
        try:
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("artifact path must be a non-symlink directory")
            document = _decode_manifest(manifest_path)
            reasons.extend(_manifest_blockers(document, policy, context, directory,
                                              now))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            reasons.append(f"verification artifacts unavailable or invalid: {exc}")

    # A v1 bundle cannot authorize activation until a separately reviewed
    # verifier key is pinned. This prevents self-asserted files from becoming
    # authority, including on systems where this offline command is run.
    if not TRUSTED_VERIFIER_KEYS:
        reasons.append("no independently reviewed Linux verifier key is pinned (v1 fail-closed)")

    # Stable de-duplication preserves the order of contract checks.
    reasons = list(dict.fromkeys(reasons))
    allowed = not reasons
    detail = ("independent Linux containment evidence accepted"
              if allowed else "activation blocked; independent Linux containment evidence is incomplete")
    return CellGateResult(
        activation_allowed=allowed,
        containment_verified=allowed,
        blocking_reasons=reasons,
        required_artifacts=list(REQUIRED_ARTIFACTS),
        detail=detail,
    )


def gate_report(policies, *, artifacts_path=None):
    """Read-only activation-gate report for one or more cells.

    ``policies`` maps a cell id to an already validated ``CellPolicy`` or
    ``ContainerCellPolicy``. Every entry is produced by
    :func:`evaluate_cell_gate`, so this helper inherits its fail-closed
    behaviour: it never activates a cell, never inspects the host, never
    runs a command and never applies a firewall rule.

    The report is deterministic: cells are ordered by id and no state is
    mutated. ``activation_performed`` is always ``False``.
    """
    if type(policies) is not dict:
        raise TypeError("mapping of cell id to validated policy required")
    cells = []
    for cell in sorted(policies):
        if type(cell) is not int or not 1 <= cell <= 254:
            raise ValueError("cell id must be an integer in 1..254")
        policy = policies[cell]
        if type(policy) not in (CellPolicy, ContainerCellPolicy):
            raise TypeError("validated CellPolicy or ContainerCellPolicy required")
        result = evaluate_cell_gate(policy, CellGateContext(cell=cell),
                                    artifacts_path)
        entry = result.as_dict()
        entry["cell"] = cell
        entry["workload"] = "container" if type(policy) is ContainerCellPolicy else "kvm"
        cells.append(entry)
    allowed = bool(cells) and all(item["activation_allowed"] for item in cells)
    return {
        "schema": GATE_REPORT_SCHEMA,
        "action": "gate-report",
        "dry_run": True,
        "host_operations": [],
        "activation_performed": False,
        "activation_allowed": allowed,
        "containment_verified": allowed,
        "trusted_verifier_keys": len(TRUSTED_VERIFIER_KEYS),
        "cells": cells,
        "required_artifacts": list(REQUIRED_ARTIFACTS),
    }


__all__ = [
    "CellGateContext", "CellGateResult", "GATE_REPORT_SCHEMA", "REQUIRED_ARTIFACTS",
    "SCHEMA", "evaluate_cell_gate", "gate_report", "load_policy", "policy_sha256",
]
