"""Offline activation-gate contract tests; no host, nft or workload operations."""
import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from runtime import cell_gate
from runtime.cell_gate import (
    REQUIRED_ARTIFACTS, CellGateContext, evaluate_cell_gate, policy_sha256,
)
from runtime.cli import main
from runtime.isolation.containers import ContainerCellPolicy
from runtime.isolation.policy import CellPolicy

HOST_ID = "lab-host-01"
BOOT_ID = "11111111-2222-3333-4444-555555555555"
OTHER_BOOT_ID = "99999999-8888-7777-6666-555555555555"
ISSUED_AT = "2026-11-02T10:00:00Z"
EXPIRES_AT = "2026-11-02T10:10:00Z"
CHALLENGE = "challenge-0123456789abcdef"


def kvm_document():
    return {
        "version": 1,
        "cell": 7,
        "bridge": "dybr7",
        "gateway_mac": "02:10:20:30:40:50",
        "services": [{"address": "198.51.100.20", "protocol": "tcp", "port": 22}],
        "telemetry": None,
        "memory_mib": 512,
        "vcpus": 1,
    }


def container_document():
    document = json.loads(
        (Path(__file__).resolve().parents[2]
         / "deploy/isolation/cell-container.example.json").read_text()
    )
    document["profile"]["image"] = "registry.example/dystopia/cowrie@sha256:" + "a" * 64
    return document


def write_policy(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_no_artifacts_means_blocked_with_explicit_evidence_requirements():
    policy = CellPolicy.from_mapping(kvm_document())

    result = evaluate_cell_gate(policy, CellGateContext(cell=7))

    assert result.activation_allowed is False
    assert result.containment_verified is False
    assert "no Linux verification artifacts were supplied" in result.blocking_reasons
    assert result.required_artifacts == list(REQUIRED_ARTIFACTS)


def test_invalid_artifacts_for_container_honeypot_policy_are_blocked(tmp_path):
    policy = ContainerCellPolicy.from_mapping(container_document())
    (tmp_path / "cell-21.attestation.json").write_text("{not-json", encoding="utf-8")

    result = evaluate_cell_gate(policy, CellGateContext(cell=21), tmp_path)

    assert policy.profile.name == "cowrie"
    assert result.activation_allowed is False
    assert result.containment_verified is False
    assert any("unavailable or invalid" in reason for reason in result.blocking_reasons)


def test_mock_self_check_and_internal_claims_never_count_as_evidence(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    for content, expected in (
        ({"verification": "mock"}, "not independent Linux evidence"),
        ({"verification": "self-check"}, "not independent Linux evidence"),
        ({"internal": True}, "internal claims are not containment evidence"),
    ):
        (tmp_path / "cell-7.attestation.json").write_text(json.dumps(content), encoding="utf-8")

        result = evaluate_cell_gate(policy, CellGateContext(cell=7), tmp_path)

        assert result.activation_allowed is False
        assert result.containment_verified is False
        assert any(expected in reason for reason in result.blocking_reasons)


def test_apply_success_does_not_bypass_gate():
    policy = CellPolicy.from_mapping(kvm_document())

    without_apply = evaluate_cell_gate(policy, CellGateContext(cell=7))
    after_apply = evaluate_cell_gate(policy, CellGateContext(cell=7, apply_succeeded=True))

    assert after_apply.activation_allowed is False
    assert after_apply.containment_verified is False
    assert after_apply.blocking_reasons == without_apply.blocking_reasons


def test_gate_never_calls_a_real_activation_or_host_command(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    with patch.object(subprocess, "run") as run, patch("os.system") as system:
        result = evaluate_cell_gate(policy, CellGateContext(cell=7), tmp_path)

    run.assert_not_called()
    system.assert_not_called()
    assert result.activation_allowed is False


def test_cli_cells_gate_is_read_only_and_json_is_deterministic(tmp_path, capsys):
    policy_path = write_policy(tmp_path / "cell.json", kvm_document())
    with patch("runtime.cli.os.umask") as umask:
        assert main(["cells", "gate", "--cell", "7", "--policy", str(policy_path)]) == 2
        first = capsys.readouterr().out
        assert main(["cells", "gate", "--cell", "7", "--policy", str(policy_path)]) == 2
        second = capsys.readouterr().out
    umask.assert_not_called()
    assert first == second
    report = json.loads(first)
    assert report["activation_allowed"] is False
    assert report["containment_verified"] is False
    assert report["required_artifacts"] == list(REQUIRED_ARTIFACTS)


def test_policy_digest_is_stable_and_type_bound():
    policy = CellPolicy.from_mapping(kvm_document())
    assert policy_sha256(policy) == policy_sha256(CellPolicy.from_mapping(kvm_document()))
    assert len(policy_sha256(policy)) == 64


# --------------------------------------------------------------------------
# Freshness, host identity and replay resistance (test key only)
# --------------------------------------------------------------------------


def signed_bundle(tmp_path, policy, **overrides):
    """Build a syntactically valid signed bundle with an ephemeral test key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    directory = tmp_path / "evidence"
    directory.mkdir()
    artifacts = {}
    for name in REQUIRED_ARTIFACTS:
        filename = f"{name}.txt"
        payload = f"{name}=pass\n".encode()
        (directory / filename).write_bytes(payload)
        artifacts[name] = {"file": filename,
                           "sha256": hashlib.sha256(payload).hexdigest(),
                           "result": "pass"}
    manifest = {
        "schema": cell_gate.SCHEMA,
        "cell": policy.cell,
        "workload": "container" if type(policy) is ContainerCellPolicy else "kvm",
        "policy_sha256": policy_sha256(policy),
        "verification": "linux-live-independent",
        "platform": {
            "distribution": "ubuntu",
            "version_id": "24.04",
            "kernel_release": "6.8.0-synthetic",
            "boot_id": BOOT_ID,
        },
        "verifier_key_id": "test-key-v1",
        "artifacts": artifacts,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "host_id": HOST_ID,
        "challenge": CHALLENGE,
    }
    manifest.update(overrides)
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
    signed = {key: value for key, value in manifest.items() if key != "signature"}
    message = json.dumps(signed, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
    manifest["signature"] = base64.b64encode(private.sign(message)).decode()
    (directory / f"cell-{policy.cell}.attestation.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    return directory, {"test-key-v1": public}


def evaluate_with_test_key(policy, context, directory, keys):
    with patch.dict(cell_gate.TRUSTED_VERIFIER_KEYS, keys, clear=True):
        return evaluate_cell_gate(policy, context, directory)


def test_fresh_bundle_bound_to_host_boot_and_window_is_accepted(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy)
    context = CellGateContext(cell=7, host_id=HOST_ID, boot_id=BOOT_ID,
                              now="2026-11-02T10:05:00Z", challenge=CHALLENGE)
    result = evaluate_with_test_key(policy, context, directory, keys)

    assert result.activation_allowed is True
    assert result.containment_verified is True


def test_same_bundle_is_rejected_on_another_boot(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy)
    context = CellGateContext(cell=7, host_id=HOST_ID, boot_id=OTHER_BOOT_ID,
                              now="2026-11-02T10:05:00Z", challenge=CHALLENGE)
    result = evaluate_with_test_key(policy, context, directory, keys)

    assert result.activation_allowed is False
    assert any("boot id" in reason for reason in result.blocking_reasons)


def test_expired_bundle_is_rejected(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy)
    context = CellGateContext(cell=7, host_id=HOST_ID, boot_id=BOOT_ID,
                              now="2026-11-02T10:20:00Z", clock_skew_seconds=0,
                              challenge=CHALLENGE)
    result = evaluate_with_test_key(policy, context, directory, keys)

    assert result.activation_allowed is False
    assert "attestation has expired" in result.blocking_reasons


def test_bundle_from_the_future_is_rejected(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy)
    context = CellGateContext(cell=7, host_id=HOST_ID, boot_id=BOOT_ID,
                              now="2026-11-02T09:00:00Z", clock_skew_seconds=0)
    result = evaluate_with_test_key(policy, context, directory, keys)

    assert result.activation_allowed is False
    assert "attestation is not valid yet" in result.blocking_reasons


def test_bundle_for_another_host_is_rejected(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy)
    context = CellGateContext(cell=7, host_id="other-host-02", boot_id=BOOT_ID,
                              now="2026-11-02T10:05:00Z")
    result = evaluate_with_test_key(policy, context, directory, keys)

    assert result.activation_allowed is False
    assert any("host does not match" in reason for reason in result.blocking_reasons)


def test_missing_expected_host_or_boot_context_is_fail_closed(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy)
    context = CellGateContext(cell=7, now="2026-11-02T10:05:00Z")
    result = evaluate_with_test_key(policy, context, directory, keys)

    assert result.activation_allowed is False
    assert any("expected host identity is missing" in reason
               for reason in result.blocking_reasons)
    assert any("expected boot id is missing" in reason
               for reason in result.blocking_reasons)


def test_challenge_mismatch_is_rejected(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy)
    context = CellGateContext(cell=7, host_id=HOST_ID, boot_id=BOOT_ID,
                              now="2026-11-02T10:05:00Z",
                              challenge="another-challenge-0123456789")
    result = evaluate_with_test_key(policy, context, directory, keys)

    assert result.activation_allowed is False
    assert any("challenge does not match" in reason
               for reason in result.blocking_reasons)


def test_overlong_validity_window_is_rejected(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy,
                                    expires_at="2026-11-02T12:00:00Z")
    context = CellGateContext(cell=7, host_id=HOST_ID, boot_id=BOOT_ID,
                              now="2026-11-02T10:05:00Z")
    result = evaluate_with_test_key(policy, context, directory, keys)

    assert result.activation_allowed is False
    assert any("maximum lifetime" in reason for reason in result.blocking_reasons)


def test_naive_context_time_is_rejected(tmp_path):
    policy = CellPolicy.from_mapping(kvm_document())
    directory, keys = signed_bundle(tmp_path, policy)
    context = CellGateContext(cell=7, host_id=HOST_ID, boot_id=BOOT_ID,
                              now=datetime(2026, 11, 2, 10, 5))
    with pytest.raises(ValueError):
        evaluate_with_test_key(policy, context, directory, keys)


def test_cli_accepts_host_boot_and_time_context(tmp_path, capsys):
    policy_path = write_policy(tmp_path / "cell.json", kvm_document())
    assert main([
        "cells", "gate", "--cell", "7", "--policy", str(policy_path),
        "--host-id", HOST_ID, "--boot-id", BOOT_ID,
        "--now", "2026-11-02T10:05:00Z", "--challenge", CHALLENGE,
    ]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["activation_allowed"] is False
    assert "expected host identity is missing" not in report["blocking_reasons"]
