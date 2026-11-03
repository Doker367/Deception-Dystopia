"""Offline activation-gate contract tests; no host, nft or workload operations."""
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

from runtime.cell_gate import (
    REQUIRED_ARTIFACTS, CellGateContext, evaluate_cell_gate, policy_sha256,
)
from runtime.cli import main
from runtime.isolation.containers import ContainerCellPolicy
from runtime.isolation.policy import CellPolicy


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
