"""Read-only activation-gate report used by the operations integration.

No host, nft, Docker, KVM or systemd operation is involved: the report only
reuses ``runtime.cell_gate.evaluate_cell_gate``.
"""
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from runtime.cell_gate import (
    GATE_REPORT_SCHEMA, CellGateContext, evaluate_cell_gate, gate_report,
    load_policy,
)
from runtime.isolation.containers import ContainerCellPolicy
from runtime.isolation.policy import CellPolicy

REPO_ROOT = Path(__file__).resolve().parents[2]


def kvm_document(cell=7):
    return {
        "version": 1,
        "cell": cell,
        "bridge": f"dybr{cell}",
        "gateway_mac": "02:10:20:30:40:50",
        "services": [{"address": "198.51.100.20", "protocol": "tcp", "port": 22}],
        "telemetry": None,
        "memory_mib": 512,
        "vcpus": 1,
    }


def container_document():
    document = json.loads(
        (REPO_ROOT / "deploy/isolation/cell-container.example.json").read_text())
    document["profile"]["image"] = "registry.example/dystopia/cowrie@sha256:" + "a" * 64
    return document


def test_gate_report_is_fail_closed_by_default():
    report = gate_report({7: CellPolicy.from_mapping(kvm_document())})

    assert report["schema"] == GATE_REPORT_SCHEMA
    assert report["activation_allowed"] is False
    assert report["containment_verified"] is False
    assert report["activation_performed"] is False
    assert report["trusted_verifier_keys"] == 0
    assert report["cells"][0]["cell"] == 7
    assert report["cells"][0]["activation_allowed"] is False
    assert report["cells"][0]["blocking_reasons"]


def test_gate_report_is_deterministic_and_sorted():
    policies = {
        21: ContainerCellPolicy.from_mapping(container_document()),
        7: CellPolicy.from_mapping(kvm_document()),
    }

    first = gate_report(policies)
    second = gate_report(dict(reversed(list(policies.items()))))

    assert first == second
    assert [item["cell"] for item in first["cells"]] == [7, 21]
    assert first["cells"][1]["workload"] == "container"
    assert first["cells"][0]["workload"] == "kvm"


def test_gate_report_never_runs_a_command_or_touches_the_host():
    policies = {7: CellPolicy.from_mapping(kvm_document())}
    with patch.object(subprocess, "run") as run, patch("os.system") as system:
        report = gate_report(policies, artifacts_path=Path("/nonexistent"))

    run.assert_not_called()
    system.assert_not_called()
    assert report["activation_performed"] is False
    assert report["host_operations"] == []


def test_gate_report_matches_the_single_cell_evaluation():
    policy = CellPolicy.from_mapping(kvm_document())

    report = gate_report({7: policy})
    direct = evaluate_cell_gate(policy, CellGateContext(cell=7))

    assert report["cells"][0]["blocking_reasons"] == direct.blocking_reasons
    assert report["cells"][0]["required_artifacts"] == direct.required_artifacts


def test_gate_report_rejects_unvalidated_input():
    with pytest.raises(TypeError):
        gate_report([])
    with pytest.raises(TypeError):
        gate_report({7: {"cell": 7}})
    with pytest.raises(ValueError):
        gate_report({0: CellPolicy.from_mapping(kvm_document())})


def test_load_policy_reads_both_workloads(tmp_path):
    kvm_path = tmp_path / "cell.json"
    kvm_path.write_text(json.dumps(kvm_document()))
    container_path = tmp_path / "container.json"
    container_path.write_text(json.dumps(container_document()))

    assert type(load_policy(kvm_path)) is CellPolicy
    assert type(load_policy(container_path)) is ContainerCellPolicy


def test_load_policy_refuses_oversized_or_duplicated_documents(tmp_path):
    oversized = tmp_path / "big.json"
    oversized.write_text(json.dumps({"version": 1, "padding": "x" * 20000}))
    duplicated = tmp_path / "duplicated.json"
    duplicated.write_text('{"version": 1, "version": 1}')

    with pytest.raises(ValueError):
        load_policy(oversized)
    with pytest.raises(ValueError):
        load_policy(duplicated)
