"""Offline supply-chain checks: hashed locks, no secrets, fail-closed bundling."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTROL_LOCK = ROOT / "deploy" / "requirements-control.lock"
TEST_LOCK = ROOT / "deploy" / "requirements-test.lock"
BUILD_SCRIPT = ROOT / "scripts" / "build_offline_bundle.sh"
SBOM_FILES = (
    ROOT / "deploy" / "sbom" / "control-cyclonedx.json",
    ROOT / "deploy" / "sbom" / "test-cyclonedx.json",
)

# Same shape runtime/install.py::verify_bundle accepts.
PIN = re.compile(
    r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+"
    r"(?:\s+--hash=sha256:[a-f0-9]{64})+"
)
HASH = re.compile(r"--hash=sha256:([a-f0-9]{64})")
TEST_TOOLS = {"pytest", "pytest-asyncio", "ruff", "pyright"}

SECRET_PATTERNS = (
    re.compile(r"CHANGEME"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
)


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_pins(path):
    text = path.read_text(encoding="utf-8")
    pins = []
    for raw in text.replace("\\\n", " ").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pins.append(line)
    return pins


def lock_hashes(path):
    hashes = set()
    for line in lock_pins(path):
        hashes.update(HASH.findall(line))
    return hashes


def test_locks_are_not_committed_as_wheels_or_archives():
    forbidden = [p for p in ROOT.joinpath("deploy").rglob("*") if p.suffix in {".whl", ".gz", ".zip"}]
    assert forbidden == []


@pytest.mark.parametrize("lock", [CONTROL_LOCK, TEST_LOCK])
def test_every_lock_line_is_a_hash_pinned_requirement(lock):
    assert lock.is_file(), f"missing lock: {lock}"
    pins = lock_pins(lock)
    assert pins, "lock has no requirements"
    for line in pins:
        assert PIN.fullmatch(line), f"not an exact hash-pinned line: {line[:120]}"
        assert HASH.search(line), f"no SHA-256 on: {line[:120]}"
    assert len(pins) == len({normalize(line.split("==", 1)[0]) for line in pins})


def test_control_lock_excludes_test_tooling():
    names = {normalize(line.split("==", 1)[0].split("[", 1)[0]) for line in lock_pins(CONTROL_LOCK)}
    assert names.isdisjoint(TEST_TOOLS)
    assert "fastapi" in names
    # JWT path: PyJWT replaced python-jose (no-fix advisories) and dropped ecdsa.
    assert "pyjwt" in names
    assert "python-jose" not in names
    assert "ecdsa" not in names
    starlette_version = next(
        line.split("==", 1)[1]
        for line in lock_pins(CONTROL_LOCK) if line.split("==", 1)[0] == "starlette"
    )
    starlette_parts = tuple(int(part) for part in re.findall(r"\d+", starlette_version))
    assert starlette_parts >= (1, 3, 1), starlette_version


def test_test_lock_is_a_superset_with_test_tooling():
    control = {normalize(line.split("==", 1)[0].split("[", 1)[0]) for line in lock_pins(CONTROL_LOCK)}
    tests = {normalize(line.split("==", 1)[0].split("[", 1)[0]) for line in lock_pins(TEST_LOCK)}
    assert control < tests
    assert {"pytest", "pytest-asyncio"} <= tests


def test_offline_artifacts_contain_no_placeholders_or_credentials():
    artifacts = [CONTROL_LOCK, TEST_LOCK, BUILD_SCRIPT, *SBOM_FILES]
    artifacts += [
        ROOT / "scripts" / "generate_sbom.py",
        ROOT / "docs" / "OFFLINE-BUNDLE.md",
        ROOT / "docs" / "SBOM.md",
    ]
    for path in artifacts:
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            assert not pattern.search(text), f"{pattern.pattern} found in {path}"


def test_build_script_requires_a_lock():
    result = subprocess.run(
        ["bash", str(BUILD_SCRIPT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "usage" in result.stderr


def test_build_script_rejects_missing_lock_without_network():
    result = subprocess.run(
        ["bash", str(BUILD_SCRIPT), str(ROOT / "deploy" / "does-not-exist.lock")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHON": sys.executable},
    )
    assert result.returncode != 0
    assert "not found" in result.stderr


def test_build_script_rejects_unhashed_lock_without_network(tmp_path):
    lock = tmp_path / "unhashed.lock"
    lock.write_text("fastapi==0.115.12\n", encoding="utf-8")
    result = subprocess.run(
        ["bash", str(BUILD_SCRIPT), str(lock), str(tmp_path / "bundle")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHON": sys.executable},
    )
    assert result.returncode != 0
    assert "not an exact pin" in result.stderr
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize("sbom_path", SBOM_FILES)
def test_sbom_is_cyclonedx_with_real_hashes_and_licenses(sbom_path):
    document = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] >= "1.5"
    components = document["components"]
    assert components
    known_hashes = lock_hashes(CONTROL_LOCK) | lock_hashes(TEST_LOCK)
    for component in components:
        assert component["name"] and component["version"]
        assert component["purl"].startswith("pkg:pypi/")
        hashes = [item["content"] for item in component["hashes"] if item["alg"] == "SHA-256"]
        assert len(hashes) == 1
        assert re.fullmatch(r"[a-f0-9]{64}", hashes[0])
        assert hashes[0] in known_hashes, f"SBOM hash not present in locks: {component['name']}"
        assert component["licenses"][0]["license"]["name"]
