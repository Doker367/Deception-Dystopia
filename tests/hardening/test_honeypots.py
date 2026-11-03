"""Read-only orchestration tests for one honeypot cell.

No Docker daemon is required except for the optional ``docker compose config``
syntax check, which is skipped when Docker is unavailable. No container,
network, port or host path is created or changed.
"""
import copy
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from runtime import honeypots
from runtime.cli import main

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "deploy/honeypots/inventory.yaml"
PROFILE = ROOT / "deploy/honeypots/profiles/cell-mvp.example.yaml"


def raw_inventory():
    return yaml.safe_load(INVENTORY.read_text())


def raw_profile():
    return yaml.safe_load(PROFILE.read_text())


def synthetic_repo(tmp_path):
    """Copy the reviewed inventory into a scratch repo with synthetic files."""
    repo = tmp_path / "repo"
    inventory_dir = repo / "deploy/honeypots"
    inventory_dir.mkdir(parents=True)
    data = raw_inventory()
    for engine in data["engines"]:
        context = (inventory_dir / engine["build"]["context"]).resolve()
        context.mkdir(parents=True, exist_ok=True)
        (context / engine["build"]["dockerfile"]).write_text("FROM scratch\n")
        (context / engine["config"]["file"]).write_text("synthetic config\n")
    path = inventory_dir / "inventory.yaml"
    path.write_text(yaml.safe_dump(data))
    return path, data, inventory_dir


def rendered(cell=1):
    inventory = honeypots.load_inventory(INVENTORY)
    profile = raw_profile()
    profile["cell"] = cell
    return inventory, honeypots.render_cell(inventory, honeypots.Cell.from_mapping(profile))


def test_inventory_and_profile_declare_the_six_mvp_engines():
    inventory = honeypots.load_inventory(INVENTORY)
    cell = honeypots.load_cell(PROFILE, inventory)
    assert tuple(sorted(inventory.engines)) == tuple(sorted(honeypots.ENGINES))
    assert cell.engines == honeypots.ENGINES
    assert cell.cell == 1
    assert cell.mode == "internal"
    assert cell.project == "dystopia-honeypot-cell-1"


def test_rendered_cell_is_safe_and_internal():
    _, document = rendered()
    assert document["name"] == "dystopia-honeypot-cell-1"
    assert set(document["services"]) == set(honeypots.ENGINES)
    for name, service in document["services"].items():
        assert service["container_name"] == f"dystopia-hp-c1-{name}"
        assert service["read_only"] is True
        assert service["init"] is True
        assert service["restart"] == "no"
        assert service["cap_drop"] == ["ALL"]
        assert service["profiles"] == ["authorized-activation"]
        assert "ports" not in service
        assert service["image"].endswith(":latest") is False
        assert service["expose"]
        assert service["mem_limit"].endswith("m")
        assert service["cpus"] > 0
        assert service["pids_limit"] > 0
        assert service["healthcheck"]["test"][0] == "CMD-SHELL"
        assert service["logging"]["options"]["max-size"] == "10m"
        assert service["ulimits"]["core"] == {"soft": 0, "hard": 0}
        assert "noexec" in service["tmpfs"][0] and "nosuid" in service["tmpfs"][0]
        # RV-02: NNP is mandatory for every service; cap_add is never a
        # substitute for it.
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["labels"]["dystopia.image-policy"] == "tag-lab-only"
        for mount in service["volumes"]:
            assert mount["type"] == "bind"
            assert mount["source"].startswith("/")
            assert "docker.sock" not in mount["source"]
        assert any(mount["read_only"] is True for mount in service["volumes"])
        writable = [mount for mount in service["volumes"] if not mount["read_only"]]
        assert len(writable) == 1
        assert writable[0]["source"].startswith("/var/lib/dystopia/honeypots/cells/1/")
    for network in document["networks"].values():
        assert network == {"driver": "bridge", "internal": True, "enable_ipv6": False}


def test_config_binds_are_read_only_files_from_the_reviewed_context():
    inventory = honeypots.load_inventory(INVENTORY)
    _, document = rendered()
    for name, engine in inventory.engines.items():
        config = [mount for mount in document["services"][name]["volumes"]
                  if mount["target"] == engine.config_target]
        assert len(config) == 1 and config[0]["read_only"] is True
        assert Path(config[0]["source"]).is_file()
        assert config[0]["source"] == str((INVENTORY.parent / engine.context
                                           / engine.config_file).resolve())


@pytest.mark.parametrize("link_kind", ["absolute", "relative", "chain"])
def test_config_symlink_outside_the_context_is_rejected(tmp_path, link_kind):
    path, data, inventory_dir = synthetic_repo(tmp_path)
    engine = data["engines"][0]
    config = (inventory_dir / engine["build"]["context"]).resolve() \
        / engine["config"]["file"]
    outside = tmp_path / "outside.cfg"
    outside.write_text("host material that must never be mounted\n")
    config.unlink()
    if link_kind == "absolute":
        config.symlink_to(outside)
    elif link_kind == "relative":
        config.symlink_to(os.path.relpath(outside, config.parent))
    else:
        inner = config.parent / "inner.cfg"
        inner.symlink_to(outside)
        config.symlink_to(inner.name)
    with pytest.raises(honeypots.HoneypotError):
        honeypots.load_inventory(path)


def test_config_symlink_to_a_host_file_is_rejected(tmp_path):
    path, data, inventory_dir = synthetic_repo(tmp_path)
    engine = data["engines"][0]
    config = (inventory_dir / engine["build"]["context"]).resolve() \
        / engine["config"]["file"]
    config.unlink()
    config.symlink_to("/etc/passwd")
    with pytest.raises(honeypots.HoneypotError):
        honeypots.load_inventory(path)


def test_render_rechecks_the_context_even_for_a_hand_built_inventory(tmp_path):
    path, data, inventory_dir = synthetic_repo(tmp_path)
    engine = data["engines"][0]
    context = (inventory_dir / engine["build"]["context"]).resolve()
    config = context / engine["config"]["file"]
    outside = tmp_path / "outside.cfg"
    outside.write_text("not reviewed\n")
    config.unlink()
    config.symlink_to(outside)
    inventory = honeypots.Inventory.from_mapping(data, inventory_dir)
    cell = honeypots.Cell.from_mapping(raw_profile())
    with pytest.raises(honeypots.HoneypotError):
        honeypots.render_cell(inventory, cell)


def test_assert_safe_rejects_a_config_bind_outside_the_build_context(tmp_path):
    inventory, cell = render_cell_objects()
    clean = honeypots.render_cell(inventory, cell)
    tampered = copy.deepcopy(clean)
    tampered["services"]["cowrie"]["volumes"][0]["source"] = str(
        (tmp_path / "outside.cfg").resolve())
    (tmp_path / "outside.cfg").write_text("outside\n")
    with pytest.raises(honeypots.HoneypotError):
        honeypots.assert_safe(tampered, cell)


def test_assert_safe_rejects_a_symlink_config_bind(tmp_path):
    inventory, cell = render_cell_objects()
    clean = honeypots.render_cell(inventory, cell)
    context = (tmp_path / "context").resolve()
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\n")
    outside = tmp_path / "outside.cfg"
    outside.write_text("outside\n")
    (context / "cowrie.cfg").symlink_to(outside)
    tampered = copy.deepcopy(clean)
    service = tampered["services"]["cowrie"]
    service["build"]["context"] = str(context)
    service["volumes"][0]["source"] = str(context / "cowrie.cfg")
    with pytest.raises(honeypots.HoneypotError):
        honeypots.assert_safe(tampered, cell)


def test_logs_are_mounted_per_cell_and_inside_declared_volumes():
    inventory = honeypots.load_inventory(INVENTORY)
    cell = honeypots.load_cell(PROFILE, inventory)
    _, document = rendered()
    for name, engine in inventory.engines.items():
        writable = [mount for mount in document["services"][name]["volumes"]
                    if not mount["read_only"]]
        assert any(engine.log_path.startswith(mount["target"] + "/") for mount in writable)
        assert all(mount["source"].startswith(cell.data_dir(name, "")) for mount in writable)


def test_render_is_deterministic_and_round_trips_through_yaml():
    inventory, cell = render_cell_objects()
    first = honeypots.dump_cell(inventory, cell)
    second = honeypots.dump_cell(inventory, cell)
    assert first == second
    assert yaml.safe_load(first) == honeypots.render_cell(inventory, cell)


def render_cell_objects():
    inventory = honeypots.load_inventory(INVENTORY)
    cell = honeypots.Cell.from_mapping(raw_profile())
    return inventory, cell


def synthetic_local_digests():
    """Synthetic per-engine digests; no real image was built or pulled."""
    data = raw_inventory()
    for engine in data["engines"]:
        engine["image"]["local_digest"] = "sha256:" + hashlib.sha256(
            engine["id"].encode("ascii")
        ).hexdigest()
    return data


def digest_cell_objects():
    inventory = honeypots.Inventory.from_mapping(
        synthetic_local_digests(), INVENTORY.parent)
    cell = honeypots.Cell.from_mapping(
        {**raw_profile(), "image_policy": "digest-required"})
    return inventory, cell


def test_digest_policy_renders_immutable_image_references():
    inventory, cell = digest_cell_objects()
    document = honeypots.render_cell(inventory, cell)
    assert document["services"]
    for name, service in document["services"].items():
        engine = inventory.engine(name)
        assert service["image"] == f"dystopia/honeypot-{name}@{engine.local_digest}"
        assert ":" not in service["image"].split("@", 1)[0].rsplit("/", 1)[1]
        assert service["labels"]["dystopia.image-policy"] == "digest-required"


def test_digest_policy_fails_closed_without_a_reviewed_local_digest():
    inventory = honeypots.load_inventory(INVENTORY)
    cell = honeypots.Cell.from_mapping(
        {**raw_profile(), "image_policy": "digest-required"})
    with pytest.raises(honeypots.HoneypotError):
        honeypots.render_cell(inventory, cell)


def test_tag_lab_policy_is_explicitly_non_productive():
    _, document = rendered()
    for service in document["services"].values():
        assert service["labels"]["dystopia.image-policy"] == "tag-lab-only"
        assert "@sha256:" not in service["image"]
    report = honeypots.validate(INVENTORY, PROFILE)
    assert report["image_policy"] == "tag-lab-only"
    assert report["mutable_images"]
    assert any("lab-only" in warning for warning in report["warnings"])


def test_assert_safe_rejects_a_mutable_tag_in_a_digest_cell():
    inventory, cell = digest_cell_objects()
    clean = honeypots.render_cell(inventory, cell)
    tampered = copy.deepcopy(clean)
    tampered["services"]["cowrie"]["image"] = "dystopia/honeypot-cowrie:3.1.4"
    with pytest.raises(honeypots.HoneypotError):
        honeypots.assert_safe(tampered, cell)


def test_assert_safe_rejects_a_digest_document_relabelled_as_tag_lab():
    inventory, cell = digest_cell_objects()
    clean = honeypots.render_cell(inventory, cell)
    tampered = copy.deepcopy(clean)
    tampered["services"]["cowrie"]["labels"]["dystopia.image-policy"] = "tag-lab-only"
    with pytest.raises(honeypots.HoneypotError):
        honeypots.assert_safe(tampered, cell)


@pytest.mark.parametrize("security_opt", [
    None,
    [],
    ["no-new-privileges:false"],
    ["no-new-privileges:true", "seccomp=unconfined"],
    ["no-new-privileges:true", "no-new-privileges:true"],
])
def test_assert_safe_requires_exactly_no_new_privileges(security_opt):
    inventory, cell = render_cell_objects()
    clean = honeypots.render_cell(inventory, cell)
    tampered = copy.deepcopy(clean)
    service = tampered["services"]["cowrie"]
    if security_opt is None:
        service.pop("security_opt")
    else:
        service["security_opt"] = security_opt
    with pytest.raises(honeypots.HoneypotError):
        honeypots.assert_safe(tampered, cell)


def test_capability_engines_keep_no_new_privileges():
    inventory, cell = render_cell_objects()
    document = honeypots.render_cell(inventory, cell)
    for name, service in document["services"].items():
        if inventory.engine(name).capabilities:
            assert service["cap_add"] == list(inventory.engine(name).capabilities)
            assert service["security_opt"] == ["no-new-privileges:true"]


@pytest.mark.parametrize("digest", [
    "sha256:" + "0" * 64,
    "not-a-digest",
    "sha256:" + "a" * 63,
    123,
])
def test_invalid_local_digest_is_rejected(digest):
    data = raw_inventory()
    data["engines"][0]["image"]["local_digest"] = digest
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(data, INVENTORY.parent)


def test_projects_and_networks_are_unique_per_cell():
    _, one = rendered(1)
    _, two = rendered(2)
    assert one["name"] != two["name"]
    assert not set(one["networks"]) & set(two["networks"])
    assert not ({s["container_name"] for s in one["services"].values()}
                & {s["container_name"] for s in two["services"].values()})


def test_loopback_lab_publishes_only_high_ports_on_loopback():
    profile = raw_profile()
    profile["mode"] = "loopback-lab"
    profile["publish"] = {"cowrie": [{"container": 2222, "proto": "tcp", "host": 12222}]}
    inventory = honeypots.load_inventory(INVENTORY)
    cell = honeypots.Cell.from_mapping(profile)
    document = honeypots.render_cell(inventory, cell)
    assert document["services"]["cowrie"]["ports"] == ["127.0.0.1:12222:2222/tcp"]
    assert "ports" not in document["services"]["endlessh"]
    report = honeypots.validate(INVENTORY, PROFILE)
    assert report["published_ports"] == []


@pytest.mark.parametrize("change", [
    {"mode": "host"},
    {"cell": 0},
    {"cell": 255},
    {"cell": True},
    {"engines": []},
    {"engines": ["cowrie", "cowrie"]},
    {"engines": ["cowrie", "nmap"]},
    {"data_root": "/etc/dystopia"},
    {"data_root": "relative/path"},
    {"data_root": "/var/lib/dystopia/../etc"},
    {"publish": {"cowrie": [{"container": 2222, "proto": "tcp", "host": 22}]}},
])
def test_invalid_cell_profiles_are_rejected(change):
    profile = {**raw_profile(), **change}
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Cell.from_mapping(profile)


def test_internal_mode_rejects_published_ports_and_unknown_engines():
    profile = raw_profile()
    profile["mode"] = "internal"
    profile["publish"] = {"cowrie": [{"container": 2222, "proto": "tcp", "host": 12222}]}
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Cell.from_mapping(profile)
    profile = raw_profile()
    profile["engines"] = ["cowrie", "cowrie", "nmap"]
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Cell.from_mapping(profile)
    profile = raw_profile()
    profile["containment"] = "verified"
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Cell.from_mapping(profile)


def test_published_container_port_must_exist_in_the_inventory():
    profile = raw_profile()
    profile["mode"] = "loopback-lab"
    profile["publish"] = {"cowrie": [{"container": 6379, "proto": "tcp", "host": 12379}]}
    inventory = honeypots.load_inventory(INVENTORY)
    cell = honeypots.Cell.from_mapping(profile)
    with pytest.raises(honeypots.HoneypotError):
        cell.check_ports(inventory)


@pytest.mark.parametrize("change", [
    {"image": "dystopia/honeypot-cowrie:latest"},
    {"image": "cowrie/cowrie:3.1.4"},
    {"image": "dystopia/honeypot-cowrie"},
    {"base_digest": "sha256:" + "0" * 64},
    {"base_digest": "not-a-digest"},
    {"user": "0:0"},
    {"user": "root"},
    {"ports": [{"container": 2222, "proto": "tcp", "purpose": "ssh"},
               {"container": 2222, "proto": "tcp", "purpose": "again"}]},
    {"ports": [{"container": 0, "proto": "tcp", "purpose": "ssh"}]},
    {"ports": [{"container": 2222, "proto": "icmp", "purpose": "ssh"}]},
])
def test_unsafe_engine_settings_are_rejected(change):
    inventory = raw_inventory()
    inventory["engines"][0] = {**inventory["engines"][0], **change}
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)


@pytest.mark.parametrize("change", [
    {"mem_limit": "512"},
    {"mem_limit": "99999m"},
    {"cpus": 0},
    {"cpus": 8.0},
    {"cpus": 0.123},
    {"pids_limit": 0},
    {"nofile": 8},
    {"tmpfs_mib": 1},
])
def test_invalid_resource_limits_are_rejected(change):
    inventory = raw_inventory()
    inventory["engines"][0]["resources"] = {**inventory["engines"][0]["resources"], **change}
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)


def test_docker_socket_host_namespace_and_host_network_are_rejected():
    inventory = raw_inventory()
    inventory["engines"][0]["volumes"] = ["/var/run/docker.sock:/var/run/docker.sock"]
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)
    inventory = raw_inventory()
    inventory["network"]["host_network"] = True
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)
    inventory = raw_inventory()
    inventory["network"]["publish_ports"] = True
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)
    inventory = raw_inventory()
    inventory["engines"][0]["capabilities_add"] = ["SYS_ADMIN"]
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)
    inventory = raw_inventory()
    inventory["engines"][0]["config"]["target"] = "/proc/1/environ"
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)


def test_inventory_totals_must_match_engine_sums():
    inventory = raw_inventory()
    inventory["totals"]["mem_limit"] = "4096m"
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)


def test_activation_metadata_cannot_be_flipped_in_the_inventory():
    inventory = raw_inventory()
    inventory["status"] = "ready"
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)
    inventory = raw_inventory()
    inventory["activation"] = "allowed"
    with pytest.raises(honeypots.HoneypotError):
        honeypots.Inventory.from_mapping(inventory, INVENTORY.parent)


def test_duplicate_yaml_keys_and_aliases_are_rejected(tmp_path):
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("schema: dystopia.honeypots.cell/v1\ncell: 1\ncell: 2\n")
    with pytest.raises(honeypots.HoneypotError):
        honeypots._load_yaml(duplicate, honeypots.PROFILE_LIMIT)
    alias = tmp_path / "alias.yaml"
    alias.write_text("schema: &s dystopia.honeypots.cell/v1\nother: *s\n")
    with pytest.raises(honeypots.HoneypotError):
        honeypots._load_yaml(alias, honeypots.PROFILE_LIMIT)


def test_assert_safe_rejects_rendered_document_tampering():
    inventory, cell = render_cell_objects()
    clean = honeypots.render_cell(inventory, cell)
    assert honeypots.assert_safe(clean, cell) is True
    for mutate in (
        lambda doc: doc["services"]["cowrie"].__setitem__("network_mode", "host"),
        lambda doc: doc["services"]["cowrie"].__setitem__("privileged", True),
        lambda doc: doc["services"]["cowrie"].__setitem__("read_only", False),
        lambda doc: doc["services"]["cowrie"].__setitem__("image", "dystopia/honeypot-cowrie:latest"),
        lambda doc: doc["services"]["cowrie"].__setitem__("ports", ["0.0.0.0:2222:2222/tcp"]),
        lambda doc: doc["services"]["cowrie"].__setitem__("cap_add", ["SYS_ADMIN"]),
        lambda doc: doc["services"]["cowrie"].__setitem__("restart", "always"),
        lambda doc: doc["networks"].__setitem__("dyhp1-cowrie", {"driver": "bridge",
                                                                 "internal": False}),
        lambda doc: doc.__setitem__("name", "dystopia-honeypot-cell-2"),
    ):
        tampered = copy.deepcopy(clean)
        mutate(tampered)
        with pytest.raises(honeypots.HoneypotError):
            honeypots.assert_safe(tampered, cell)


def test_validate_and_plan_never_claim_activation_or_containment():
    report = honeypots.validate(INVENTORY, PROFILE)
    assert report["activation_allowed"] is False
    assert report["containment_verified"] is False
    assert report["published_ports"] == []
    assert report["memory_mib"] == 2304
    assert report["cpus"] == 2.6
    assert report["pids_limit"] == 1344
    plan = honeypots.plan(INVENTORY, PROFILE)
    assert plan["dry_run"] is True
    assert plan["host_operations"] == []
    assert plan["activation_allowed"] is False
    assert any("containment" in item for item in plan["requires"])
    assert len(plan["data_directories"]) == len(honeypots.ENGINES)


@pytest.mark.parametrize("action", honeypots.BLOCKED_ACTIONS)
def test_activation_actions_are_permanently_blocked(action):
    with pytest.raises(honeypots.HoneypotBlocked) as raised:
        honeypots.blocked(action)
    assert "internal:true is not containment" in str(raised.value)
    with pytest.raises(honeypots.HoneypotError):
        honeypots.blocked("start")


def test_cli_blocks_apply_up_and_down_with_explicit_error(capsys):
    for action in honeypots.BLOCKED_ACTIONS:
        assert main(["honeypots", action]) == 2
        captured = capsys.readouterr()
        payload = json.loads(captured.err)
        assert payload["state"] == "blocked"
        assert payload["containment_verified"] is False
        assert "no Linux containment verification exists" in payload["detail"]
        assert captured.out == ""


def test_cli_render_writes_yaml_and_cli_validate_prints_report(tmp_path, capsys):
    output = tmp_path / "cell-1.yaml"
    assert main(["honeypots", "render", "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["containment_verified"] is False
    document = yaml.safe_load(output.read_text())
    assert document["name"] == "dystopia-honeypot-cell-1"
    assert all("ports" not in service for service in document["services"].values())

    assert main(["honeypots", "validate"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["activation_allowed"] is False
    assert report["cell"] == 1

    assert main(["honeypots", "plan"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["host_operations"] == []


def test_cli_render_to_stdout_is_valid_compose_yaml(capsys):
    assert main(["honeypots", "render"]) == 0
    document = yaml.safe_load(capsys.readouterr().out)
    assert set(document) == {"name", "services", "networks"}
    assert len(document["services"]) == 6


def test_cli_rejects_unknown_or_unsafe_profiles(tmp_path, capsys):
    profile = tmp_path / "cell.yaml"
    profile.write_text(PROFILE.read_text().replace("mode: internal", "mode: host"))
    with pytest.raises(SystemExit):
        main(["honeypots", "validate", "--profile", str(profile)])
    assert "cell mode" in capsys.readouterr().err


def test_docker_compose_accepts_the_rendered_document(tmp_path):
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("docker is not installed")
    inventory, cell = render_cell_objects()
    path = tmp_path / "compose.yaml"
    path.write_text(honeypots.dump_cell(inventory, cell))
    result = subprocess.run(
        [docker, "compose", "-f", str(path), "--profile", honeypots.ACTIVATION_PROFILE,
         "config", "--quiet"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0 and "Cannot connect to the Docker daemon" in result.stderr:
        pytest.skip("docker daemon unavailable")
    assert result.returncode == 0, result.stderr
    assert "ports:" not in path.read_text()
