"""Declarative, read-only orchestration for one honeypot cell.

This module loads the reviewed inventory (``deploy/honeypots/inventory.yaml``)
and a per-cell profile, validates both strictly, and renders a Compose document
for exactly one cell. It never invokes Docker, never starts or stops a
container, never creates a network and never changes host networking.

``apply``/``up``/``down`` are blocked unconditionally: a well-formed Compose
file or an ``internal: true`` Docker network is not containment evidence. Real
containment needs an independently verified Linux boundary (network namespace,
nftables cell policy, cgroup limits, userns/rootless runtime and log quotas).
"""
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import MappingProxyType
from typing import NoReturn
import os
import re
import stat

import yaml

SCHEMA_INVENTORY = "dystopia.honeypots/v1"
SCHEMA_CELL = "dystopia.honeypots.cell/v1"
ENGINES = ("cowrie", "opencanary", "dionaea", "heralding", "redishoneypot", "endlessh")
MODES = ("internal", "loopback-lab")
IMAGE_POLICIES = ("digest-required", "tag-lab-only")
ACTIVATION_PROFILE = "authorized-activation"
BLOCKED_ACTIONS = ("apply", "up", "down")
ALLOWED_CAPABILITIES = frozenset({"NET_BIND_SERVICE"})
REQUIRED_SECURITY_OPT = ("no-new-privileges:true",)
FORBIDDEN_TARGET_PREFIXES = ("/proc", "/sys", "/dev", "/var/run/docker.sock")
INVENTORY_LIMIT = 256 * 1024
PROFILE_LIMIT = 64 * 1024

_IMAGE = re.compile(
    r"[a-z0-9][a-z0-9._-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*:"
    r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}\Z"
)
_PINNED_IMAGE = re.compile(
    r"[a-z0-9][a-z0-9._-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*"
    r"@sha256:[0-9a-f]{64}\Z"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{7,40}\Z")
_USER = re.compile(r"([0-9]{1,5}):([0-9]{1,5})\Z")
_MEM = re.compile(r"([1-9][0-9]{0,4})m\Z")
_DURATION = re.compile(r"([1-9][0-9]{0,3})s\Z")
_MARKER = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_PURPOSE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
_RELATIVE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
_CONTEXT = re.compile(r"(?:\.\./)*[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
_HOST_PATH = re.compile(r"(/[A-Za-z0-9._-]+)+\Z")


class HoneypotError(ValueError):
    """Invalid inventory, profile or rendered document."""


class HoneypotBlocked(RuntimeError):
    """An activation action was requested; only Linux verification can lift it."""


def _fail(message) -> NoReturn:
    raise HoneypotError(message)


def _mapping(value, label, required, optional=()):
    if type(value) is not dict:
        _fail(f"{label} must be a mapping")
    allowed, keys = set(required) | set(optional), set(required)
    missing, unknown = sorted(keys - set(value)), sorted(set(value) - allowed)
    if missing or unknown:
        _fail(f"{label} has missing keys {missing} or unknown keys {unknown}")
    return value


def _sequence(value, label, minimum=0, maximum=64):
    if type(value) is not list or not minimum <= len(value) <= maximum:
        _fail(f"{label} must be a list of {minimum}..{maximum} entries")
    return tuple(value)


def _integer(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        _fail(f"{label} must be an integer in {low}..{high}")
    return value


def _text(value, label, maximum=512, pattern=None):
    if type(value) is not str or not 1 <= len(value) <= maximum:
        _fail(f"{label} must be a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        _fail(f"{label} has an unsupported format")
    return value


def _host_path(value, label, absolute=True):
    _text(value, label, maximum=256)
    if any(ord(char) < 0x20 or char in ",:\"'\\" for char in value):
        _fail(f"{label} contains unsupported characters")
    if ".." in value.split("/"):
        _fail(f"{label} must not contain '..'")
    if absolute and (not value.startswith("/") or _HOST_PATH.fullmatch(value) is None):
        _fail(f"{label} must be a canonical absolute path")
    if value.startswith(FORBIDDEN_TARGET_PREFIXES):
        _fail(f"{label} points at a host namespace or the Docker socket")
    return value


class _Loader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys and aliases fail-closed."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise HoneypotError("YAML aliases are not accepted")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError:
                raise HoneypotError("YAML mapping keys must be scalar") from None
            if duplicate:
                raise HoneypotError(f"duplicate YAML key: {key!r}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _load_yaml(path, limit):
    stream = Path(path)
    if stream.is_symlink() or not stream.is_file():
        raise HoneypotError(f"missing regular file: {stream}")
    raw = stream.read_bytes()
    if len(raw) > limit:
        raise HoneypotError(f"{stream.name} exceeds {limit} bytes")
    try:
        return yaml.load(raw, Loader=_Loader)
    except HoneypotError:
        raise
    except yaml.YAMLError as exc:
        raise HoneypotError(f"invalid YAML in {stream.name}") from exc


def _reviewed_context(context, repository=None):
    """Resolve a build context and require a real directory inside the repo."""
    context = Path(context)
    try:
        info = context.lstat()
    except OSError as exc:
        raise HoneypotError(f"missing build context: {context}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise HoneypotError(f"build context must be a real directory: {context}")
    resolved = context.resolve()
    if repository is not None \
            and not resolved.is_relative_to(Path(repository).resolve()):
        raise HoneypotError("build context must stay inside the repository")
    return resolved


def _reviewed_file(context, name, label):
    """Open a context file without symlinks and prove it stays in the context."""
    context = _reviewed_context(context)
    if Path(name).name != name or name in (".", ".."):
        raise HoneypotError(f"{label} must be a direct file name: {name}")
    leaf = context / name
    try:
        info = leaf.lstat()
    except OSError as exc:
        raise HoneypotError(f"missing reviewed {label}: {leaf}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise HoneypotError(f"reviewed {label} must be a regular non-symlink "
                            f"file: {leaf}")
    try:
        descriptor = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise HoneypotError(f"reviewed {label} cannot be opened safely: "
                            f"{leaf}") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise HoneypotError(f"reviewed {label} must be a regular file: {leaf}")
    finally:
        os.close(descriptor)
    resolved = leaf.resolve()
    if not resolved.is_relative_to(context):
        raise HoneypotError(f"reviewed {label} escapes its build context: {leaf}")
    return resolved


def _reviewed_absolute_file(source, context):
    """Re-check an already absolute bind source against a reviewed context."""
    source = Path(source)
    if not source.is_absolute():
        raise HoneypotError(f"reviewed bind source must be absolute: {source}")
    context = _reviewed_context(context)
    try:
        info = source.lstat()
    except OSError as exc:
        raise HoneypotError(f"missing reviewed bind source: {source}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise HoneypotError(f"reviewed bind source must be a regular non-symlink "
                            f"file: {source}")
    resolved = source.resolve()
    if not resolved.is_relative_to(context):
        raise HoneypotError(f"reviewed bind source escapes its build context: "
                            f"{source}")
    return resolved


@dataclass(frozen=True)
class Port:
    container: int
    proto: str
    purpose: str

    def __post_init__(self):
        _integer(self.container, "port", 1, 65535)
        if self.proto not in ("tcp", "udp"):
            _fail("port protocol must be tcp or udp")
        _text(self.purpose, "port purpose", maximum=32, pattern=_PURPOSE)

    @property
    def expose(self):
        return f"{self.container}/{self.proto}"

    @classmethod
    def from_mapping(cls, value, label="port"):
        data = _mapping(value, label, {"container", "proto", "purpose"})
        return cls(container=data["container"], proto=data["proto"], purpose=data["purpose"])


@dataclass(frozen=True)
class Resources:
    mem_mib: int
    cpus: float
    pids: int
    nofile: int
    tmpfs_mib: int

    def __post_init__(self):
        _integer(self.mem_mib, "mem_limit", 16, 4096)
        _integer(self.pids, "pids_limit", 16, 4096)
        _integer(self.nofile, "nofile", 64, 65536)
        _integer(self.tmpfs_mib, "tmpfs_mib", 8, 256)
        if type(self.cpus) is not float or not 0.05 <= self.cpus <= 4.0:
            _fail("cpus must be one decimal number in 0.05..4.0")
        try:
            exponent = int(Decimal(str(self.cpus)).as_tuple().exponent)
        except (InvalidOperation, TypeError, ValueError):
            _fail("cpus must be a decimal number")
        if exponent < -2:
            _fail("cpus supports at most two decimals")

    @classmethod
    def from_mapping(cls, value, label="resources"):
        data = _mapping(value, label, {"mem_limit", "cpus", "pids_limit", "nofile", "tmpfs_mib"})
        match = _MEM.fullmatch(data["mem_limit"]) if type(data["mem_limit"]) is str else None
        if match is None:
            _fail("mem_limit must use an explicit MiB suffix, e.g. 512m")
        cpus = data["cpus"]
        if type(cpus) is int:
            cpus = float(cpus)
        return cls(mem_mib=int(match.group(1)), cpus=cpus, pids=data["pids_limit"],
                   nofile=data["nofile"], tmpfs_mib=data["tmpfs_mib"])


@dataclass(frozen=True)
class Healthcheck:
    marker: str
    interval: str
    start_period: str

    def __post_init__(self):
        _text(self.marker, "healthcheck marker", maximum=64, pattern=_MARKER)
        for value, label, high in ((self.interval, "interval", 600),
                                   (self.start_period, "start_period", 600)):
            match = _DURATION.fullmatch(value) if type(value) is str else None
            if match is None or not 5 <= int(match.group(1)) <= high:
                _fail(f"healthcheck {label} must be seconds in 5..{high}")

    @classmethod
    def from_mapping(cls, value, label="healthcheck"):
        data = _mapping(value, label, {"type", "marker", "interval", "start_period"})
        if data["type"] != "process":
            _fail("only process healthchecks are supported")
        return cls(marker=data["marker"], interval=data["interval"],
                   start_period=data["start_period"])


@dataclass(frozen=True)
class Engine:
    name: str
    description: str
    device_id: str
    context: str
    dockerfile: str
    image: str
    base_digest: str
    local_digest: str | None
    upstream_commit: str
    user: str
    config_file: str
    config_target: str
    ports: tuple[Port, ...]
    log_path: str
    log_format: str
    fixture: str
    secondary_paths: tuple[str, ...]
    volumes: tuple[tuple[str, str], ...]
    healthcheck: Healthcheck
    resources: Resources
    capabilities: tuple[str, ...]

    def __post_init__(self):
        if self.name not in ENGINES:
            _fail("unsupported honeypot engine")
        _text(self.description, "engine description", maximum=200)
        _text(self.device_id, "device_id", maximum=64, pattern=_PURPOSE)
        _text(self.context, "build context", maximum=200, pattern=_CONTEXT)
        if self.context.startswith("/") or self.context.split("/")[-1] == "..":
            _fail("build context must be a relative directory")
        _text(self.dockerfile, "dockerfile", maximum=64, pattern=_RELATIVE)
        if "/" in self.dockerfile:
            _fail("dockerfile must be a direct file name")
        if type(self.image) is not str or _IMAGE.fullmatch(self.image) is None:
            _fail("image must be a tagged local dystopia/honeypot-* reference")
        if not self.image.startswith("dystopia/honeypot-"):
            _fail("image must use the reviewed dystopia/honeypot-* namespace")
        if self.image.rsplit(":", 1)[1].lower() in ("latest", "stable", "main", "edge"):
            _fail("floating image tags are forbidden")
        if type(self.base_digest) is not str or _DIGEST.fullmatch(self.base_digest) is None \
                or self.base_digest == "sha256:" + "0" * 64:
            _fail("base_digest must be a real sha256 digest")
        if self.local_digest is not None:
            if type(self.local_digest) is not str or _DIGEST.fullmatch(self.local_digest) is None \
                    or self.local_digest == "sha256:" + "0" * 64:
                _fail("local_digest must be a real sha256 digest")
            if self.local_digest == self.base_digest:
                _fail("local_digest must be the built image digest, not the base digest")
        if type(self.upstream_commit) is not str or _COMMIT.fullmatch(self.upstream_commit) is None:
            _fail("upstream_commit must be a hexadecimal commit")
        match = _USER.fullmatch(self.user) if type(self.user) is str else None
        if match is None or int(match.group(1)) == 0 or int(match.group(2)) == 0:
            _fail("engines must run as a non-root numeric uid:gid")
        _text(self.config_file, "config file", maximum=128, pattern=_RELATIVE)
        if "/" in self.config_file or ".." in self.config_file:
            _fail("config file must be a direct file name")
        _host_path(self.config_target, "config target")
        if type(self.ports) is not tuple or not 1 <= len(self.ports) <= 32 \
                or any(type(port) is not Port for port in self.ports):
            _fail("one to thirty-two immutable ports required")
        if len({(port.container, port.proto) for port in self.ports}) != len(self.ports):
            _fail("duplicate port")
        if len({port.purpose for port in self.ports}) != len(self.ports):
            _fail("duplicate port purpose")
        _host_path(self.log_path, "log path")
        if self.log_format not in ("jsonl", "text"):
            _fail("log format must be jsonl or text")
        _text(self.fixture, "fixture", maximum=128, pattern=_RELATIVE)
        if not self.fixture.startswith("fixtures/") or ".." in self.fixture.split("/"):
            _fail("fixture must live under fixtures/")
        if type(self.secondary_paths) is not tuple \
                or any(type(item) is not str for item in self.secondary_paths):
            _fail("secondary log paths must be strings")
        for secondary in self.secondary_paths:
            _host_path(secondary, "secondary log path")
        if type(self.volumes) is not tuple or not 1 <= len(self.volumes) <= 8:
            _fail("one to eight log volumes required")
        for source, target in self.volumes:
            if type(source) is not str or _RELATIVE.fullmatch(source) is None \
                    or ".." in source.split("/") or source.startswith("/"):
                _fail("volume source must be a relative path inside the cell root")
            _host_path(target, "volume target")
        if len({target for _, target in self.volumes}) != len(self.volumes):
            _fail("duplicate volume target")
        if not any(self._inside(self.log_path, target) for _, target in self.volumes):
            _fail("log path must live inside a declared log volume")
        if any(not any(self._inside(path, target) for _, target in self.volumes)
               for path in self.secondary_paths):
            _fail("secondary log paths must live inside a declared log volume")
        if self.config_target == self.log_path or self.config_target in self.secondary_paths:
            _fail("config target must not be a log file")
        if any(self._inside(self.config_target, target) for _, target in self.volumes):
            _fail("config target must not be nested in a writable log volume")
        if type(self.healthcheck) is not Healthcheck or type(self.resources) is not Resources:
            _fail("immutable healthcheck and resources required")
        if type(self.capabilities) is not tuple \
                or any(capability not in ALLOWED_CAPABILITIES for capability in self.capabilities):
            _fail("only NET_BIND_SERVICE is an accepted capability")
        if len(set(self.capabilities)) != len(self.capabilities):
            _fail("duplicate capability")

    @staticmethod
    def _inside(path, root):
        return path == root or path.startswith(root.rstrip("/") + "/")

    @property
    def image_repository(self):
        """Reviewed ``dystopia/honeypot-*`` repository without the mutable tag."""
        return self.image.rsplit(":", 1)[0]

    @property
    def pinned_reference(self):
        """Immutable reference used for digest-required renders (RT-10)."""
        if self.local_digest is None:
            _fail(f"{self.name} has no reviewed local image digest")
        return f"{self.image_repository}@{self.local_digest}"

    @classmethod
    def from_mapping(cls, value):
        data = _mapping(value, "engine", {
            "id", "description", "device_id", "build", "image", "config", "user",
            "ports", "logs", "volumes", "healthcheck", "resources",
        }, {"capabilities_add"})
        build = _mapping(data["build"], "build", {"context", "dockerfile"})
        image = _mapping(data["image"], "image",
                         {"local_image", "base_reference", "base_digest", "upstream_commit"},
                         {"package", "local_digest"})
        config = _mapping(data["config"], "config", {"file", "target"})
        logs = _mapping(data["logs"], "logs", {"path", "format", "fixture"}, {"secondary_paths"})
        volumes = []
        for entry in _sequence(data["volumes"], "volumes", 1, 8):
            if type(entry) is not str or entry.count(":") != 1:
                _fail("volume entries must be source:target")
            source, target = entry.split(":")
            volumes.append((source, target))
        return cls(
            name=data["id"], description=data["description"], device_id=data["device_id"],
            context=build["context"], dockerfile=build["dockerfile"],
            image=image["local_image"], base_digest=image["base_digest"],
            local_digest=image.get("local_digest"),
            upstream_commit=image["upstream_commit"], user=data["user"],
            config_file=config["file"], config_target=config["target"],
            ports=tuple(Port.from_mapping(item, "port")
                        for item in _sequence(data["ports"], "ports", 1, 32)),
            log_path=logs["path"], log_format=logs["format"], fixture=logs["fixture"],
            secondary_paths=tuple(logs.get("secondary_paths", ())),
            volumes=tuple(volumes),
            healthcheck=Healthcheck.from_mapping(data["healthcheck"]),
            resources=Resources.from_mapping(data["resources"]),
            capabilities=tuple(data.get("capabilities_add", ())),
        )


@dataclass(frozen=True)
class Inventory:
    revision: str
    host_root: str
    engines: Mapping[str, Engine]
    base: Path

    def engine(self, name):
        try:
            return self.engines[name]
        except KeyError:
            raise HoneypotError(f"engine {name!r} is not in the inventory") from None

    @classmethod
    def from_mapping(cls, value, base):
        data = _mapping(value, "inventory", {
            "schema", "revision", "status", "activation", "network", "storage",
            "engines", "totals",
        })
        if data["schema"] != SCHEMA_INVENTORY:
            _fail("unsupported inventory schema")
        if data["status"] != "static-reference-only":
            _fail("inventory status must remain static-reference-only")
        if data["activation"] != "requires-separate-authorization":
            _fail("inventory activation must require separate authorization")
        _text(data["revision"], "revision", maximum=32)
        network = _mapping(data["network"], "network", {
            "topology", "networks", "driver", "internal", "host_network",
            "publish_ports", "note",
        })
        if network["internal"] is not True or network["host_network"] is not False \
                or network["publish_ports"] is not False:
            _fail("inventory network must stay internal without host networking or published ports")
        if network["driver"] != "bridge":
            _fail("inventory network driver must be bridge")
        storage = _mapping(data["storage"], "storage", {"host_root", "note"})
        host_root = _host_path(storage["host_root"], "storage.host_root")
        if not host_root.startswith("/var/lib/dystopia/"):
            _fail("storage.host_root must live under /var/lib/dystopia")
        engines = {}
        for entry in _sequence(data["engines"], "engines", 1, len(ENGINES)):
            engine = Engine.from_mapping(entry)
            if engine.name in engines:
                _fail(f"duplicate engine: {engine.name}")
            engines[engine.name] = engine
        if len({engine.image for engine in engines.values()}) != len(engines):
            _fail("duplicate engine image")
        totals = _mapping(data["totals"], "totals",
                          {"mem_limit", "cpus", "pids_limit", "recommendation"})
        match = _MEM.fullmatch(totals["mem_limit"]) if type(totals["mem_limit"]) is str else None
        if match is None or int(match.group(1)) != sum(engine.resources.mem_mib for engine in engines.values()):
            _fail("totals.mem_limit must equal the sum of engine limits")
        if type(totals["cpus"]) is not float \
                or abs(totals["cpus"] - sum(engine.resources.cpus for engine in engines.values())) > 1e-9:
            _fail("totals.cpus must equal the sum of engine limits")
        if totals["pids_limit"] != sum(engine.resources.pids for engine in engines.values()):
            _fail("totals.pids_limit must equal the sum of engine limits")
        return cls(revision=data["revision"], host_root=host_root,
                   engines=MappingProxyType(engines), base=Path(base))


@dataclass(frozen=True)
class Publication:
    container: int
    proto: str
    host: int

    def __post_init__(self):
        _integer(self.container, "published container port", 1, 65535)
        _integer(self.host, "published host port", 1024, 65535)
        if self.proto not in ("tcp", "udp"):
            _fail("published protocol must be tcp or udp")

    @property
    def mapping(self):
        return f"127.0.0.1:{self.host}:{self.container}/{self.proto}"


@dataclass(frozen=True)
class Cell:
    cell: int
    mode: str
    data_root: str
    engines: tuple[str, ...]
    publish: Mapping[str, tuple[Publication, ...]]
    # RT-10: digest-required is the fail-closed default. ``tag-lab-only`` must
    # be declared explicitly and renders a visibly non-production document.
    image_policy: str = "digest-required"

    def __post_init__(self):
        _integer(self.cell, "cell", 1, 254)
        if self.mode not in MODES:
            _fail("cell mode must be internal or loopback-lab")
        if self.image_policy not in IMAGE_POLICIES:
            _fail("cell image_policy must be digest-required or tag-lab-only")
        _host_path(self.data_root, "data_root")
        if not self.data_root.startswith("/var/lib/dystopia/"):
            _fail("data_root must live under /var/lib/dystopia")
        if type(self.engines) is not tuple or not 1 <= len(self.engines) <= len(ENGINES):
            _fail("one to six engines required")
        if len(set(self.engines)) != len(self.engines):
            _fail("duplicate engine in cell")
        if any(engine not in ENGINES for engine in self.engines):
            _fail("unsupported engine in cell")
        if self.mode == "internal" and self.publish:
            _fail("published ports require the explicit loopback-lab mode")
        if type(self.publish) is not MappingProxyType:
            _fail("publish must be an immutable mapping")
        host_ports = []
        for engine, publications in self.publish.items():
            if engine not in self.engines:
                _fail("publish references an engine outside the cell")
            if type(publications) is not tuple or not publications \
                    or any(type(item) is not Publication for item in publications):
                _fail("publish entries must be immutable publications")
            host_ports.extend(item.host for item in publications)
        if len(set(host_ports)) != len(host_ports):
            _fail("duplicate host port")

    @property
    def project(self):
        return f"dystopia-honeypot-cell-{self.cell}"

    @property
    def network_prefix(self):
        return f"dyhp{self.cell}"

    def network(self, engine):
        return f"{self.network_prefix}-{engine}"

    def container(self, engine):
        return f"dystopia-hp-c{self.cell}-{engine}"

    def data_dir(self, engine, source):
        return f"{self.data_root}/cells/{self.cell}/{source}"

    def check_ports(self, inventory):
        for engine, publications in self.publish.items():
            supported = {(port.container, port.proto) for port in inventory.engine(engine).ports}
            if any((item.container, item.proto) not in supported for item in publications):
                _fail(f"published port is not declared by {engine}")

    @classmethod
    def from_mapping(cls, value):
        data = _mapping(value, "cell profile",
                        {"schema", "cell", "mode", "data_root", "engines"},
                        {"publish", "image_policy"})
        if data["schema"] != SCHEMA_CELL:
            _fail("unsupported cell profile schema")
        engines = _sequence(data["engines"], "engines", 1, len(ENGINES))
        if any(type(engine) is not str for engine in engines):
            _fail("engine names must be strings")
        raw_publish = data.get("publish", {}) or {}
        if type(raw_publish) is not dict:
            _fail("publish must be a mapping of engine to port list")
        publish = {}
        for engine, entries in raw_publish.items():
            if type(engine) is not str:
                _fail("publish keys must be engine names")
            parsed = []
            for entry in _sequence(entries, "publish", 1, 32):
                item = _mapping(entry, "publish entry", {"container", "proto", "host"})
                parsed.append(Publication(container=item["container"],
                                          proto=item["proto"], host=item["host"]))
            if len({(item.container, item.proto) for item in parsed}) != len(parsed):
                _fail("duplicate published container port")
            publish[engine] = tuple(parsed)
        return cls(cell=data["cell"], mode=data["mode"], data_root=data["data_root"],
                   engines=engines, publish=MappingProxyType(publish),
                   image_policy=data.get("image_policy", "digest-required"))


def load_inventory(path):
    path = Path(path)
    data = _load_yaml(path, INVENTORY_LIMIT)
    inventory = Inventory.from_mapping(data, path.parent)
    repository = path.resolve().parent.parent.parent
    for engine in inventory.engines.values():
        context = _reviewed_context(path.parent / engine.context, repository)
        for name in (engine.dockerfile, engine.config_file):
            _reviewed_file(context, name, "file")
    return inventory


def load_cell(path, inventory):
    cell = Cell.from_mapping(_load_yaml(path, PROFILE_LIMIT))
    cell.check_ports(inventory)
    for engine in cell.engines:
        inventory.engine(engine)
    return cell


def _image_reference(cell, engine):
    """Return the image reference allowed by the cell's explicit policy."""
    if cell.image_policy == "digest-required":
        return engine.pinned_reference
    return engine.image


def _service(inventory, cell, engine):
    resources = engine.resources
    repository = inventory.base.resolve().parent.parent.parent
    context = _reviewed_context(inventory.base / engine.context, repository)
    dockerfile = _reviewed_file(context, engine.dockerfile, "dockerfile")
    config_source = _reviewed_file(context, engine.config_file, "config file")
    service = {
        "container_name": cell.container(engine.name),
        "image": _image_reference(cell, engine),
        "build": {
            "context": str(context),
            "dockerfile": dockerfile.name,
        },
        "user": engine.user,
        "read_only": True,
        "init": True,
        "restart": "no",
        "stop_grace_period": "30s",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "profiles": [ACTIVATION_PROFILE],
        "expose": [port.expose for port in engine.ports],
        "tmpfs": [f"/tmp:rw,noexec,nosuid,size={resources.tmpfs_mib}m"],
        "volumes": [
            # Reviewed configuration is always a read-only bind, and always a
            # regular non-symlink file resolved inside its reviewed context.
            {"type": "bind",
             "source": str(config_source),
             "target": engine.config_target, "read_only": True},
            # Only logs are writable, and only inside the per-cell data root.
            *({"type": "bind", "source": cell.data_dir(engine.name, source),
               "target": target, "read_only": False}
              for source, target in engine.volumes),
        ],
        "mem_limit": f"{resources.mem_mib}m",
        "cpus": resources.cpus,
        "pids_limit": resources.pids,
        "ulimits": {
            "nofile": {"soft": resources.nofile, "hard": resources.nofile},
            "core": {"soft": 0, "hard": 0},
        },
        "healthcheck": {
            "test": ["CMD-SHELL", f"grep -q {engine.healthcheck.marker} /proc/1/cmdline"],
            "interval": engine.healthcheck.interval,
            "timeout": "5s",
            "start_period": engine.healthcheck.start_period,
            "retries": 3,
        },
        "logging": {
            "driver": "json-file",
            "options": {"max-size": "10m", "max-file": "3"},
        },
        "labels": {
            "dystopia.cell": str(cell.cell),
            "dystopia.engine": engine.name,
            "dystopia.role": "honeypot",
            "dystopia.activation": "manual-authorized-only",
            "dystopia.image-policy": cell.image_policy,
        },
        "networks": [cell.network(engine.name)],
    }
    if engine.capabilities:
        # RT-10/RV-02: the capability is granted explicitly, but NNP is never
        # dropped. Effective privileges (and any setuid/file-cap binaries in
        # the image) must be verified in Linux before activation.
        service["cap_add"] = list(engine.capabilities)
    publications = cell.publish.get(engine.name, ())
    if publications:
        service["ports"] = [item.mapping for item in publications]
    return service


def render_cell(inventory, cell):
    """Return a deterministic Compose mapping for exactly one cell."""
    if type(inventory) is not Inventory or type(cell) is not Cell:
        raise TypeError("Inventory and Cell required")
    cell.check_ports(inventory)
    document = {
        "name": cell.project,
        "services": {name: _service(inventory, cell, inventory.engine(name))
                     for name in cell.engines},
        "networks": {
            cell.network(name): {"driver": "bridge", "internal": True, "enable_ipv6": False}
            for name in cell.engines
        },
    }
    assert_safe(document, cell)
    return document


def dump_cell(inventory, cell):
    return yaml.safe_dump(render_cell(inventory, cell), sort_keys=False,
                          default_flow_style=False, allow_unicode=True, width=100)


def assert_safe(document, cell):
    """Fail closed if a rendered document drifts from the safety invariants."""
    if type(document) is not dict or set(document) != {"name", "services", "networks"}:
        raise HoneypotError("rendered document has unexpected keys")
    if document["name"] != cell.project:
        raise HoneypotError("rendered project name must be unique per cell")
    if not document["services"]:
        raise HoneypotError("rendered cell has no services")
    forbidden = {
        "network_mode", "privileged", "pid", "ipc", "uts", "userns_mode", "devices",
        "device_cgroup_rules", "group_add", "sysctls", "cgroup_parent", "volumes_from",
        "external_links", "links",
    }
    if type(document["networks"]) is not dict or not document["networks"]:
        raise HoneypotError("rendered cell has no networks")
    container_names = set()
    for name, service in document["services"].items():
        if name not in ENGINES:
            raise HoneypotError("unexpected service name")
        if type(service) is not dict or set(service) & forbidden:
            raise HoneypotError(f"forbidden compose key for {name}")
        build = service.get("build")
        if type(build) is not dict or set(build) != {"context", "dockerfile"}:
            raise HoneypotError(f"{name} must declare a reviewed build context")
        context_path = Path(build["context"])
        if not context_path.is_absolute():
            raise HoneypotError(f"{name} build context must be absolute")
        reviewed_context = _reviewed_context(context_path)
        if str(reviewed_context) != build["context"]:
            raise HoneypotError(f"{name} build context must be canonical and "
                                "non-symlink")
        _reviewed_file(reviewed_context, build["dockerfile"], "dockerfile")
        if service.get("container_name") != cell.container(name) \
                or service["container_name"] in container_names:
            raise HoneypotError(f"{name} container name must be unique per cell")
        container_names.add(service["container_name"])
        if not set(service.get("networks", ())) <= set(document["networks"]):
            raise HoneypotError(f"{name} references an unknown network")
        if service.get("read_only") is not True or service.get("init") is not True:
            raise HoneypotError(f"{name} must use a read-only rootfs")
        if service.get("restart") != "no":
            raise HoneypotError(f"{name} must not restart automatically")
        if service.get("cap_drop") != ["ALL"]:
            raise HoneypotError(f"{name} must drop all capabilities")
        # RV-02: NNP is mandatory and is never traded for cap_add. Without it,
        # a setuid/file-capability binary inside the image can raise privileges
        # inside the workload even though the container started non-root.
        if service.get("security_opt") != list(REQUIRED_SECURITY_OPT):
            raise HoneypotError(
                f"{name} must set security_opt exactly to {list(REQUIRED_SECURITY_OPT)}"
            )
        cap_add = service.get("cap_add", [])
        if type(cap_add) is not list or not set(cap_add) <= ALLOWED_CAPABILITIES \
                or len(set(cap_add)) != len(cap_add):
            raise HoneypotError(f"{name} adds an unnecessary capability")
        if not _USER.fullmatch(str(service.get("user", ""))) \
                or str(service["user"]).startswith("0:"):
            raise HoneypotError(f"{name} must run as a non-root user")
        if service.get("profiles") != [ACTIVATION_PROFILE]:
            raise HoneypotError(f"{name} must stay behind the activation profile")
        image = service.get("image")
        if type(image) is not str or not image.startswith("dystopia/honeypot-"):
            raise HoneypotError(f"{name} image must use the reviewed honeypot namespace")
        # RT-10: the activation path may not accept a mutable tag. A tag is
        # tolerated only when the cell explicitly opted into tag-lab-only,
        # which is reported as non-production and remains behind the blocked
        # activation path.
        if cell.image_policy == "digest-required":
            if _PINNED_IMAGE.fullmatch(image) is None \
                    or image.rsplit("@", 1)[1] == "sha256:" + "0" * 64:
                raise HoneypotError(
                    f"{name} image must be pinned by @sha256 under "
                    "image_policy=digest-required"
                )
        else:
            if _IMAGE.fullmatch(image) is None \
                    or image.rsplit(":", 1)[1].lower() in ("latest", "stable", "main", "edge"):
                raise HoneypotError(
                    f"{name} image must be an explicit non-floating tag in tag-lab-only mode"
                )
        labels = service.get("labels")
        if type(labels) is not dict \
                or labels.get("dystopia.image-policy") != cell.image_policy:
            raise HoneypotError(f"{name} must declare the image policy label")
        for key in ("mem_limit", "cpus", "pids_limit", "healthcheck", "logging", "ulimits"):
            if key not in service:
                raise HoneypotError(f"{name} is missing {key}")
        if not service.get("expose"):
            raise HoneypotError(f"{name} must declare internal exposes")
        config_mounts = [mount for mount in service["volumes"] if mount.get("read_only") is True]
        if not config_mounts:
            raise HoneypotError(f"{name} must mount configuration read-only")
        for mount in service["volumes"]:
            source, target = str(mount.get("source", "")), str(mount.get("target", ""))
            if not source.startswith("/") or not target.startswith("/"):
                raise HoneypotError(f"{name} bind mounts must be absolute")
            if "docker.sock" in source or source.startswith(FORBIDDEN_TARGET_PREFIXES) \
                    or target.startswith(FORBIDDEN_TARGET_PREFIXES):
                raise HoneypotError(f"{name} bind mount reaches a host namespace")
            if mount.get("read_only") is True:
                resolved = _reviewed_absolute_file(source, reviewed_context)
                if str(resolved) != source:
                    raise HoneypotError(f"{name} config bind must be a canonical "
                                        "reviewed context path")
            elif not source.startswith(cell.data_dir(name, "")):
                raise HoneypotError(f"{name} writable mount escapes the cell data root")
        if "ports" in service:
            if cell.mode != "loopback-lab":
                raise HoneypotError("published ports require the loopback-lab mode")
            if any(not str(item).startswith("127.0.0.1:") for item in service["ports"]):
                raise HoneypotError("published ports must bind loopback only")
    for name, network in document["networks"].items():
        if network != {"driver": "bridge", "internal": True, "enable_ipv6": False}:
            raise HoneypotError(f"network {name} must be a private internal bridge")
        if not name.startswith(cell.network_prefix + "-"):
            raise HoneypotError("network name must be unique per cell")
    if set(document["networks"]) != {cell.network(engine) for engine in document["services"]}:
        raise HoneypotError("one dedicated internal network per engine is required")
    return True


def validate(path, profile):
    """Return a read-only validation report; raises on invalid input."""
    inventory = load_inventory(path)
    cell = load_cell(profile, inventory)
    document = render_cell(inventory, cell)
    resources = [inventory.engine(name).resources for name in cell.engines]
    warnings = []
    published = [item.mapping for entries in cell.publish.values() for item in entries]
    if published:
        warnings.append("loopback-lab publishes ports; this is not containment evidence")
    if any(engine.capabilities for engine in (inventory.engine(name) for name in cell.engines)):
        warnings.append(
            "NET_BIND_SERVICE is granted with no-new-privileges still enabled; "
            "effective privileges need Linux verification"
        )
    if cell.image_policy != "digest-required":
        warnings.append(
            "image_policy=tag-lab-only renders mutable tags; this is "
            "lab-only and activation remains blocked"
        )
    unpinned = [name for name in cell.engines
                if inventory.engine(name).local_digest is None]
    if unpinned:
        warnings.append(
            "no reviewed local_digest for: " + ", ".join(sorted(unpinned))
        )
    return {
        "inventory_revision": inventory.revision,
        "cell": cell.cell,
        "project": cell.project,
        "mode": cell.mode,
        "image_policy": cell.image_policy,
        "image_digests": {
            name: inventory.engine(name).local_digest for name in cell.engines
        },
        "mutable_images": sorted(unpinned),
        "engines": list(cell.engines),
        "services": sorted(document["services"]),
        "networks": sorted(document["networks"]),
        "published_ports": published,
        "memory_mib": sum(item.mem_mib for item in resources),
        "cpus": round(sum(item.cpus for item in resources), 2),
        "pids_limit": sum(item.pids for item in resources),
        "warnings": warnings,
        "activation_allowed": False,
        "containment_verified": False,
        "data_directories": [
            {"path": cell.data_dir(name, source),
             "user": inventory.engine(name).user}
            for name in cell.engines
            for source, _ in inventory.engine(name).volumes
        ],
    }


def plan(path, profile):
    report = validate(path, profile)
    report["dry_run"] = True
    report["host_operations"] = []
    report["requires"] = [
        "independent Linux containment verification (network namespace, nftables cell policy)",
        "verified cgroup v2 memory/pids/CPU enforcement",
        "per-cell filesystem quota and log rotation provisioned by the operator",
        "rootless or user-namespaced Docker runtime reviewed for this host",
        "reviewed image digests and SBOM/CVE scan for every engine",
    ]
    return report


def blocked(action):
    """Activation is unreachable by design; there is no force or override flag."""
    if action not in BLOCKED_ACTIONS:
        raise HoneypotError("unsupported action")
    raise HoneypotBlocked(
        f"honeypots {action} is blocked: no Linux containment verification exists. "
        "internal:true is not containment; provision and verify the cell boundary, "
        "cgroups, quotas and runtime first, then add a separately reviewed activation path."
    )


__all__ = [
    "ENGINES", "SCHEMA_CELL", "SCHEMA_INVENTORY", "Cell", "Engine", "HoneypotBlocked",
    "HoneypotError", "Inventory", "Port", "Resources", "assert_safe", "blocked",
    "dump_cell", "load_cell", "load_inventory", "plan", "render_cell", "validate",
]
