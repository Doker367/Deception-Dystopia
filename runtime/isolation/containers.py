"""Declarative isolation for containerized honeypot cells; activation blocked.

This module is validation and rendering only. It never starts, stops, inspects
or reconfigures a container, network namespace, cgroup, disk quota or firewall.
Container cells reuse the strict per-cell KVM traffic policy; they do not widen
it. A parsed file, a well-formed unit or a successful ``nft`` transaction is
not containment evidence, and a Docker ``internal=true`` network is not either.
"""
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
import re

from .policy import CellPolicy, Endpoint, PolicyError, _integer, _keys
from .render import nft_rules


PROFILES = ("cowrie", "opencanary", "dionaea", "heralding", "redishoneypot", "endlessh")
_DIGEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:([0-9a-f]{64})\Z")
_DECEPTION_V4 = ip_network("192.0.2.0/24")
_DECEPTION_V6 = ip_network("fd42:d570::/64")


def _required_flag(value: object, expected: bool, label: str) -> None:
    if type(value) is not bool or value is not expected:
        raise PolicyError(f"{label} must be {str(expected).lower()}")


@dataclass(frozen=True)
class HoneypotProfile:
    """A named honeypot image plus the exact inbound flows it is allowed."""

    name: str
    image: str | None
    services: tuple[Endpoint, ...]

    def __post_init__(self):
        if type(self.name) is not str or self.name not in PROFILES:
            raise PolicyError("unsupported honeypot profile")
        if self.image is not None:
            if (type(self.image) is not str or len(self.image) > 512
                    or ".." in self.image):
                raise PolicyError("reviewed image digest required")
            match = _DIGEST.fullmatch(self.image)
            if match is None:
                raise PolicyError("image must be pinned by sha256 digest")
            if match.group(1) == "0" * 64:
                raise PolicyError("placeholder image digest forbidden")
        if (type(self.services) is not tuple or not 1 <= len(self.services) <= 16
                or any(type(item) is not Endpoint for item in self.services)):
            raise PolicyError("one to sixteen immutable service endpoints required")
        if len(set(self.services)) != len(self.services):
            raise PolicyError("duplicate service endpoint")

    @classmethod
    def from_mapping(cls, value):
        data = _keys(value, {"name", "image", "services"}).copy()
        if type(data["services"]) is not list:
            raise PolicyError("services must be a list")
        data["services"] = tuple(Endpoint.from_mapping(item) for item in data["services"])
        return cls(**data)


@dataclass(frozen=True)
class ContainerCellPolicy:
    """One exclusive cell, either a KVM guest or one honeypot container."""

    version: int
    cell: int
    workload: str
    bridge: str
    gateway_mac: str
    profile: HoneypotProfile
    ingest: Endpoint
    mgmt_networks: tuple[IPv4Network | IPv6Network, ...]
    memory_mib: int
    vcpus: int
    pids: int
    run_as_uid: int
    writable_mib: int
    log_mib: int
    tmpfs_mib: int
    read_only_root: bool
    no_new_privileges: bool
    drop_all_capabilities: bool
    docker_socket: bool

    def __post_init__(self):
        _integer(self.version, 1, 1)
        _integer(self.cell, 1, 254)
        if self.workload != "container":
            raise PolicyError("workload must be container")
        if self.bridge != f"dybr{self.cell}":
            raise PolicyError("bridge must be the explicitly approved dedicated cell bridge")
        if type(self.profile) is not HoneypotProfile:
            raise PolicyError("immutable honeypot profile required")
        if type(self.ingest) is not Endpoint or self.ingest.protocol != "tcp":
            raise PolicyError("ingest must be one TCP endpoint")
        if (type(self.mgmt_networks) is not tuple or not self.mgmt_networks
                or any(type(net) not in (IPv4Network, IPv6Network)
                       for net in self.mgmt_networks)):
            raise PolicyError("at least one canonical management CIDR required")
        if len(set(self.mgmt_networks)) != len(self.mgmt_networks):
            raise PolicyError("duplicate management network")
        if any(net.overlaps(_DECEPTION_V4) or net.overlaps(_DECEPTION_V6)
               for net in self.mgmt_networks):
            raise PolicyError("management must not overlap the deception ranges")
        _integer(self.memory_mib, 256, 4096)
        _integer(self.vcpus, 1, 4)
        _integer(self.pids, 16, 1024)
        _integer(self.run_as_uid, 1, 65535)
        _integer(self.writable_mib, 16, 10240)
        _integer(self.log_mib, 8, 1024)
        _integer(self.tmpfs_mib, 8, 256)
        _required_flag(self.read_only_root, True, "read_only_root")
        _required_flag(self.no_new_privileges, True, "no_new_privileges")
        _required_flag(self.drop_all_capabilities, True, "drop_all_capabilities")
        _required_flag(self.docker_socket, False, "docker_socket")
        # Shared cell validation: bridge, MAC, endpoints, memory, vCPUs.
        self.as_cell_policy()
        addresses = [self.ipv4, self.ipv6, self.ingest.address]
        addresses.extend(endpoint.address for endpoint in self.profile.services)
        for text in addresses:
            address = ip_address(text)
            if any(address in net for net in self.mgmt_networks):
                raise PolicyError("management network overlap forbidden")

    @classmethod
    def from_mapping(cls, value):
        data = _keys(value, {
            "version", "cell", "workload", "bridge", "gateway_mac", "profile",
            "ingest", "mgmt_networks", "memory_mib", "vcpus", "pids", "run_as_uid",
            "writable_mib", "log_mib", "tmpfs_mib", "read_only_root",
            "no_new_privileges", "drop_all_capabilities", "docker_socket",
        }).copy()
        data["profile"] = HoneypotProfile.from_mapping(data["profile"])
        data["ingest"] = Endpoint.from_mapping(data["ingest"])
        if type(data["mgmt_networks"]) is not list:
            raise PolicyError("mgmt_networks must be a list")
        networks = []
        for item in data["mgmt_networks"]:
            if type(item) is not str:
                raise PolicyError("canonical management CIDR required")
            try:
                network = ip_network(item, strict=True)
            except ValueError as exc:
                raise PolicyError("canonical management CIDR required") from exc
            if str(network) != item:
                raise PolicyError("noncanonical management CIDR")
            networks.append(network)
        data["mgmt_networks"] = tuple(networks)
        return cls(**data)

    @property
    def tap(self) -> str:
        return f"dytap{self.cell}"

    @property
    def uplink(self) -> str:
        return f"dyup{self.cell}"

    @property
    def mac(self) -> str:
        return f"02:00:00:00:00:{self.cell:02x}"

    @property
    def ipv4(self) -> str:
        return f"192.0.2.{self.cell}"

    @property
    def ipv6(self) -> str:
        return f"fd42:d570::{self.cell:x}"

    @property
    def state_dir(self) -> str:
        return f"/var/lib/dystopia/cells/{self.cell}/container"

    def as_cell_policy(self) -> CellPolicy:
        """Reuse the exact KVM/container traffic policy for this cell."""
        return CellPolicy(
            version=self.version,
            cell=self.cell,
            bridge=self.bridge,
            gateway_mac=self.gateway_mac,
            services=self.profile.services,
            telemetry=self.ingest,
            memory_mib=self.memory_mib,
            vcpus=self.vcpus,
        )

    def deployment_errors(self) -> list[str]:
        errors = []
        if self.profile.image is None:
            errors.append("reviewed image digest required before apply")
        return errors

    def resource_limits(self) -> dict:
        """Declarative limits; this module applies none of them."""
        mib = 1024 * 1024
        return {
            "cgroup_version": 2,
            "MemoryMax": f"{self.memory_mib}M",
            "TasksMax": self.pids,
            "CPUQuota": f"{self.vcpus * 100}%",
            "LimitNOFILE": 1024,
            "LimitCORE": 0,
            "LimitFSIZE": self.log_mib * mib,
            "ReadWritePaths": [self.state_dir],
            "quota": {
                "path": self.state_dir,
                "project_id": 10000 + self.cell,
                "bytes": self.writable_mib * mib,
                "enforcement": "operator-provisioned XFS/ext4 project quota; not applied here",
            },
            "logs": {
                "path": f"{self.state_dir}/logs",
                "max_bytes": self.log_mib * mib,
                "rotation": "operator-provisioned; no unbounded runtime logs",
            },
            "tmpfs": {
                "path": "/tmp",
                "bytes": self.tmpfs_mib * mib,
                "options": "nosuid,nodev,noexec",
            },
            "enforcement": "external cgroup/quota provisioning and verification required",
        }

    def container_spec(self) -> dict:
        return {
            "workload": self.workload,
            "cell": self.cell,
            "name": f"dystopia-honeypot-{self.cell}",
            "profile": self.profile.name,
            "image": self.profile.image,
            "network": {
                "mode": "dedicated-cell-bridge",
                "bridge": self.bridge,
                "host_veth": self.tap,
                "uplink": self.uplink,
                "container_interface": "eth0",
                "mac": self.mac,
                "ipv4": self.ipv4,
                "ipv6": self.ipv6,
                "gateway_mac": self.gateway_mac,
                "link": "down until independent verification and explicit attach",
                "default_route": False,
                "publish_ports": [],
                "nat": False,
                "host_network": False,
                "dns": [],
                "vlan": None,
            },
            "security": {
                "read_only_root": self.read_only_root,
                "no_new_privileges": self.no_new_privileges,
                "cap_drop": ["ALL"],
                "run_as_uid": self.run_as_uid,
                "docker_socket": self.docker_socket,
                "host_pid": False,
                "host_ipc": False,
                "host_uts": False,
                "seccomp": "runtime default; operator reviewed",
                "rootless_recommended": True,
            },
            "resources": self.resource_limits(),
            "ingest": {
                "address": self.ingest.address,
                "protocol": self.ingest.protocol,
                "port": self.ingest.port,
            },
            "management_networks": [str(net) for net in self.mgmt_networks],
            "activation_allowed": False,
            "containment_verified": False,
            "deployment_errors": self.deployment_errors(),
            "notes": [
                "No container start/stop/inspect operation is implemented here.",
                "No published ports, NAT, host networking, default route or DNS.",
                "Static neighbours and link-down start are operator preconditions.",
                "Quota, cgroup and runtime enforcement are external and unverified.",
            ],
        }


def container_nft_rules(policy: ContainerCellPolicy, *, quarantine: bool = False) -> str:
    """Exclusive per-cell bridge table; never flush, delete or replace."""
    if type(policy) is not ContainerCellPolicy:
        raise TypeError("ContainerCellPolicy required")
    if type(quarantine) is not bool:
        raise TypeError("quarantine must be bool")
    return nft_rules(policy.as_cell_policy(), quarantine=quarantine)


def container_manifest(policy: ContainerCellPolicy) -> dict:
    """Return a declarative provisioning review; it starts nothing."""
    if type(policy) is not ContainerCellPolicy:
        raise TypeError("ContainerCellPolicy required")
    return policy.container_spec()
