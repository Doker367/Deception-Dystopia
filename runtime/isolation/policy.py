"""Strict, deliberately narrow policy for an Ubuntu 24.04 laboratory cell."""
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import re


class PolicyError(ValueError):
    pass


def _integer(value: object, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        raise PolicyError(f"expected integer in [{low}, {high}]")


def _keys(value: object, expected: set[str]) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise PolicyError("missing or unknown policy fields")
    return value


@dataclass(frozen=True)
class Endpoint:
    address: str
    protocol: str
    port: int

    def __post_init__(self):
        if type(self.address) is not str or "%" in self.address:
            raise PolicyError("literal IP required")
        try:
            address = ip_address(self.address)
        except ValueError as exc:
            raise PolicyError("literal IP required") from exc
        if (str(address) != self.address or address.is_multicast or address.is_loopback
                or address.is_unspecified or address.is_link_local or address.is_reserved
                or getattr(address, "ipv4_mapped", None)
                or address in ip_network("0.0.0.0/8")
                or address in ip_network("192.0.2.0/24")
                or address in ip_network("fd42:d570::/64")):
            raise PolicyError("noncanonical, special or decoy address forbidden")
        if self.protocol not in ("tcp", "udp"):
            raise PolicyError("only TCP/UDP supported")
        _integer(self.port, 1, 65535)

    @classmethod
    def from_mapping(cls, value):
        return cls(**_keys(value, {"address", "protocol", "port"}))


@dataclass(frozen=True)
class CellPolicy:
    version: int
    cell: int
    bridge: str
    gateway_mac: str
    services: tuple[Endpoint, ...]
    telemetry: Endpoint | None
    memory_mib: int
    vcpus: int

    def __post_init__(self):
        _integer(self.version, 1, 1)
        _integer(self.cell, 1, 254)
        if self.bridge != f"dybr{self.cell}":
            raise PolicyError("bridge must be the explicitly approved dedicated cell bridge")
        if (type(self.gateway_mac) is not str
                or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", self.gateway_mac)
                or int(self.gateway_mac[:2], 16) & 1
                or self.gateway_mac == "00:00:00:00:00:00"
                or self.gateway_mac.startswith("02:00:00:00:00:")):
            raise PolicyError("unicast gateway MAC outside decoy range required")
        if (type(self.services) is not tuple or len(self.services) > 16
                or any(type(item) is not Endpoint for item in self.services)):
            raise PolicyError("at most 16 immutable service endpoints required")
        if len(set(self.services)) != len(self.services):
            raise PolicyError("duplicate service endpoint")
        if self.telemetry is not None:
            if type(self.telemetry) is not Endpoint or self.telemetry.protocol != "tcp":
                raise PolicyError("telemetry must be a single TCP endpoint or null")
        _integer(self.memory_mib, 256, 4096)
        _integer(self.vcpus, 1, 4)

    @classmethod
    def from_mapping(cls, value):
        data = _keys(value, {"version", "cell", "bridge", "gateway_mac", "services",
                             "telemetry", "memory_mib", "vcpus"}).copy()
        if type(data["services"]) is not list:
            raise PolicyError("services must be a list")
        data["services"] = tuple(Endpoint.from_mapping(item) for item in data["services"])
        if data["telemetry"] is not None:
            data["telemetry"] = Endpoint.from_mapping(data["telemetry"])
        return cls(**data)

    @property
    def tap(self):
        return f"dytap{self.cell}"

    @property
    def uplink(self):
        return f"dyup{self.cell}"

    @property
    def mac(self):
        return f"02:00:00:00:00:{self.cell:02x}"

    @property
    def ipv4(self):
        return f"192.0.2.{self.cell}"

    @property
    def ipv6(self):
        return f"fd42:d570::{self.cell:x}"

    @property
    def disk(self):
        return f"/var/lib/dystopia/cells/{self.cell}/root.raw"
