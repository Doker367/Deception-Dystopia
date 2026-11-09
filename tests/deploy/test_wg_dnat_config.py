"""Offline invariants for the eight-port DNAT design (not a live network test)."""

import importlib.util
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PORTS = {12222, 12223, 13022, 13080, 14021, 15021, 16379, 17222}
SERVICES = {"cowrie", "opencanary", "dionaea", "heralding", "redishoneypot", "endlessh"}


class ComposeLoader(yaml.SafeLoader):
    pass


def _override(loader, node):
    return loader.construct_sequence(node)


ComposeLoader.add_constructor("!override", _override)


def _ports_from_script(path: Path) -> set[int]:
    content = path.read_text()
    match = re.search(r"^PORTS=([\d,]+)$", content, re.MULTILINE)
    assert match, f"missing explicit whitelist in {path.name}"
    return {int(port) for port in match.group(1).split(",")}


def test_wg_overlay_publishes_only_eight_honeypot_ports_and_private_panel():
    overlay = yaml.load(
        (ROOT / "deploy/local/docker-compose.remote.yml").read_text(), Loader=ComposeLoader
    )["services"]
    published = {}
    for name in SERVICES:
        for mapping in overlay[name]["ports"]:
            address, port, _target = mapping.split(":")
            assert address == "10.66.0.3"
            assert int(port) not in published
            published[int(port)] = name
    assert set(published) == PORTS

    panel = overlay["control"]["ports"]
    assert len(panel) == 2
    assert "127.0.0.1:8082:8082/tcp" in panel
    assert any(p.startswith("${DYSTOPIA_TAILSCALE_IP:?") and p.endswith(":8082:8082/tcp")
               for p in panel)
    assert all("10.66.0.3:8082" not in port and "0.0.0.0:8082" not in port for port in panel)


def test_vps_dnat_and_server_conntrack_marks_share_whitelist():
    vps = ROOT / "deploy/vps/dystopia-dnat.sh"
    server = ROOT / "deploy/server/dystopia-wg-return.sh"
    assert _ports_from_script(vps) == _ports_from_script(server) == PORTS

    dnat = vps.read_text()
    assert "-j DNAT --to-destination \"$TARGET\"" in dnat
    assert "SNAT" not in dnat.replace("# VPS only: eight TCP honeypots. NO SNAT/MASQUERADE", "")
    assert "MASQUERADE" not in dnat.replace("# VPS only: eight TCP honeypots. NO SNAT/MASQUERADE", "")
    assert "-i \"$WAN_IF\" -d \"$VPS_INGRESS_IP\"" in dnat

    route = server.read_text()
    assert "-m conntrack --ctstate NEW --ctdir ORIGINAL" in route
    assert "-j CONNMARK --set-xmark \"$MARK\"" in route
    assert "-i 'br-+'" in route
    assert "-m conntrack --ctstate ESTABLISHED --ctdir REPLY" in route
    assert "-m connmark --mark \"$MARK\" -j MARK --set-xmark \"$MARK\"" in route
    assert "ip -4 rule add pref \"$PRIORITY\" fwmark \"$MARK\" lookup \"$TABLE\"" in route
    assert "ip -4 route add default dev wg0 table \"$TABLE\"" in route
    assert "old_rpf=$(sysctl -n net.ipv4.conf.wg0.rp_filter)" in route
    assert "trap 'stop || true; sysctl -w net.ipv4.conf.wg0.rp_filter=" in route


def test_runbook_ufw_is_exact_and_reverts_persistent_forwarding():
    readme = (ROOT / "deploy/vps/README.md").read_text()
    rule = re.search(r"for p in ([\d ]+); do\s+sudo ufw route allow", readme)
    assert rule and {int(port) for port in rule.group(1).split()} == PORTS
    assert "sudo ufw allow" not in readme
    assert "retirar **solo** `/etc/sysctl.d/90-dystopia-forward.conf`" in readme


def test_analytics_verifier_requires_actual_event_source_and_geolocated_origin():
    path = ROOT / "deploy/server/verify-source-ip.py"
    assert "address.version != 4 or not address.is_global" in path.read_text()
    spec = importlib.util.spec_from_file_location("wg_source_verifier", path)
    assert spec and spec.loader
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    event = {"source": "203.0.113.7", "countryCode": "US", "regionCode": "CA"}
    origin = {"countryCode": "US", "regionCode": "CA", "events": 1,
              "lat": 34.05, "lng": -118.0, "ip": "198.51.100.8"}
    assert verifier.check([event], [origin], "203.0.113.7", "US", "CA")
    # The group IP can differ; it must NOT substitute for the true source.
    assert not verifier.check([event], [origin], "198.51.100.8", "US", "CA")
    assert not verifier.check([event], [{**origin, "regionCode": "TX"}], "203.0.113.7", "US", "CA")
    assert not verifier.check([event], [{**origin, "lat": None}], "203.0.113.7", "US", "CA")


def test_effective_compose_preflight_fails_closed_for_panel_and_extra_ports():
    path = ROOT / "deploy/server/check-compose-bindings.py"
    spec = importlib.util.spec_from_file_location("compose_bindings_preflight", path)
    assert spec and spec.loader
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    tail = "100.64.0.10"  # Synthetic tailnet address, not a deployed endpoint.
    def binding(host, port, target):
        return {"host_ip": host, "published": str(port), "target": target, "protocol": "tcp"}

    services = {
        name: {"ports": [binding(host, port, target) for host in ("127.0.0.1", "10.66.0.3")
                         for port, target in ports.items()]}
        for name, ports in preflight.PORTS.items()
    }
    services["control"] = {"ports": [binding("127.0.0.1", 8082, 8082),
                                      binding(tail, 8082, 8082)]}
    config = {"services": services}
    assert preflight.valid(config, tail, {tail})
    assert not preflight.valid(config, tail, set())
    services["control"]["ports"][1]["host_ip"] = "0.0.0.0"
    assert not preflight.valid(config, tail, {tail})
    services["control"]["ports"][1]["host_ip"] = tail
    services["cowrie"]["ports"].append(binding("10.66.0.3", 13021, 21))
    assert not preflight.valid(config, tail, {tail})
