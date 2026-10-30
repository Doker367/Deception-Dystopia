"""Pure renderers; neither rendered text nor nft success proves containment."""
from xml.etree.ElementTree import Element, SubElement, tostring

from .policy import CellPolicy


def domain_xml(policy: CellPolicy) -> str:
    """Offline definition only: no define/start operation is provided."""
    root = Element("domain", {"type": "kvm"})
    SubElement(root, "name").text = f"dystopia-cell-{policy.cell}"
    SubElement(root, "memory", {"unit": "MiB"}).text = str(policy.memory_mib)
    SubElement(root, "vcpu").text = str(policy.vcpus)
    os_node = SubElement(root, "os")
    SubElement(os_node, "type", {"arch": "x86_64", "machine": "q35"}).text = "hvm"
    SubElement(os_node, "boot", {"dev": "hd"})
    SubElement(root, "on_poweroff").text = "destroy"
    SubElement(root, "on_reboot").text = "destroy"
    SubElement(root, "on_crash").text = "destroy"
    devices = SubElement(root, "devices")
    SubElement(devices, "emulator").text = "/usr/bin/qemu-system-x86_64"
    disk = SubElement(devices, "disk", {"type": "file", "device": "disk"})
    SubElement(disk, "driver", {"name": "qemu", "type": "raw"})
    SubElement(disk, "source", {"file": policy.disk})
    SubElement(disk, "target", {"dev": "vda", "bus": "virtio"})
    nic = SubElement(devices, "interface", {"type": "bridge"})
    SubElement(nic, "mac", {"address": policy.mac})
    SubElement(nic, "source", {"bridge": policy.bridge})
    SubElement(nic, "target", {"dev": policy.tap})
    SubElement(nic, "model", {"type": "virtio"})
    # Even a manually defined domain starts without connectivity by default.
    SubElement(nic, "link", {"state": "down"})
    SubElement(devices, "controller", {"type": "usb", "model": "none"})
    video = SubElement(devices, "video")
    SubElement(video, "model", {"type": "none"})
    return tostring(root, encoding="unicode")


def nft_rules(policy: CellPolicy, *, quarantine: bool = False) -> str:
    """Exclusive-create transaction; never flush/delete/replace any existing table.

    Static IPv4/IPv6 neighbours are required: ARP, ND, RA, DHCP, VLAN and all
    non-IP frames are intentionally denied, not automatically permitted.
    """
    if type(quarantine) is not bool:
        raise TypeError("quarantine must be bool")
    p = policy
    table = f"dy_{'quarantine' if quarantine else 'cell'}_{p.cell}"
    lines = [f"create table bridge {table}"]

    def chain(name, hook=None, priority=-200):
        suffix = (f" {{ type filter hook {hook} priority {priority}; policy accept; }}"
                  if hook else "")
        lines.append(f"add chain bridge {table} {name}{suffix}")

    def rule(name, text):
        lines.append(f"add rule bridge {table} {name} {text}")

    chain("host_in", "input")
    chain("host_out", "output")
    chain("forward", "forward")
    rule("host_in", f'iifname "{p.tap}" counter drop')
    rule("host_out", f'oifname "{p.tap}" counter drop')
    if quarantine:
        chain("early", "prerouting", -310)
        rule("early", f'iifname "{p.tap}" counter drop')
        rule("forward", f'iifname "{p.tap}" counter drop')
        rule("forward", f'oifname "{p.tap}" counter drop')
        return "\n".join(lines) + "\n"

    chain("early", "prerouting", -310)
    chain("zone", "prerouting", -300)
    chain("from_guest")
    chain("to_guest")
    for interface in (p.tap, p.uplink):
        scope = f'iifname "{interface}"'
        rule("early", f'{scope} meta ibrname != "{p.bridge}" counter drop')
        rule("early", f"{scope} ether type != {{ ip, ip6 }} counter drop")
        rule("early", f"{scope} ether type ip ip frag-off & 0x3fff != 0 counter drop")
        rule("early", f"{scope} ether type ip6 ip6 nexthdr != {{ tcp, udp }} counter drop")
        rule("zone", f"{scope} ct zone set {p.cell}")
    rule("forward", f'iifname "{p.tap}" oifname "{p.uplink}" jump from_guest')
    rule("forward", f'iifname "{p.uplink}" oifname "{p.tap}" jump to_guest')
    rule("forward", f'iifname "{p.tap}" counter drop')
    rule("forward", f'oifname "{p.tap}" counter drop')
    for name, src, dst in (("from_guest", p.mac, p.gateway_mac),
                           ("to_guest", p.gateway_mac, p.mac)):
        rule(name, f"ether saddr != {src} counter drop")
        rule(name, f"ether daddr != {dst} counter drop")
        rule(name, "ct state invalid,untracked counter drop")

    mark = hex(0xd5700000 + p.cell)

    def flow(endpoint, telemetry=False):
        family = "ip6" if ":" in endpoint.address else "ip"
        local = p.ipv6 if family == "ip6" else p.ipv4
        proto, port, remote = endpoint.protocol, endpoint.port, endpoint.address
        outgoing = (f"ether type {family} {family} saddr {local} "
                    f"{family} daddr {remote} {proto}")
        incoming = (f"ether type {family} {family} saddr {remote} "
                    f"{family} daddr {local} {proto}")
        if telemetry:
            origin_chain, reply_chain = "from_guest", "to_guest"
            origin, reply = f"{outgoing} dport {port}", f"{incoming} sport {port}"
            rate = "limit rate 10/second burst 20 packets "
        else:
            origin_chain, reply_chain = "to_guest", "from_guest"
            origin, reply = f"{incoming} dport {port}", f"{outgoing} sport {port}"
            rate = ""
        syn = "tcp flags & (fin | syn | rst | ack) == syn " if proto == "tcp" else ""
        rule(origin_chain, f"{origin} ct direction original ct state new {syn}"
             f"{rate}ct mark set {mark} counter accept")
        rule(origin_chain, f"{origin} ct direction original ct state established "
             f"ct mark {mark} {rate}counter accept")
        rule(reply_chain, f"{reply} ct direction reply ct state established "
             f"ct mark {mark} {rate}counter accept")

    for endpoint in p.services:
        flow(endpoint)
    if p.telemetry is not None:
        flow(p.telemetry, telemetry=True)
    rule("from_guest", "counter drop")
    rule("to_guest", "counter drop")
    return "\n".join(lines) + "\n"
