"""Unit plans only: run solely inside the OS sandbox described in the lab guide.

All local runner calls are mocked. These tests cannot establish kernel isolation.
"""
import copy
import json
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree

from runtime.isolation import (
    ActivationBlocked, CellPolicy, IsolationError, LocalCellBackend, PolicyError,
    State, domain_xml, nft_rules,
)
from runtime.isolation import backend


def document():
    return {
        "version": 1, "cell": 7, "bridge": "dybr7",
        "gateway_mac": "02:10:20:30:40:50",
        "services": [
            {"address": "198.51.100.20", "protocol": "tcp", "port": 22},
            {"address": "2001:db8:20::1", "protocol": "udp", "port": 53},
        ],
        "telemetry": None, "memory_mib": 512, "vcpus": 1,
    }


def policy():
    return CellPolicy.from_mapping(document())


class PolicyTests(unittest.TestCase):
    def test_valid_dual_stack_is_immutable(self):
        p = policy()
        self.assertEqual(p.disk, "/var/lib/dystopia/cells/7/root.raw")
        self.assertEqual(p.ipv6, "fd42:d570::7")
        with self.assertRaises(AttributeError):
            p.cell = 8

    def test_unknown_and_missing_fields_rejected(self):
        for key in ("isolated", "verified", "disk", "command", "network", "nat", "uri"):
            data = document()
            data[key] = True
            with self.subTest(key=key), self.assertRaises(PolicyError):
                CellPolicy.from_mapping(data)
        data = document()
        del data["bridge"]
        with self.assertRaises(PolicyError):
            CellPolicy.from_mapping(data)

    def test_invalid_values_and_injection_rejected(self):
        for key, value in (
            ("cell", True), ("cell", 0), ("cell", 255), ("version", 2),
            ("memory_mib", True), ("vcpus", 5), ("bridge", "virbr0"),
            ("bridge", "default"), ("bridge", "dybr8"),
            ("bridge", 'dybr7"; flush ruleset'),
            ("gateway_mac", "ff:ff:ff:ff:ff:ff"),
            ("gateway_mac", "02:00:00:00:00:08"),
        ):
            data = document()
            data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(PolicyError):
                CellPolicy.from_mapping(data)

    def test_endpoint_rejections(self):
        for address in ("localhost", "198.51.100.0/24", "0.0.0.1", "::", "::1", "fe80::1",
                        "ff02::1", "::ffff:198.51.100.1", "192.0.2.8",
                        "fd42:d570::8", "198.51.100.20; accept", "2001:db8::1%eth0"):
            data = document()
            data["services"][0]["address"] = address
            with self.subTest(address=address), self.assertRaises(PolicyError):
                CellPolicy.from_mapping(data)
        for key, value in (("port", True), ("port", 0), ("port", 65536),
                           ("protocol", "icmp"), ("extra", "ignored?")):
            data = document()
            data["services"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(PolicyError):
                CellPolicy.from_mapping(data)

    def test_telemetry_is_explicit_single_tcp_endpoint(self):
        data = document()
        data["telemetry"] = {"address": "198.51.100.90", "protocol": "tcp", "port": 443}
        text = nft_rules(CellPolicy.from_mapping(data))
        self.assertIn("ip daddr 198.51.100.90 tcp dport 443", text)
        self.assertIn("limit rate 10/second burst 20 packets", text)
        data["telemetry"]["protocol"] = "udp"
        with self.assertRaises(PolicyError):
            CellPolicy.from_mapping(data)

    def test_duplicate_services_and_json_keys_rejected(self):
        data = document()
        data["services"].append(copy.deepcopy(data["services"][0]))
        with self.assertRaises(PolicyError):
            CellPolicy.from_mapping(data)
        with self.assertRaises(PolicyError):
            json.loads('{"cell":7,"cell":8}', object_pairs_hook=backend._unique_object)


class RenderTests(unittest.TestCase):
    def test_domain_has_one_fixed_raw_disk_and_explicit_down_bridge_nic(self):
        root = ElementTree.fromstring(domain_xml(policy()))
        self.assertEqual(root.attrib, {"type": "kvm"})
        devices = root.find("devices")
        self.assertEqual(len(devices.findall("interface")), 1)
        self.assertEqual(devices.find("interface").attrib, {"type": "bridge"})
        self.assertEqual(devices.find("interface/source").attrib, {"bridge": "dybr7"})
        self.assertEqual(devices.find("interface/target").attrib, {"dev": "dytap7"})
        self.assertEqual(devices.find("interface/link").attrib, {"state": "down"})
        self.assertEqual(devices.find("disk/source").attrib,
                         {"file": "/var/lib/dystopia/cells/7/root.raw"})
        self.assertEqual(devices.find("disk/driver").get("type"), "raw")
        for tag in ("graphics", "serial", "console", "channel", "filesystem", "hostdev",
                    "redirdev", "vsock", "smartcard"):
            self.assertIsNone(devices.find(tag))
        self.assertNotIn("network=", domain_xml(policy()))

    def test_cell_scoping_and_no_destructive_or_global_commands(self):
        text = nft_rules(policy())
        self.assertTrue(text.startswith("create table bridge dy_cell_7\n"))
        for line in text.splitlines():
            self.assertIn("bridge dy_cell_7", line)
        for forbidden in ("flush", "delete", "destroy", "replace", "masquerade", "snat",
                          "dnat", "related", "table inet", "table ip"):
            self.assertNotIn(forbidden, text)
        data = document()
        data.update(cell=8, bridge="dybr8")
        other = nft_rules(CellPolicy.from_mapping(data))
        self.assertNotIn("dy_cell_7", other)
        self.assertNotIn('"dytap7"', other)

    def test_l2_host_spoofing_fragments_and_default_drop(self):
        text = nft_rules(policy())
        for expected in (
            'iifname "dytap7" counter drop', 'oifname "dytap7" counter drop',
            'meta ibrname != "dybr7" counter drop',
            "ether type != { ip, ip6 } counter drop",
            "ip frag-off & 0x3fff != 0 counter drop",
            "ip6 nexthdr != { tcp, udp } counter drop",
            "ether saddr != 02:00:00:00:00:07 counter drop",
            "ether daddr != 02:10:20:30:40:50 counter drop",
            "ct state invalid,untracked counter drop", "ct zone set 7",
            "from_guest counter drop", "to_guest counter drop",
        ):
            self.assertIn(expected, text)

    def test_only_authorized_new_ingress_and_conntrack_replies(self):
        text = nft_rules(policy())
        accepts = [line for line in text.splitlines() if line.endswith("accept")]
        self.assertEqual(len(accepts), 6)
        for line in accepts:
            self.assertIn("ct direction", line)
            self.assertIn("ct mark", line)
            if "from_guest" in line:
                self.assertIn("ct direction reply ct state established", line)
                self.assertNotIn("ct state new", line)
        self.assertIn("tcp flags & (fin | syn | rst | ack) == syn", text)
        self.assertIn("ip6 saddr fd42:d570::7 ip6 daddr 2001:db8:20::1 udp sport 53", text)

    def test_quarantine_is_additive_drop_only(self):
        text = nft_rules(policy(), quarantine=True)
        self.assertTrue(text.startswith("create table bridge dy_quarantine_7\n"))
        self.assertNotIn("dy_cell_7", text)
        self.assertNotIn("counter accept", text)
        self.assertNotIn("delete", text)
        self.assertIn("hook prerouting priority -310", text)


class BackendTests(unittest.TestCase):
    def setUp(self):
        loader = patch.object(backend, "_load_policy", return_value=policy())
        self.load = loader.start()
        self.addCleanup(loader.stop)
        installer = patch.object(backend, "_install")
        self.install = installer.start()
        self.addCleanup(installer.stop)
        self.controller = LocalCellBackend(7)

    def test_apply_never_verifies_or_enables_activation(self):
        self.assertEqual(self.controller.state, State.CONFIGURED)
        self.assertEqual(self.controller.apply(), State.APPLIED)
        self.install.assert_called_once_with(policy(), quarantine=False)
        with self.assertRaises(ActivationBlocked):
            self.controller.activate()
        with self.assertRaises(ActivationBlocked):
            self.controller.verify()
        self.assertEqual(self.controller.state, State.DEGRADED)
        with self.assertRaises(TypeError):
            self.controller.activate(verified=True)

    def test_even_forged_internal_state_does_not_enable_activation(self):
        self.controller._state = State.VERIFIED
        with self.assertRaises(ActivationBlocked):
            self.controller.activate()

    def test_apply_failure_attempts_quarantine_and_stays_degraded(self):
        self.install.side_effect = [IsolationError("collision"), None]
        with self.assertRaises(IsolationError):
            self.controller.apply()
        self.assertEqual(self.install.call_count, 2)
        self.assertEqual(self.install.call_args.kwargs, {"quarantine": True})
        self.assertEqual(self.controller.state, State.DEGRADED)
        with self.assertRaises(IsolationError):
            self.controller.apply()

    def test_stop_and_emergency_never_remove_rules(self):
        self.controller.apply()
        self.controller.stop()
        self.assertEqual(self.install.call_args.kwargs, {"quarantine": True})
        with self.assertRaises(IsolationError):
            self.controller.apply()
        self.controller.emergency()
        self.assertEqual(self.install.call_args.kwargs, {"quarantine": True})

    def test_quarantine_failure_is_explicit_not_a_false_success(self):
        self.install.side_effect = IsolationError("nft failed")
        with self.assertRaises(IsolationError):
            self.controller.stop()
        self.assertEqual(self.controller.state, State.DEGRADED)
        self.assertIn("NOT confirmed", self.controller.detail)


class TrustedRunnerTests(unittest.TestCase):
    def test_nonlinux_or_nonroot_rejected(self):
        with patch.object(backend.platform, "system", return_value="Darwin"):
            with self.assertRaises(IsolationError):
                backend._local_root()
        with patch.object(backend.platform, "system", return_value="Linux"), \
                patch.object(backend.os, "geteuid", return_value=1000):
            with self.assertRaises(IsolationError):
                backend._local_root()

    def test_root_file_permissions_type_and_link_count_checked(self):
        for mode, uid, links in ((stat.S_IFREG | 0o666, 0, 1),
                                 (stat.S_IFREG | 0o600, 1000, 1),
                                 (stat.S_IFLNK | 0o600, 0, 1),
                                 (stat.S_IFIFO | 0o600, 0, 1),
                                 (stat.S_IFREG | 0o600, 0, 2)):
            with self.subTest(mode=mode, uid=uid, links=links):
                with self.assertRaises(IsolationError):
                    backend._trusted_stat(SimpleNamespace(st_mode=mode, st_uid=uid,
                                                          st_nlink=links))

    def test_runner_argv_and_environment_are_fixed(self):
        # No actual fd, nft, root check or subprocess is used.
        with patch.object(backend, "_local_root"), \
                patch.object(backend, "_open_trusted", return_value=999), \
                patch.object(backend.os, "fstat", return_value=SimpleNamespace(st_mode=0o755)), \
                patch.object(backend.os, "close"), \
                patch.object(backend.subprocess, "run",
                             return_value=SimpleNamespace(returncode=0)) as run:
            backend._install(policy(), quarantine=False)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0],
                         ("/usr/sbin/nft", "--check", "--file", "-"))
        self.assertEqual(run.call_args.args[0], ("/usr/sbin/nft", "--file", "-"))
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        self.assertEqual(run.call_args.kwargs["env"],
                         {"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(run.call_args.kwargs["input"], nft_rules(policy()))
        self.assertEqual(run.call_args.kwargs["timeout"], 5)


if __name__ == "__main__":
    unittest.main()
