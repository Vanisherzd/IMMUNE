import pathlib
import sys
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from ops_safety import diagnostic_argv  # noqa: E402


class NetworkDiagnosticPolicyTest(unittest.TestCase):
    def test_ip_read_only_forms_are_accepted(self):
        cases = (
            "ip addr show",
            "ip addr show eth0",
            "ip address list eth0.10",
            "ip a show veth0@if2",
            "ip route",
            "ip r list",
            "ip link show",
            "ip l list br-0:1",
            "ip neigh",
            "ip n show eth0",
        )
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(diagnostic_argv(command), command.split())

    def test_ss_read_only_options_are_accepted(self):
        cases = ("ss", "ss -ltnp", "ss -l -t -u -n -p -a -s -i -e -4 -6")
        for command in cases:
            with self.subTest(command=command):
                self.assertEqual(diagnostic_argv(command), command.split())

    def test_getent_network_databases_are_accepted(self):
        for database in ("hosts", "ahosts", "ahostsv4", "ahostsv6", "services"):
            command = f"getent {database} edge-victim-app"
            with self.subTest(database=database):
                self.assertEqual(diagnostic_argv(command), command.split())

    def test_single_name_lookup_commands_are_accepted(self):
        for command in ("nslookup edge-victim-app", "dig example.com", "host 127.0.0.1"):
            with self.subTest(command=command):
                self.assertEqual(diagnostic_argv(command), command.split())

    def test_network_configuration_files_remain_readable(self):
        for command in ("cat /etc/hosts", "cat /etc/resolv.conf", "cat /proc/net/tcp", "head /proc/net/udp"):
            with self.subTest(command=command):
                self.assertEqual(diagnostic_argv(command), command.split())

    def test_mutating_or_expansive_ip_forms_are_denied(self):
        cases = (
            "ip addr add 10.0.0.2/24 dev eth0",
            "ip link set eth0 down",
            "ip route del default",
            "ip netns exec red ip addr",
            "ip addr flush dev eth0",
            "ip -batch commands",
        )
        for command in cases:
            with self.subTest(command=command), self.assertRaises(ValueError) as denied:
                diagnostic_argv(command)
            self.assertIn("ip addr/address/a, route/r, link/l, or neigh/n", str(denied.exception))

    def test_ss_kill_filters_and_other_options_are_denied(self):
        for command in ("ss -K", "ss --kill", "ss -ltnp state listening", "ss --tcp"):
            with self.subTest(command=command), self.assertRaises(ValueError) as denied:
                diagnostic_argv(command)
            self.assertIn("ss options are limited to", str(denied.exception))

    def test_non_network_getent_database_is_denied(self):
        with self.assertRaises(ValueError):
            diagnostic_argv("getent passwd root")

    def test_lookup_servers_and_options_are_denied(self):
        for command in ("dig @8.8.8.8 example.com", "dig +short", "nslookup -type=any x", "host -a"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                diagnostic_argv(command)


if __name__ == "__main__":
    unittest.main()
