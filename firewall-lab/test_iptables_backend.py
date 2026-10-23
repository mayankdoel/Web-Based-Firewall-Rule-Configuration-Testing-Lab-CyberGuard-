"""Run with: python -m unittest test_iptables_backend -v   (safe: never touches the firewall)"""
import unittest

from iptables_backend import (IptablesBackend, LockoutRisk, ValidationError,
                              build_spec, parse_counters, validate_rule)


class ValidationTests(unittest.TestCase):
    def test_valid_rule_builds_expected_command(self):
        r = validate_rule({"id": 101, "chain": "input", "protocol": "TCP",
                           "src": "192.168.1.50", "dport": "22", "action": "accept"})
        self.assertEqual(build_spec(r), ["-p", "tcp", "-s", "192.168.1.50/32", "--dport", "22",
                                         "-m", "comment", "--comment", "cyberguard-101", "-j", "ACCEPT"])

    def test_injection_attempts_rejected(self):
        for bad in ({"src": "1.1.1.1; rm -rf /"}, {"dport": "22 -j ACCEPT"}, {"dport": "70000"},
                    {"dport": "0"}, {"src": "300.1.1.1"}, {"src": "10.0.0.0/33"}, {"chain": "NAT"},
                    {"action": "ALLOW"}, {"protocol": "icmp", "dport": "80"}, {"src": "::1"}):
            data = {"chain": "INPUT", "protocol": "tcp", "action": "DROP", **bad}
            with self.assertRaises(ValidationError, msg=str(bad)):
                validate_rule(data)

    def test_any_means_no_filter(self):
        r = validate_rule({"chain": "INPUT", "protocol": "all", "src": "0.0.0.0/0", "action": "DROP"})
        self.assertEqual(build_spec(r), ["-j", "DROP"])


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.fw = IptablesBackend(lab_mode=True, dry_run=True)

    def test_dry_run_never_executes(self):
        res = self.fw.apply_rule({"chain": "INPUT", "protocol": "tcp", "dport": 80, "action": "ACCEPT"})
        self.assertTrue(res.ok)
        self.assertFalse(res.executed)
        self.assertIn("iptables -w 5 -A INPUT", res.command)
        self.assertFalse(self.fw.live)

    def test_lockout_blocked_without_ssh_rule(self):
        rules = [{"id": 1, "chain": "INPUT", "protocol": "tcp", "src": None, "dst": None,
                  "sport": None, "dport": 80, "action": "ACCEPT"}]
        with self.assertRaises(LockoutRisk):
            self.fw.sync_all(rules, {"INPUT": "DROP", "OUTPUT": "ACCEPT", "FORWARD": "DROP"})

    def test_sync_orders_policies_last(self):
        rules = [{"id": 1, "chain": "INPUT", "protocol": "tcp", "dport": 22, "action": "ACCEPT"}]
        info = self.fw.sync_all(rules, {"INPUT": "DROP", "OUTPUT": "ACCEPT", "FORWARD": "DROP"})
        cmds = [r["command"] for r in info["results"]]
        self.assertIn("-P INPUT DROP", cmds[-3])
        self.assertTrue(any("-A INPUT -p tcp --dport 22" in c for c in cmds))


class ParseTests(unittest.TestCase):
    def test_counter_parsing(self):
        text = ("Chain INPUT (policy DROP 0 packets, 0 bytes)\n"
                "    pkts      bytes target     prot opt in     out     source               destination\n"
                "      12       960 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            "
                "tcp dpt:22 /* cyberguard-101 */\n")
        self.assertEqual(parse_counters(text), {101: {"packets": 12, "bytes": 960}})


if __name__ == "__main__":
    unittest.main()
