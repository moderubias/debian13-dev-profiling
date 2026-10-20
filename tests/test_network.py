import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from d13dp.network import NetworkError, inspect_rules, session, ssh_listeners, unit_text
from d13dp.network_policy import NetworkPolicy, expected_state, load_network_policy, normalize, render_network


class NetworkPolicyTests(unittest.TestCase):
    def test_profile_transition(self):
        minimal, web = (load_network_policy(p) for p in ("minimal", "web"))
        self.assertEqual(minimal.tcp, (22,))
        self.assertEqual(web.tcp, (22, 80, 443))
        self.assertEqual(render_network(web), render_network(load_network_policy("web")))
        self.assertEqual(expected_state(minimal), expected_state(load_network_policy("minimal")))
        for policy in (minimal, web, load_network_policy("docker")):
            text = render_network(policy)
            self.assertNotIn("flush ruleset", text)
            self.assertNotIn("chain forward", text)
            self.assertNotIn("chain output", text)
            self.assertIn("ct state established,related accept", text)
            self.assertIn("ipv6-icmp accept", text)
            self.assertEqual(text.count("tcp dport"), 1)
            self.assertEqual(text.count("udp dport"), 1)

    def test_custom_ports_and_protocols(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "network.toml"
            path.write_text("tcp = [8443, 2222]\nudp = [51820, 53]\nssh_ports = [2222]\n")
            policy = load_network_policy(config=path)
            self.assertEqual(policy.tcp, (2222, 8443))
            self.assertEqual(policy.udp, (53, 51820))
            self.assertIn("elements = { 53, 51820 }", render_network(policy))

    def test_bad_custom_config(self):
        cases = ["tcp = [22]\n", "tcp = [22,22]\nudp=[]\nssh_ports=[22]", "tcp = [true]\nudp=[]\nssh_ports=[22]", "tcp = [80]\nudp=[]\nssh_ports=[22]", "tcp = [22]\nudp=[]\nssh_ports=[]", "tcp = [22]\nudp=[65536]\nssh_ports=[22]", "tcp = [22]\nudp=53\nssh_ports=[22]", "tcp = [22]\nudp=[]\nssh_ports=[22]\nunknown=1"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "network.toml"
            for text in cases:
                with self.subTest(text=text):
                    path.write_text(text)
                    with self.assertRaises(ValueError):
                        load_network_policy(config=path)

    def test_normalize_retains_semantic_drift_and_rule_order(self):
        original = expected_state(load_network_policy("web"))
        with_handles = copy.deepcopy(original)
        for index, item in enumerate(with_handles):
            next(iter(item.values()))["handle"] = index + 1
        self.assertEqual(normalize(with_handles), original)
        changed = copy.deepcopy(original)
        changed[-1]["rule"]["expr"] = [{"accept": None}]
        self.assertNotEqual(normalize(changed), original)
        reversed_rules = original[:-2] + [original[-1], original[-2]]
        self.assertNotEqual(normalize(reversed_rules), original)

    def test_custom_port_contents_do_not_change_object_order(self):
        for tcp, udp in (((22,), (53,)), ((22, 443), (1,)), ((22,), ())):
            live = expected_state(NetworkPolicy("custom", tcp, udp))
            names = [item["set"]["name"] for item in live if "set" in item]
            self.assertEqual(names, ["allowed_tcp", "allowed_udp"])


class NetworkInspectionTests(unittest.TestCase):
    def test_foreign_input_and_ingress_conflicts(self):
        for family, hook in (("inet", "input"), ("ip", "prerouting"), ("ip6", "input"), ("netdev", "ingress")):
            with self.subTest(family=family, hook=hook):
                _, issues = inspect_rules([{"chain": {"family": family, "table": "filter", "name": "custom", "type": "filter", "hook": hook, "policy": "accept"}}])
                self.assertTrue(issues)

    def test_forwarding_is_preserved_but_not_managed(self):
        own, issues = inspect_rules([{"chain": {"family": "ip", "table": "docker-bridges", "name": "forward", "hook": "forward", "policy": "drop"}}])
        self.assertEqual((own, issues), ([], []))

    def test_fail2ban_drop_only_exception(self):
        chain = {"chain": {"family": "inet", "table": "f2b-table", "name": "f2b-chain", "type": "filter", "hook": "input", "policy": "accept"}}
        rule = {"rule": {"family": "inet", "table": "f2b-table", "chain": "f2b-chain", "expr": [{"match": {"op":"==", "left":{"payload":{"protocol":"tcp","field":"dport"}}, "right":22}}, {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@bans"}}, {"reject": None}]}}
        address_set = {"set":{"family":"inet","table":"f2b-table","name":"bans","type":"ipv4_addr"}}
        self.assertFalse(inspect_rules([chain, rule, address_set])[1])
        self.assertTrue(inspect_rules([chain, rule])[1])
        bad = copy.deepcopy(rule)
        bad["rule"]["expr"][-1] = {"accept": None}
        self.assertTrue(inspect_rules([chain, bad])[1])
        self.assertTrue(inspect_rules([rule])[1])

    def test_ruleset_shape_rejected(self):
        for items in ([None], [{"table": None}], [{"table": {}, "chain": {}}]):
            with self.subTest(items=items), self.assertRaises(NetworkError):
                inspect_rules(items)

    def test_ssh_session_validation(self):
        self.assertEqual(session("192.0.2.1 1234 192.0.2.2 22")[3], 22)
        self.assertEqual(session("2001:db8::1 1234 2001:db8::2 2222")[3], 2222)
        self.assertIsNone(session(None))
        for value in ("invalid", "not-an-ip 1234 192.0.2.2 22", "192.0.2.1 0 192.0.2.2 22"):
            with self.subTest(value=value), self.assertRaises(NetworkError):
                session(value)

    @patch("d13dp.network.run")
    def test_effective_and_listening_ssh_ports(self, run):
        run.side_effect = ["port 22\nport 2222", 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\nLISTEN 0 128 [::]:2222 [::]:* users:(("sshd",pid=1,fd=4))']
        self.assertEqual(ssh_listeners(), {22, 2222})
        run.side_effect = ["port 2222", 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))']
        with self.assertRaises(NetworkError):
            ssh_listeners()

    def test_systemd_unit_has_safe_stop_and_boot_recovery(self):
        unit = unit_text("/opt/d13dp/bin/python -I -m d13dp.network")
        self.assertIn("ExecStop=/usr/bin/true", unit)
        self.assertIn("ExecStartPre=/opt/d13dp/bin/python -I -m d13dp.network recover", unit)
        self.assertIn("Before=network-pre.target shutdown.target", unit)
        self.assertNotIn("flush", unit)


class ConfirmationTests(unittest.TestCase):
    def controller_with(self, transaction):
        from contextlib import nullcontext
        from d13dp.network import Controller
        controller = Controller()
        controller.locked = lambda: nullcontext()
        controller.read_state = lambda: {"pending": "a" * 32}
        controller.load_transaction = lambda identifier: transaction
        return controller

    @patch("d13dp.network.host_preflight")
    def test_original_ssh_session_cannot_confirm(self, host):
        tx = {"session": ["192.0.2.2", 1234, "192.0.2.1", 22], "policy": {"ssh_ports": [22]}}
        controller = self.controller_with(tx)
        with patch.dict(os.environ, SSH_CONNECTION="192.0.2.2 1234 192.0.2.1 22"), self.assertRaisesRegex(NetworkError, "new SSH connection"):
            controller.confirm("a" * 32)

    @patch("d13dp.network.host_preflight")
    def test_console_confirmation_is_explicit(self, host):
        controller = self.controller_with({"session": None})
        with self.assertRaisesRegex(NetworkError, "explicit --console"):
            controller.confirm("a" * 32)

    @patch("d13dp.network.host_preflight")
    @patch("d13dp.network.boot_id", return_value="boot")
    @patch("d13dp.network.time.monotonic", return_value=100)
    def test_expired_deadline_rolls_back(self, monotonic, boot, host):
        controller = self.controller_with({"session": None, "boot": "boot", "deadline": 99})
        with patch.object(controller, "_rollback") as rollback, self.assertRaisesRegex(NetworkError, "deadline expired"):
            controller.confirm("a" * 32, console=True)
        rollback.assert_called_once_with("a" * 32)

    @patch("d13dp.network.host_preflight")
    @patch("d13dp.network.boot_id", return_value="new-boot")
    def test_new_boot_cannot_commit_old_pending_state(self, boot, host):
        controller = self.controller_with({"session": None, "boot": "old-boot", "deadline": 999999999})
        with patch.object(controller, "_rollback") as rollback, self.assertRaisesRegex(NetworkError, "deadline expired"):
            controller.confirm("a" * 32, console=True)
        rollback.assert_called_once()


class ApplyValidationTests(unittest.TestCase):
    def test_non_integer_timeout_is_rejected_before_host_mutation(self):
        from d13dp.network import Controller
        for timeout in (120.5, True, '120', 0, 601):
            with self.subTest(timeout=timeout), self.assertRaises(NetworkError):
                Controller().apply(load_network_policy('minimal'), '', timeout=timeout)
