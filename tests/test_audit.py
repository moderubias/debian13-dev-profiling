import json
import subprocess
import unittest
from unittest.mock import patch

from d13dp.audit import _ssh_options, collect, run_command


class AuditTests(unittest.TestCase):
    def test_ssh_options(self):
        self.assertEqual(_ssh_options("permitrootlogin without-password\npasswordauthentication no"), {"permitrootlogin": "without-password", "passwordauthentication": "no"})

    @patch("d13dp.audit._os_release")
    @patch("d13dp.audit.run_command")
    def test_baseline_findings(self, command, os_release):
        os_release.return_value = {"ID": "debian", "VERSION_ID": "13"}
        outputs = {
            "/usr/sbin/sshd": (0, "port 22\npermitrootlogin without-password\npasswordauthentication no\nkbdinteractiveauthentication no\nx11forwarding no"),
            "nft": (0, json.dumps({"nftables": [{"chain": {"family": "inet", "name": "custom_input", "type": "filter", "hook": "input", "policy": "drop"}}]})),
            "fail2ban-client": (0, "Server replied: pong"),
            "apt-config": (0, 'APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Update-Package-Lists "1";\nUnattended-Upgrade::Automatic-Reboot "false";'),
            "dpkg-query": (0, "install ok installed"),
            "aa-status": (0, ""),
            "systemctl": (0, "active"),
            "ss": (0, "State Recv-Q Send-Q Local Address:Port")
        }
        command.side_effect = lambda *a: outputs[a[0]]
        findings = {f["id"]: f for f in collect()["findings"]}
        self.assertEqual(findings["ssh-passwords"]["status"], "pass")
        self.assertEqual(findings["firewall-input"]["status"], "pass")
        self.assertEqual(findings["security-updates"]["status"], "pass")


class AuditFailureTests(unittest.TestCase):
    def collect_with(self, nft=(127, "missing"), apt=(127, "missing"), ssh=(127, "missing")):
        outputs = {"nft": nft, "apt-config": apt, "/usr/sbin/sshd": ssh, "dpkg-query": (0, "install ok installed")}
        with patch("d13dp.audit._os_release", return_value={"ID": "debian", "VERSION_ID": "13"}), patch("d13dp.audit.run_command", side_effect=lambda *a: outputs.get(a[0], (127, "missing"))):
            return {f["id"]: f for f in collect()["findings"]}

    def test_firewall_families_and_chain_names(self):
        for families, expected in [( ["inet"], "pass"), (["ip", "ip6"], "pass"), (["ip"], "review"), (["bridge"], "review"), ([], "review")]:
            with self.subTest(families=families):
                data = {"nftables": [{"chain": {"family": family, "name": "unusual_name", "type": "filter", "hook": "input", "policy": "drop"}} for family in families]}
                findings = self.collect_with(nft=(0, json.dumps(data)))
                self.assertEqual(findings["firewall-input"]["status"], expected)

    def test_malformed_nft_is_unknown(self):
        for data in ("not json", "[]", '{"nftables": [null]}', '{"nftables": [{"chain": []}]}'):
            with self.subTest(data=data):
                self.assertEqual(self.collect_with(nft=(0, data))["firewall"]["status"], "unknown")

    def test_missing_commands_never_pass(self):
        self.assertTrue(all(f["status"] != "pass" for key, f in self.collect_with().items() if key != "os"))

    def test_updates_need_package_lists_and_enabled_periodic_jobs(self):
        for config in ('APT::Periodic::Unattended-Upgrade "1";', 'APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Enable "0";'):
            with self.subTest(config=config):
                self.assertEqual(self.collect_with(apt=(0, config))["security-updates"]["status"], "review")

    def test_missing_ssh_auth_options_do_not_pass(self):
        findings = self.collect_with(ssh=(0, "port 22"))
        self.assertEqual(findings["ssh-passwords"]["status"], "fail")

    @patch("d13dp.audit.subprocess.run", side_effect=FileNotFoundError("missing"))
    def test_command_missing(self, command):
        self.assertEqual(run_command("missing"), (127, "missing"))

    @patch("d13dp.audit.subprocess.run", side_effect=subprocess.TimeoutExpired("hung", 12))
    def test_command_timeout(self, command):
        code, detail = run_command("hung")
        self.assertEqual(code, 127)
        self.assertIn("timed out", detail)


if __name__ == "__main__":
    unittest.main()
