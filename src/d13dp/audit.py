from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import re
import subprocess


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    status: str
    detail: str
    action: str


def run_command(*args: str) -> tuple[int, str]:
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return result.returncode, result.stdout.strip() if result.returncode == 0 else (result.stderr.strip() or result.stdout.strip())


def _ssh_options(output: str) -> dict[str, str]:
    values = {}
    for line in output.splitlines():
        fields = line.split(None, 1)
        if len(fields) == 2:
            values[fields[0]] = fields[1].strip()
    return values


def _os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    result = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, val = line.split("=", 1)
                result[key] = val.strip('"')
    except (OSError, UnicodeError):
        pass
    return result


def collect() -> dict:
    result: dict = {"host": {}, "findings": [], "notes": []}
    findings: list[Finding] = []
    os_data = _os_release()
    result["host"] = {"id": os_data.get("ID", "unknown"), "version": os_data.get("VERSION_ID", "unknown")}
    if result["host"] != {"id": "debian", "version": "13"}:
        findings.append(Finding("os", "high", "unsupported", "This project targets Debian 13 only", "Do not apply generated configurations to this host"))
    else:
        findings.append(Finding("os", "info", "pass", "Debian 13 detected", ""))

    ssh_code, ssh_data = run_command("/usr/sbin/sshd", "-T")
    if ssh_code != 0:
        findings.append(Finding("ssh", "high", "unknown", f"Unable to inspect sshd: {ssh_data[:180]}", "Check OpenSSH installation and privileges"))
    else:
        ssh = _ssh_options(ssh_data)
        pw = ssh.get("passwordauthentication") == "no" and ssh.get("kbdinteractiveauthentication") == "no"
        findings.append(Finding("ssh-passwords", "high", "pass" if pw else "fail", f"PasswordAuthentication={ssh.get('passwordauthentication', 'unknown')}; KbdInteractiveAuthentication={ssh.get('kbdinteractiveauthentication', 'unknown')}", "Disable password-based authentication after confirming working key-based access" if not pw else ""))
        root = ssh.get("permitrootlogin", "unknown")
        findings.append(Finding("ssh-root", "medium", "pass" if root in {"no", "prohibit-password", "without-password", "forced-commands-only"} else "fail", f"PermitRootLogin={root}", "Restrict root login or use an unprivileged administrative account"))
        x11 = ssh.get("x11forwarding")
        findings.append(Finding("ssh-x11", "low", "pass" if x11 == "no" else "fail", f"X11Forwarding={x11}", "Disable X11 forwarding unless required"))
        result["host"]["sshd_port"] = ssh.get("port", "unknown")

    nft_code, nft = run_command("nft", "-j", "list", "ruleset")
    if nft_code != 0:
        findings.append(Finding("firewall", "high", "unknown", f"Unable to inspect nftables: {nft[:180]}", "Run as root and check nftables installation"))
    else:
        try:
            ruleset = json.loads(nft)
            if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
                raise ValueError("Missing nftables array")
            entries = ruleset["nftables"]
            if not all(isinstance(entry, dict) for entry in entries):
                raise ValueError("Invalid nftables entry")
            families = set()
            tables = []
            for entry in entries:
                chain = entry.get("chain", {})
                table = entry.get("table", {})
                if not isinstance(chain, dict) or not isinstance(table, dict):
                    raise ValueError("Invalid chain or table")
                if chain.get("type") == "filter" and chain.get("hook") == "input" and chain.get("policy") == "drop":
                    family = chain.get("family")
                    if isinstance(family, str):
                        families.add(family)
                if table:
                    tables.append(f"table {table.get('family', 'unknown')} {table.get('name', 'unknown')}")
            input_drop = "inet" in families or {"ip", "ip6"} <= families
        except (ValueError, RecursionError) as exc:
            findings.append(Finding("firewall", "high", "unknown", f"Unable to parse nftables JSON: {exc}", "Inspect nft -j list ruleset manually"))
        else:
            findings.append(Finding("firewall-input", "high", "pass" if input_drop else "review", "Found default-drop input base chains covering IPv4 and IPv6" if input_drop else "Default-drop input chains covering both IPv4 and IPv6 not detected; custom policies may still provide filtering", "Review the full firewall ruleset and published container ports"))
            result["host"]["nft_tables"] = tables

    f2b_code, f2b = run_command("fail2ban-client", "ping")
    findings.append(Finding("fail2ban", "medium", "pass" if f2b_code == 0 and "pong" in f2b else "review", "Daemon responds to ping" if f2b_code == 0 else f"Daemon not responding: {f2b[:180]}", "Review active SSH jail and its nftables ban action"))

    apt_code, apt = run_command("apt-config", "dump")
    lists = re.search(r'^APT::Periodic::Update-Package-Lists\s+"1";', apt, flags=re.M) is not None
    periodic_enabled = re.search(r'^APT::Periodic::Enable\s+"0";', apt, flags=re.M) is None
    period = re.search(r'^APT::Periodic::Unattended-Upgrade\s+"1";', apt, flags=re.M) is not None
    reboot = re.search(r'^Unattended-Upgrade::Automatic-Reboot\s+"false";', apt, flags=re.M) is not None
    pkg_code, pkg_info = run_command("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
    installed = pkg_code == 0 and pkg_info.strip() == "install ok installed"
    updates_ok = apt_code == 0 and installed and period and lists and periodic_enabled
    findings.append(Finding("security-updates", "high", "pass" if updates_ok else "review", f"unattended-upgrades installed={installed}; daily upgrades={period}; daily package lists={lists}; periodic enabled={periodic_enabled}; reboot explicitly disabled={reboot}", "Install unattended-upgrades and review origin / reboot policies"))

    aa_code, aa = run_command("aa-status", "--enabled")
    findings.append(Finding("apparmor", "medium", "pass" if aa_code == 0 else "review", "AppArmor enabled" if aa_code == 0 else "AppArmor state not verified", "Check enforcement and service-specific profiles before changing MAC policies"))

    audit_code, auditd = run_command("systemctl", "is-active", "auditd")
    findings.append(Finding("auditd", "medium", "pass" if audit_code == 0 and auditd == "active" else "review", f"auditd={auditd}", "Consider auditd with a disk/retention budget"))

    ss_code, listeners = run_command("ss", "-lnt")
    if ss_code == 0:
        result["host"]["tcp_listeners"] = listeners.splitlines()[:50]
    else:
        result["notes"].append(f"Cannot inspect TCP listeners: {listeners[:180]}")

    result["findings"] = [asdict(f) for f in findings]
    result["notes"] += [
        "This audit is local and not a penetration test or guarantee of security.",
        "Off-site backups, credentials, cloud firewall, DDoS capacity, application security, and recovery console need independent verification.",
        "Docker-published ports can bypass assumptions based only on host input-chain filtering.",
    ]
    return result
