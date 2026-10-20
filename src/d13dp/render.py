from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import tempfile

from .policy import Policy


GENERATED_PATHS = frozenset({
    "ssh/00-d13dp-hardening.conf",
    "nft/d13dp.nft",
    "fail2ban/52-d13dp-sshd.local",
    "apt/52-d13dp-security",
    "apt/90-d13dp-periodic",
    "sysctl/52-d13dp.conf",
})


def _ssh(policy: Policy) -> str:
    return (
        f"Port {policy.ssh_port}\n"
        f"PermitRootLogin {policy.root_login}\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PubkeyAuthentication yes\n"
        "X11Forwarding no\n"
        f"LoginGraceTime {policy.login_grace_seconds}\n"
    )


def _nft(policy: Policy) -> str:
    ports = ", ".join(str(port) for port in sorted(policy.inbound_tcp))
    selector = f"{{ {ports} }}" if len(policy.inbound_tcp) > 1 else ports
    return (
        "destroy table inet d13dp_filter\n"
        "table inet d13dp_filter {\n"
        "    chain input {\n"
        "        type filter hook input priority filter; policy drop;\n"
        '        iifname "lo" accept\n'
        "        ct state invalid drop\n"
        "        ct state established,related accept\n"
        "        ip protocol icmp accept\n"
        "        meta l4proto ipv6-icmp accept\n"
        f"        tcp dport {selector} accept\n"
        "    }\n"
        "    chain forward {\n"
        "        type filter hook forward priority filter; policy drop;\n"
        "    }\n"
        "    chain output {\n"
        "        type filter hook output priority filter; policy accept;\n"
        "    }\n"
        "}\n"
    )


def _fail2ban(policy: Policy) -> str:
    return (
        "[sshd]\n"
        "enabled = true\n"
        "backend = systemd\n"
        f"port = {policy.ssh_port}\n"
        "maxretry = 5\n"
        "findtime = 10m\n"
        "bantime = 1h\n"
        "banaction = nftables-multiport\n"
    )


def generate(policy: Policy) -> dict[str, str]:
    files: dict[str, str] = {}
    if "ssh" in policy.modules:
        files["ssh/00-d13dp-hardening.conf"] = _ssh(policy)
    if "nftables" in policy.modules:
        files["nft/d13dp.nft"] = _nft(policy)
    if "fail2ban" in policy.modules:
        files["fail2ban/52-d13dp-sshd.local"] = _fail2ban(policy)
    if "unattended_upgrades" in policy.modules:
        files["apt/52-d13dp-security"] = (
            'Unattended-Upgrade::Automatic-Reboot "false";\n'
            'Unattended-Upgrade::Remove-Unused-Dependencies "false";\n'
        )
        files["apt/90-d13dp-periodic"] = (
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n'
        )
    if "sysctl" in policy.modules:
        files["sysctl/52-d13dp.conf"] = (
            "net.ipv4.tcp_syncookies = 1\n"
            "net.ipv4.icmp_echo_ignore_broadcasts = 1\n"
            "fs.protected_hardlinks = 1\n"
            "fs.protected_symlinks = 1\n"
        )
    return files


def digest_manifest(files: dict[str, str]) -> dict[str, str]:
    return {name: sha256(content.encode("utf-8")).hexdigest() for name, content in sorted(files.items())}


def _check_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing to write through symlink directory: {path}")
    if path.exists() and not path.is_dir():
        raise ValueError(f"Output parent is not a directory: {path}")


def write_generated(files: dict[str, str], destination: Path, replace: bool = False) -> dict[str, str]:
    # Keep symlinks visible: resolve() would hide them before validation.
    destination = Path(os.path.abspath(destination))
    for directory in (*reversed(destination.parents), destination):
        _check_directory(directory)
    changes = {}
    for name, content in sorted(files.items()):
        relative = Path(name)
        if not name or relative.is_absolute() or ".." in relative.parts or relative == Path("."):
            raise ValueError(f"Invalid generated path: {name!r}")
        target = destination / relative
        for parent in reversed(target.parents):
            _check_directory(parent)
        if target.is_symlink():
            raise ValueError(f"Refusing to write through symlink: {target}")
        if target.is_file():
            old = target.read_bytes()
            if old == content.encode("utf-8"):
                changes[name] = "unchanged"
                continue
            if not replace:
                raise ValueError(f"Refusing to overwrite modified file without --replace: {target}")
        elif target.exists():
            raise ValueError(f"Refusing to overwrite non-file: {target}")
    stale = [name for name in sorted(GENERATED_PATHS - files.keys())
             if (destination / name).exists() or (destination / name).is_symlink()]
    if stale:
        raise ValueError(f"Output contains files omitted by this profile: {', '.join(stale)}. Use a fresh output directory")
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(files.items()):
        if changes.get(name) == "unchanged":
            continue
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=target.parent, delete=False) as temp:
                temp_path = Path(temp.name)
                temp.write(content)
                temp.flush()
                os.fsync(temp.fileno())
            temp_path.chmod(0o644)
            os.replace(temp_path, target)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        changes[name] = "written"
    return changes
