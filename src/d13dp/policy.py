from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import tomllib


PROFILE_DIR = Path(__file__).resolve().parent / "profiles"


@dataclass(frozen=True)
class Policy:
    name: str
    description: str
    ssh_port: int
    root_login: str
    login_grace_seconds: int
    firewall_mode: str
    inbound_tcp: tuple[int, ...]
    modules: frozenset[str]


def load_policy(name: str, directory: Path = PROFILE_DIR) -> Policy:
    if name not in {"minimal", "web", "docker"}:
        raise ValueError(f"Unsupported profile: {name}")
    return load_policy_file(directory / f"{name}.toml")


def _table(value: object, label: str, required: set[str], optional: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a TOML table")
    missing = required - value.keys()
    unknown = value.keys() - required - (optional or set())
    if missing:
        raise ValueError(f"Missing {label} keys: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"Unknown {label} keys: {', '.join(sorted(unknown))}")
    return value


def load_policy_file(path: Path) -> Policy:
    with path.open("rb") as handle:
        cfg = tomllib.load(handle)
    _table(cfg, "profile", {"name", "description", "ssh", "firewall", "modules"})
    if not isinstance(cfg["name"], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", cfg["name"]):
        raise ValueError("Profile name must be a safe lowercase identifier")
    if not isinstance(cfg["description"], str) or not cfg["description"].strip():
        raise ValueError("Profile description must be a non-empty string")
    ssh = _table(cfg["ssh"], "ssh", {"port", "root_login", "login_grace_seconds"})
    firewall = _table(cfg["firewall"], "firewall", {"mode", "inbound_tcp"})
    ports = firewall["inbound_tcp"]
    if not isinstance(ports, list) or not ports or not all(type(p) is int and 1 <= p <= 65535 for p in ports):
        raise ValueError("Inbound TCP ports must be a non-empty array of integers from 1 to 65535")
    if len(ports) != len(set(ports)):
        raise ValueError("Duplicated inbound TCP ports")
    if not (type(ssh["port"]) is int and 1 <= ssh["port"] <= 65535):
        raise ValueError("Invalid SSH port")
    if ssh["port"] not in ports:
        raise ValueError("SSH port must appear in the allowed inbound TCP ports")
    if not isinstance(ssh["root_login"], str) or ssh["root_login"] not in {"no", "prohibit-password"}:
        raise ValueError("Unsafe root-login policy")
    if not (type(ssh["login_grace_seconds"]) is int and 10 <= ssh["login_grace_seconds"] <= 120):
        raise ValueError("Invalid LoginGraceTime")
    if not isinstance(firewall["mode"], str) or firewall["mode"] not in {"standalone", "external"}:
        raise ValueError("Invalid firewall mode")
    allowed_modules = {"ssh", "nftables", "fail2ban", "unattended_upgrades", "sysctl"}
    flags = _table(cfg["modules"], "modules", set(), allowed_modules)
    if not all(type(enabled) is bool for enabled in flags.values()):
        raise ValueError("Module flags must be booleans")
    modules = frozenset(k for k, enabled in flags.items() if enabled)
    if firewall["mode"] == "external" and "nftables" in modules:
        raise ValueError("External firewall mode must not generate standalone rules")
    return Policy(
        name=cfg["name"],
        description=cfg["description"],
        ssh_port=ssh["port"],
        root_login=ssh["root_login"],
        login_grace_seconds=ssh["login_grace_seconds"],
        firewall_mode=firewall["mode"],
        inbound_tcp=tuple(ports),
        modules=modules,
    )
