"""Narrow host-input policy; independent of the read-only hardening renderer."""
from dataclasses import dataclass
from pathlib import Path
import tomllib

TABLE = "d13dp_network"
OWNER = "d13dp-network-v1"


@dataclass(frozen=True)
class NetworkPolicy:
    name: str
    tcp: tuple[int, ...]
    udp: tuple[int, ...] = ()
    ssh_ports: tuple[int, ...] = (22,)


def ports(value: object, label: str, empty: bool = True) -> tuple[int, ...]:
    if not isinstance(value, list) or (not value and not empty):
        raise ValueError(f"{label} must be an array of ports")
    if not all(type(p) is int and 1 <= p <= 65535 for p in value):
        raise ValueError(f"{label} ports must be integers from 1 to 65535")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} contains duplicate ports")
    return tuple(sorted(value))


def load_network_policy(profile: str = "minimal", config: Path | None = None) -> NetworkPolicy:
    if config is None:
        if profile not in {"minimal", "web", "docker"}:
            raise ValueError("Unsupported network profile")
        return NetworkPolicy(profile, (22,) if profile == "minimal" else (22, 80, 443))
    with config.open("rb") as stream:
        data = tomllib.load(stream)
    if set(data) != {"tcp", "udp", "ssh_ports"}:
        raise ValueError("Custom network configuration requires exactly tcp, udp, and ssh_ports arrays")
    policy = NetworkPolicy("custom", ports(data["tcp"], "tcp"), ports(data["udp"], "udp"), ports(data["ssh_ports"], "ssh_ports", empty=False))
    if not set(policy.ssh_ports) <= set(policy.tcp):
        raise ValueError("Every declared SSH port must remain allowed over TCP")
    return policy


def render_network(policy: NetworkPolicy) -> str:
    lines = [f"destroy table inet {TABLE}", f"table inet {TABLE} {{", f'    comment "{OWNER}"']
    for protocol, values in (("tcp", policy.tcp), ("udp", policy.udp)):
        lines.extend([f"    set allowed_{protocol} {{", "        type inet_service"])
        if values:
            lines.append("        elements = { " + ", ".join(map(str, values)) + " }")
        lines.append("    }")
    lines.extend([
        "    chain input {", "        type filter hook input priority filter; policy drop;",
        '        iifname "lo" accept', "        ct state invalid drop",
        "        ct state established,related accept", "        ip protocol icmp accept",
        "        meta l4proto ipv6-icmp accept", "        tcp dport @allowed_tcp accept",
        "        udp dport @allowed_udp accept", "    }", "}", "",
    ])
    return "\n".join(lines)


def expected_state(policy: NetworkPolicy) -> list[dict]:
    """Exact nft JSON objects, excluding kernel-assigned handles."""
    result = [{"table": {"family": "inet", "name": TABLE, "comment": OWNER}},
              {"chain": {"family": "inet", "table": TABLE, "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}]
    for protocol, values in (("tcp", policy.tcp), ("udp", policy.udp)):
        result.append({"set": {"family": "inet", "table": TABLE, "name": f"allowed_{protocol}", "type": "inet_service", "elem": list(values)}})
    expressions = [
        [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": None}],
        [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "invalid"}}, {"drop": None}],
        [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": None}],
        [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "protocol"}}, "right": "icmp"}}, {"accept": None}],
        [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "ipv6-icmp"}}, {"accept": None}],
    ]
    for protocol in ("tcp", "udp"):
        expressions.append([{"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": f"@allowed_{protocol}"}}, {"accept": None}])
    result.extend({"rule": {"family": "inet", "table": TABLE, "chain": "input", "expr": expr}} for expr in expressions)
    return normalize(result)


def normalize(objects: list[dict]) -> list[dict]:
    """Retain rule order and all unknown semantics; ignore only object handles."""
    definitions, rules = [], []
    for item in objects:
        kind, value = next(iter(item.items()))
        obj = {key: val for key, val in value.items() if key != "handle"}
        if kind == "set":
            obj["elem"] = sorted(obj.get("elem", []))
        (rules if kind == "rule" else definitions).append({kind: obj})
    def key(item):
        kind, value = next(iter(item.items()))
        return kind, value.get("family", ""), value.get("table", ""), value.get("name", "")
    return sorted(definitions, key=key) + rules
