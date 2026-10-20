"""Strict parsing for privileged durable state; corruption never becomes an action."""
import json
import ipaddress
import math
from pathlib import Path

from . import migration
from .network_policy import NetworkPolicy, declared_policy, expected_state, render_network


class JournalError(ValueError):
    pass


def load_json(path: Path) -> dict:
    def invalid(value):
        raise JournalError(f"Non-finite JSON number: {value}")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise JournalError(f"Duplicate journal key: {key}")
            result[key] = value
        return result
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise JournalError("Journal exceeds the 16 MiB limit")
        value = json.loads(path.read_text(encoding="utf-8"), parse_constant=invalid, object_pairs_hook=unique)
        if not isinstance(value, dict):
            raise JournalError("Journal root must be an object")
        return value
    except (RecursionError, UnicodeError) as exc:
        raise JournalError(f"Unreadable journal {path}: {exc}") from exc


def committed_record(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) not in ({"policy", "effective"}, {"policy", "effective", "legacy"}):
        raise JournalError("Invalid committed record")
    if "legacy" in value:
        migration.validate(value["legacy"])
    policy = declared_policy(value["policy"])
    if value["effective"] != expected_state(policy):
        raise JournalError("Committed effective state does not match its policy")
    return value


def state_record(value: dict) -> dict:
    if type(value.get("version")) is not int or value["version"] != 1 or set(value) != {"version", "committed", "pending"}:
        raise JournalError("Unsupported network journal schema")
    committed_record(value["committed"])
    pending = value["pending"]
    if pending is not None:
        import re
        if not isinstance(pending, str) or not re.fullmatch(r"[a-f0-9]{32}", pending):
            raise JournalError("Invalid pending transaction identifier")
    return value


def live_policy(objects: list[dict]) -> NetworkPolicy | None:
    if objects == []:
        return None
    if not isinstance(objects, list):
        raise JournalError("Invalid previous effective state")
    sets = {}
    for item in objects:
        if not isinstance(item, dict):
            raise JournalError("Invalid previous nft object")
        obj = item.get("set", {})
        if obj.get("name") in {"allowed_tcp", "allowed_udp"}:
            sets[obj["name"]] = obj.get("elem", [])
    if set(sets) != {"allowed_tcp", "allowed_udp"}:
        raise JournalError("Missing managed port sets")
    policy = NetworkPolicy("custom", tuple(sets["allowed_tcp"]), tuple(sets["allowed_udp"]), ())
    if objects != expected_state(policy):
        raise JournalError("Unsupported previous firewall structure")
    return policy


def rollback_text(objects: list[dict]) -> str:
    from .network_policy import TABLE
    policy = live_policy(objects)
    return render_network(policy) if policy is not None else f"destroy table inet {TABLE}\n"


def transaction_record(value: dict, identifier: str) -> dict:
    required = {"id", "before", "before_config", "restore", "before_live", "after", "config", "policy", "session", "boot", "deadline", "timeout"}
    if set(value) not in (required, required | {"migration"}) or value["id"] != identifier:
        raise JournalError("Invalid transaction identity or fields")
    if "migration" in value:
        migration.validate(value["migration"])
        if value["before"] is not None or value["before_live"] != []:
            raise JournalError("Migration requires an unowned initial state")
    previous = committed_record(value["before"])
    expected_before = render_network(declared_policy(previous["policy"])) if previous else "# No committed d13dp network policy.\n"
    if value["before_config"] != expected_before:
        raise JournalError("Previous persistent file is inconsistent with the journal")
    policy = declared_policy(value["policy"])
    if value["after"] != expected_state(policy) or value["config"] != render_network(policy):
        raise JournalError("Candidate is inconsistent with its declared policy")
    live_policy(value["before_live"])
    if not isinstance(value["restore"], str):
        raise JournalError("Invalid legacy restoration field")
    # The saved raw nft text is retained for old-journal compatibility, never executed.
    if not isinstance(value["boot"], str) or not value["boot"]:
        raise JournalError("Missing boot identity")
    if type(value["timeout"]) is not int or not 15 <= value["timeout"] <= 600:
        raise JournalError("Invalid timeout")
    if type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"]) or value["deadline"] < 0:
        raise JournalError("Invalid monotonic deadline")
    connection = value["session"]
    if connection is not None:
        if not isinstance(connection, list) or len(connection) != 4:
            raise JournalError("Invalid original SSH connection")
        try:
            for index in (0, 2):
                if not isinstance(connection[index], str) or str(ipaddress.ip_address(connection[index])) != connection[index]:
                    raise ValueError("Invalid IP address")
            for index in (1, 3):
                if type(connection[index]) is not int or not 1 <= connection[index] <= 65535:
                    raise ValueError("Invalid SSH port")
        except ValueError as exc:
            raise JournalError("Invalid original SSH connection") from exc
    return value
