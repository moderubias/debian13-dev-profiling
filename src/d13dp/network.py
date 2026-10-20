"""Experimental, fail-closed host-input transactions. No service hardening executor."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import difflib
import fcntl
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

from .network_policy import TABLE, NetworkPolicy, expected_state, load_network_policy, normalize, render_network


class NetworkError(RuntimeError):
    pass


def run(*args: str, input: str | None = None) -> str:
    try:
        result = subprocess.run(args, input=input, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NetworkError(str(exc)) from exc
    if result.returncode:
        raise NetworkError(f"{' '.join(args)}: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def trusted(path: Path) -> None:
    """All existing path components must be root-owned and privately writable."""
    for part in (*reversed(path.parents), path):
        if part.is_symlink():
            raise NetworkError(f"Symlink is not allowed: {part}")
        if part.exists():
            st = part.stat()
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise NetworkError(f"Path must be root-owned and not group/world writable: {part}")


def make_directory(path: Path) -> None:
    trusted(path)
    for directory in (*reversed(path.parents), path):
        if not directory.exists():
            directory.mkdir(mode=0o700)
            sync_dir(directory.parent)
        elif not directory.is_dir():
            raise NetworkError(f"Expected a directory: {directory}")


def atomic(path: Path, content: bytes, mode: int = 0o600) -> None:
    trusted(path)
    make_directory(path.parent)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temp = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def encode(data: object) -> bytes:
    return (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()


def session(value: str | None) -> tuple[str, int, str, int] | None:
    if not value:
        return None
    parts = value.split()
    try:
        if len(parts) != 4:
            raise ValueError("Expected four fields")
        source_port, target_port = int(parts[1]), int(parts[3])
        if not (1 <= source_port <= 65535 and 1 <= target_port <= 65535):
            raise ValueError("Invalid port")
        return str(ipaddress.ip_address(parts[0])), source_port, str(ipaddress.ip_address(parts[2])), target_port
    except ValueError as exc:
        raise NetworkError("Invalid SSH_CONNECTION; preserve the actual SSH environment") from exc


def boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


@dataclass(frozen=True)
class Paths:
    config: Path = Path("/etc/d13dp/network.nft")
    directory: Path = Path("/var/lib/d13dp/network")
    unit: Path = Path("/etc/systemd/system/d13dp-network.service")

    @property
    def state(self) -> Path:
        return self.directory / "state.json"

    @property
    def lock(self) -> Path:
        return self.directory / "lock"


def runtime_command() -> str:
    executable = Path(sys.prefix) / "bin/python3"
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(executable)):
        raise NetworkError("Install into a root-owned virtualenv at a simple absolute path")
    # The venv interpreter may be a symlink, but its parent and resolved target must be trusted.
    trusted(executable.parent)
    trusted(executable.resolve())
    trusted(Path(__file__).resolve())
    return f"{executable} -I -m d13dp.network"


def unit_text(command: str) -> str:
    return f"""[Unit]
Description=d13dp experimental host-input firewall
DefaultDependencies=no
Wants=network-pre.target
After=local-fs.target nftables.service
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
RequiresMountsFor=/etc/d13dp /var/lib/d13dp/network

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre={command} recover
ExecStart=/usr/sbin/nft -f /etc/d13dp/network.nft
ExecStop=/usr/bin/true
TimeoutStartSec=90

[Install]
WantedBy=sysinit.target
"""


def host_preflight() -> None:
    if os.geteuid() != 0:
        raise NetworkError("Network commands require root for effective nftables inspection")
    os_data = Path("/etc/os-release").read_text()
    if not re.search(r'^ID=[\"\']?debian[\"\']?$', os_data, re.M) or not re.search(r'^VERSION_ID=[\"\']?13[\"\']?$', os_data, re.M):
        raise NetworkError("Network transactions target Debian 13 only")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise NetworkError("A real systemd PID 1 is required")


def system_conflicts() -> list[str]:
    problems = []
    global_config = Path("/etc/nftables.conf")
    if global_config.exists():
        text = global_config.read_text()
        if re.search(r"\bflush\s+ruleset\b|\binclude\b", text):
            problems.append("Review /etc/nftables.conf: global flush or includes are unsupported")
    stop = run("systemctl", "show", "nftables.service", "-p", "ExecStop", "--value")
    if re.search(r"\bflush\s+ruleset\b", stop):
        problems.append("nftables.service ExecStop contains a global flush; configure an explicit safe override first")
    return problems


def inspect_rules(objects: list[dict]) -> tuple[list[dict], list[str]]:
    own, conflicts = [], []
    f2b_chains = set()
    for item in objects:
        if not isinstance(item, dict) or len(item) != 1:
            raise NetworkError("Malformed nftables JSON object")
        kind, obj = next(iter(item.items()))
        if kind == "metainfo":
            continue
        if not isinstance(obj, dict):
            raise NetworkError("Malformed nftables JSON payload")
        family = obj.get("family")
        table = obj.get("name") if kind == "table" else obj.get("table")
        if family == "inet" and table == TABLE:
            own.append(item)
            continue
        if kind == "chain" and obj.get("hook") in {"input", "prerouting", "ingress"}:
            if family == "inet" and table == "f2b-table" and obj.get("type") == "filter" and obj.get("hook") == "input" and obj.get("policy") == "accept":
                f2b_chains.add(obj["name"])
            else:
                conflicts.append(f"Foreign inbound base chain: {family} {table} {obj.get('name')}")
    for item in objects:
        rule = item.get("rule", {})
        if rule.get("family") == "inet" and rule.get("table") == "f2b-table":
            expr = rule.get("expr", [])
            if rule.get("chain") not in f2b_chains or not expr or not any(key in expr[-1] for key in ("drop", "reject")) or any(set(part) - {"match", "counter", "drop", "reject"} for part in expr):
                conflicts.append("Unsupported Fail2ban rule; review required")
    return normalize(own), sorted(set(conflicts))


def declared_ports(objects: list[dict], protocol: str) -> list[int]:
    for item in objects:
        obj = item.get("set", {})
        if obj.get("name") == f"allowed_{protocol}":
            return obj.get("elem", [])
    return []


def ssh_listeners() -> set[int]:
    # Both effective configuration and live listening sockets must agree.
    configured = {int(line.split()[1]) for line in run("/usr/sbin/sshd", "-T").splitlines() if line.startswith("port ")}
    live = set()
    for line in run("ss", "-H", "-lntp").splitlines():
        parts = line.split()
        if len(parts) >= 5 and re.search(r'\("sshd(?:-session)?"', line):
            live.add(int(parts[3].rsplit(":", 1)[1]))
    if not configured or not live or not configured <= live:
        raise NetworkError("Cannot verify configured SSH ports against live sshd listeners; socket activation is unsupported")
    return configured | live


class Controller:
    def __init__(self, paths: Paths = Paths()):
        self.paths = paths

    def read_state(self) -> dict:
        trusted(self.paths.state)
        if not self.paths.state.exists():
            return {"version": 1, "committed": None, "pending": None}
        state = json.loads(self.paths.state.read_text())
        if state.get("version") != 1 or set(state) != {"version", "committed", "pending"}:
            raise NetworkError("Unsupported network journal")
        return state

    @contextmanager
    def locked(self):
        trusted(self.paths.lock)
        with self.paths.lock.open("r") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def save_state(self, state: dict) -> None:
        atomic(self.paths.state, encode(state))

    def transaction_path(self, identifier: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise NetworkError("Invalid transaction identifier")
        return self.paths.directory / "transactions" / f"{identifier}.json"

    def load_transaction(self, identifier: str) -> dict:
        path = self.transaction_path(identifier)
        trusted(path)
        return json.loads(path.read_text())

    def prerequisites(self) -> list[str]:
        issues = system_conflicts()
        for path in (self.paths.config, self.paths.unit, self.paths.lock):
            trusted(path)
            if not path.is_file():
                issues.append(f"Run network install first; missing {path}")
        if not issues:
            expected = unit_text(runtime_command())
            if self.paths.unit.read_text() != expected:
                issues.append("Managed systemd unit has changed")
            fragment = run("systemctl", "show", "d13dp-network.service", "-p", "FragmentPath", "--value").strip()
            dropins = run("systemctl", "show", "d13dp-network.service", "-p", "DropInPaths", "--value").strip()
            if fragment != str(self.paths.unit) or dropins:
                issues.append("Unexpected systemd unit fragment or drop-ins")
            if run("systemctl", "show", "d13dp-network.service", "-p", "UnitFileState", "--value").strip() != "enabled":
                issues.append("Managed firewall boot unit must be enabled")
            if run("systemctl", "show", "d13dp-network.service", "-p", "ActiveState", "--value").strip() != "active":
                issues.append("Managed firewall unit must be active")
        return issues

    def install(self) -> dict:
        host_preflight()
        command = runtime_command()
        problems = system_conflicts()
        if problems:
            raise NetworkError("; ".join(problems))
        for path in (self.paths.config, self.paths.unit, self.paths.state, self.paths.lock):
            trusted(path)
        wanted = unit_text(command)
        if self.paths.unit.exists() and self.paths.unit.read_text() != wanted:
            raise NetworkError("Existing network unit differs; refusing takeover")
        if self.paths.config.exists() and not self.paths.state.exists():
            raise NetworkError("Existing unjournaled network configuration; refusing takeover")
        own, inbound_conflicts = self.snapshot()
        if inbound_conflicts:
            raise NetworkError("; ".join(inbound_conflicts))
        if own and not self.read_state()["committed"]:
            raise NetworkError("Existing unowned d13dp table; refusing takeover")
        changed = []
        make_directory(self.paths.lock.parent)
        try:
            fd = os.open(self.paths.lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            os.fsync(fd)
            os.close(fd)
            sync_dir(self.paths.lock.parent)
            changed.append(str(self.paths.lock))
        with self.locked():
            if self.read_state()["pending"]:
                raise NetworkError("A transaction is pending; confirm or roll back before installation changes")
            # Persist the journal before the first config file for resumable installation.
            if not self.paths.state.exists():
                self.save_state(self.read_state())
                changed.append(str(self.paths.state))
            if not self.paths.config.exists():
                atomic(self.paths.config, b"# No committed d13dp network policy.\n", 0o600)
                changed.append(str(self.paths.config))
            if not self.paths.unit.exists():
                atomic(self.paths.unit, wanted.encode(), 0o644)
                changed.append(str(self.paths.unit))
                run("systemctl", "daemon-reload")
        # ExecStartPre takes the journal lock itself: never wait for it while holding the lock.
        if run("systemctl", "show", "d13dp-network.service", "-p", "UnitFileState", "--value").strip() != "enabled":
            run("systemctl", "enable", "d13dp-network.service")
            changed.append("enable d13dp-network.service")
        if run("systemctl", "show", "d13dp-network.service", "-p", "ActiveState", "--value").strip() != "active":
            run("systemctl", "start", "d13dp-network.service")
            changed.append("start d13dp-network.service")
        return {"changes": changed, "scope": "Installed only the owned firewall unit; no other services restarted"}

    def snapshot(self) -> tuple[list[dict], list[str]]:
        data = json.loads(run("nft", "-j", "list", "ruleset"))
        if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
            raise NetworkError("Malformed nftables ruleset")
        return inspect_rules(data["nftables"])

    def plan(self, policy: NetworkPolicy) -> dict:
        host_preflight()
        state = self.read_state()
        own, issues = self.snapshot()
        issues.extend(self.prerequisites())
        if state["pending"]:
            issues.append(f"Pending transaction: {state['pending']}; confirm or roll back first")
        if own and state["committed"] is None:
            issues.append("Unowned d13dp table exists; automatic adoption is forbidden")
        protected = ssh_listeners()
        active_session = session(os.environ.get("SSH_CONNECTION"))
        if active_session:
            protected.add(active_session[3])
        if not protected <= set(policy.ssh_ports) or not protected <= set(policy.tcp):
            issues.append(f"Policy must retain all observed SSH ports: {sorted(protected)}")
        wanted = expected_state(policy)
        # Unexpected structural edits are conflicts; changed port-set contents are explicit drift.
        def structure(items):
            return [{kind: {k: v for k, v in obj.items() if not (kind == 'set' and k == 'elem')}
                     for kind, obj in item.items()} for item in items]
        if own and structure(own) != structure(wanted):
            issues.append("Owned table structure differs from the supported schema; review required")
        content = render_network(policy)
        trusted(self.paths.config)
        old = self.paths.config.read_text() if self.paths.config.exists() else ""
        committed = state["committed"]
        if committed:
            previous_policy = NetworkPolicy(**{key: tuple(value) if isinstance(value, list) else value for key, value in committed["policy"].items()})
            expected_file = render_network(previous_policy)
        else:
            expected_file = "# No committed d13dp network policy.\n"
        if old and old != expected_file:
            issues.append("Persisted configuration drift; restore the committed file before applying")
        changed = own != wanted or old != content or committed is None
        delta = {proto: {"add": sorted(set(values) - set(declared_ports(own, proto))), "remove": sorted(set(declared_ports(own, proto)) - set(values))}
                 for proto, values in (("tcp", policy.tcp), ("udp", policy.udp))}
        report = {"profile": policy.name, "changed": changed, "conflicts": sorted(set(issues)), "ports": delta,
                  "protected_ssh_ports": sorted(protected), "effective_before": own, "effective_after": wanted,
                  "file_diff": list(difflib.unified_diff(old.splitlines(), content.splitlines(), fromfile=str(self.paths.config), tofile="desired")),
                  "removal_policy": "Removed ports deny new connections; existing conntrack-established flows remain allowed",
                  "scope": "Host INPUT only; forwarding, NAT, Docker-published ports and foreign tables are not modified"}
        report["digest"] = sha256(encode(report)).hexdigest()
        return report

    def apply(self, policy: NetworkPolicy, digest: str, timeout: int = 120, console: bool = False) -> dict:
        if not 15 <= timeout <= 600:
            raise NetworkError("Confirmation timeout must be between 15 and 600 seconds")
        with self.locked():
            report = self.plan(policy)
            if report["conflicts"]:
                raise NetworkError("; ".join(report["conflicts"]))
            if not report["changed"]:
                return {"changed": False, "message": "Effective state, persisted configuration and boot unit already match"}
            if digest != report["digest"]:
                raise NetworkError("Plan changed; inspect a fresh dry-run and supply its digest")
            connection = session(os.environ.get("SSH_CONNECTION"))
            if connection is None and not console:
                raise NetworkError("Preserve SSH_CONNECTION or explicitly use --console with verified console access")
            content = render_network(policy)
            run("nft", "-c", "-f", "-", input=content)
            before = self.read_state()
            identifier = uuid.uuid4().hex
            restore = f"destroy table inet {TABLE}\n"
            if report["effective_before"]:
                restore += run("nft", "list", "table", "inet", TABLE)
            run("nft", "-c", "-f", "-", input=restore)
            tx = {"id": identifier, "before": before["committed"], "before_config": self.paths.config.read_text(), "restore": restore,
                  "before_live": report["effective_before"], "after": report["effective_after"], "config": content,
                  "policy": asdict(policy), "session": list(connection) if connection else None,
                  "boot": boot_id(), "deadline": time.monotonic() + timeout, "timeout": timeout}
            atomic(self.transaction_path(identifier), encode(tx))
            self.save_state({**before, "pending": identifier})
            timer = "d13dp-network-rollback-" + identifier
            try:
                run("systemd-run", "--unit=" + timer, f"--on-active={timeout}s", "--timer-property=AccuracySec=1s", "--property=Type=oneshot", "--property=Restart=on-failure", "--property=RestartSec=2s", str(Path(sys.prefix) / "bin/python3"), "-I", "-m", "d13dp.network", "rollback", identifier)
                if run("systemctl", "show", timer + ".timer", "-p", "ActiveState", "--value").strip() != "active":
                    raise NetworkError("Rollback timer did not become active")
                # Reinspect immediately before mutation; dynamic Fail2ban data is intentionally excluded.
                check = self.plan(policy)
                check["conflicts"] = [c for c in check["conflicts"] if not c.startswith("Pending transaction:")]
                if check["effective_before"] != report["effective_before"] or check["conflicts"]:
                    raise NetworkError("Effective firewall or prerequisites changed during staging")
                if boot_id() != tx["boot"] or time.monotonic() >= tx["deadline"]:
                    raise NetworkError("Confirmation deadline elapsed while staging")
                atomic(self.paths.config, content.encode())
                run("nft", "-f", "-", input=content)
                actual, conflicts = self.snapshot()
                if actual != tx["after"] or conflicts or time.monotonic() >= tx["deadline"]:
                    raise NetworkError("Post-apply effective state verification failed")
            except BaseException:
                self._rollback(identifier)
                raise
            return {"changed": True, "transaction": identifier, "confirm_within_seconds": timeout,
                    "message": "Provisional: verify external access, then confirm from a new SSH connection"}

    def cancel_timer(self, identifier: str) -> None:
        # A queued worker is harmless after the durable pending pointer is cleared.
        # Transient units are absent following reboot, which must not prevent recovery.
        try:
            run("systemctl", "stop", "d13dp-network-rollback-" + identifier + ".timer")
        except NetworkError:
            pass

    def _rollback(self, identifier: str) -> dict:
        state = self.read_state()
        if state["pending"] != identifier:
            return {"changed": False, "message": "Transaction is no longer pending"}
        tx = self.load_transaction(identifier)
        # Retain the journal until BOTH runtime and persistent restoration succeed.
        run("nft", "-c", "-f", "-", input=tx["restore"])
        atomic(self.paths.config, tx["before_config"].encode())
        run("nft", "-f", "-", input=tx["restore"])
        actual, _ = self.snapshot()
        if actual != tx["before_live"]:
            raise NetworkError("Rollback verification failed; pending journal retained for retry")
        self.save_state({"version": 1, "committed": tx["before"], "pending": None})
        self.cancel_timer(identifier)
        return {"changed": True, "rolled_back": identifier}

    def recover(self) -> dict:
        host_preflight()
        with self.locked():
            state = self.read_state()
            result = {"changed": False, "message": "No pending transaction"}
            if state["pending"]:
                result = self._rollback(state["pending"])
                state = self.read_state()
            committed = state["committed"]
            expected_file = "# No committed d13dp network policy.\n"
            expected_live = []
            if committed:
                policy = NetworkPolicy(**{key: tuple(value) if isinstance(value, list) else value for key, value in committed["policy"].items()})
                expected_file = render_network(policy)
                expected_live = expected_state(policy)
            trusted(self.paths.config)
            if self.paths.config.read_text() != expected_file:
                raise NetworkError("Refusing startup: persistent configuration differs from the committed policy")
            live, conflicts = self.snapshot()
            conflicts.extend(system_conflicts())
            if conflicts or (live and live != expected_live):
                raise NetworkError("Refusing startup: unsupported inbound topology or managed-table drift: " + "; ".join(conflicts))
            return result

    def rollback(self, identifier: str | None = None) -> dict:
        host_preflight()
        with self.locked():
            pending = self.read_state()["pending"]
            if identifier is None:
                identifier = pending
            if identifier is None:
                return {"changed": False, "message": "No pending transaction"}
            self.transaction_path(identifier)
            return self._rollback(identifier)

    def confirm(self, identifier: str, console: bool = False) -> dict:
        host_preflight()
        with self.locked():
            state = self.read_state()
            if state["pending"] != identifier:
                raise NetworkError("Transaction is not pending")
            tx = self.load_transaction(identifier)
            connection = session(os.environ.get("SSH_CONNECTION"))
            if tx["session"]:
                if not connection or list(connection) == tx["session"] or connection[3] not in tx["policy"]["ssh_ports"]:
                    raise NetworkError("Confirm from a new SSH connection with SSH_CONNECTION preserved")
            elif not console:
                raise NetworkError("Console-originated transactions require explicit --console confirmation")
            if tx["boot"] != boot_id() or time.monotonic() >= tx["deadline"]:
                self._rollback(identifier)
                raise NetworkError("Confirmation deadline expired; transaction rolled back")
            policy = NetworkPolicy(**{k: tuple(v) if isinstance(v, list) else v for k, v in tx["policy"].items()})
            actual, issues = self.snapshot()
            issues.extend(self.prerequisites())
            if actual != tx["after"] or self.paths.config.read_text() != tx["config"] or issues or not ssh_listeners() <= set(policy.tcp):
                raise NetworkError("State or prerequisites changed; cannot confirm; rollback remains armed")
            if time.monotonic() >= tx["deadline"]:
                self._rollback(identifier)
                raise NetworkError("Confirmation deadline expired; transaction rolled back")
            # Commit first. A queued timer subsequently sees no pending transaction and does nothing.
            self.save_state({"version": 1, "committed": {"policy": tx["policy"], "effective": tx["after"]}, "pending": None})
            self.cancel_timer(identifier)
            return {"changed": True, "committed": identifier}


def dispatch(args) -> int:
    controller = Controller()
    try:
        if args.network_command == "install":
            result = controller.install()
        elif args.network_command == "rollback":
            result = controller.rollback(getattr(args, "transaction", None))
        elif args.network_command == "confirm":
            result = controller.confirm(args.transaction, args.console)
        elif args.network_command == "status":
            host_preflight()
            live, conflicts = controller.snapshot()
            state = controller.read_state()
            committed = state["committed"]
            result = {"journal": state, "effective": live,
                      "effective_matches_committed": live == committed["effective"] if committed else None,
                      "conflicts": conflicts + controller.prerequisites()}
        else:
            policy = load_network_policy(args.profile, args.config)
            if args.network_command == "plan" or args.dry_run:
                result = controller.plan(policy)
            else:
                result = controller.apply(policy, args.expect_plan, args.confirm_timeout, args.console)
        print(json.dumps(result, indent=2))
        return 1 if result.get("conflicts") else 0
    except (NetworkError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Network operation refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Internal systemd workers expose only recovery operations.
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("recover", "rollback"))
    parser.add_argument("transaction", nargs="?")
    arguments = parser.parse_args()
    try:
        controller = Controller()
        result = controller.recover() if arguments.operation == "recover" else controller.rollback(arguments.transaction)
        print(json.dumps(result))
    except (NetworkError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Network recovery failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
