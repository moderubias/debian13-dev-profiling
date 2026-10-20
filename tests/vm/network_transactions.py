"""Run ONLY in the disposable Debian 13 QEMU QA VM."""
import json
import os
from pathlib import Path
import shlex
import socket
import socketserver
import subprocess
import sys
import threading
import time
from unittest.mock import patch

def guard():
    if os.environ.get("D13DP_ISOLATED_QA") != "1" or not Path("/etc/d13dp-qa-vm").is_file() or run("systemd-detect-virt", "--vm", check=False).stdout.strip() != "qemu":
        raise SystemExit("Requires the disposable QEMU VM and D13DP_ISOLATED_QA=1")


CLI = "/opt/d13dp/bin/d13dp"
SSH = ["ip", "netns", "exec", "qa-client", "ssh", "-F", "/dev/null", "-i", "/run/qa-key", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=3", "-o", "ControlMaster=no"]


def run(*args, check=True, input=None, timeout=40):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f"{args}: {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def cli(*args, remote=False, success=True):
    command = [CLI, "network", *args]
    if remote:
        command = [*SSH, "root@192.0.2.1", shlex.join(command)]
    result = run(*command, check=success)
    if not success:
        assert result.returncode != 0, result.stdout
        return result
    return json.loads(result.stdout)


def nft(text):
    run("nft", "-f", "-", input=text)


def all_rules():
    return run("nft", "-j", "list", "ruleset").stdout


def marker():
    paths = [Path("/etc/d13dp/network.nft"), Path("/var/lib/d13dp/network/state.json")]
    return all_rules(), [(p.read_bytes(), p.stat().st_mtime_ns) for p in paths]


def transition(profile, confirm=True, timeout=120, remote=True):
    plan = cli("plan", "--profile", profile, remote=remote)
    assert not plan["conflicts"], plan
    response = cli("apply", "--profile", profile, "--expect-plan", plan["digest"], "--confirm-timeout", str(timeout), *([] if remote else ["--console"]), remote=remote)
    if response["changed"] and confirm:
        cli("confirm", response["transaction"], *([] if remote else ["--console"]), remote=remote)
    return response


def connect(address, port, expected=True):
    program = "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=0.5); s.close()"
    result = run("ip", "netns", "exec", "qa-client", "python3", "-c", program, address, str(port), check=False)
    assert (result.returncode == 0) == expected, (address, port, expected, result.stderr)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(data)


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class UdpServer(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6
    daemon_threads = True


def udp_check(address, source_port, expected=True):
    program = "import socket,sys; a=sys.argv[1]; s=socket.socket(socket.AF_INET6 if ':' in a else socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.5); s.bind(('::' if ':' in a else '0.0.0.0',int(sys.argv[2]))); s.sendto(b'ping',(a,5353)); assert s.recv(4)==b'ping'"
    result = run("ip", "netns", "exec", "qa-client", "python3", "-c", program, address, str(source_port), check=False)
    assert (result.returncode == 0) == expected, result.stderr


class EchoServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True


def persistent(address):
    program = "import socket,sys; s=socket.create_connection((sys.argv[1],80),timeout=2); print('ready',flush=True); [(s.sendall(b'ping'),print(s.recv(4).decode(),flush=True)) for line in sys.stdin]"
    process = subprocess.Popen(["ip", "netns", "exec", "qa-client", "python3", "-c", program, address], text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert process.stdout.readline().strip() == "ready"
    return process


def check_persistent(process):
    process.stdin.write("ping\n")
    process.stdin.flush()
    assert process.stdout.readline().strip() == "ping"


def main():
    guard()
    run("systemctl", "disable", "--now", "docker.service", "docker.socket", "caddy.service")
    for family, table in (("ip", "nat"), ("ip", "filter")):
        run("nft", "delete", "table", family, table, check=False)
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    for _ in range(50):
        if run("systemctl", "show", "-p", "Version", check=False).returncode == 0:
            break
        time.sleep(0.2)
    # Explicit fixture preparation only inside the disposable namespace.
    Path("/etc/nftables.conf").write_text("# QA: externally owned tables only\n")
    override = Path("/etc/systemd/system/nftables.service.d/qa.conf")
    override.parent.mkdir(parents=True, exist_ok=True)
    override.write_text("[Service]\nExecStop=\nExecStop=/usr/bin/true\n")
    run("systemctl", "daemon-reload")
    run("ssh-keygen", "-A")
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/run/qa-key")
    Path("/root/.ssh").mkdir(mode=0o700, exist_ok=True)
    auth = Path("/root/.ssh/authorized_keys")
    auth.write_bytes(Path("/run/qa-key.pub").read_bytes())
    auth.chmod(0o600)
    run("systemctl", "start", "ssh.service")
    ssh_pid = run("systemctl", "show", "ssh.service", "-p", "MainPID", "--value").stdout
    run("ip", "netns", "add", "qa-client")
    run("ip", "link", "add", "qa-host", "type", "veth", "peer", "name", "qa-peer")
    run("ip", "link", "set", "qa-peer", "netns", "qa-client")
    for prefix, device, address in (([], "qa-host", "192.0.2.1/24"), ([], "qa-host", "fd42:13::1/64"), (["ip", "netns", "exec", "qa-client"], "qa-peer", "192.0.2.2/24"), (["ip", "netns", "exec", "qa-client"], "qa-peer", "fd42:13::2/64")):
        run(*prefix, "ip", "address", "add", address, "dev", device, *(["nodad"] if ":" in address else []))
        run(*prefix, "ip", "link", "set", device, "up")
    run("ip", "netns", "exec", "qa-client", "ip", "link", "set", "lo", "up")
    servers = [EchoServer(("::", port), Echo) for port in (80, 443, 8443)]
    servers.append(UdpServer(("::", 5353), UdpEcho))
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    nft('''table inet f2b-table {
set addr-set-sshd { type ipv4_addr; elements = { 203.0.113.99 }; }
chain f2b-chain { type filter hook input priority -1; policy accept;
tcp dport 22 ip saddr @addr-set-sshd reject
}
}
table ip docker_qa {
chain forward { type filter hook forward priority 0; policy accept; }
}
''')
    f2b = run("nft", "-j", "list", "table", "inet", "f2b-table").stdout
    docker = run("nft", "-j", "list", "table", "ip", "docker_qa").stdout
    print("Installing owned unit and checking initial minimal policy", flush=True)
    cli("install")
    run("systemd-analyze", "verify", "/etc/systemd/system/d13dp-network.service")
    assert cli("install")["changes"] == []
    transition("minimal")
    for address in ("192.0.2.1", "fd42:13::1"):
        connect(address, 22)
        connect(address, 80, False)
        connect(address, 443, False)
    print("Checking minimal -> web -> web -> minimal, IPv4/IPv6 and established flows", flush=True)
    before = marker()
    dry = cli("apply", "--profile", "web", "--dry-run", remote=True)
    assert dry["ports"]["tcp"]["add"] == [80, 443]
    assert marker() == before
    transition("web")
    for address in ("192.0.2.1", "fd42:13::1"):
        for port in (22, 80, 443):
            connect(address, port)
    clients = [persistent(address) for address in ("192.0.2.1", "fd42:13::1")]
    for client in clients:
        check_persistent(client)
    before = marker()
    assert cli("apply", "--profile", "web", remote=True)["changed"] is False
    assert marker() == before
    for _ in range(10):
        assert cli("apply", "--profile", "web", remote=True)["changed"] is False
        assert marker() == before
    transition("minimal")
    for address in ("192.0.2.1", "fd42:13::1"):
        connect(address, 22)
        connect(address, 80, False)
        connect(address, 443, False)
    assert "ESTABLISHED" in run("conntrack", "-L", "-p", "tcp").stdout
    for client in clients:
        check_persistent(client)
        client.stdin.close()
        client.wait(timeout=5)
    assert run("nft", "-j", "list", "table", "inet", "f2b-table").stdout == f2b
    assert run("nft", "-j", "list", "table", "ip", "docker_qa").stdout == docker
    print("Checking custom TCP/UDP policy and host-only Docker profile", flush=True)
    custom = Path("/run/custom-network.toml")
    custom.write_text("tcp=[22,8443]\nudp=[5353]\nssh_ports=[22]\n")
    invalid_ssh = Path("/run/missing-ssh.toml")
    invalid_ssh.write_text("tcp=[2222]\nudp=[]\nssh_ports=[2222]\n")
    protected_before = marker()
    assert "retain all observed SSH ports" in cli("plan", "--config", str(invalid_ssh), success=False).stdout
    cli("apply", "--config", str(invalid_ssh), "--expect-plan", "invalid", remote=True, success=False)
    assert marker() == protected_before
    plan = cli("plan", "--config", str(custom), remote=True)
    pending_custom = cli("apply", "--config", str(custom), "--expect-plan", plan["digest"], remote=True)
    cli("confirm", pending_custom["transaction"], remote=True)
    for index, address in enumerate(("192.0.2.1", "fd42:13::1")):
        connect(address, 8443)
        udp_check(address, 41000 + index)
    transition("docker")
    for index, address in enumerate(("192.0.2.1", "fd42:13::1")):
        connect(address, 80)
        connect(address, 8443, False)
        udp_check(address, 42000 + index, False)
    transition("minimal")
    assert run("nft", "-j", "list", "table", "ip", "docker_qa").stdout == docker
    print("Checking stale-plan refusal and foreign-chain conflicts", flush=True)
    cli("apply", "--profile", "web", "--expect-plan", "stale", remote=True, success=False)
    nft("table inet foreign_qa {\nchain inbound { type filter hook input priority 10; policy accept; }\n}\n")
    blocked = cli("plan", "--profile", "web", success=False)
    assert "Foreign inbound base chain" in blocked.stdout
    cli("apply", "--profile", "web", "--expect-plan", "stale", remote=True, success=False)
    nft("delete table inet foreign_qa\n")
    print("Checking persistent and live structural drift conflicts", flush=True)
    config = Path("/etc/d13dp/network.nft")
    original = config.read_bytes()
    config.write_bytes(original + b"# external edit\n")
    assert "Persisted configuration drift" in cli("plan", "--profile", "web", success=False).stdout
    preserved = all_rules()
    assert run("systemctl", "restart", "d13dp-network.service", check=False).returncode != 0
    assert all_rules() == preserved
    config.write_bytes(original)
    run("systemctl", "start", "d13dp-network.service")
    preserved = all_rules()
    assert run("systemctl", "reload", "d13dp-network.service", check=False).returncode != 0
    assert all_rules() == preserved
    nft("add rule inet d13dp_network input tcp dport 5555 accept\n")
    assert "structure differs" in cli("plan", "--profile", "web", success=False).stdout
    rules = json.loads(run("nft", "-j", "list", "chain", "inet", "d13dp_network", "input").stdout)["nftables"]
    handle = [obj["rule"]["handle"] for obj in rules if "rule" in obj][-1]
    nft(f"delete rule inet d13dp_network input handle {handle}\n")
    print("Checking observed port drift and guarded reconciliation", flush=True)
    nft('add element inet d13dp_network allowed_tcp { 8443 }\n')
    drift = cli('status', success=False)
    assert drift.returncode == 2 and json.loads(drift.stdout)['drift'] is True
    verification = cli('verify', '--profile', 'minimal', success=False)
    assert verification.returncode == 2
    transition('minimal')
    assert cli('verify', '--profile', 'minimal')['changed'] is False
    print("Checking immediate recovery after a simulated nft load failure", flush=True)
    from d13dp.network import Controller, NetworkError
    from d13dp.network_policy import load_network_policy
    import d13dp.network as network
    controller = Controller()
    policy = load_network_policy("web")
    planned = controller.plan(policy)
    baseline = controller.snapshot()[0]
    before_config = Path("/etc/d13dp/network.nft").read_bytes()
    actual_run = network.run
    injected = False
    def fail_candidate(*args, **kwargs):
        nonlocal injected
        if args == ("nft", "-f", "-") and not injected:
            injected = True
            raise NetworkError("Simulated netlink load failure")
        return actual_run(*args, **kwargs)
    with patch("d13dp.network.run", side_effect=fail_candidate):
        try:
            controller.apply(policy, planned["digest"], console=True)
        except NetworkError:
            pass
        else:
            raise AssertionError("Injected failure was not propagated")
    assert injected and controller.read_state()["pending"] is None
    assert controller.snapshot()[0] == baseline
    assert Path("/etc/d13dp/network.nft").read_bytes() == before_config
    print("Checking timed automatic rollback and dynamic Fail2ban preservation", flush=True)
    pending = transition("web", confirm=False, timeout=15)
    nft("add element inet f2b-table addr-set-sshd { 203.0.113.100 }\n")
    cli("apply", "--profile", "web", "--expect-plan", "stale", remote=True, success=False)
    def fail_restore(*args, **kwargs):
        if args == ("nft", "-f", "-"):
            raise NetworkError("Simulated rollback netlink failure")
        return actual_run(*args, **kwargs)
    with patch("d13dp.network.run", side_effect=fail_restore):
        try:
            controller.rollback(pending["transaction"])
        except NetworkError:
            pass
        else:
            raise AssertionError("Rollback failure was not propagated")
    assert controller.read_state()["pending"] == pending["transaction"]
    deadline = time.monotonic() + 25
    while cli("status")["journal"]["pending"] and time.monotonic() < deadline:
        time.sleep(0.5)
    assert cli("status")["journal"]["pending"] is None
    assert "203.0.113.100" in run("nft", "list", "table", "inet", "f2b-table").stdout
    connect("192.0.2.1", 80, False)
    cli("confirm", pending["transaction"], remote=True, success=False)
    print("Checking recovery on service restart and non-destructive service stop", flush=True)
    transition("web", confirm=False)
    run("systemctl", "restart", "d13dp-network.service")
    assert cli("status")["journal"]["pending"] is None
    connect("192.0.2.1", 80, False)
    before_rules = all_rules()
    run("systemctl", "stop", "d13dp-network.service")
    assert all_rules() == before_rules
    run("systemctl", "start", "d13dp-network.service")
    assert ssh_pid == run("systemctl", "show", "ssh.service", "-p", "MainPID", "--value").stdout
    cli("confirm", "0" * 32, "--console", success=False)
    # Real Fail2ban-style bans must continue to override the managed SSH allowance.
    nft("add element inet f2b-table addr-set-sshd { 192.0.2.2 }\n")
    connect("192.0.2.1", 22, False)
    nft("delete element inet f2b-table addr-set-sshd { 192.0.2.2 }\n")
    connect("192.0.2.1", 22)
    print("Real nftables + systemd transaction checks passed.", flush=True)


def boot_prepare():
    guard()
    pending = transition("web", confirm=False, remote=False, timeout=120)
    assert pending["changed"]
    Path("/var/lib/d13dp/qa-boot-transaction").write_text(pending["transaction"])
    print("Pending transaction prepared for cold VM boot", flush=True)


def boot_check():
    guard()
    for _ in range(100):
        state = run("systemctl", "is-active", "d13dp-network.service", check=False)
        if state.stdout.strip() == "active":
            break
        time.sleep(0.2)
    else:
        raise AssertionError(run("journalctl", "-u", "d13dp-network.service", "--no-pager").stdout)
    status = cli("status")
    assert status["journal"]["pending"] is None
    assert status["journal"]["committed"]["policy"]["tcp"] == [22]
    live = status["effective"]
    assert [obj["set"]["elem"] for obj in live if obj.get("set", {}).get("name") == "allowed_tcp"] == [[22]]
    assert "elements = { 22 }" in Path("/etc/d13dp/network.nft").read_text()
    assert "22, 80, 443" not in Path("/etc/d13dp/network.nft").read_text()
    print("Pending transaction recovered after cold VM boot", flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--prepare-boot"]:
        boot_prepare()
    elif sys.argv[1:] == ["--check-boot"]:
        boot_check()
    else:
        main()
