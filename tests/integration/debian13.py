"""Exercise Debian parsers and nftables only inside a disposable container."""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


def run(*args, **kwargs):
    print("+", *map(str, args), flush=True)
    try:
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=60, **kwargs).stdout
    except subprocess.CalledProcessError as exc:
        print(exc.stdout, exc.stderr, flush=True)
        raise


def main():
    if not Path("/.dockerenv").is_file() or set(os.listdir("/sys/class/net")) != {"lo"}:
        raise SystemExit("Run only inside the documented disposable --network none QA container")
    suite = unittest.defaultTestLoader.discover("tests")
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        raise SystemExit(1)
    cli = "/opt/d13dp/bin/d13dp"
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    Path("/run/sshd").mkdir(exist_ok=True)
    run("ssh-keygen", "-A")
    with tempfile.TemporaryDirectory() as tmp:
        for profile in ("minimal", "web", "docker"):
            output = Path(tmp) / profile
            run(cli, "plan", "--profile", profile, cwd=tmp, env=env)
            run(cli, "render", "--profile", profile, "--output", str(output), cwd=tmp, env=env)
            again = run(cli, "render", "--profile", profile, "--output", str(output), cwd=tmp, env=env)
            assert "written" not in again and "unchanged" in again
            manifest = json.loads(run(cli, "manifest", "--profile", profile, cwd=tmp, env=env))
            for name, digest in manifest.items():
                assert sha256((output / name).read_bytes()).hexdigest() == digest
            ssh = output / "ssh/00-d13dp-hardening.conf"
            run("/usr/sbin/sshd", "-t", "-f", str(ssh))
            effective = run("/usr/sbin/sshd", "-T", "-f", str(ssh))
            assert "passwordauthentication no" in effective
            assert "permitrootlogin without-password" in effective
            jail = Path("/etc/fail2ban/jail.d/52-d13dp-sshd.local")
            jail.write_bytes((output / "fail2ban/52-d13dp-sshd.local").read_bytes())
            run("fail2ban-client", "-t")
            for candidate in (output / "apt").iterdir():
                (Path("/etc/apt/apt.conf.d") / candidate.name).write_bytes(candidate.read_bytes())
            apt = run("apt-config", "dump")
            assert 'APT::Periodic::Unattended-Upgrade "1";' in apt
            assert 'Unattended-Upgrade::Automatic-Reboot "false";' in apt
            # These rules are loaded into this container's isolated network namespace.
            if profile != "docker":
                nft = output / "nft/d13dp.nft"
                run("nft", "add", "table", "inet", "f2b_qa_sentinel")
                run("nft", "-c", "-f", str(nft))
                run("nft", "-f", str(nft))
                run("nft", "-f", str(nft))
                tables = run("nft", "list", "tables")
                assert "f2b_qa_sentinel" in tables
                run("nft", "delete", "table", "inet", "f2b_qa_sentinel")
            else:
                assert not (output / "nft").exists()
        report = json.loads(run(cli, "audit", "--json", cwd=tmp, env=env))
        assert report["host"]["id"] == "debian" and report["host"]["version"] == "13"
        assert any(f["id"] == "firewall-input" and f["status"] == "pass" for f in report["findings"])
    print("Debian 13 integration checks passed.")


if __name__ == "__main__":
    main()
