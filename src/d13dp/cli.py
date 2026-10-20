from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import collect
from .policy import load_policy, load_policy_file
from .render import digest_manifest, generate, write_generated


STAGES = (
    ("preflight", "Inventory OS, ports, active firewalls, SSH keys, Docker, backups, and console access"),
    ("backup", "Take provider snapshot and encrypted off-host backups before invasive changes"),
    ("access", "Provision independent rescue access and verify new SSH login before restricting access"),
    ("firewall", "Apply only host-owned nftables table with rollback timer and reachability verification"),
    ("abuse", "Configure Fail2ban and verify effective kernel rules"),
    ("host", "Configure security updates, AppArmor, audit logging, sysctl, and permissions"),
    ("application", "Set up reverse proxy/TLS, network isolation, secrets, sandboxed services, rate limits"),
    ("upstream", "Configure provider anti-DDoS and upstream CDN/WAF as applicable"),
    ("operations", "Configure monitoring, alerting, backup restore tests, drift detection, patch windows"),
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="d13dp", description="Debian 13 security audit and deterministic config planning")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="Read-only local security audit")
    audit.add_argument("--json", action="store_true", help="Machine-readable output")
    audit.add_argument("--strict", action="store_true", help="Exit 2 when high-severity findings are not passing")
    plan = sub.add_parser("plan", help="Print ordered security implementation stages")
    plan_source = plan.add_mutually_exclusive_group()
    plan_source.add_argument("--profile", choices=("minimal", "web", "docker"), default="minimal")
    plan_source.add_argument("--config", type=Path, help="Custom TOML profile instead of --profile")
    render = sub.add_parser("render", help="Write candidate configuration files; never applies to the host")
    render_source = render.add_mutually_exclusive_group()
    render_source.add_argument("--profile", choices=("minimal", "web", "docker"), default="minimal")
    render_source.add_argument("--config", type=Path, help="Custom TOML profile instead of --profile")
    render.add_argument("--output", type=Path, default=None)
    render.add_argument("--replace", action="store_true", help="Explicitly overwrite changed generated files")
    manifest = sub.add_parser("manifest", help="Print stable hashes of generated configuration files")
    manifest_source = manifest.add_mutually_exclusive_group()
    manifest_source.add_argument("--profile", choices=("minimal", "web", "docker"), default="minimal")
    manifest_source.add_argument("--config", type=Path, help="Custom TOML profile instead of --profile")
    network = sub.add_parser("network", help="Experimental transactional host-input firewall management")
    commands = network.add_subparsers(dest="network_command", required=True)
    install = commands.add_parser("install", help="Explicitly install the owned boot/recovery unit; no policy is applied")
    install.add_argument("--adopt-filter", action="store_true", help="Permit only the recognized legacy inet filter template")
    commands.add_parser("status", help="Inspect effective rules, journal and boot unit")
    migration_plan = commands.add_parser('migration-plan', help='Offline analysis of a captured legacy ruleset; never changes the host')
    migration_plan.add_argument('--ruleset', required=True, type=Path)
    migration_plan.add_argument('--source', required=True, type=Path)
    migration_source = migration_plan.add_mutually_exclusive_group()
    migration_source.add_argument('--profile', choices=('minimal','web','docker'), default='web')
    migration_source.add_argument('--config', type=Path)

    for operation in ("plan", "diff", "verify", "apply"):
        command = commands.add_parser(operation)
        command.add_argument("--adopt-filter", action="store_true", help="Explicitly migrate the recognized legacy INPUT chain")
        source = command.add_mutually_exclusive_group()
        source.add_argument("--profile", choices=("minimal", "web", "docker"), default="minimal")
        source.add_argument("--config", type=Path, help="Custom network TOML: tcp, udp, ssh_ports arrays")
        if operation == "apply":
            command.add_argument("--dry-run", action="store_true")
            command.add_argument("--expect-plan", default="", help="Digest from a fresh plan; required for changes")
            command.add_argument("--confirm-timeout", type=int, default=120)
            command.add_argument("--console", action="store_true", help="Explicitly attest local console access")
    confirm = commands.add_parser("confirm")
    confirm.add_argument("transaction")
    confirm.add_argument("--console", action="store_true")
    rollback = commands.add_parser("rollback")
    rollback.add_argument("transaction", nargs="?")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "network":
        from .network import dispatch
        return dispatch(args)
    if args.command == "audit":
        report = collect()
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(f"Host: {report['host'].get('id')} {report['host'].get('version')}")
            for finding in report["findings"]:
                print(f"[{finding['status'].upper():11}] {finding['id']:20} {finding['detail']}")
                if finding["status"] not in {"pass"} and finding["action"]:
                    print(f"              Next: {finding['action']}")
            print("\nUnverified external areas: backups, upstream DDoS, secrets, service isolation, application security")
        if args.strict and any(f["severity"] == "high" and f["status"] != "pass" for f in report["findings"]):
            return 2
        return 0
    try:
        policy = load_policy_file(args.config) if args.config is not None else load_policy(args.profile)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"Invalid profile: {exc}", file=sys.stderr)
        return 1
    if args.command == "plan":
        print(f"Profile: {policy.name} — {policy.description}")
        print(f"Modules: {', '.join(sorted(policy.modules))}")
        print(f"Allowed inbound TCP: {', '.join(str(p) for p in policy.inbound_tcp)}")
        for i, (stage, explanation) in enumerate(STAGES, start=1):
            print(f"{i}. {stage}: {explanation}")
        if policy.firewall_mode == "external":
            print("WARNING: Firewall rules are externally managed; review the firewall backend and published ports separately")
        print("No actions have been applied to the host")
        return 0
    files = generate(policy)
    if args.command == "manifest":
        print(json.dumps(digest_manifest(files), indent=2))
        return 0
    if args.command == "render":
        location = args.output if args.output is not None else Path("build") / policy.name
        try:
            changes = write_generated(files, location, args.replace)
        except (OSError, ValueError) as exc:
            print(f"Render aborted: {exc}", file=sys.stderr)
            return 1
        for name, state in changes.items():
            print(f"{state:9} {location / name}")
        print("Candidate files only. Nothing was installed, enabled, reloaded, or restarted.")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
