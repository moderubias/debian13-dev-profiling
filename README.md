# debian13-dev-profiling

A Debian 13 (trixie) host security auditing, policy planning, and deterministic configuration generator. `d13dp` is the CLI name.

**Status: v0.1.0, pre-production.** The executable is deliberately read-only with respect to the host. It can render candidate configuration files to a working directory; it does **not** install packages, change `/etc`, reload firewall rules, or restart SSH. There is no unattended `apply` command yet. Treat rendered files as review material, not a ready-to-run universal security deployment.

## What is implemented

- Read-only security audit (`audit`, `audit --json`, `audit --strict`).
- Ordered implementation checklist (`plan`).
- Deterministic configuration generator (`render`).
- Stable SHA-256 manifest for the rendered configuration (`manifest`).
- Three baseline profiles: `minimal`, `web`, and `docker`.
- Refusal to overwrite differing generated files without `--replace`.
- Tests for deterministic output, CLI behavior, invalid profiles, safe output paths, preservation of local edits, and avoiding `flush ruleset`.
- Debian 13 container checks for packaging, OpenSSH, Fail2ban, APT configuration, and repeated nftables loading.

## Quick start

```bash
git clone https://github.com/moderubias/debian13-dev-profiling.git
cd debian13-dev-profiling
./d13dp --help
./d13dp plan --profile web
./d13dp render --profile web --output ./build/web
```

Review the output under `build/web`; no generated configuration is installed automatically.

## Run from a clone

Requires Python 3.11+ (Debian 13 ships Python 3.13). No third-party runtime libraries.

```bash
./d13dp --help
./d13dp audit
./d13dp audit --json
./d13dp plan --profile minimal
./d13dp plan --profile web
./d13dp plan --profile docker
./d13dp render --profile minimal
./d13dp render --profile web --output ./build/web
./d13dp manifest --profile web
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Run `sudo ./d13dp audit` if full access to nftables is required. `render` should run as an ordinary user, not root.

Audit probes use `openssh-server`, `nftables`, `fail2ban`, `unattended-upgrades`, `apparmor`, `auditd`, `iproute2`, and systemd tools when available. Missing commands, insufficient privileges, or unavailable services produce non-passing findings or notes; the tool does not install dependencies.

## Install the CLI

Use a virtual environment to keep the Debian system Python untouched. Install `python3-venv` first if your host does not provide it.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/d13dp --help
.venv/bin/d13dp plan --profile minimal
```

The installed wheel includes all three TOML profiles and works outside the source checkout.

## Commands and exit codes

| Command | Result |
| --- | --- |
| `audit [--json] [--strict]` | Local findings; `--json` emits a JSON report |
| `plan [--profile NAME \| --config FILE]` | Ordered checklist; executes no deployment stages |
| `render [--profile NAME \| --config FILE] [--output DIR] [--replace]` | Candidate files; default directory is `build/<profile-name>` |
| `manifest [--profile NAME \| --config FILE]` | JSON mapping of relative candidate paths to SHA-256 hashes |

Exit `0` means the command completed; ordinary `audit` can return `0` with failing findings. Invalid profiles and render conflicts return `1`. Invalid command syntax returns `2`; `audit --strict` also returns `2` if any high-severity finding has a status other than `pass`. Medium- and low-severity findings do not change the strict exit code.

## Profiles

| Profile | Intended host | Inbound TCP in rendered *candidate* rules | Firewall output |
| --- | --- | --- | --- |
| `minimal` | Fresh SSH-only VPS | 22 | Standalone nftables candidate |
| `web` | Reverse-proxy VPS | 22, 80, 443 | Standalone nftables candidate |
| `docker` | Docker host | Not automatically configured | **Omitted** until Docker network discovery and compatibility checks are implemented |

The firewall is **not** a DDoS bandwidth shield. `nftables` can restrict local attack surfaces, but a saturated upstream link remains unavailable. An HTTPS-facing service generally also needs upstream anti-DDoS, a rate-limiting reverse proxy, TLS, and app-level controls.

The profiles live at `src/d13dp/profiles/*.toml`. Create a customized copy and render it with `--config`:

```bash
cp src/d13dp/profiles/web.toml ./my-server.toml
./d13dp plan --config ./my-server.toml
./d13dp render --config ./my-server.toml --output ./build/my-server
```

Use either `--profile` or `--config`. The custom profile validator rejects unknown keys, incorrect types, duplicate or invalid ports, and unsafe SSH settings, and ensures the SSH port is part of the allowlist. **Do not copy generated files directly into `/etc` without reviewing the existing firewall/SSH ordering, open connections, rescue access, and application requirements.**

## Repeatability contract

`render` is idempotent with respect to content: a second invocation leaves matching files untouched. Modified files are not overwritten unless `--replace` is explicitly supplied. Comparisons use exact UTF-8 bytes, including line endings. Existing symlink files, symlink directories in the output path, and non-directory parents are rejected. Conflicts are checked before generated files are changed; individual writes use temporary files and atomic replacement.

Use a fresh output directory when changing which modules are enabled. Rendering refuses an output containing known generated files omitted by the new profile, even with `--replace`; this prevents stale standalone firewall rules from surviving a switch to `docker`. Unrelated files are preserved.

Choose an output directory writable only by you. Rendering does not defend against concurrent hostile directory replacement, and an I/O failure can leave a partially updated set of files; it is not a multi-file transaction. Repeatability and conflict handling are covered by automated tests.

**Host-application idempotence is not yet implemented.** The planned `apply` state machine will use typed resources, discovery, change plans, precondition checks, durable backups, atomic file updates, service-level validation, staged restart/reload, connectivity confirmation, rollback, and post-apply drift checks. An identical second `apply` should yield zero actions. Enabling a module already configured by another tool will require either verified adoption or explicit conflict resolution, never duplicate insertion of firewall rules.

See [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/deployment-safety.md`](docs/deployment-safety.md).

## Non-goals and limitations

- No tool can provide comprehensive protection against *every* cyberattack.
- The local audit cannot verify ISP/cloud anti-DDoS capabilities, server provider rescue access, off-site backup restorability, stolen credentials, application vulnerabilities, container escape, supply-chain integrity, or all compromise indicators.
- A status of `pass` means a **specific configuration condition** was observed, not that the whole subsystem is secure.
- The current audit checks nftables JSON for default-drop input base chains covering IPv4 and IPv6; it does not prove reachability or effective filtering under overlapping chains, Docker DNAT, or XDP.
- Generated nftables policy uses its own table and does not delete Fail2ban tables, but adding another base chain cannot be assumed to permit ports blocked by an existing chain. Test and migrate deliberately.
- SSH auditing uses `sshd -T` without connection-specific `-C` parameters; `Match` blocks for particular users or source addresses require separate review.
- Automatic-update checks inspect installed packages and APT configuration, not timer execution, successful upgrades, or the security coverage of configured origins.
- Currently targets Debian 13 only. Container integration exercises real Debian parsers and an isolated nftables network namespace. Full VM deployment, reboot, remote access, and packet reachability remain unverified. See the [QA report](docs/qa.md).

## Development and QA

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests

docker build -t d13dp-qa -f tests/integration/Dockerfile .
docker run --rm --network none --cap-add NET_ADMIN d13dp-qa
```

The Docker run command requires Docker and grants network administration only inside the disposable container's network namespace. It loads test rules there; use the command exactly as shown. CI runs unit and packaging checks on Python 3.11, 3.13, and 3.14, plus Debian 13 integration. See [docs/qa.md](docs/qa.md) for coverage and remaining limits.

## Agent-assisted development

Repository preparation, code review, bug fixes, documentation updates, and QA were performed with the **OpenAI Codex agent, powered by GPT-6**. The agent worked from the supplied v0.1.0 archive. This records development provenance; independent security review and production deployment validation remain outstanding.

## Roadmap

0.1: audit, plan, config rendering, deterministic output, CI.

0.2: reachability analysis, netfilter integration tests in disposable Debian 13 VMs, safe access bootstrap with independent SSH key, machine-readable change plans.

0.3: guarded `apply`/`rollback` state machine with timed failsafe, proof of new SSH connectivity, state snapshots, reproducible verification, and drift detection.

0.4: application profiles: reverse proxy, TLS, Docker/podman network discovery, AppArmor/auditd/systemd sandboxing, restricted service accounts, secrets and backup policies.

1.0: published test matrix, reproducible install, signed releases, threat-model review, network-level integration tests, operator recovery playbook, and independent security review.

## License

No open-source license has been selected yet. Decide licensing terms before publishing the repository as an open-source project.
