# debian13-dev-profiling

A Debian 13 (trixie) host security auditing, policy planning, and deterministic configuration generator. `d13dp` is the CLI name.

**Status: v0.2.0a1, experimental and pre-production.** `audit`, `plan`, `render`, and `manifest` retain their read-only/candidate-generation behavior. The separate `network` command provides a narrowly scoped, explicitly installed host-input firewall transaction workflow with timed confirmation and rollback. It is **not a general production hardening executor**: it does not configure SSH, install application services, manage Docker DNAT, or apply the other rendered modules. Read the [network transaction guide](docs/network.md) before using it.

## What is implemented

- Experimental `network install|plan|apply|confirm|rollback|status` with an owned nftables table, observed-state diffs, SSH preservation checks, durable transactions, a systemd rollback timer, and startup recovery.
- `minimal`, `web`, host-input-only `docker`, and custom TCP/UDP network policies. Unsupported existing inbound chains are conflicts, not automatically adopted.

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

## Candidate-rendering profiles

The `render` command uses the baseline profiles below. Transactional network profiles and their separate custom TOML format are described in [docs/network.md](docs/network.md).

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

**General host-application idempotence is not yet implemented.** The experimental `network apply` slice verifies effective nftables JSON and performs no writes when the same committed policy already matches. The planned general hardening executor still needs typed resources, module discovery, service-level validation, connectivity supervision, and post-apply drift checks. An identical second `apply` should yield zero actions. Enabling a module already configured by another tool will require either verified adoption or explicit conflict resolution, never duplicate insertion of firewall rules.

See [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/deployment-safety.md`](docs/deployment-safety.md).

## Non-goals and limitations

- No tool can provide comprehensive protection against *every* cyberattack.
- The local audit cannot verify ISP/cloud anti-DDoS capabilities, server provider rescue access, off-site backup restorability, stolen credentials, application vulnerabilities, container escape, supply-chain integrity, or all compromise indicators.
- A status of `pass` means a **specific configuration condition** was observed, not that the whole subsystem is secure.
- The current audit checks nftables JSON for default-drop input base chains covering IPv4 and IPv6; it does not prove reachability or effective filtering under overlapping chains, Docker DNAT, or XDP.
- Generated nftables policy uses its own table and does not delete Fail2ban tables, but adding another base chain cannot be assumed to permit ports blocked by an existing chain. Test and migrate deliberately.
- SSH auditing uses `sshd -T` without connection-specific `-C` parameters; `Match` blocks for particular users or source addresses require separate review.
- Automatic-update checks inspect installed packages and APT configuration, not timer execution, successful upgrades, or the security coverage of configured origins.
- Currently targets Debian 13 only. Container integration exercises real Debian parsers and an isolated nftables network namespace. The network slice also has isolated systemd, SSH, IPv4/IPv6 packet, conntrack, timer, failure-injection, and container-restart tests. Full VM deployment and cold reboot remain unverified. See the [network QA report](docs/network-qa.md) and [initial archive QA report](docs/qa.md).

## Development and QA

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests

docker build -t d13dp-qa -f tests/integration/Dockerfile .
docker run --rm --network none --cap-add NET_ADMIN d13dp-qa

# Real systemd/nftables transaction checks in a disposable container:
tests/integration/run-systemd.sh
```

The Docker run command requires Docker and grants network administration only inside the disposable container's network namespace. It loads test rules there; use the command exactly as shown. CI runs unit and packaging checks on Python 3.11, 3.13, and 3.14, plus Debian 13 parser integration and a separate systemd transaction job. The systemd runner uses an isolated privileged container, private cgroups, and no host mounts. See [docs/network-qa.md](docs/network-qa.md) for coverage and remaining limits.

## Agent-assisted development

Repository preparation, code review, bug fixes, documentation updates, and QA were performed with the **OpenAI Codex agent, powered by GPT-6**. The agent prepared the initial repository from the supplied v0.1.0 archive and implemented the experimental network slice and its regression tests. See the separate [Kiyoro recovery report](docs/kiyoro-recovery.md) for the explicitly applied VPS repair. This records development provenance; independent security review and production deployment validation remain outstanding.

## Roadmap

0.1: audit, plan, config rendering, deterministic output, CI.

0.2: reachability analysis, netfilter integration tests in disposable Debian 13 VMs, safe access bootstrap with independent SSH key, machine-readable change plans.

0.3: guarded `apply`/`rollback` state machine with timed failsafe, proof of new SSH connectivity, state snapshots, reproducible verification, and drift detection.

0.4: application profiles: reverse proxy, TLS, Docker/podman network discovery, AppArmor/auditd/systemd sandboxing, restricted service accounts, secrets and backup policies.

1.0: published test matrix, reproducible install, signed releases, threat-model review, network-level integration tests, operator recovery playbook, and independent security review.

## License

No open-source license has been selected yet. Decide licensing terms before publishing the repository as an open-source project.
