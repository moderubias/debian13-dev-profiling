# Architecture and resource ownership

## Goal

A reproducible Debian 13 security posture with explicit trust boundaries, idempotent operations, and a usable developer/operator workflow. The final CLI should make secure defaults practical without treating unknown existing settings as disposable.

## Desired CLI

```text
d13dp audit [--json] [--strict]
d13dp plan [--profile {minimal,web,docker} | --config FILE]
d13dp render [--profile PROFILE | --config FILE] [--output DIR]
d13dp manifest [--profile PROFILE | --config FILE]
d13dp network install|plan|apply|confirm|rollback|status

d13dp doctor
d13dp diff
d13dp apply --profile PROFILE --confirm-plan DIGEST
d13dp verify --profile PROFILE
d13dp status
d13dp rollback --transaction ID
d13dp configure ssh|ports|tls|docker|backups|alerts
```

The first four commands existed in v0.1. The experimental network command was added in v0.2.0a1; its bounded host-input implementation is described in [network.md](network.md). The other commands remain design targets and must not be presented as implemented.

## System invariants

1. Observing or planning may not mutate the server.
2. Host writes require an explicit operator-reviewed plan. No `curl | bash` deployment.
3. Host operations are serialized by a lock and journaled in a durable transaction record.
4. Desired state and observed state must be compared before any mutation.
5. Re-running an applied, verified desired state produces no new changes.
6. Foreign configuration is never silently overwritten or reset. Existing service ownership must be discovered and conflicts surfaced.
7. Firewall and SSH changes require retained access, a provider rescue path, timed rollback, and successful second-session verification.
8. Before each write, create a versioned backup with file metadata and a known-good rollback procedure. An interrupted multi-file apply must be recoverable.
9. Each module performs `inspect → plan → validate → stage → apply → verify → commit`, and can separately roll back its own changes.
10. Dynamic nftables tables, Docker rules, and Fail2ban sets belong to their respective owners. Never flush the global ruleset.
11. Shutdown behavior and systemd unit `ExecStop` must be included in firewall migration tests.
12. Installation or removal of packages, SSH host keys, authentication policies, kernel LSM changes, IPv6 changes, and container forwarding require separate precondition checks.

## Idempotence, convergence, and safe adoption

There are two distinct cases: (1) resources already managed by this tool, and (2) equivalent resources managed by a different program or manually. The first should converge through content hashes and state comparison. The second requires explicit safe adoption. For example, two independently defined Fail2ban jails for port 22 can create conflicting behavior even if both are independently idempotent. A new SSH drop-in can fail to override earlier settings due to OpenSSH's first-value-wins semantics.

Avoid relying on file names or service `active` status as proof of effective configuration. Use `sshd -T`, `nft -a list ruleset`, `fail2ban-client status`, `apt-config dump`, and end-to-end connection checks.

## Planned modules

- Inventory: OS, kernel, interfaces, public listeners, cloud and local firewalls, installed packages, containers, services, users, package repos, boot environment.
- Remote access: SSH key workflows, emergency console checks, login policies, access revocation, service users.
- Network: nftables owned table, dynamic port policy, IPv4 and IPv6, Fail2ban integration, conntrack telemetry, safe firewall change transaction.
- Host patching: APT origin policy, unattended-upgrades, reboot scheduling, kernel maintenance, software inventory.
- Process security: AppArmor profiles, auditd retention, systemd sandboxing, Linux capabilities, system permissions, kernel sysctl.
- App deployment: HTTP reverse proxy, TLS issuance/renewal, request budgets, webhook authentication, secret provisioning, isolated process identities.
- Containers: Docker engine version detection, effective backend, iptables/nftables policy, published ports, bridge and forward compatibility, host networking review.
- Recovery: off-host backups, restoration drills, provider snapshots, immutable backups where supported, credentials and key rotation.
- Observability: structured logs, alert delivery, uptime, TLS expiry, file integrity, suspicious login detection, drift detection, saturation metrics.
- Developer experience: status, plan diff, interactive configuration, project templates, diagnostics, self-check and explain commands.

## Hardening tiers

`baseline`: minimal known-good SSH access, explicit ports, automatic patching, simple logs.

`strict`: minimize reachable services, service-level sandboxing, access controls, audit logging, backup validation, constrained deployment workflow.

`isolated`: private admin path, separate deployment identities, private management network, restricted egress, higher audit coverage, upstream security products. Requires site-specific infrastructure.

Tier and application profile are orthogonal: for example, `strict + docker` must not accidentally break Docker forwarding.
