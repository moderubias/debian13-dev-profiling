# Delivery status and engineering handoff

Date: 2026-10-20. Release: **0.3.0a1, pre-production**. The requested universal production manager is not complete. The implemented deliverable is a guarded firewall lifecycle with strictly recognized legacy migration, durable recovery and real VM regression infrastructure. Do not apply it to Kiyoro merely because this code has been published.

## Delivered

- Kiyoshima Open profile generated/verified by the owner's local `klicense`; controlling license Apache-2.0, machine passport in `KIYOSHIMA.json`.
- Root-owned firewall runtime and explicit systemd installation; observed-state plan/diff, provisional apply, new-SSH-session confirmation, verify/status/drift and retryable pending rollback.
- Strict configuration and journal schemas; sanitized privileged child execution; backups and file/directory fsync; recovery after errors, interruption and reboot.
- Opt-in adoption of the exact supported manual `inet filter` layout; persistent two-file migration; preserve legacy forward/output policy and Fail2ban's independent dynamic table. Unknown layouts block mutation.
- Offline migration analysis from captured source/JSON, showing actual port changes, concrete file diff, runtime candidate and restoration batch.
- Real Debian 13 QEMU environment, regression/failure/crash/cold-boot tests, CI/static security checks and machine-readable reports.
- A separate [Kiyoro proposal](kiyoro-migration-plan.md), [security self-review](implementation-security-review.md), [transaction guide](network.md) and [QA matrix](network-qa.md).

The legacy audit and configuration renderer remain available. They do not install hardening modules. `minimal` and `web` are actual network policies; `docker` remains explicitly host-input-only and refuses common NAT layouts. Custom TCP/UDP host policy is supported. Database/development/production host lifecycle profiles are not implemented and must not be represented as working presets.

## Readiness gates still open

| Requested capability | Current boundary / remaining work |
| --- | --- |
| General declarative resource engine | Extract reviewed lifecycle adapters and a typed ownership/resource manifest from the network slice; implement dependency DAG, composition, strict workload schemas, interrupted installation recovery and versioned upgrades |
| Access hardening | Independent rescue access, key enrollment/revocation, effective `sshd -T -C` validation, least-privilege users, transactional reload and independent reachability supervisor |
| Fail2ban management | Preserve supported existing bans today; add owned jail/action lifecycle, duplicate/precedence detection and safe adoption of supported external resources |
| Host system modules | Unattended-upgrades origin policy and reboot controls, AppArmor workload compatibility, auditd retention/availability, file ownership/permissions and validated sysctl lifecycle |
| Applications | Validated Caddy/reverse-proxy lifecycle, certificate issue/renewal tests, rate limiting per supported proxy build, secrets, service users and sandbox compatibility |
| Containers | Detect/version backend; implement and test iptables-nft/native nftables ownership, rootless compatibility, bridge/NAT/forwarding, original-destination published-port policy, IPv6 and capability/socket restrictions |
| Operations | Monitoring/notifications with real delivery tests, off-host backups and restoration, certificate expiry checks, update/maintenance workflows |
| DDoS | Provider ACL/protection inventory and external policy confirmation; local firewall cannot protect against link saturation |
| Recovery coverage | Runtime/self-upgrade interruption, real disk/power failure, concurrent external managers and independent console/backup restore drill |
| Security review | Obtain a separate qualified external review; automated scans and agent self-review are not substitutes |
| Production rollout | Approve the exact reviewed commit/diff only after workload-specific VM tests and the independent rescue checks; no live migration is authorized yet |

## Next implementation sequence

1. Keep the network adapter's transaction and journal invariants. Add a versioned ownership/resource interface and dependency graph with one fully tested service adapter; avoid parallel execution of mutating modules.
2. Add access provisioning/recovery first, before changing authentication policy. Extend VM failures to service reloads, second-channel loss and socket-activated SSH handling.
3. Implement Fail2ban and APT update adapters on installed prerequisites. Treat package installation/upgrades as a separate non-atomic boundary; do not advertise arbitrary package rollback.
4. Implement Docker per actual backend/version, with outside-client IPv4/IPv6 TCP/UDP tests through DNAT and bridge forwarding. Do not relax Kiyoro's retained forward drop automatically.
5. Add reverse proxy/TLS and sandbox adapters with staging ACME renewal fixtures, then databases/development/production profile composition. Backups/observability must have real restore/delivery tests before a profile can claim them.
6. Expand adversarial/reboot/upgrade matrix, complete independent audit and only then consider a production release and separately approved Kiyoro deployment.

## Working state and reproducibility

Code is published as logical commits; the conversation's final delivery records the exact SHA and CI link. Reproduce unit, scan and VM commands from the QA/security documents. Existing `.build/` inventories and guest disks are local diagnostics, excluded from Git and artifacts containing keys. They are not required to build the package.

In this development stage Kiyoro was accessed for read-only inventory and service checks. Its HTTPS installation was previously repaired under separate authorization; the experimental engine is still absent. Current external HTTPS checks are recorded in the proposed rollout. No production firewall mutation, package update, service restart, data removal or reboot was performed in this stage.
