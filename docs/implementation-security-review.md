# Implementation security review — 2026-10-20

Scope: v0.3.0a1 privileged firewall and migration code. Review and remediation were performed with OpenAI Codex (GPT-6), separately from the implementation test phase. This is a self-review assisted by static tools, **not an independent external security audit or production certification**.

## Findings corrected

| Finding | Remediation and evidence |
| --- | --- |
| Recovery trusted loosely parsed durable JSON and saved raw nft text | Exact state/transaction/policy schemas; duplicate keys, non-finite numbers, invalid ports and inconsistent effective state are refused. Rollback reconstructs only the supported template. The legacy raw field remains readable but is never executed. Unit regressions cover corruption/injected commands. |
| Privileged child commands inherited the caller's environment/search path | Fixed system executable search path and minimal child environment; no shell. Regression checks remove `LD_PRELOAD`/`PYTHONPATH` influence on children. This does not make launching an untrusted Python runtime safe; root-owned installed code remains mandatory. |
| Apply errors could be hidden by a second rollback error | Report both failures and the retained pending transaction; real VM command-failure/retry tests exercise this path. |
| File-only status could obscure live drift | Verify compares observed rules, persisted policy, boot unit and SSH prerequisites; status exposes drift with a nonzero code. Port-set drift requires a fresh reviewed transaction; structural drift is a conflict. |
| Broad Fail2ban-name exception accepted unknown expressions | Restrict the compatible shape to explicit TCP ports, a typed source-address set and deny action. Unknown action layouts fail closed; the daemon's dynamic sets are never restored from a global snapshot. |
| Legacy migration could overwrite unsupported manual policy | Validate both live objects and source against one exact supported template; explicit adoption is required. Retain legacy FORWARD/OUTPUT; refuse foreign overlapping hooks and active legacy iptables rules. |
| Multi-file migration needed recovery and metadata preservation | Journal original source, mode/group and canonical state before mutation; independent timer before writes; fsync and atomic replacement per file; one netlink batch; strict post-apply/confirmation checks. Preserve mode/group during apply and rollback. |
| Container restart was insufficient evidence for cold reboot | Replace privileged networking containers with an unprivileged QEMU runner and an independent Debian kernel. Test six SIGKILL boundaries, a failed rollback retry and real cold boots. |

## Automated scans

Ruff checks undefined/unused code (`F` rules), compilation checks all sources, and Bandit scans the implementation. The local scan found no medium/high findings. Its low-severity subprocess import/call findings were reviewed: command arguments are structured and shell execution is disabled. CI retains the full JSON scan rather than presenting this as proof of exploit absence.

The application has no third-party runtime dependencies. `pip-audit` checks the installed environment and emits JSON; the unpublished project distribution itself is reported as skipped by the vulnerability database. That skip is expected and does not audit project source. Build/CI tools are separate dependencies; their version pins and maintenance remain part of the supply-chain review.

## Outstanding risks and review gates

- No independent reviewer has audited the full privileged implementation. Root can alter code, environment attestations, files or tables outside the tool's advisory lock.
- No universal firewall equivalence solver exists. Unknown rules, includes, overlapping inbound hooks, socket-activated SSH, arbitrary Fail2ban actions and Docker NAT/bridge backends are refused. Public reachability is verified operationally, not proved from a listener alone.
- Full atomicity across two files, systemd, disk and kernel is impossible here. Recovery assumes functioning systemd, writable durable storage, a usable kernel and the installed root-owned runtime. SIGKILL/cold-boot tests are not storage power-loss fault injection.
- Package-manager transactions and runtime upgrades are not rolled back by the firewall journal. Do not upgrade/remove the runtime while pending. A general safe self-updater is not implemented.
- Only pending transactions can be rolled back. Historical policy changes use a fresh reviewed plan; there is no arbitrary historical snapshot replay.
- Out-of-band console access, off-host backup restoration, external provider ACL/DDoS controls, real ACME renewal and monitoring delivery remain unverified by this release.
- SSH, AppArmor, auditd, unattended-upgrades, TLS, application sandboxing, secrets and Docker are not managed lifecycle modules yet. Candidate file generation must not be mistaken for applied or certified hardening.

The production-readiness gate remains closed. See [delivery status](delivery-status.md) for the remaining implementation and validation work.
