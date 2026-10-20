# Threat model

## Assets

Remote administrative access, server availability, host integrity, secrets and SSH keys, workloads (bots and web apps), user information, backups, software supply chain, and DNS/TLS control.

## Threats, controls, and limits

| Threat | Local and application controls | Residual or external dependency |
| --- | --- | --- |
| SSH brute force and credential stuffing | Key-only SSH, verification, Fail2ban or equivalent, reduced attack surface | Stolen private keys, breached administrator device, provider console |
| Network scanning and unexpected listeners | Deny-by-default firewall, service discovery, network isolation | Exposed IP and provider-level policy |
| SYN/connection exhaustion | SYN cookies, connection telemetry, per-service limits | Large traffic floods consume host/network resources |
| Bandwidth/packet-rate DDoS | Provider upstream filtering; optional scrubbing service | Host firewall cannot reclaim saturated upstream bandwidth |
| HTTP request flooding, bot abuse | CDN/WAF when appropriate, reverse-proxy limits, application quotas and request budgets | Layer-7 attacks can resemble legitimate traffic |
| Injection, authentication bypass, application RCE | Dependency policy, input validation, least privilege, AppArmor/systemd isolation, code review and tests | App-specific vulnerabilities cannot be eliminated by generic host settings |
| Container escape or exposed service | Docker engine patching, container identities, permissions, network policies, published-port discovery | Kernel and container runtime vulnerabilities |
| Secret leakage | Separate secrets from git, least-privilege accounts, rotation, log sanitization | Supply-chain and developer endpoint compromise |
| Persistence following compromise | Audit logs, immutable/off-host forwarding, integrity monitoring, incident response | Root attackers may tamper with local evidence |
| Ransomware/destructive commands | Independent backups, snapshots, restore drills, access controls | Backup deletion without separate credentials or immutable retention |
| Supply-chain compromise | Pinning, provenance, updates, attestations, dependency review | Maintainer and upstream compromise |
| DNS hijack or certificate abuse | Registrar MFA, DNSSEC when supported, TLS renewal monitoring | Provider account and DNS operator trust |

## Baseline safety constraints

Disabling password SSH alone does not prevent stolen-key access. Fail2ban blocks identified login attempts, not all DDoS traffic. AppArmor and auditd may disrupt applications or exhaust storage if configured indiscriminately. Changing sysctls without a network topology review may break routing. Docker's networking uses separate firewall semantics and must not be treated as an ordinary standalone host.

## Acceptance criteria for a future full release

Every supported deployment profile needs a tested install, re-run with zero drift, controlled profile change, rollback, cold reboot, key rotation, loss-of-access recovery, coexistence with Fail2ban, IPv4/IPv6, and service reachability tests. Docker profiles additionally need published-port and forwarding tests. DDoS claims must distinguish packet filtering from contracted upstream mitigation. User-visible scores may only summarize defined checks, not imply absolute security.
