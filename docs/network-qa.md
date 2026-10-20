# Network transaction QA — 2026-10-20

Scope: v0.3.0a1 host-input lifecycle and recognized legacy migration. Development used OpenAI Codex (GPT-6). This is a bounded integration matrix, not production certification. The original archive QA and separately authorized HTTPS repair have different scopes.

## Environment and reproduction

The runner uses a checksum-pinned official Debian 13 genericcloud image, version `20261017-2634`, booted under QEMU TCG. It has its own Debian kernel, systemd PID 1, real nftables, OpenSSH, conntrack and Fail2ban. Docker runs **only the unprivileged emulator process**, with no host network administration capabilities, host cgroup mounts or host service configuration. The runner uses host networking to expose one **loopback-only** SSH forwarding port and to provide QEMU user-mode egress. All firewall mutations and nested client namespaces run inside the VM's own kernel.

```bash
python3 -m pip install build
python3 tests/run_unit.py
python3 tests/vm/run.py
```

Requires Docker, internet access, approximately 2 GiB available memory and several GiB disk space. Hardware virtualization is unnecessary. The runner refuses an existing `.build/vm/lab.json` to avoid destroying retained diagnostics. Use a new checkout or explicitly archive previous task-owned VM state before preparing another run. Do not run guest programs directly on a host. Guards require QEMU virtualization, a cloud-init fixture marker and `D13DP_ISOLATED_QA=1`.

The runner downloads only the pinned base image and verifies its embedded SHA-512. Debian package updates are obtained at provisioning time; versions are captured in the report rather than claimed to be bit-for-bit immutable. No production credentials are used. Guest-only SSH keys remain in the private `.build/vm` directory and are never uploaded as CI artifacts.

`tests/integration/run-systemd.sh` is a compatibility wrapper for the VM runner. The former privileged-container networking tests have been replaced; a container restart is no longer called a cold reboot.

## Matrix

| Area | Automated checks |
| --- | --- |
| Installation | Installed wheel outside checkout; explicit owned unit; unit syntax; repeated install has no changes |
| Policy transitions | `minimal → web → web → minimal`; TCP 22/80/443 over IPv4 and IPv6; ten identical applications preserve rules, file bytes and mtimes |
| Protocols and conntrack | Custom TCP 8443/UDP 5353 over both families; existing established TCP flows survive removal while new flows are denied |
| Remote safety | Real key-authenticated SSH; confirmation from a separate connection; observed SSH ports retained; service PID unchanged |
| Dry-run and drift | Actual deltas; no writes during dry-run; stale digest refusal; structural/persistent drift conflicts; port-set drift and guarded reconciliation; `verify`/`status` exit codes |
| Ownership | Foreign inbound hooks refused; no global reset; unrelated forwarding table preserved; unknown migration objects/source refused |
| Fail2ban | First transaction fixture checks and then real daemon-created bans; dynamic ban during timeout survives; actual banned client loses SSH and unban restores it |
| Migration | Recognized source and live JSON; explicit adoption; runtime FORWARD/OUTPUT handles preserved; original CRLF bytes and file permissions restored; ten applications; reverse profile transition; reintroduced INPUT and file drift refused |
| Error handling | Inject candidate/rollback netlink failures; retain pending on failed restoration; retry successfully |
| Process interruption | Real SIGKILL after transaction, pending pointer, timer, legacy file, owned file and netlink load; recover recognized legacy state and preserve Fail2ban |
| Boot | Initial adoption pending at full guest power-off; recover legacy policy on fresh boot; committed adoption plus later pending change; recover committed minimal policy; second cold boot retains it |
| Parsers | Real Debian OpenSSH, Fail2ban and APT parsing of candidates in isolated fixture directories; repeated nft candidate loading inside the guest |
| Static/dependencies | Python compilation, Ruff, Bandit medium/high gate, installed runtime dependency audit; JSON/JUnit artifacts |

Local development runs completed the main transactions, migration, parser tests, six SIGKILL points and cold-boot checks. The consolidated fresh-VM runner and GitHub Actions provide the authoritative per-phase result for the selected commit; inspect their JSON/JUnit artifacts instead of inferring a pass from this matrix definition. Failure traces from fixture startup/metadata parsing were corrected during development, not counted as successful tests.

## Reports and CI

Unit tests currently total **64** and produce `.build/reports/unit.xml`. The VM runner produces `.build/reports/vm/matrix.json`, `junit.xml`, phase logs, effective rules, package versions, unit journals and Fail2ban status. CI uploads these reports even on failure. Security scan JSON is stored separately. Raw VM disks and SSH keys are excluded from Docker build context and artifact upload.

CI runs Python 3.11, 3.13 and 3.14 packaging/unit checks, security analysis, and the real Debian VM suite. Debian/kernel/package versions in each artifact identify what was actually exercised. A skipped or failed phase is not a passing scenario.

## Not certified

Docker bridge/NAT policy management, published-port enforcement, rootless Docker, real ACME renewal, provider ACL/DDoS protection, independent rescue/backup restoration, hostile-root concurrency and storage power-loss behavior remain outside the passing scope. Installing Docker in the fixture image does not establish Docker support. No lifecycle application of the other hardening modules is implemented. See [delivery status](delivery-status.md) and [implementation security review](implementation-security-review.md).
