# Network transaction QA, 2026-10-20

Scope: experimental v0.2.0a1 host-input transactions. Implemented and tested with OpenAI Codex (GPT-6). The [initial archive QA](qa.md) and the [separate authorized VPS repair](kiyoro-recovery.md) have their own scopes.

## Automated coverage

The 48 unit tests cover the existing audit/renderer plus network policy validation, custom TCP/UDP ports, supported profiles, SSH-session parsing, live/effective SSH consistency, exact semantic comparison with rule ordering preserved, inbound-chain conflicts, the supported drop-only Fail2ban exception, safe systemd stop/startup recovery declarations, refusal to confirm from the original SSH session, explicit console confirmation, expired deadlines, and old-boot confirmation rejection.

The real integration runner builds a Debian 13 container with the installed wheel, nftables, systemd PID 1, OpenSSH, iproute2, and conntrack. The container has a private network/cgroup namespace, no external network, no host bind mounts, and temporary runtime directories. A nested network namespace acts as a client over a veth pair with IPv4 and IPv6 addresses. This is a suitable isolated systemd test environment, not a complete VM or a cold reboot of Debian.

Executed scenarios:

- Explicit installation and repeated installation; `systemd-analyze verify` accepts the owned unit.
- Real key-authenticated SSH apply and confirmation from separate connections.
- `minimal -> web -> web -> minimal`: new TCP 80/443 connections work only in `web`; TCP 22 remains reachable on IPv4 and IPv6.
- Repeated `web` returns `changed: false`; full nftables JSON, persistent file bytes, and managed-file modification times are unchanged.
- Dry-run reports real additions and leaves those same snapshots unchanged.
- Existing IPv4/IPv6 TCP connections remain usable after port removal; conntrack contains established flows, while fresh connection attempts are denied.
- Custom TCP 8443 and UDP 5353 work on IPv4/IPv6; a subsequent profile removes their permissions for new connections.
- The Docker host-input profile preserves a separate forwarding table. This does not certify Docker bridge/DNAT operation.
- Foreign input hooks, stale plan digests, persistent file edits, structural live-rule drift, and policies omitting observed SSH ports are refused.
- An injected nft load failure restores the previous effective rules and persistent file immediately.
- An injected rollback load failure retains the pending journal; the real systemd timer subsequently completes rollback.
- An overlapping apply while another transaction is pending is refused.
- A dynamic Fail2ban-style ban added during a provisional transaction survives timeout rollback.
- A real Fail2ban-style source ban continues to override the owned TCP 22 allowance.
- Restarting the owned unit while a transaction is pending restores the committed profile first; stopping it preserves rules. Startup refuses edited persistent configuration without changing live rules, and direct systemd reload is unsupported.
- SSH's service PID remains unchanged across network transitions.
- A pending transaction is persisted, the entire container is restarted (discarding transient timer/runtime namespaces), and startup recovery restores the committed `minimal` policy and file.

## Reproduce

From the reviewed repository root:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
tests/integration/run-systemd.sh
```

The host script builds and removes its disposable test container, including on failure. It requires a Docker environment capable of booting systemd with private cgroups and a privileged container. It mounts no host state. The integration program refuses a normal host execution and requires a fresh `--network none` Docker environment plus `D13DP_ISOLATED_QA=1`. All live nftables and systemd mutation checks occur inside this environment. Do not replace the isolated Docker invocation with execution on a production host.

Where Docker bridge egress is unavailable during the image build, use `D13DP_BUILD_NETWORK=host tests/integration/run-systemd.sh`. The actual runtime still uses `--network none`. This build-only adjustment was needed on the development workstation.

CI runs unit/packaging checks on Python 3.11, 3.13, and 3.14, the existing Debian parser integration, and the independent systemd transaction suite. The package version is a prerelease; no production certification is implied.

## Remaining limits

No full Debian VM cold reboot, provider recovery drill, hostile-root concurrency test, disk power-loss fault injection, or independent security review has been performed. Kernel/systemd/disk failure can defeat an in-band failsafe. Root can forge SSH environment attestations. Socket-activated SSH, foreign ingress/prerouting policies, arbitrary Fail2ban layouts, automatic migration of existing tables, and Docker bridge/NAT ownership are unsupported and refused. The engine manages only host INPUT and requires an explicitly installed root-owned runtime; the other hardening modules remain read-only candidates.
