# Experimental host-input network transactions

Version 0.3.0a1 implements one vertical slice: an owned nftables INPUT policy, a persistent boot unit, a reviewed observed-state plan, provisional apply, bounded confirmation, and rollback. It is not a complete production hardening tool. The legacy `render` output is not consumed by this engine.

## Scope and profiles

| Policy | Allowed new host TCP connections | UDP | Forwarding and NAT |
| --- | --- | --- | --- |
| `minimal` | 22 | None | Unchanged |
| `web` | 22, 80, 443 | None | Unchanged |
| `docker` | 22, 80, 443 on the host | None | Unchanged; host-input slice only |
| Custom TOML | Declared `tcp` ports | Declared `udp` ports | Unchanged |

The owned table is `inet d13dp_network`. One INPUT base chain defaults to drop. Loopback, established/related connections, ICMP, and IPv6 ICMP are allowed; invalid conntrack state is dropped. Named port sets prevent duplicate permissions. The rules apply to IPv4 and IPv6 together. HTTP/3 needs explicit UDP 443 in a custom policy; `web` intentionally opens TCP only.

Removing a permission denies **new connections**. Already established TCP/UDP flows remain accepted through conntrack until they close or expire. The tool does not flush conntrack or terminate application connections.

The engine never changes forwarding, output chains, Docker rules, Fail2ban tables, SSH configuration, or application services. In particular, Docker-published ports traverse DNAT/forwarding and are **not controlled by host INPUT allowances**. Existing foreign INPUT, prerouting, or ingress hooks are rejected, except for the explicit, strictly recognized legacy INPUT migration described in [firewall-migration.md](firewall-migration.md). Consequently, common Docker bridge/NAT installations require a future backend-specific integration and are currently refused, even with `--profile docker`. The Docker profile does not claim full Docker networking support; only coexistence with non-conflicting forwarding rules and host networking is covered.

## Prerequisites and explicit installation

Use a disposable Debian 13 VM with console access first. Commands require root, a real systemd PID 1, nftables JSON support, working `sshd -T`, and matching live sshd listeners discoverable through `ss -lntp`. SSH socket activation and other firewall managers' inbound layouts are unsupported. Keep independent provider rescue access; the tool cannot prove that it works.

Install the reviewed package into a root-owned virtual environment. Network installation refuses a runtime or state path writable by another user. Python 3.11+ and `python3-venv` are needed.

```bash
sudo python3 -m venv /opt/d13dp
sudo /opt/d13dp/bin/python -m pip install .
```

Before installation, review `nft -a list ruleset`, `/etc/nftables.conf`, and `systemctl cat nftables.service`. A global reset in the existing persistent config or `ExecStop` is a blocking conflict. Includes are conservatively refused because their ownership and restart effects are not analyzed. Do not discard existing configuration to satisfy this check.

On a reviewed host where preserving rules on service stop is intended, the nftables service override is:

```ini
[Service]
ExecStop=
ExecStop=/usr/bin/true
```

After an explicitly reviewed override, `systemctl daemon-reload` updates unit metadata without reloading the firewall. Any persistent rules must replace only their owned tables. An existing `inet filter` INPUT chain remains a conflict without explicit adoption. The supported template can be reviewed offline and migrated through the [guarded migration workflow](firewall-migration.md). Kiyoro requires its own separately approved rollout; see [the proposed plan](kiyoro-migration-plan.md).

Install the dedicated unit explicitly:

```bash
sudo /opt/d13dp/bin/d13dp network install
sudo /opt/d13dp/bin/d13dp network status
```

This creates `/etc/d13dp/network.nft`, `/var/lib/d13dp/network/`, and `/etc/systemd/system/d13dp-network.service`, enables the owned boot unit, and starts it with an empty initial policy. It does not start or reload existing firewall/application services. Repeating installation makes no changes when these resources already match. Existing conflicting units, drop-ins, unjournaled files, and unowned reserved tables are refused.

## Plan, apply, and confirm

Preserve the real `SSH_CONNECTION` environment through sudo. A plan reads effective nftables JSON, existing file content, unit configuration/state, and live SSH listeners. It reports TCP/UDP additions/removals, the actual before/after objects, a file diff, conflicts, and a digest. Planning does not create files, locks, timers, or rules.

```bash
sudo --preserve-env=SSH_CONNECTION /opt/d13dp/bin/d13dp network plan --profile web
sudo --preserve-env=SSH_CONNECTION /opt/d13dp/bin/d13dp network apply --profile web --dry-run

# Replace DIGEST with the value from the reviewed, fresh plan.
sudo --preserve-env=SSH_CONNECTION /opt/d13dp/bin/d13dp network apply \
  --profile web --expect-plan DIGEST --confirm-timeout 120
```

Every discovered SSH port, plus the server-side port in the actual SSH session, must be declared and remain allowed. The engine does not change SSH ports. For a host using port 2222, use custom policy with 2222 in both `tcp` and `ssh_ports`; a built-in port-22 profile is refused.

Apply checks the digest again under an exclusive journal lock, validates both candidate and rollback with `nft -c`, saves the before-state, arms and verifies an independent systemd timer, rechecks live state, atomically replaces the persistent file, and sends one atomic nftables batch affecting only its table. Exact effective JSON is checked after loading. Errors trigger immediate rollback; the durable pending journal and timer remain available if rollback itself fails.

Apply prints a transaction identifier. Verify the intended service externally and open a **new SSH connection** before confirming:

```bash
sudo --preserve-env=SSH_CONNECTION /opt/d13dp/bin/d13dp network confirm TRANSACTION
```

The original SSH connection tuple cannot confirm its own transaction. This is an operational guard, not cryptographic attestation: root can forge environment variables. Independent IPv4/IPv6/service reachability still requires operator checks. A local console workflow requires explicit `--console` on apply and confirm.

Confirmation is limited to 15–600 seconds and uses a monotonic deadline. It checks the boot identifier, effective rules, persistent candidate, unit prerequisites, and SSH listeners again. Expired confirmation rolls back. Commit clears the pending pointer durably **before** cancelling the timer, so an already queued rollback worker safely becomes a no-op. Only one provisional transaction may exist.

Repeat the same committed profile:

```bash
sudo --preserve-env=SSH_CONNECTION /opt/d13dp/bin/d13dp network apply --profile web
```

It returns `changed: false` and performs no file, nftables, timer, or service changes when effective and persisted state match. A digest is required only when changes are needed. For removal, plan/apply/confirm `minimal` through the same protocol; new TCP 80/443 connections will be denied while SSH remains allowed.

Custom policy example:

```toml
tcp = [22, 8443]
udp = [51820]
ssh_ports = [22]
```

Use `--config examples/network-custom.toml` instead of `--profile`. Unknown keys, protocols outside TCP/UDP, invalid/duplicate ports, or omitted SSH ports are rejected. Structural live drift and persistent file edits require manual review. Port-set drift is visible in a fresh plan and may be corrected through a new guarded transaction.

## Rollback, systemd, and recovery

```bash
sudo /opt/d13dp/bin/d13dp network status
sudo /opt/d13dp/bin/d13dp network rollback TRANSACTION
```

Rollback restores only the previous owned table and persistent file; it never restores a global ruleset snapshot. Fail2ban changes made while a transaction is pending therefore survive. Rollback is retryable, and the pending pointer remains until runtime and file restoration both succeed. Calling rollback for a non-pending transaction is a no-op. Previously committed policies are changed through a new plan/apply/confirm cycle, not arbitrary historical replay.

The transient timer runs `d13dp-network-rollback-<transaction>.service` with retry on failure. The permanent unit runs a recovery worker in `ExecStartPre`, **before loading the persistent candidate**. Any pending transaction is restored on a unit start or boot, including when transient timers disappeared across a restart. `ExecStop=/usr/bin/true` preserves rules; no global ruleset reset is used. Starting/restarting the unit validates committed file content and inbound topology, then deliberately recreates only its owned table in one batch. Direct systemd reload is unsupported; policy changes use the guarded CLI. Routine CLI reapplication avoids even this replacement when nothing changed.

Backups and the journal are under `/var/lib/d13dp/network`, with root-only writes and atomic replacement plus file/directory `fsync`. Runtime modules and unit text are rooted in the installed virtualenv. Do not upgrade/remove that runtime or edit managed units while a transaction is pending. Installer writes and boot-unit enabling are explicit setup operations, not a transaction spanning all systemd files.

This is a Linux/systemd failsafe, not an out-of-band recovery system. Disk failure, unavailable systemd/kernel, root interference, unsupported boot ordering, and loss of the installed runtime can prevent timely recovery. No external connectivity supervisor or provider-console verification exists. Recovery errors retain the journal and require console inspection. Real VM cold reboot is covered by the current matrix; deployment certification remains outstanding; see [the QA report](network-qa.md).

## Inspection exit codes

`network diff` is an alias for the observed-state `plan`. `network verify` returns 0 only when desired live rules, persistence, SSH prerequisites and unit ownership match; it returns 2 for differences/conflicts and 1 for an operational/validation error. `network status` returns 2 for committed live/persistent drift, 1 for conflicts/errors, and 0 for a valid inspected state (including a visibly pending transaction). Other network commands return 1 on refusal and 0 on success; argument syntax errors return 2. `changed: false` means no system writes were needed. Read the JSON fields rather than treating successful inspection as external reachability proof.
