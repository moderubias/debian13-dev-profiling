# Kiyoro proposed rollout — not applied

Date: 2026-10-20 UTC. This is a separate proposal for the already working server, not authorization to migrate it. No d13dp runtime, unit, policy, or migration has been installed/applied on Kiyoro during this development stage. Existing services have not been restarted by this stage.

## Read-only evidence

The captured live JSON and `/etc/nftables.conf` match the recognized legacy template: INPUT drop with TCP `{22,80,443}`, FORWARD drop and OUTPUT accept. Fail2ban maintains a separate `inet f2b-table`; the nftables stop override preserves the ruleset. SSH uses keys. Read-only checks at approximately 02:56 UTC found ssh, nftables, Fail2ban and Caddy active, Caddy 2.11.7, and a live SSH jail with one ban.

External checks at approximately 02:57 UTC used explicit `--resolve DOMAIN:443:94.249.172.51` and TLS verification: apex HTTPS returned 200 and `www` returned 301 to the apex. These checks do not prove future certificate renewal, IPv6 reachability, or provider-console access. The development workstation uses a synthetic DNS resolver, so its local `getaddrinfo` address must not be presented as authoritative public DNS.

Google public DNS-over-HTTPS returned A `94.249.172.51` and no AAAA answer during this check. Public DNS and provider ACLs must be checked again immediately before deployment. The provider firewall dashboard/rescue console has not been accessed. There is no reason to change a working Caddy installation as part of firewall ownership migration.

## Exact intended changes

The offline migration plan reports **zero TCP/UDP permission additions or removals** for `web`. The actual ownership/persistence changes would be:

1. Install the reviewed package into `/opt/d13dp` and explicitly install the dedicated empty boot/recovery unit.
2. Back up the recognized original source, permission mode/group, policy and live owned-state boundary in `/var/lib/d13dp/network/transactions/`.
3. Arm a 120-second independent systemd rollback timer.
4. Replace `/etc/nftables.conf` with the following retained legacy subset, preserving its original mode and group:

```nft
destroy table inet filter
table inet filter {
chain forward { type filter hook forward priority filter; policy drop; }
chain output { type filter hook output priority filter; policy accept; }
}
```

5. Write `/etc/d13dp/network.nft` with the deterministic `web` policy: owned table/comment, TCP set `{22,80,443}`, empty UDP set, INPUT drop, loopback/conntrack/ICMP allowances.
6. Submit this runtime operation as one batch:

```nft
flush chain inet filter input
delete chain inet filter input
# Then the full generated inet d13dp_network table from render_network(web).
```

This is a **chain-specific** flush within the atomic batch, not a global ruleset reset. FORWARD and OUTPUT retain their handles during apply. The Fail2ban table/sets/rules remain owned by Fail2ban, including bans added while the migration is pending. No SSH, Caddy, Docker, nftables or Fail2ban restart is part of this transaction.

The exact full candidate/rollback batches and unified file diff can be regenerated without deploying anything:

```bash
./d13dp network migration-plan --ruleset ruleset.json --source nftables.conf --profile web > migration-plan.json
```

A fresh live plan digest is required for application; the offline digest cannot authorize a live apply. Keep captured rules private because ban addresses and deployment details may be sensitive.

## Conditions before requesting deployment approval

- The complete VM matrix and CI for the selected commit must be green; review the separate implementation security report and outstanding readiness gaps.
- Obtain a provider snapshot and verify actual independent console/rescue access; record their identifiers privately.
- Refresh nftables JSON, source file including metadata, systemd unit/drop-ins, SSH listeners, Fail2ban status/action configuration, DNS and application probes. Any mismatch or additional rule blocks the rollout.
- Verify that no other automation will reload an older INPUT definition, and that the retained FORWARD drop is compatible with this host's workloads. Full Docker bridge hosting is outside this release.
- Review the concrete target diff and rollback procedure, then obtain the owner's **separate permission** to install/apply on the running VPS.

## Post-permission procedure and abort conditions

Use the guarded commands in [firewall-migration.md](firewall-migration.md) with `--profile web --adopt-filter`. Keep the original SSH session and console available. Before confirming, open a fresh key-authenticated SSH connection, probe HTTPS for both hostnames from outside the VPS, verify listeners, and inspect nftables/Fail2ban effective state. Confirm from the new SSH session only if all checks pass within the deadline.

On timeout/error, the worker restores the original legacy source/mode/group, reinstates only the recognized legacy INPUT rules, removes the provisional owned table and verifies restoration. Dynamic Fail2ban bans are not rolled back. If recovery fails, pending state remains and the timer retries; use the independent console and inspect the exact retained journal. Do not replace unknown new rules with a global snapshot.

After a successful commit, record the transaction and commit SHA privately, run `network verify --profile web`, and observe the existing certificate renewal/monitoring workflow. A production reboot requires its own maintenance decision; VM cold-boot tests are not permission to reboot this server.
