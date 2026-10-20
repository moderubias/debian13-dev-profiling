# Recognized legacy firewall migration

Version 0.3.0a1 adds an explicit, bounded migration path. It does not adopt arbitrary nftables rules or certify production readiness. Test the exact workload in a disposable Debian 13 VM and retain provider console access before deployment.

## Ownership boundary

Supported legacy input is a complete `inet filter` table with exactly:

- INPUT: priority 0, policy drop; loopback accept, invalid conntrack drop, established/related accept, IPv4 ICMP accept, IPv6 ICMP accept, and one TCP port allowance, in that order.
- FORWARD: priority 0, policy drop, no rules.
- OUTPUT: priority 0, policy accept, no rules.
- A persistent `/etc/nftables.conf` matching this template, preceded by `destroy table inet filter`. Comments and whitespace are permitted; unknown commands, includes, objects, counters, expressions, priorities, or policies are refused.

Both the live JSON and source file must match. A table's name alone does not establish ownership. Dynamic `inet f2b-table` data is externally owned; the supported exception accepts only TCP port/source-address-set deny rules in accepting INPUT base chains. Unknown Fail2ban action layouts block mutation. Legacy iptables rules outside nftables are also a conflict.

Migration removes **only the legacy INPUT chain** and creates `inet d13dp_network` in one atomic nft batch. Existing FORWARD/OUTPUT chains retain their runtime handles. The persisted legacy file retains those two chains and its table-specific replacement header. The new INPUT policy lives in `/etc/d13dp/network.nft` and is loaded by the separately owned unit after `nftables.service`. No global ruleset reset is used.

The retained FORWARD drop policy is intentional. It can block routing and Docker bridge traffic; migration does not silently relax it. Docker NAT/bridge backends remain unsupported and are refused by the inbound topology checks.

## Offline review

Capture files using read-only access and keep the inventory private:

```bash
ssh HOST 'sudo nft -j list ruleset' > ruleset.json
ssh HOST 'sudo cat /etc/nftables.conf' > nftables.conf
./d13dp network migration-plan --ruleset ruleset.json --source nftables.conf --profile web
```

This command needs no root privileges and executes no host probes. It reports the actual port delta, legacy file diff, canonical before/after objects, candidate and rollback batches, and a review digest. It is **not an executable authorization or live preflight**: service units, SSH listeners, console access, application reachability and freshness must be checked on the target. Do not pipe its candidate batch to nft; the transaction engine adds recovery protection.

## Guarded application

A separate deployment decision is required for the live Kiyoro server; see [its proposed rollout](kiyoro-migration-plan.md). On an independently approved, supported target with a reviewed root-owned runtime:

```bash
sudo /opt/d13dp/bin/d13dp network install --adopt-filter
sudo --preserve-env=SSH_CONNECTION /opt/d13dp/bin/d13dp network plan --profile web --adopt-filter
sudo --preserve-env=SSH_CONNECTION /opt/d13dp/bin/d13dp network apply \
  --profile web --adopt-filter --expect-plan DIGEST --confirm-timeout 120
# Verify applications externally and open a new SSH connection before confirming.
sudo --preserve-env=SSH_CONNECTION /opt/d13dp/bin/d13dp network confirm TRANSACTION
```

`nftables.service` must already be active and enabled, use table-specific persistent rules, and have safe stop/reload behavior. Installation does not modify that service, SSH, Caddy, or Fail2ban. It installs only the owned empty boot/recovery unit. Without `--adopt-filter`, a previously unowned legacy INPUT remains a blocking conflict. After confirmation, normal policy changes no longer need the adoption flag.

## Transaction and recovery boundaries

The journal records the original legacy file and recognized policy before mutation. Candidate and restoration batches are validated with `nft -c`; an independent systemd rollback timer is armed before either persistent file is changed. Each file replacement is atomic and fsynced; **two files plus the kernel cannot be committed as one filesystem transaction**. The durable pending pointer, timeout worker, and startup recovery cover those intermediate states.

Before confirmation, rollback restores the original legacy file, reconstructs only its recognized INPUT chain, and removes the provisional owned table. After confirmation, rollback of a later port change restores the previous owned policy and leaves the adopted legacy chains intact. Arbitrary historical commits cannot be replayed through `rollback`; use a fresh reviewed policy transaction.

A process killed before the pending pointer leaves an unused transaction record and no changed firewall/configuration. A kill after the pointer is persisted is recovered on the next startup, even if a timer had not yet been armed. A kill after mutation is covered by the timer and boot recovery. Recovery retains pending state if validation, disk writes, netlink operations, or verification fail, allowing explicit retry from the console.

Unknown edits to the retained table block rollback rather than deleting someone else's new rules. A corrupt journal fails closed; the engine never executes saved arbitrary nft text. Existing valid v1 journals remain readable. Root interference, unavailable disk/systemd/kernel/runtime, power-loss storage behavior, and provider access are outside the tested guarantee.
