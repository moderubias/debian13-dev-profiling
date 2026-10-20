# Safe deployment protocol

This release only generates candidate files. It has **no `apply` command**.

Before implementing any automated apply workflow:

1. Confirm Debian 13, machine architecture, actual remote administration path, and out-of-band provider rescue console.
2. Confirm two independent working SSH credentials and identify which key is currently in use.
3. Record all listening ports, service dependencies, current firewall owners, existing dynamic tables, the Docker backend, and IPv6 state.
4. Back up critical configuration and verify an off-host restoration path; record the rescue procedure.
5. Produce a deterministic change plan with expected files, exact diffs, preconditions, impacted services, and plan hash.
6. Run parsers and validators (`sshd -t`, `sshd -T`, `nft -c -f`, `fail2ban-client -t`, `apt-config dump`) before changes.
7. Schedule an out-of-band-capable rollback before changing SSH or firewall rules. Keeping an old SSH session open is useful but not sufficient as proof.
8. Stage and atomically apply only tool-owned resources. Avoid global `flush ruleset`, duplicated Fail2ban jails, and conflicting existing SSH drop-ins.
9. Verify *new* SSH connectivity from a distinct session, affected application health, and expected packet filtering before confirming the transaction.
10. Verify again after service reload and cold reboot in a disposable VM. Only then certify the deployment profile for real servers.

Rollback must cover settings files, service reloading and restoration of effective network state. `systemd-run --on-active` by itself is only a best-effort rollback timer, not a complete remotely supervised safety mechanism.

## Handling a live VPS

Do not test initial automated hardening directly on a production VPS. Use disposable Debian 13 virtual machines with snapshots. Preserve the known-working firewall and SSH setup on existing servers until the tool's executor is built and tested.

## Repeated configuration

Running a configuration action twice must converge to the exact intended state and must neither append duplicate rules nor overwrite unrelated administrator settings. The tool must detect incompatible active configurations and fail closed with an explanation rather than trying to forcibly merge them. Do not confuse idempotent generation of candidate files with safe and idempotent live application.
