# Kiyoro HTTPS recovery, 2026-10-20

This records a separately authorized live repair, not a production deployment of the experimental network engine. The new engine was **not installed or applied on the VPS**. Development and verification used OpenAI Codex (GPT-6).

## Observed state

SSH access to the Debian 13 VPS at `94.249.172.51` was available. The actual nftables rules showed `inet filter` with INPUT policy drop and TCP 22 allowed, plus loopback, conntrack established/related, ICMP, and IPv6 ICMP. Forward policy was drop and output policy accept. Fail2ban used its own `inet f2b-table`, with two active SSH bans.

`/etc/nftables.conf` replaced only `inet filter`. The existing nftables systemd override already replaced `ExecStop` with `/usr/bin/true`; it was preserved. Caddy listened on wildcard TCP 80/443 and UDP 443, with its admin listener restricted to loopback. The host had IPv4 and link-local IPv6, with no configured global IPv6 address.

Caddy was Debian's `2.6.2-12+deb13u1`. Logs showed Let's Encrypt connection timeouts and a separate ZeroSSL account-registration response `HTTP 422: caddy_legacy_user_removed`. The ZeroSSL failure occurred in the logged EAB/account pre-registration callback, separately from the inbound ACME connection timeouts. Selecting only Let's Encrypt removes that failing fallback; opening HTTP/HTTPS fixes the observed reachability fault. See the [official issuer configuration](https://caddyserver.com/docs/caddyfile/options#acme-ca) and [Caddy installation documentation](https://caddyserver.com/docs/install#debian-ubuntu-raspbian).

## Applied firewall repair

Backups were created under `/root/d13dp-https-recovery-20261020T014315Z` on the VPS. They contain the old persistent firewall file, an owned-table runtime snapshot, Caddy configuration/binary/unit, an archive of Caddy's existing storage, and both old/new Caddy packages. They are root-protected and are not in this repository.

A three-minute independent systemd rollback timer was armed and checked before changing the firewall. A candidate passed `nft -c -f`. The only persistent rule change was:

```diff
-        tcp dport 22 accept
+        tcp dport { 22, 80, 443 } accept
```

The persistent file was replaced atomically and its owned table loaded in one nftables transaction. No global ruleset reset was issued. TCP 22, INPUT drop, conntrack behavior, and the existing forward/output policies remained intact. Fail2ban's separate table and both pre-existing bans survived. The timer was cancelled after a fresh independent SSH connection and external HTTP reachability succeeded. The rollback script and backups remain available on the host.

## Caddy update and certificate issuance

The official stable Caddy APT repository was added with its repository-specific signing key, following the [official package instructions](https://caddyserver.com/docs/install#debian-ubuntu-raspbian). The APT simulation showed only Caddy would be upgraded. The downloaded new binary validated the candidate Caddyfile before installation; its adapted JSON contained a sole Let's Encrypt ACME issuer. Caddy was upgraded to the then-current official stable [v2.11.7](https://github.com/caddyserver/caddy/releases/tag/v2.11.7). No unrelated packages were upgraded or removed.

The following explicit global option was added; the site's content and redirect behavior were preserved:

```caddyfile
{
    acme_ca https://acme-v02.api.letsencrypt.org/directory
}
```

A separate five-minute Caddy rollback timer and the old Debian package covered the upgrade. Caddy was validated and explicitly reloaded/restarted as part of this authorized repair. `www.kiyo.ro` obtained its certificate first. The apex domain temporarily encountered the existing failed-authorization rate limit; Caddy's normal retry subsequently obtained its production certificate at 01:49:16 UTC. No new account or repeated manual issuance requests were used to bypass the limit. Both rollback timers were cancelled only after their respective checks succeeded.

## External verification

Public DNS-over-HTTPS queries returned `kiyo.ro A 94.249.172.51` and `www.kiyo.ro CNAME kiyo.ro`; neither name had an AAAA answer. The development workstation uses a synthetic DNS resolver, so HTTP/TLS probes explicitly resolved each hostname to the VPS IP while retaining normal SNI and certificate validation.

From outside the VPS:

```bash
curl --noproxy '*' --resolve kiyo.ro:80:94.249.172.51 -I http://kiyo.ro
curl --noproxy '*' --resolve kiyo.ro:443:94.249.172.51 -I https://kiyo.ro
curl --noproxy '*' --resolve www.kiyo.ro:443:94.249.172.51 -I https://www.kiyo.ro
openssl s_client -connect 94.249.172.51:443 -servername kiyo.ro </dev/null
```

Observed results: HTTP 308 to HTTPS; apex HTTPS 200; `www` HTTPS 301 to the apex. TLS checks did not use `-k`. The apex leaf certificate's subject and SAN were `kiyo.ro`, issued by Let's Encrypt `YE1`, valid from 2026-10-20 to 2027-01-18. Caddy logs independently confirmed successful production certificate acquisition for both hostnames, including successful public ACME validation from multiple remote addresses.

The provider firewall account/panel was not inspected. Successful external TCP 80/443 connections and public ACME validation demonstrate that it did not block the tested paths at verification time; its complete configured ACL remains unverified. External IPv6 was not tested because this VPS had no global IPv6 address or AAAA records. UDP 443 remains blocked by the declared host policy; HTTP/3 over UDP was not made externally available by this repair, and HTTPS over TCP works.

At completion, `caddy`, `nftables`, and `fail2ban` were active; `nft -c -f /etc/nftables.conf` succeeded, a new SSH session worked, and both original Fail2ban bans remained present. There was no firewall shutdown, SSH reconfiguration, reboot, or deployment of the new transaction engine.
