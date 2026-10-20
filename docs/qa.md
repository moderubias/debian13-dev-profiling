# QA report

Date: 2026-10-20. Scope: the supplied v0.1.0 archive, reviewed and corrected for the initial repository publication using OpenAI Codex (GPT-6).

## Findings and fixes

| Finding | Change | Regression coverage |
| --- | --- | --- |
| Invalid TOML value types raised uncaught `TypeError` or `AttributeError`; unknown keys could hide typos | Validate required keys, tables, strings, arrays, integer bounds, module flags, and supported values before use | Invalid schema cases, CLI errors without tracebacks |
| Parent-directory symlinks could redirect output outside the selected directory | Reject symlink files, symlink directory components, escaping generated paths, and non-directory parents during preflight | Existing, dangling, root, ancestor, and nested symlinks; path traversal; preflight preservation |
| Text comparisons silently normalized CRLF and crashed on non-UTF-8 local edits | Compare exact bytes and require `--replace` for any differing content | CRLF, invalid UTF-8, explicit replacement |
| A failure while writing a temporary file could leave it behind | Register the temporary path before writing and clean it in `finally` | Simulated `fsync` failure |
| Switching from `web` to `docker` in one output directory could leave standalone firewall rules behind | Refuse stale known generated files omitted by the selected profile, including with `--replace` | Profile switch preserves all existing files and requests a fresh directory |
| Firewall audit depended on the chain being named `input` and did not distinguish IPv4-only filtering | Read nftables JSON; check input hook, filter type, drop policy, and IPv4/IPv6 families | Arbitrary names; `inet`, `ip`, `ip6`, and `bridge`; malformed JSON |
| Daily upgrades alone could pass without daily package-list refresh or with periodic APT jobs explicitly disabled | Require daily list refresh and upgrades, installed package, successful APT inspection, and no explicit periodic disable | Missing refresh and disabled periodic configuration |
| `--profile` and `--config` could be supplied together with one silently ignored | Make them mutually exclusive | All three profile-based CLI commands |
| Packaging and Debian parser checks were absent from CI | Build source/wheel distributions, install outside the checkout, and run a separate Debian integration job | Three Python versions and Debian 13 container |

The first hosted run exposed deprecated Node.js 20 actions. CI now uses the documented v7 releases of [checkout](https://github.com/actions/checkout) and [setup-python](https://github.com/actions/setup-python), and pins the runner to Ubuntu 24.04 to avoid the announced `ubuntu-latest` migration during validation.

## Executed checks

- All 32 unit tests passed on Python 3.11, 3.13, and 3.14, using isolated temporary files and mocked audit commands.
- Python bytecode compilation passed for source and tests.
- A source distribution and wheel were built successfully; the installed CLI resolved all bundled profiles outside the source checkout.
- A disposable Debian 13 container passed all 32 unit tests against the installed wheel and exercised `plan`, two successive `render` calls, and `manifest` for every profile. Manifest hashes matched the actual file bytes.
- Debian OpenSSH accepted generated SSH configuration through `sshd -t`; `sshd -T` confirmed password authentication was disabled and root login was restricted.
- Debian Fail2ban accepted the generated SSH jail through `fail2ban-client -t`.
- Debian APT parsed generated drop-ins and reported daily unattended upgrades with automatic reboot disabled.
- Both standalone nftables profiles passed `nft -c -f` and loaded twice successfully in the container's network namespace. A separate sentinel table survived both loads; the Docker profile produced no firewall candidate.
- The installed CLI returned a Debian 13 JSON audit and detected the test default-drop input policy. A read-only smoke audit on the Arch Linux development host correctly marked the OS unsupported.

## Reproduce

From the repository root:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
docker build -t d13dp-qa -f tests/integration/Dockerfile .
docker run --rm --network none --cap-add NET_ADMIN d13dp-qa
```

The build requires access to Docker Hub and Debian package mirrors. The run has no external network. `NET_ADMIN` permits test firewall changes inside the disposable container's network namespace; retain network isolation when running this test. No host directories are mounted. The integration runner uses the installed wheel, while configuration parsers come from Debian packages.

On the development host, Docker bridge egress was unavailable, so the image was built using `docker build --network host` to reach Debian mirrors. The actual test run still used `--network none`; no host firewall rules were changed.

## Remaining validation

This is parser and container integration coverage, not production hardening certification. It does not prove packet reachability, SSH access from a remote client, service reload/reboot behavior, AppArmor enforcement, successful scheduled updates, Fail2ban runtime bans, Docker forwarding compatibility, recovery access, or rollback. The sysctl candidates were not applied. Debian VM and independent security review remain future work.

Rendering requires an output directory controlled by the operator. Static symlink checks do not provide protection against concurrent hostile directory replacement. Each file replacement is atomic; the complete set is not transactional on I/O failure. Automatic host configuration remains unimplemented.
