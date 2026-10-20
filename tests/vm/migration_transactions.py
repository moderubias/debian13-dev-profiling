"""Migration/recovery tests: this file is destructive ONLY inside the QA VM."""
import json
from pathlib import Path
import sys
import time
import threading
from unittest.mock import patch

sys.path.insert(0, '/tmp')
from network_transactions import guard, run, nft, cli, transition, connect, marker, EchoServer, Echo
from d13dp import migration
from d13dp.network import Controller, NetworkError, encode
from d13dp.network_policy import load_network_policy


def prepare():
    guard()
    # Reset only owned fixtures; real Fail2ban now creates and maintains its own table.
    run('systemctl', 'stop', 'd13dp-network.service', 'fail2ban.service')
    nft('destroy table inet d13dp_network\ndestroy table inet f2b-table\n')
    run('systemctl', 'start', 'fail2ban.service')
    for _ in range(100):
        if run('fail2ban-client', 'ping', check=False).returncode == 0:
            break
        time.sleep(.2)
    else:
        raise AssertionError('Fail2ban did not become ready')
    run('fail2ban-client', 'set', 'sshd', 'banip', '203.0.113.99')
    source = migration.source([22])
    Path('/etc/nftables.conf').write_text(source)
    Path('/etc/nftables.conf').chmod(0o640)
    run('systemctl', 'enable', '--now', 'nftables.service')
    run('nft', '-f', '/etc/nftables.conf')
    # A fresh journal is a test fixture, never a supported deployment operation.
    Path('/var/lib/d13dp/network/state.json').write_bytes(encode({'version': 1, 'committed': None, 'pending': None}))
    Path('/etc/d13dp/network.nft').write_text('# No committed d13dp network policy.\n')
    cli('install', '--adopt-filter')
    return source


def adopted_transition(profile, confirm=True, timeout=120):
    plan = cli('plan', '--profile', profile, '--adopt-filter', remote=True)
    assert not plan['conflicts'], plan
    assert plan['migration'] and plan['legacy_file_diff']
    response = cli('apply', '--profile', profile, '--adopt-filter', '--expect-plan', plan['digest'], '--confirm-timeout', str(timeout), remote=True)
    if confirm:
        cli('confirm', response['transaction'], remote=True)
    return response


def main():
    original = prepare()
    servers = [EchoServer(("::", port), Echo) for port in (80,443)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    assert 'Foreign inbound base chain' in cli('plan', '--profile', 'web', success=False).stdout
    bans = run('nft', '-j', 'list', 'table', 'inet', 'f2b-table').stdout
    retained = [item for item in json.loads(run('nft', '-j', 'list', 'table', 'inet', 'filter').stdout)['nftables']
                if item.get('chain', {}).get('name') in ('forward', 'output')]
    print('Checking recognized migration, new SSH confirmation and real Fail2ban bans', flush=True)
    plan = cli('plan', '--profile', 'web', '--adopt-filter', remote=True)
    before = marker(), Path('/etc/nftables.conf').read_bytes()
    assert cli('apply', '--profile', 'web', '--adopt-filter', '--dry-run', remote=True)['digest'] == plan['digest']
    assert before == (marker(), Path('/etc/nftables.conf').read_bytes())
    adopted_transition('web', confirm=False, timeout=15)
    for address in ('192.0.2.1', 'fd42:13::1'):
        for port in (22,80,443):
            connect(address, port)
    assert migration.table_objects(Controller().rules()) == migration.objects([22], retained=True)
    run('fail2ban-client', 'set', 'sshd', 'banip', '203.0.113.100')
    deadline = time.monotonic() + 30
    while Controller().read_state()['pending'] and time.monotonic() < deadline:
        time.sleep(.5)
    assert Controller().read_state()['pending'] is None
    for address in ('192.0.2.1', 'fd42:13::1'):
        connect(address, 22)
        connect(address, 80, False)
        connect(address, 443, False)
    assert Path('/etc/nftables.conf').stat().st_mode & 0o777 == 0o640
    assert Path('/etc/nftables.conf').read_text() == original
    assert migration.table_objects(Controller().rules()) == migration.objects([22])
    assert '203.0.113.100' in run('nft', 'list', 'table', 'inet', 'f2b-table').stdout
    print('Checking command failure after persistent legacy rewrite and rollback retry', flush=True)
    controller = Controller()
    import d13dp.network as network
    real_run = network.run
    count = 0
    def fail_load(*args, **kwargs):
        nonlocal count
        if args == ('nft', '-f', '-'):
            count += 1
            if count <= 2:
                raise NetworkError('Injected candidate and first rollback load failures')
        return real_run(*args, **kwargs)
    planned = controller.plan(load_network_policy('web'), adopt_filter=True)
    with patch('d13dp.network.run', side_effect=fail_load):
        try:
            controller.apply(load_network_policy('web'), planned['digest'], console=True, adopt_filter=True)
        except NetworkError as exc:
            assert 'rollback failed' in str(exc)
        else:
            raise AssertionError('Command failure was not propagated')
    assert controller.read_state()['pending']
    controller.rollback()
    assert controller.read_state()['pending'] is None
    assert migration.table_objects(controller.rules()) == migration.objects([22])
    print('Checking committed adoption and ten repeated applications', flush=True)
    adopted_transition('web')
    baseline = marker()
    for _ in range(10):
        assert cli('apply', '--profile', 'web', remote=True)['changed'] is False
        assert marker() == baseline
    current = [item for item in json.loads(run('nft', '-j', 'list', 'table', 'inet', 'filter').stdout)['nftables']
               if item.get('chain', {}).get('name') in ('forward', 'output')]
    assert retained == current, 'Unowned chain handles changed'
    transition('minimal')
    assert cli('verify', '--profile', 'minimal')['changed'] is False
    # Live daemon ban must override the new managed SSH allowance.
    run('fail2ban-client', 'set', 'sshd', 'banip', '192.0.2.2')
    connect('192.0.2.1', 22, False)
    run('fail2ban-client', 'set', 'sshd', 'unbanip', '192.0.2.2')
    connect('192.0.2.1', 22)
    print('Checking refusal of reintroduced INPUT, persisted drift and unknown semantics', flush=True)
    nft('add chain inet filter input { type filter hook input priority 0; policy accept; }\n')
    assert 'legacy table drift' in cli('plan', '--profile', 'web', success=False).stdout
    nft('delete chain inet filter input\n')
    saved = Path('/etc/nftables.conf').read_text()
    Path('/etc/nftables.conf').write_text(saved + '# external edit\n')
    assert 'persistent configuration drift' in cli('plan', '--profile', 'web', success=False).stdout
    Path('/etc/nftables.conf').write_text(saved)
    assert next(x['table']['handle'] for x in json.loads(bans)['nftables'] if 'table' in x) == next(x['table']['handle'] for x in json.loads(run('nft', '-j', 'list', 'table', 'inet', 'f2b-table').stdout)['nftables'] if 'table' in x)
    Path('/var/lib/d13dp/qa-migration-passed').write_text('passed\n')
    print('Migration and real Fail2ban checks passed', flush=True)


if __name__ == '__main__':
    main()
