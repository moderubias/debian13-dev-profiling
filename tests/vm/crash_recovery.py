"""Kill the mutating process at durable boundaries inside the disposable VM."""
import json
import os
from pathlib import Path
import signal
import sys
from unittest.mock import patch

sys.path.insert(0, '/tmp')
from network_transactions import guard, run
from migration_transactions import prepare
from d13dp.network import Controller
from d13dp.network_policy import load_network_policy
from d13dp import migration

STAGES = ('transaction', 'pending', 'timer', 'legacy-file', 'owned-file', 'netlink')


def child(stage):
    import d13dp.network as network
    real_atomic, real_run = network.atomic, network.run
    def crash():
        os.kill(os.getpid(), signal.SIGKILL)
    def atomic(path, content, *args, **kwargs):
        real_atomic(path, content, *args, **kwargs)
        target = str(path)
        if ((stage == 'transaction' and '/transactions/' in target)
            or (stage == 'pending' and target.endswith('state.json') and json.loads(content)['pending'])
            or (stage == 'legacy-file' and target == '/etc/nftables.conf')
            or (stage == 'owned-file' and target == '/etc/d13dp/network.nft')):
            crash()
    def command(*args, **kwargs):
        result = real_run(*args, **kwargs)
        if (stage == 'timer' and args[0] == 'systemd-run') or (stage == 'netlink' and args == ('nft', '-f', '-')):
            crash()
        return result
    controller = Controller()
    policy = load_network_policy('web')
    plan = controller.plan(policy, adopt_filter=True)
    with patch('d13dp.network.atomic', side_effect=atomic), patch('d13dp.network.run', side_effect=command):
        controller.apply(policy, plan['digest'], timeout=120, console=True, adopt_filter=True)
    raise AssertionError('Crash point was not reached')


def main():
    guard()
    for stage in STAGES:
        print('SIGKILL at ' + stage, flush=True)
        original = prepare()
        f2b = run('nft', '-j', 'list', 'table', 'inet', 'f2b-table').stdout
        result = run(sys.executable, __file__, '--child', stage, check=False, timeout=120)
        assert result.returncode == -signal.SIGKILL, (stage, result)
        controller = Controller()
        controller.recover()
        assert controller.read_state() == {'version': 1, 'committed': None, 'pending': None}
        assert controller.snapshot(adopt_filter=True) == ([], [])
        assert Path('/etc/nftables.conf').read_text() == original
        assert migration.table_objects(controller.rules()) == migration.objects([22])
        assert run('nft', '-j', 'list', 'table', 'inet', 'f2b-table').stdout == f2b
    # Leave a committed baseline for the general cold-reboot checks.
    controller = Controller()
    policy = load_network_policy('minimal')
    plan = controller.plan(policy, adopt_filter=True)
    response = controller.apply(policy, plan['digest'], console=True, adopt_filter=True)
    controller.confirm(response['transaction'], console=True)
    print('All six SIGKILL recovery boundaries passed', flush=True)


def migration_boot_prepare():
    guard()
    original = prepare()
    controller = Controller()
    policy = load_network_policy('web')
    plan = controller.plan(policy, adopt_filter=True)
    controller.apply(policy, plan['digest'], timeout=120, console=True, adopt_filter=True)
    Path('/var/lib/d13dp/qa-migration-boot-source').write_text(original)
    print('Pending initial migration prepared for cold boot', flush=True)


def migration_boot_check():
    guard()
    controller = Controller()
    assert controller.read_state() == {'version':1,'committed':None,'pending':None}
    assert controller.snapshot(adopt_filter=True) == ([], [])
    assert Path('/etc/nftables.conf').read_text() == Path('/var/lib/d13dp/qa-migration-boot-source').read_text()
    assert Path('/etc/nftables.conf').stat().st_mode & 0o777 == 0o640
    policy = load_network_policy('minimal')
    plan = controller.plan(policy, adopt_filter=True)
    response = controller.apply(policy, plan['digest'], console=True, adopt_filter=True)
    controller.confirm(response['transaction'], console=True)
    print('Initial migration restored its legacy INPUT/file after cold boot', flush=True)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--child']:
        child(sys.argv[2])
    elif sys.argv[1:] == ['--prepare-migration-boot']:
        migration_boot_prepare()
    elif sys.argv[1:] == ['--check-migration-boot']:
        migration_boot_check()
    else:
        main()
